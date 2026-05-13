"""Python eitb — runs every wrapper × ITB example end-to-end.

Mirrors ``tools/eitb/main.go`` in the root repository, adapted to the
Python binding asymmetry: there is no Streaming No MAC IO-Driven
example (``noaead-easy-io`` / ``noaead-lowlevel-io`` from the Go
matrix), because the Python binding does not expose a file-like /
stream-like wrapper writer/reader pair for Non-AEAD streaming. The
Non-AEAD streaming arm is the User-Driven Loop only.

Matrix: 8 examples × 3 outer ciphers (aes / chacha / siphash) =
24 PASS/FAIL cells.

Examples covered:

  - aead-easy-io               Streaming AEAD Easy   (MAC Authenticated, IO-Driven)
  - aead-lowlevel-io           Streaming AEAD Low-Level (MAC Authenticated, IO-Driven)
  - noaead-easy-userloop       Streaming Easy        (No MAC, User-Driven Loop)
  - noaead-lowlevel-userloop   Streaming Low-Level   (No MAC, User-Driven Loop)
  - message-easy-nomac         Easy Single Message      (No MAC)
  - message-easy-auth          Easy Single Message      (MAC Authenticated)
  - message-lowlevel-nomac     Low-Level Single Message (No MAC)
  - message-lowlevel-auth      Low-Level Single Message (MAC Authenticated)

Single-message examples encrypt 1024 bytes; streaming examples
encrypt 64 KiB through 16 KiB chunks. Each example runs sender +
receiver in the same process, wraps the ITB ciphertext under the
chosen outer cipher, hands the wrapped bytes to the receiver path,
and verifies sha256 byte-equality of the recovered plaintext
against the original.

Usage::

    PYTHONPATH=bindings/python python3 -m bindings.python.eitb.eitb
    PYTHONPATH=bindings/python python3 -m bindings.python.eitb.eitb --example aead
    PYTHONPATH=bindings/python python3 -m bindings.python.eitb.eitb --cipher aes -v
"""

from __future__ import annotations

import argparse
import hashlib
import io
import os
import secrets
import struct
import sys
from pathlib import Path

HERE = Path(__file__).resolve()
sys.path.insert(0, str(HERE.parents[1]))

import itb  # noqa: E402
from itb import wrapper  # noqa: E402


SINGLE_MESSAGE_BYTES = 1024
STREAM_BYTES = 64 * 1024
STREAM_CHUNK_SIZE = 16 * 1024


# --------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------


def _sha256_short(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()[:16]


def _seeds_512(n: int):
    """Builds n width-512 seeds at 1024-bit ITB key width under
    Areion-SoEM-512. Mirrors :func:`itb.NewSeed512` from the Go
    side — every example uses the same seed factory."""
    return [itb.Seed("areion512", 1024) for _ in range(n)]


def _free_seeds(seeds):
    for s in seeds:
        s.free()


# --------------------------------------------------------------------
# Streaming AEAD Easy (MAC Authenticated, IO-Driven)
# --------------------------------------------------------------------
#
# Sender uses :class:`itb.StreamEncryptorAuth` driven by the
# :class:`itb.Encryptor.encrypt_stream_auth` style FFI helper. The
# format-deniability layer wraps the entire bytestream under one
# WrapStreamWriter — the 32-byte stream prefix + every per-chunk
# wire all XOR through one keystream session. Receiver reverses
# with UnwrapStreamReader feeding StreamDecryptorAuth.


def run_aead_easy_io(cipher_name: str, plaintext: bytes):
    enc = itb.Encryptor("areion512", 1024, "hmac-blake3", mode=1)
    enc.set_nonce_bits(512)
    enc.set_barrier_fill(4)
    enc.set_bit_soup(1)
    enc.set_lock_soup(1)

    outer_key = wrapper.generate_key(cipher_name)

    try:
        # Sender — wrap the streaming AEAD bytestream end-to-end.
        wire_buf = io.BytesIO()
        with wrapper.WrapStreamWriter(cipher_name, outer_key) as ww:
            wire_buf.write(ww.nonce)
            inner_buf = io.BytesIO()
            enc.encrypt_stream_auth(io.BytesIO(plaintext), inner_buf, chunk_size=STREAM_CHUNK_SIZE)
            wire_buf.write(ww.update(inner_buf.getvalue()))
        wrapped_wire = wire_buf.getvalue()

        # Receiver — strip the leading nonce, unwrap the body, decrypt.
        nonce_len = wrapper.nonce_size(cipher_name)
        nonce_part = wrapped_wire[:nonce_len]
        body_part = wrapped_wire[nonce_len:]
        with wrapper.UnwrapStreamReader(cipher_name, outer_key, nonce_part) as ur:
            inner_wire = ur.update(body_part)
        out_buf = io.BytesIO()
        enc.decrypt_stream_auth(io.BytesIO(inner_wire), out_buf)
        return out_buf.getvalue(), len(wrapped_wire), None
    except Exception as e:
        return b"", 0, e
    finally:
        enc.close()


# --------------------------------------------------------------------
# Streaming AEAD Low-Level (MAC Authenticated, IO-Driven)
# --------------------------------------------------------------------
#
# Drives the low-level :func:`itb.encrypt_stream_auth` /
# :func:`itb.decrypt_stream_auth` over the wrap-writer / unwrap-
# reader. Three explicit Seed handles + an HMAC-BLAKE3 MAC handle.


def run_aead_lowlevel_io(cipher_name: str, plaintext: bytes):
    itb.set_nonce_bits(512)
    itb.set_barrier_fill(4)
    itb.set_bit_soup(1)
    itb.set_lock_soup(1)

    seeds = _seeds_512(3)
    mac_key = secrets.token_bytes(32)
    mac = itb.MAC("hmac-blake3", mac_key)
    outer_key = wrapper.generate_key(cipher_name)

    try:
        wire_buf = io.BytesIO()
        with wrapper.WrapStreamWriter(cipher_name, outer_key) as ww:
            wire_buf.write(ww.nonce)
            inner_buf = io.BytesIO()
            itb.encrypt_stream_auth(*seeds, mac, io.BytesIO(plaintext), inner_buf, chunk_size=STREAM_CHUNK_SIZE)
            wire_buf.write(ww.update(inner_buf.getvalue()))
        wrapped_wire = wire_buf.getvalue()

        nonce_len = wrapper.nonce_size(cipher_name)
        nonce_part = wrapped_wire[:nonce_len]
        body_part = wrapped_wire[nonce_len:]
        with wrapper.UnwrapStreamReader(cipher_name, outer_key, nonce_part) as ur:
            inner_wire = ur.update(body_part)
        out_buf = io.BytesIO()
        itb.decrypt_stream_auth(*seeds, mac, io.BytesIO(inner_wire), out_buf)
        return out_buf.getvalue(), len(wrapped_wire), None
    except Exception as e:
        return b"", 0, e
    finally:
        mac.free()
        _free_seeds(seeds)


# --------------------------------------------------------------------
# Streaming Easy (No MAC, User-Driven Loop)
# --------------------------------------------------------------------
#
# Per-chunk :meth:`itb.Encryptor.encrypt` / :meth:`decrypt` with
# caller-side framing. Each chunk is emitted as ``u32_LE_len || ct``
# through the WrapStreamWriter; the length prefix and the body XOR
# through the keystream together so neither appears in cleartext on
# the wire.


def run_noaead_easy_userloop(cipher_name: str, plaintext: bytes):
    enc = itb.Encryptor("areion512", 1024, mac=None, mode=1)
    enc.set_nonce_bits(512)
    enc.set_barrier_fill(4)
    enc.set_bit_soup(1)
    enc.set_lock_soup(1)

    outer_key = wrapper.generate_key(cipher_name)

    try:
        # Sender
        wire_buf = io.BytesIO()
        with wrapper.WrapStreamWriter(cipher_name, outer_key) as ww:
            wire_buf.write(ww.nonce)
            for off in range(0, len(plaintext), STREAM_CHUNK_SIZE):
                chunk = plaintext[off : off + STREAM_CHUNK_SIZE]
                ct = enc.encrypt(chunk)
                wire_buf.write(ww.update(struct.pack("<I", len(ct))))
                wire_buf.write(ww.update(ct))
        wrapped_wire = wire_buf.getvalue()

        # Receiver
        nonce_len = wrapper.nonce_size(cipher_name)
        nonce_part = wrapped_wire[:nonce_len]
        body_part = wrapped_wire[nonce_len:]
        recovered_buf = io.BytesIO()
        with wrapper.UnwrapStreamReader(cipher_name, outer_key, nonce_part) as ur:
            decrypted = ur.update(body_part)
        # Walk the decrypted byte stream chunk by chunk using the
        # 4-byte LE length prefix.
        view = memoryview(decrypted)
        off = 0
        while off < len(view):
            if off + 4 > len(view):
                raise RuntimeError("truncated length prefix")
            (clen,) = struct.unpack("<I", bytes(view[off : off + 4]))
            off += 4
            ct = bytes(view[off : off + clen])
            off += clen
            recovered_buf.write(enc.decrypt(ct))
        return recovered_buf.getvalue(), len(wrapped_wire), None
    except Exception as e:
        return b"", 0, e
    finally:
        enc.close()


# --------------------------------------------------------------------
# Streaming Low-Level (No MAC, User-Driven Loop)
# --------------------------------------------------------------------


def run_noaead_lowlevel_userloop(cipher_name: str, plaintext: bytes):
    itb.set_nonce_bits(512)
    itb.set_barrier_fill(4)
    itb.set_bit_soup(1)
    itb.set_lock_soup(1)

    seeds = _seeds_512(3)
    outer_key = wrapper.generate_key(cipher_name)

    try:
        wire_buf = io.BytesIO()
        with wrapper.WrapStreamWriter(cipher_name, outer_key) as ww:
            wire_buf.write(ww.nonce)
            for off in range(0, len(plaintext), STREAM_CHUNK_SIZE):
                chunk = plaintext[off : off + STREAM_CHUNK_SIZE]
                ct = itb.encrypt(*seeds, chunk)
                wire_buf.write(ww.update(struct.pack("<I", len(ct))))
                wire_buf.write(ww.update(ct))
        wrapped_wire = wire_buf.getvalue()

        nonce_len = wrapper.nonce_size(cipher_name)
        nonce_part = wrapped_wire[:nonce_len]
        body_part = wrapped_wire[nonce_len:]
        recovered_buf = io.BytesIO()
        with wrapper.UnwrapStreamReader(cipher_name, outer_key, nonce_part) as ur:
            decrypted = ur.update(body_part)
        view = memoryview(decrypted)
        off = 0
        while off < len(view):
            if off + 4 > len(view):
                raise RuntimeError("truncated length prefix")
            (clen,) = struct.unpack("<I", bytes(view[off : off + 4]))
            off += 4
            ct = bytes(view[off : off + clen])
            off += clen
            recovered_buf.write(itb.decrypt(*seeds, ct))
        return recovered_buf.getvalue(), len(wrapped_wire), None
    except Exception as e:
        return b"", 0, e
    finally:
        _free_seeds(seeds)


# --------------------------------------------------------------------
# Single Message — Easy: Areion-SoEM-512 (No MAC)
#
# One enc.encrypt() call → one ITB blob. WrapInPlace mutates the
# blob and returns the per-stream nonce; the caller composes
# nonce || mutated-blob to produce the wire. UnwrapInPlace mutates
# the wire and returns an aliased view over the recovered blob.
# --------------------------------------------------------------------


def run_message_easy_nomac(cipher_name: str, plaintext: bytes):
    enc = itb.Encryptor("areion512", 2048, mac=None, mode=1)
    enc.set_nonce_bits(512)
    enc.set_barrier_fill(4)
    enc.set_bit_soup(1)
    enc.set_lock_soup(1)

    outer_key = wrapper.generate_key(cipher_name)

    try:
        encrypted = enc.encrypt(plaintext)
        # Wrap respects immutability of `encrypted` (allocates a fresh wire buffer).
        # wire = wrapper.wrap(cipher_name, outer_key, encrypted)
        mutable_blob = bytearray(encrypted)
        nonce = wrapper.wrap_in_place(cipher_name, outer_key, mutable_blob)
        wire = bytes(nonce) + bytes(mutable_blob)

        # Receiver
        # Unwrap respects immutability of `wire` (allocates a fresh recovered buffer).
        # recovered = wrapper.unwrap(cipher_name, outer_key, wire)
        wire_buf = bytearray(wire)
        recovered_view = wrapper.unwrap_in_place(cipher_name, outer_key, wire_buf)
        recovered = bytes(recovered_view)

        pt = enc.decrypt(recovered)
        return pt, len(wire), None
    except Exception as e:
        return b"", 0, e
    finally:
        enc.close()


# --------------------------------------------------------------------
# Single Message — Easy: Areion-SoEM-512 + HMAC-BLAKE3 (MAC Authenticated)
# --------------------------------------------------------------------


def run_message_easy_auth(cipher_name: str, plaintext: bytes):
    enc = itb.Encryptor("areion512", 2048, "hmac-blake3", mode=1)
    enc.set_nonce_bits(512)
    enc.set_barrier_fill(4)
    enc.set_bit_soup(1)
    enc.set_lock_soup(1)

    outer_key = wrapper.generate_key(cipher_name)

    try:
        encrypted = enc.encrypt_auth(plaintext)
        # Wrap respects immutability of `encrypted` (allocates a fresh wire buffer).
        # wire = wrapper.wrap(cipher_name, outer_key, encrypted)
        mutable_blob = bytearray(encrypted)
        nonce = wrapper.wrap_in_place(cipher_name, outer_key, mutable_blob)
        wire = bytes(nonce) + bytes(mutable_blob)

        # Unwrap respects immutability of `wire` (allocates a fresh recovered buffer).
        # recovered = wrapper.unwrap(cipher_name, outer_key, wire)
        wire_buf = bytearray(wire)
        recovered_view = wrapper.unwrap_in_place(cipher_name, outer_key, wire_buf)
        recovered = bytes(recovered_view)

        pt = enc.decrypt_auth(recovered)
        return pt, len(wire), None
    except Exception as e:
        return b"", 0, e
    finally:
        enc.close()


# --------------------------------------------------------------------
# Single Message — Low-Level: Areion-SoEM-512 (No MAC)
# --------------------------------------------------------------------


def run_message_lowlevel_nomac(cipher_name: str, plaintext: bytes):
    itb.set_nonce_bits(512)
    itb.set_barrier_fill(4)
    itb.set_bit_soup(1)
    itb.set_lock_soup(1)

    seeds = [itb.Seed("areion512", 2048) for _ in range(3)]
    outer_key = wrapper.generate_key(cipher_name)

    try:
        encrypted = itb.encrypt(*seeds, plaintext)
        # Wrap respects immutability of `encrypted` (allocates a fresh wire buffer).
        # wire = wrapper.wrap(cipher_name, outer_key, encrypted)
        mutable_blob = bytearray(encrypted)
        nonce = wrapper.wrap_in_place(cipher_name, outer_key, mutable_blob)
        wire = bytes(nonce) + bytes(mutable_blob)

        # Unwrap respects immutability of `wire` (allocates a fresh recovered buffer).
        # recovered = wrapper.unwrap(cipher_name, outer_key, wire)
        wire_buf = bytearray(wire)
        recovered_view = wrapper.unwrap_in_place(cipher_name, outer_key, wire_buf)
        recovered = bytes(recovered_view)

        pt = itb.decrypt(*seeds, recovered)
        return pt, len(wire), None
    except Exception as e:
        return b"", 0, e
    finally:
        _free_seeds(seeds)


# --------------------------------------------------------------------
# Single Message — Low-Level: Areion-SoEM-512 + HMAC-BLAKE3 (MAC Authenticated)
# --------------------------------------------------------------------


def run_message_lowlevel_auth(cipher_name: str, plaintext: bytes):
    itb.set_nonce_bits(512)
    itb.set_barrier_fill(4)
    itb.set_bit_soup(1)
    itb.set_lock_soup(1)

    seeds = [itb.Seed("areion512", 2048) for _ in range(3)]
    mac_key = secrets.token_bytes(32)
    mac = itb.MAC("hmac-blake3", mac_key)
    outer_key = wrapper.generate_key(cipher_name)

    try:
        encrypted = itb.encrypt_auth(*seeds, mac, plaintext)
        # Wrap respects immutability of `encrypted` (allocates a fresh wire buffer).
        # wire = wrapper.wrap(cipher_name, outer_key, encrypted)
        mutable_blob = bytearray(encrypted)
        nonce = wrapper.wrap_in_place(cipher_name, outer_key, mutable_blob)
        wire = bytes(nonce) + bytes(mutable_blob)

        # Unwrap respects immutability of `wire` (allocates a fresh recovered buffer).
        # recovered = wrapper.unwrap(cipher_name, outer_key, wire)
        wire_buf = bytearray(wire)
        recovered_view = wrapper.unwrap_in_place(cipher_name, outer_key, wire_buf)
        recovered = bytes(recovered_view)

        pt = itb.decrypt_auth(*seeds, mac, recovered)
        return pt, len(wire), None
    except Exception as e:
        return b"", 0, e
    finally:
        mac.free()
        _free_seeds(seeds)


# --------------------------------------------------------------------
# Matrix runner
# --------------------------------------------------------------------


EXAMPLES = [
    ("aead-easy-io", "Streaming AEAD Easy (MAC Authenticated, IO-Driven)", STREAM_BYTES, run_aead_easy_io),
    ("aead-lowlevel-io", "Streaming AEAD Low-Level (MAC Authenticated, IO-Driven)", STREAM_BYTES, run_aead_lowlevel_io),
    ("noaead-easy-userloop", "Streaming Easy (No MAC, User-Driven Loop)", STREAM_BYTES, run_noaead_easy_userloop),
    ("noaead-lowlevel-userloop", "Streaming Low-Level (No MAC, User-Driven Loop)", STREAM_BYTES, run_noaead_lowlevel_userloop),
    ("message-easy-nomac", "Easy: Areion-SoEM-512 (No MAC, Single Message)", SINGLE_MESSAGE_BYTES, run_message_easy_nomac),
    ("message-easy-auth", "Easy: Areion-SoEM-512 + HMAC-BLAKE3 (MAC Authenticated, Single Message)", SINGLE_MESSAGE_BYTES, run_message_easy_auth),
    ("message-lowlevel-nomac", "Low-Level: Areion-SoEM-512 (No MAC, Single Message)", SINGLE_MESSAGE_BYTES, run_message_lowlevel_nomac),
    ("message-lowlevel-auth", "Low-Level: Areion-SoEM-512 + HMAC-BLAKE3 (MAC Authenticated, Single Message)", SINGLE_MESSAGE_BYTES, run_message_lowlevel_auth),
]


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Python eitb runner — wrapper × ITB binding example matrix"
    )
    parser.add_argument(
        "--example", default="",
        help="run only examples whose name contains this substring",
    )
    parser.add_argument(
        "--cipher", default="",
        help="run only the given outer cipher (aes|chacha|siphash)",
    )
    parser.add_argument(
        "-v", "--verbose", action="store_true",
        help="print per-run details",
    )
    args = parser.parse_args(argv)

    itb.set_max_workers(0)

    pass_count = 0
    fail_count = 0
    rows = []

    for name, desc, ptN, fn in EXAMPLES:
        if args.example and args.example not in name:
            continue
        for cipher_name in wrapper.CIPHER_NAMES:
            if args.cipher and cipher_name != args.cipher:
                continue
            plaintext = secrets.token_bytes(ptN)
            recovered, wire_n, err = fn(cipher_name, plaintext)
            ok = err is None and recovered == plaintext
            if ok:
                pass_count += 1
                tag = "PASS"
            else:
                fail_count += 1
                tag = "FAIL"
            line = f"[{tag}] {name:<26s} + {cipher_name:<8s}   pt={ptN} wire={wire_n}"
            if not ok and err is not None:
                line += f"  err: {err!r}"
            elif not ok:
                line += (
                    f"  err: plaintext hash mismatch "
                    f"(pt={_sha256_short(plaintext)} rcv={_sha256_short(recovered)})"
                )
            print(line)
            if args.verbose and ok:
                print(f"       pt sha256:  {hashlib.sha256(plaintext).hexdigest()}")
                print(f"       rcv sha256: {hashlib.sha256(recovered).hexdigest()}")
            rows.append((name, cipher_name, ok))

    print()
    print(f"=== Summary: {pass_count} PASS, {fail_count} FAIL ===")
    if fail_count > 0:
        sys.exit(1)


if __name__ == "__main__":
    main()
