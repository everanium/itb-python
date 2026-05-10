"""Format-deniability wrapper benchmarks for the Python binding.

Mirrors ``wrapper/bench_test.go`` from the root repository, adapted
for the Python binding asymmetry: the Streaming No MAC arm covers
only the User-Driven Loop variant (the binding does not expose a
file-like Streaming No MAC writer / reader pair).

Total sub-bench count: **102**.

  - Wrapper Only round-trip (16 MiB blob)              :  6  ( 3 ciphers × 2 variants {Wrap, WrapInPlace} )
  - Message Single — 4 modes × 3 ciphers × 2 dirs      : 24
  - Message Triple — 4 modes × 3 ciphers × 2 dirs      : 24
  - Streaming Single — 4 modes × 3 ciphers × 2 dirs    : 24
  - Streaming Triple — 4 modes × 3 ciphers × 2 dirs    : 24

The 4 streaming modes are:

  - ``aead-easy-io``                Streaming AEAD Easy (MAC Authenticated, IO-Driven)
  - ``aead-lowlevel-io``            Streaming AEAD Low-Level (MAC Authenticated, IO-Driven)
  - ``noaead-easy-userloop``        Streaming Easy (No MAC, User-Driven Loop)
  - ``noaead-lowlevel-userloop``    Streaming Low-Level (No MAC, User-Driven Loop)

Both encrypt and decrypt are timed separately (split sub-benches
``…/encrypt`` and ``…/decrypt``) so the per-direction breakdown is
visible. Decrypt benches refresh the working wire from a pristine
copy each iteration; the memcpy is included in the timed total.

Run with::

    PYTHONPATH=bindings/python python3 -m bindings.python.wrapper.benchmarks.bench_wrapper

    ITB_BENCH_FILTER=BenchmarkWrapperOnly \\
        PYTHONPATH=bindings/python python3 -m bindings.python.wrapper.benchmarks.bench_wrapper

    ITB_BENCH_FILTER=BenchmarkStreamingTriple \\
        PYTHONPATH=bindings/python python3 -m bindings.python.wrapper.benchmarks.bench_wrapper

The harness emits one Go-bench-style line per case (name, iters,
ns/op, MB/s).
"""

from __future__ import annotations

import io
import secrets
import struct
from typing import Callable, List, Tuple

import itb
from itb import wrapper

from . import _common


# --------------------------------------------------------------------
# Configuration
# --------------------------------------------------------------------

CIPHERS: Tuple[str, ...] = (
    wrapper.CIPHER_AES128_CTR,
    wrapper.CIPHER_CHACHA20,
    wrapper.CIPHER_SIPHASH24,
)

PRIMITIVE = "areion512"
KEY_BITS = 1024
MAC_NAME = "hmac-blake3"

WRAPPER_PAYLOAD_BYTES = _common.PAYLOAD_16MB  # 16 MiB
MESSAGE_PAYLOAD_BYTES = _common.PAYLOAD_16MB  # 16 MiB
STREAM_PAYLOAD_BYTES = _common.PAYLOAD_64MB  # 64 MiB
STREAM_CHUNK_SIZE = _common.PAYLOAD_16MB  # 16 MiB


# --------------------------------------------------------------------
# Wrapper Only round-trip — pure outer cipher cost (no ITB)
# --------------------------------------------------------------------


def _make_wrapper_only_wrap_case(cipher_name: str) -> _common.BenchCase:
    name = f"BenchmarkWrapperOnlyWrap/{cipher_name}"
    payload = _common.random_bytes(WRAPPER_PAYLOAD_BYTES)
    key = wrapper.generate_key(cipher_name)

    def fn(iters: int) -> None:
        for _ in range(iters):
            wire = wrapper.wrap(cipher_name, key, payload)
            _ = wrapper.unwrap(cipher_name, key, wire)

    return (name, fn, WRAPPER_PAYLOAD_BYTES)


def _make_wrapper_only_inplace_case(cipher_name: str) -> _common.BenchCase:
    name = f"BenchmarkWrapperOnlyInPlace/{cipher_name}"
    payload = _common.random_bytes(WRAPPER_PAYLOAD_BYTES)
    key = wrapper.generate_key(cipher_name)
    nlen = wrapper.nonce_size(cipher_name)

    def fn(iters: int) -> None:
        # Steady state: a single re-used bytearray. Each iter writes
        # a fresh blob, wraps in place, then unwraps in place.
        buf = bytearray(payload)
        for _ in range(iters):
            # Refresh contents to keep work realistic.
            buf[:] = payload
            nonce = wrapper.wrap_in_place(cipher_name, key, buf)
            wire = bytearray(nonce + bytes(buf))
            _ = wrapper.unwrap_in_place(cipher_name, key, wire)

    return (name, fn, WRAPPER_PAYLOAD_BYTES)


def _build_wrapper_only_cases() -> List[_common.BenchCase]:
    cases: List[_common.BenchCase] = []
    for cn in CIPHERS:
        cases.append(_make_wrapper_only_wrap_case(cn))
        cases.append(_make_wrapper_only_inplace_case(cn))
    return cases


# --------------------------------------------------------------------
# Message benches — Easy + Low-Level × {nomac, auth} × {Single, Triple}
# --------------------------------------------------------------------


def _new_easy_encryptor(mode: int, with_mac: bool) -> itb.Encryptor:
    enc = itb.Encryptor(
        PRIMITIVE, KEY_BITS,
        MAC_NAME if with_mac else None,
        mode=mode,
    )
    enc.set_nonce_bits(128)
    enc.set_barrier_fill(1)
    enc.set_bit_soup(0)
    enc.set_lock_soup(0)
    return enc


def _make_message_encrypt_case(
    label: str,
    mode_name: str,  # "single" / "triple"
    cipher_name: str,
    encryptor_factory: Callable[[], itb.Encryptor],
    auth: bool,
) -> _common.BenchCase:
    name = f"BenchmarkMessage{mode_name.capitalize()}/{label}/{cipher_name}/encrypt"
    payload = _common.random_bytes(MESSAGE_PAYLOAD_BYTES)
    enc = encryptor_factory()
    key = wrapper.generate_key(cipher_name)

    def fn(iters: int) -> None:
        for _ in range(iters):
            ct = enc.encrypt_auth(payload) if auth else enc.encrypt(payload)
            _ = wrapper.wrap(cipher_name, key, ct)

    return (name, fn, MESSAGE_PAYLOAD_BYTES)


def _make_message_decrypt_case(
    label: str,
    mode_name: str,
    cipher_name: str,
    encryptor_factory: Callable[[], itb.Encryptor],
    auth: bool,
) -> _common.BenchCase:
    name = f"BenchmarkMessage{mode_name.capitalize()}/{label}/{cipher_name}/decrypt"
    payload = _common.random_bytes(MESSAGE_PAYLOAD_BYTES)
    enc = encryptor_factory()
    key = wrapper.generate_key(cipher_name)
    ct = enc.encrypt_auth(payload) if auth else enc.encrypt(payload)
    pristine_wire = wrapper.wrap(cipher_name, key, ct)

    def fn(iters: int) -> None:
        for _ in range(iters):
            # Refresh wire from pristine copy each iter so the unwrap-
            # decrypt pair sees a valid input every time. The memcpy
            # is included in the timed total — same convention as
            # wrapper/bench_test.go.
            wire = bytes(pristine_wire)
            recovered = wrapper.unwrap(cipher_name, key, wire)
            _ = enc.decrypt_auth(recovered) if auth else enc.decrypt(recovered)

    return (name, fn, MESSAGE_PAYLOAD_BYTES)


def _build_message_cases(mode: int) -> List[_common.BenchCase]:
    """Build the 24 message sub-benches for one mode (Single = mode 1
    or Triple = mode 3). Order is (mode/cipher/direction)."""
    mode_name = "single" if mode == 1 else "triple"
    labels = [
        ("easy-nomac", lambda: _new_easy_encryptor(mode, with_mac=False), False),
        ("easy-auth", lambda: _new_easy_encryptor(mode, with_mac=True), True),
        ("lowlevel-nomac", lambda: _new_easy_encryptor(mode, with_mac=False), False),
        ("lowlevel-auth", lambda: _new_easy_encryptor(mode, with_mac=True), True),
    ]
    cases: List[_common.BenchCase] = []
    for label, factory, auth in labels:
        for cipher_name in CIPHERS:
            cases.append(_make_message_encrypt_case(label, mode_name, cipher_name, factory, auth))
            cases.append(_make_message_decrypt_case(label, mode_name, cipher_name, factory, auth))
    return cases


# --------------------------------------------------------------------
# Streaming benches — 4 modes × 3 ciphers × 2 dirs × {Single, Triple}
# --------------------------------------------------------------------


def _stream_encrypt_aead_io(
    mode: int, cipher_name: str, plaintext: bytes,
) -> bytes:
    """Encrypt a Streaming AEAD plaintext blob through the wrap-writer
    end-to-end. Mirrors run_aead_easy_io in eitb.py — full bytestream
    XOR through a single keystream session."""
    enc = _new_easy_encryptor(mode, with_mac=True)
    outer_key = wrapper.generate_key(cipher_name)
    try:
        wire_buf = io.BytesIO()
        with wrapper.WrapStreamWriter(cipher_name, outer_key) as ww:
            wire_buf.write(ww.nonce)
            inner = io.BytesIO()
            enc.encrypt_stream_auth(io.BytesIO(plaintext), inner, chunk_size=STREAM_CHUNK_SIZE)
            wire_buf.write(ww.update(inner.getvalue()))
        return outer_key, wire_buf.getvalue()
    finally:
        enc.close()


def _stream_decrypt_aead_io(
    mode: int, cipher_name: str, outer_key: bytes, wire: bytes,
) -> bytes:
    enc = _new_easy_encryptor(mode, with_mac=True)
    try:
        nlen = wrapper.nonce_size(cipher_name)
        with wrapper.UnwrapStreamReader(cipher_name, outer_key, wire[:nlen]) as ur:
            inner = ur.update(wire[nlen:])
        out = io.BytesIO()
        enc.decrypt_stream_auth(io.BytesIO(inner), out)
        return out.getvalue()
    finally:
        enc.close()


def _stream_encrypt_userloop(
    mode: int, cipher_name: str, plaintext: bytes, with_mac: bool = False,
) -> Tuple[bytes, bytes]:
    """User-Driven Loop: per-chunk Encryptor.encrypt() with caller
    framing through the wrap-writer."""
    enc = _new_easy_encryptor(mode, with_mac=False)
    outer_key = wrapper.generate_key(cipher_name)
    try:
        wire_buf = io.BytesIO()
        with wrapper.WrapStreamWriter(cipher_name, outer_key) as ww:
            wire_buf.write(ww.nonce)
            for off in range(0, len(plaintext), STREAM_CHUNK_SIZE):
                chunk = plaintext[off : off + STREAM_CHUNK_SIZE]
                ct = enc.encrypt(chunk)
                wire_buf.write(ww.update(struct.pack("<I", len(ct))))
                wire_buf.write(ww.update(ct))
        return outer_key, wire_buf.getvalue()
    finally:
        enc.close()


def _stream_decrypt_userloop(
    mode: int, cipher_name: str, outer_key: bytes, wire: bytes,
) -> bytes:
    enc = _new_easy_encryptor(mode, with_mac=False)
    try:
        nlen = wrapper.nonce_size(cipher_name)
        with wrapper.UnwrapStreamReader(cipher_name, outer_key, wire[:nlen]) as ur:
            inner = ur.update(wire[nlen:])
        out = io.BytesIO()
        view = memoryview(inner)
        off = 0
        while off < len(view):
            (clen,) = struct.unpack("<I", bytes(view[off : off + 4]))
            off += 4
            ct = bytes(view[off : off + clen])
            off += clen
            out.write(enc.decrypt(ct))
        return out.getvalue()
    finally:
        enc.close()


def _make_stream_aead_io_encrypt_case(
    label: str, mode: int, cipher_name: str,
) -> _common.BenchCase:
    mode_name = "single" if mode == 1 else "triple"
    name = f"BenchmarkStreaming{mode_name.capitalize()}/{label}/{cipher_name}/encrypt"
    payload = _common.random_bytes(STREAM_PAYLOAD_BYTES)

    def fn(iters: int) -> None:
        for _ in range(iters):
            _stream_encrypt_aead_io(mode, cipher_name, payload)

    return (name, fn, STREAM_PAYLOAD_BYTES)


def _make_stream_aead_io_decrypt_case(
    label: str, mode: int, cipher_name: str,
) -> _common.BenchCase:
    mode_name = "single" if mode == 1 else "triple"
    name = f"BenchmarkStreaming{mode_name.capitalize()}/{label}/{cipher_name}/decrypt"
    payload = _common.random_bytes(STREAM_PAYLOAD_BYTES)

    # Streaming AEAD MAC binding ties the wire to the encryptor's
    # seeds + MAC key. Build one long-lived encryptor up front, use
    # it to produce the pristine wire, then reuse the same encryptor
    # in the timed decrypt loop. Mirrors runAEADEasyIODecrypt in
    # wrapper/bench_test.go: the Go reference also pins one encryptor
    # across the setup + per-iteration body.
    enc = _new_easy_encryptor(mode, with_mac=True)
    outer_key = wrapper.generate_key(cipher_name)
    wire_buf = io.BytesIO()
    with wrapper.WrapStreamWriter(cipher_name, outer_key) as ww:
        wire_buf.write(ww.nonce)
        inner = io.BytesIO()
        enc.encrypt_stream_auth(io.BytesIO(payload), inner, chunk_size=STREAM_CHUNK_SIZE)
        wire_buf.write(ww.update(inner.getvalue()))
    pristine_wire = wire_buf.getvalue()
    nlen = wrapper.nonce_size(cipher_name)

    def fn(iters: int) -> None:
        for _ in range(iters):
            wire = bytes(pristine_wire)
            with wrapper.UnwrapStreamReader(cipher_name, outer_key, wire[:nlen]) as ur:
                inner_wire = ur.update(wire[nlen:])
            out = io.BytesIO()
            enc.decrypt_stream_auth(io.BytesIO(inner_wire), out)

    return (name, fn, STREAM_PAYLOAD_BYTES)


def _make_stream_userloop_encrypt_case(
    label: str, mode: int, cipher_name: str,
) -> _common.BenchCase:
    mode_name = "single" if mode == 1 else "triple"
    name = f"BenchmarkStreaming{mode_name.capitalize()}/{label}/{cipher_name}/encrypt"
    payload = _common.random_bytes(STREAM_PAYLOAD_BYTES)

    def fn(iters: int) -> None:
        for _ in range(iters):
            _stream_encrypt_userloop(mode, cipher_name, payload)

    return (name, fn, STREAM_PAYLOAD_BYTES)


def _make_stream_userloop_decrypt_case(
    label: str, mode: int, cipher_name: str,
) -> _common.BenchCase:
    mode_name = "single" if mode == 1 else "triple"
    name = f"BenchmarkStreaming{mode_name.capitalize()}/{label}/{cipher_name}/decrypt"
    payload = _common.random_bytes(STREAM_PAYLOAD_BYTES)

    # No MAC user-loop wire still depends on encryptor seeds for
    # correct plaintext recovery. Pin one encryptor across the
    # pristine-wire setup and the timed decrypt loop so the per-chunk
    # decrypt() observes the same seed material that produced the
    # ciphertext. Without a MAC the mismatch surfaces as silent
    # garbage rather than a visible FAIL, but the throughput then
    # measures wrong-plaintext work — pinning the encryptor matches
    # both correctness and the wrapper/bench_test.go pattern.
    enc = _new_easy_encryptor(mode, with_mac=False)
    outer_key = wrapper.generate_key(cipher_name)
    wire_buf = io.BytesIO()
    with wrapper.WrapStreamWriter(cipher_name, outer_key) as ww:
        wire_buf.write(ww.nonce)
        for off in range(0, len(payload), STREAM_CHUNK_SIZE):
            chunk = payload[off : off + STREAM_CHUNK_SIZE]
            ct = enc.encrypt(chunk)
            wire_buf.write(ww.update(struct.pack("<I", len(ct))))
            wire_buf.write(ww.update(ct))
    pristine_wire = wire_buf.getvalue()
    nlen = wrapper.nonce_size(cipher_name)

    def fn(iters: int) -> None:
        for _ in range(iters):
            wire = bytes(pristine_wire)
            with wrapper.UnwrapStreamReader(cipher_name, outer_key, wire[:nlen]) as ur:
                inner = ur.update(wire[nlen:])
            out = io.BytesIO()
            view = memoryview(inner)
            off = 0
            while off < len(view):
                (clen,) = struct.unpack("<I", bytes(view[off : off + 4]))
                off += 4
                ct = bytes(view[off : off + clen])
                off += clen
                out.write(enc.decrypt(ct))

    return (name, fn, STREAM_PAYLOAD_BYTES)


def _build_streaming_cases(mode: int) -> List[_common.BenchCase]:
    """Build the 24 streaming sub-benches for one mode."""
    cases: List[_common.BenchCase] = []
    aead_labels = ("aead-easy-io", "aead-lowlevel-io")
    userloop_labels = ("noaead-easy-userloop", "noaead-lowlevel-userloop")

    for label in aead_labels:
        for cn in CIPHERS:
            cases.append(_make_stream_aead_io_encrypt_case(label, mode, cn))
            cases.append(_make_stream_aead_io_decrypt_case(label, mode, cn))

    for label in userloop_labels:
        for cn in CIPHERS:
            cases.append(_make_stream_userloop_encrypt_case(label, mode, cn))
            cases.append(_make_stream_userloop_decrypt_case(label, mode, cn))

    return cases


# --------------------------------------------------------------------
# Driver
# --------------------------------------------------------------------


def _build_all_cases() -> List[_common.BenchCase]:
    cases: List[_common.BenchCase] = []
    cases.extend(_build_wrapper_only_cases())
    cases.extend(_build_message_cases(mode=1))
    cases.extend(_build_message_cases(mode=3))
    cases.extend(_build_streaming_cases(mode=1))
    cases.extend(_build_streaming_cases(mode=3))
    return cases


def main() -> None:
    itb.set_max_workers(0)
    cases = _build_all_cases()
    print(
        f"# wrapper bench primitives={PRIMITIVE} key_bits={KEY_BITS} "
        f"mac={MAC_NAME} ciphers={CIPHERS} cases={len(cases)}",
        flush=True,
    )
    _common.run_all(cases)


if __name__ == "__main__":
    main()
