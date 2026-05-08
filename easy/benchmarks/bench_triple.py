"""Easy Mode Triple-Ouroboros benchmarks for the Python binding.

Mirrors the BenchmarkTriple* cohort from itb3_ext_test.go for the
nine PRF-grade primitives, locked at 1024-bit ITB key width and 16
MiB CSPRNG-filled payload. One mixed-primitive variant
(:meth:`itb.Encryptor.mixed_triple` cycling the same BLAKE family +
Areion-SoEM-256 dedicated lockSeed used by bench_single_mixed)
covers the Easy Mode Mixed surface alongside the single-primitive
grid.

Run with::

    python -m bindings.python.easy.benchmarks.bench_triple

    ITB_NONCE_BITS=512 \
    ITB_LOCKSEED=1 \
        python -m bindings.python.easy.benchmarks.bench_triple

    ITB_BENCH_FILTER=blake3_encrypt \
        python -m bindings.python.easy.benchmarks.bench_triple

The harness emits one Go-bench-style line per case (name, iters,
ns/op, MB/s). See ``_common.py`` for the supported environment
variables and the convergence policy. The pure Bit-Soup
configuration is intentionally not exercised on the Triple side —
the BitSoup/LockSoup overlay routes through the auto-coupled path
when ITB_LOCKSEED=1, which already covers the Triple bit-level
split surface end-to-end.
"""

from __future__ import annotations

import io
import os
import struct
import sys
from typing import Callable, List, Tuple

import itb

from . import _common


# Canonical 9-primitive PRF-grade order from CLAUDE.md (positions
# 4 through 12).
PRIMITIVES_CANONICAL: List[str] = [
    "areion256",
    "areion512",
    "blake2b256",
    "blake2b512",
    "blake2s",
    "blake3",
    "aescmac",
    "siphash24",
    "chacha20",
]

# Mixed-primitive composition for Triple Ouroboros — the same four
# 256-bit-wide names used by bench_single_mixed are cycled across
# the seven seed slots (noise + 3 data + 3 start) plus
# Areion-SoEM-256 on the dedicated lockSeed slot.
MIXED_NOISE = "blake3"
MIXED_DATA1 = "blake2s"
MIXED_DATA2 = "blake2b256"
MIXED_DATA3 = "blake3"
MIXED_START1 = "blake2s"
MIXED_START2 = "blake2b256"
MIXED_START3 = "blake3"
MIXED_LOCK = "areion256"

KEY_BITS = 1024
MAC_NAME = "hmac-blake3"
PAYLOAD_BYTES = _common.PAYLOAD_16MB


def _apply_lockseed_if_requested(enc: itb.Encryptor) -> None:
    """When ``ITB_LOCKSEED`` is set the harness flips the dedicated
    lockSeed channel on every encryptor. Easy Mode auto-couples
    BitSoup + LockSoup as a side effect."""
    if _common.env_lock_seed():
        enc.set_lock_seed(1)


def _build_triple(primitive: str) -> itb.Encryptor:
    """Construct a single-primitive 1024-bit Triple-Ouroboros
    encryptor with HMAC-BLAKE3 authentication. Triple = mode=3, 7-seed
    layout."""
    enc = itb.Encryptor(primitive, KEY_BITS, MAC_NAME, mode=3)
    _apply_lockseed_if_requested(enc)
    return enc


def _build_mixed_triple() -> itb.Encryptor:
    """Construct a mixed-primitive Triple-Ouroboros encryptor with
    the four-name BLAKE family across the seven middle slots. The
    dedicated Areion-SoEM-256 lockSeed slot is allocated only when
    ``ITB_LOCKSEED`` is set, so the no-LockSeed bench arm measures
    the plain mixed-primitive cost without the BitSoup + LockSoup
    auto-couple. The four primitive names share the same native hash
    width so the Encryptor.mixed_triple width-check passes."""
    primL = MIXED_LOCK if _common.env_lock_seed() else None
    enc = itb.Encryptor.mixed_triple(
        primitive_n=MIXED_NOISE,
        primitive_d1=MIXED_DATA1,
        primitive_d2=MIXED_DATA2,
        primitive_d3=MIXED_DATA3,
        primitive_s1=MIXED_START1,
        primitive_s2=MIXED_START2,
        primitive_s3=MIXED_START3,
        primitive_l=primL,
        key_bits=KEY_BITS,
        mac=MAC_NAME,
    )
    return enc


def _make_encrypt_case(name: str, builder: Callable[[], itb.Encryptor]) -> _common.BenchCase:
    enc = builder()
    payload = _common.random_bytes(PAYLOAD_BYTES)

    def fn(iters: int) -> None:
        for _ in range(iters):
            enc.encrypt(payload)

    return (name, fn, PAYLOAD_BYTES)


def _make_decrypt_case(name: str, builder: Callable[[], itb.Encryptor]) -> _common.BenchCase:
    enc = builder()
    payload = _common.random_bytes(PAYLOAD_BYTES)
    ciphertext = enc.encrypt(payload)

    def fn(iters: int) -> None:
        for _ in range(iters):
            enc.decrypt(ciphertext)

    return (name, fn, PAYLOAD_BYTES)


def _make_encrypt_auth_case(name: str, builder: Callable[[], itb.Encryptor]) -> _common.BenchCase:
    enc = builder()
    payload = _common.random_bytes(PAYLOAD_BYTES)

    def fn(iters: int) -> None:
        for _ in range(iters):
            enc.encrypt_auth(payload)

    return (name, fn, PAYLOAD_BYTES)


def _make_decrypt_auth_case(name: str, builder: Callable[[], itb.Encryptor]) -> _common.BenchCase:
    enc = builder()
    payload = _common.random_bytes(PAYLOAD_BYTES)
    ciphertext = enc.encrypt_auth(payload)

    def fn(iters: int) -> None:
        for _ in range(iters):
            enc.decrypt_auth(ciphertext)

    return (name, fn, PAYLOAD_BYTES)


def _build_cases() -> List[_common.BenchCase]:
    """Assemble the full case list: 9 single-primitive entries
    × 4 ops + 1 mixed entry × 4 ops = 40 cases. Order is
    primitive-major / op-minor so a filter on a primitive name
    keeps all four ops grouped together in the output."""
    cases: List[_common.BenchCase] = []
    for prim in PRIMITIVES_CANONICAL:
        builder = (lambda p=prim: _build_triple(p))
        base = f"bench_triple_{prim}_{KEY_BITS}bit"
        cases.append(_make_encrypt_case(f"{base}_encrypt_16mb", builder))
        cases.append(_make_decrypt_case(f"{base}_decrypt_16mb", builder))
        cases.append(_make_encrypt_auth_case(f"{base}_encrypt_auth_16mb", builder))
        cases.append(_make_decrypt_auth_case(f"{base}_decrypt_auth_16mb", builder))

    base = f"bench_triple_mixed_{KEY_BITS}bit"
    cases.append(_make_encrypt_case(f"{base}_encrypt_16mb", _build_mixed_triple))
    cases.append(_make_decrypt_case(f"{base}_decrypt_16mb", _build_mixed_triple))
    cases.append(_make_encrypt_auth_case(f"{base}_encrypt_auth_16mb", _build_mixed_triple))
    cases.append(_make_decrypt_auth_case(f"{base}_decrypt_auth_16mb", _build_mixed_triple))

    return cases


def main() -> None:
    nonce_bits = _common.env_nonce_bits()
    itb.set_max_workers(0)
    itb.set_nonce_bits(nonce_bits)

    print(
        f"# easy_triple primitives={len(PRIMITIVES_CANONICAL)} "
        f"key_bits={KEY_BITS} mac={MAC_NAME} "
        f"nonce_bits={nonce_bits} "
        f"lockseed={'on' if _common.env_lock_seed() else 'off'} "
        f"workers=auto",
        flush=True,
    )

    cases = _build_cases()
    cases.extend(_build_stream_cases())
    _common.run_all(cases)


# ─── Streaming benchmarks (Triple Ouroboros) ─────────────────────────
#
# The eight cases below cover the (Mode × Variant × Op) matrix at the
# Triple-Ouroboros width: Easy Mode and Low-Level Mode × StreamAuthIO
# and StreamUserLoop × Encrypt and Decrypt. Every case streams a
# 64 MiB CSPRNG payload through 16 MiB chunks. The measured wall-clock
# slice covers only the streaming path; CSPRNG payload generation,
# encryptor / Seed / MAC construction, and pre-encryption for the
# decrypt arms run outside the timer.
#
# StreamAuthIO drives the binding's authenticated streaming entry
# points (:meth:`Encryptor.encrypt_stream_auth` /
# :meth:`Encryptor.decrypt_stream_auth` for Easy Mode mode=3;
# :func:`itb.encrypt_stream_auth_triple` /
# :func:`itb.decrypt_stream_auth_triple` for Low-Level Mode). The
# on-wire transcript carries the 32-byte CSPRNG ``stream_id`` prefix
# followed by chunked authenticated bodies.
#
# StreamUserLoop drives the per-chunk plain cipher entry points
# (:meth:`Encryptor.encrypt` / :meth:`Encryptor.decrypt` on the
# Triple Mode encryptor for Easy Mode; :func:`itb.encrypt_stream_triple`
# / :func:`itb.decrypt_stream_triple` for Low-Level Mode). The Easy
# Mode arm wraps the per-chunk plain calls in a caller-side loop with
# a 4-byte big-endian length prefix per chunk; the Low-Level Mode arm
# calls the binding's Triple free-function wrapper which manages the
# chunk loop internally without the MAC tag.

STREAM_PAYLOAD_BYTES = 64 * 1024 * 1024
STREAM_CHUNK_SIZE = 16 * 1024 * 1024
STREAM_PRIMITIVE = "areion512"


def _build_easy_stream_encryptor() -> itb.Encryptor:
    """Construct the Easy Mode Triple-Ouroboros encryptor used for
    every streaming case in this module — Areion-SoEM-512 / 1024-bit
    key / HMAC-BLAKE3 MAC, mode=3."""
    enc = itb.Encryptor(STREAM_PRIMITIVE, KEY_BITS, MAC_NAME, mode=3)
    _apply_lockseed_if_requested(enc)
    return enc


def _build_lowlevel_stream_seeds() -> Tuple[
    itb.Seed, itb.Seed, itb.Seed, itb.Seed,
    itb.Seed, itb.Seed, itb.Seed,
]:
    """Allocate the seven Seed handles used by the Low-Level Mode
    Triple-Ouroboros streaming cases (noise + 3 data + 3 start)."""
    return (
        itb.Seed(STREAM_PRIMITIVE, KEY_BITS),
        itb.Seed(STREAM_PRIMITIVE, KEY_BITS),
        itb.Seed(STREAM_PRIMITIVE, KEY_BITS),
        itb.Seed(STREAM_PRIMITIVE, KEY_BITS),
        itb.Seed(STREAM_PRIMITIVE, KEY_BITS),
        itb.Seed(STREAM_PRIMITIVE, KEY_BITS),
        itb.Seed(STREAM_PRIMITIVE, KEY_BITS),
    )


def _make_easy_stream_auth_encrypt_case(name: str) -> _common.BenchCase:
    """Easy Mode Triple-Ouroboros Streaming AEAD encrypt — full
    64 MiB through 16 MiB chunks per iteration."""
    enc = _build_easy_stream_encryptor()
    payload = _common.random_bytes(STREAM_PAYLOAD_BYTES)

    def fn(iters: int) -> None:
        for _ in range(iters):
            fin = io.BytesIO(payload)
            fout = io.BytesIO()
            enc.encrypt_stream_auth(fin, fout, chunk_size=STREAM_CHUNK_SIZE)

    return (name, fn, STREAM_PAYLOAD_BYTES)


def _make_easy_stream_auth_decrypt_case(name: str) -> _common.BenchCase:
    """Easy Mode Triple-Ouroboros Streaming AEAD decrypt —
    pre-encrypts a 64 MiB transcript outside the timer; the iter loop
    only times the decrypt path."""
    enc = _build_easy_stream_encryptor()
    payload = _common.random_bytes(STREAM_PAYLOAD_BYTES)
    pre = io.BytesIO()
    enc.encrypt_stream_auth(io.BytesIO(payload), pre,
                            chunk_size=STREAM_CHUNK_SIZE)
    transcript = pre.getvalue()

    def fn(iters: int) -> None:
        for _ in range(iters):
            fin = io.BytesIO(transcript)
            fout = io.BytesIO()
            enc.decrypt_stream_auth(fin, fout, read_size=STREAM_CHUNK_SIZE)

    return (name, fn, STREAM_PAYLOAD_BYTES)


def _make_easy_user_loop_encrypt_case(name: str) -> _common.BenchCase:
    """Easy Mode Triple-Ouroboros user-driven loop encrypt —
    per-chunk :meth:`Encryptor.encrypt` calls wrapped in a
    caller-side loop with a 4-byte big-endian ciphertext-length
    prefix per chunk."""
    enc = _build_easy_stream_encryptor()
    payload = _common.random_bytes(STREAM_PAYLOAD_BYTES)

    def fn(iters: int) -> None:
        for _ in range(iters):
            fin = io.BytesIO(payload)
            fout = io.BytesIO()
            while True:
                chunk = fin.read(STREAM_CHUNK_SIZE)
                if not chunk:
                    break
                ct = enc.encrypt(chunk)
                fout.write(struct.pack(">I", len(ct)))
                fout.write(ct)

    return (name, fn, STREAM_PAYLOAD_BYTES)


def _make_easy_user_loop_decrypt_case(name: str) -> _common.BenchCase:
    """Easy Mode Triple-Ouroboros user-driven loop decrypt —
    pre-encrypts the chunked transcript outside the timer, then walks
    4-byte BE length prefixes feeding each ciphertext slice to
    :meth:`Encryptor.decrypt`."""
    enc = _build_easy_stream_encryptor()
    payload = _common.random_bytes(STREAM_PAYLOAD_BYTES)
    pre = io.BytesIO()
    src = io.BytesIO(payload)
    while True:
        chunk = src.read(STREAM_CHUNK_SIZE)
        if not chunk:
            break
        ct = enc.encrypt(chunk)
        pre.write(struct.pack(">I", len(ct)))
        pre.write(ct)
    transcript = pre.getvalue()

    def fn(iters: int) -> None:
        for _ in range(iters):
            fin = io.BytesIO(transcript)
            fout = io.BytesIO()
            while True:
                hdr = fin.read(4)
                if not hdr:
                    break
                (n,) = struct.unpack(">I", hdr)
                ct = fin.read(n)
                pt = enc.decrypt(ct)
                fout.write(pt)

    return (name, fn, STREAM_PAYLOAD_BYTES)


def _make_lowlevel_stream_auth_encrypt_case(name: str) -> _common.BenchCase:
    """Low-Level Mode Triple-Ouroboros Streaming AEAD encrypt —
    module-level :func:`itb.encrypt_stream_auth_triple` driving seven
    caller-owned Seeds plus an explicitly-keyed :class:`itb.MAC`
    handle."""
    n_seed, d1, d2, d3, s1, s2, s3 = _build_lowlevel_stream_seeds()
    mac_key = os.urandom(32)
    mac = itb.MAC("hmac-blake3", mac_key)
    payload = _common.random_bytes(STREAM_PAYLOAD_BYTES)

    def fn(iters: int) -> None:
        for _ in range(iters):
            fin = io.BytesIO(payload)
            fout = io.BytesIO()
            itb.encrypt_stream_auth_triple(
                n_seed, d1, d2, d3, s1, s2, s3,
                mac, fin, fout, chunk_size=STREAM_CHUNK_SIZE,
            )

    return (name, fn, STREAM_PAYLOAD_BYTES)


def _make_lowlevel_stream_auth_decrypt_case(name: str) -> _common.BenchCase:
    """Low-Level Mode Triple-Ouroboros Streaming AEAD decrypt —
    pre-encrypts a 64 MiB transcript with the same Seed / MAC
    septet, then times the inverse path."""
    n_seed, d1, d2, d3, s1, s2, s3 = _build_lowlevel_stream_seeds()
    mac_key = os.urandom(32)
    mac = itb.MAC("hmac-blake3", mac_key)
    payload = _common.random_bytes(STREAM_PAYLOAD_BYTES)
    pre = io.BytesIO()
    itb.encrypt_stream_auth_triple(
        n_seed, d1, d2, d3, s1, s2, s3,
        mac, io.BytesIO(payload), pre,
        chunk_size=STREAM_CHUNK_SIZE,
    )
    transcript = pre.getvalue()

    def fn(iters: int) -> None:
        for _ in range(iters):
            fin = io.BytesIO(transcript)
            fout = io.BytesIO()
            itb.decrypt_stream_auth_triple(
                n_seed, d1, d2, d3, s1, s2, s3,
                mac, fin, fout, read_size=STREAM_CHUNK_SIZE,
            )

    return (name, fn, STREAM_PAYLOAD_BYTES)


def _make_lowlevel_user_loop_encrypt_case(name: str) -> _common.BenchCase:
    """Low-Level Mode Triple-Ouroboros user-driven loop encrypt —
    module-level :func:`itb.encrypt_stream_triple` running the plain
    (no-MAC) chunked cipher pipeline."""
    n_seed, d1, d2, d3, s1, s2, s3 = _build_lowlevel_stream_seeds()
    payload = _common.random_bytes(STREAM_PAYLOAD_BYTES)

    def fn(iters: int) -> None:
        for _ in range(iters):
            fin = io.BytesIO(payload)
            fout = io.BytesIO()
            itb.encrypt_stream_triple(
                n_seed, d1, d2, d3, s1, s2, s3,
                fin, fout, chunk_size=STREAM_CHUNK_SIZE,
            )

    return (name, fn, STREAM_PAYLOAD_BYTES)


def _make_lowlevel_user_loop_decrypt_case(name: str) -> _common.BenchCase:
    """Low-Level Mode Triple-Ouroboros user-driven loop decrypt —
    pre-encrypts the plain transcript outside the timer; the iter
    body invokes :func:`itb.decrypt_stream_triple` against the
    captured wire bytes."""
    n_seed, d1, d2, d3, s1, s2, s3 = _build_lowlevel_stream_seeds()
    payload = _common.random_bytes(STREAM_PAYLOAD_BYTES)
    pre = io.BytesIO()
    itb.encrypt_stream_triple(
        n_seed, d1, d2, d3, s1, s2, s3,
        io.BytesIO(payload), pre, chunk_size=STREAM_CHUNK_SIZE,
    )
    transcript = pre.getvalue()

    def fn(iters: int) -> None:
        for _ in range(iters):
            fin = io.BytesIO(transcript)
            fout = io.BytesIO()
            itb.decrypt_stream_triple(
                n_seed, d1, d2, d3, s1, s2, s3,
                fin, fout, read_size=STREAM_CHUNK_SIZE,
            )

    return (name, fn, STREAM_PAYLOAD_BYTES)


def _build_stream_cases() -> List[_common.BenchCase]:
    """Assemble the eight Triple-Ouroboros streaming cases. Order is
    (Mode × Variant × Op) — Easy / Low-Level outer, AEAD-IO /
    user-loop middle, encrypt / decrypt inner — so a substring filter
    on the variant name groups the four ops together."""
    base = f"bench_triple_{STREAM_PRIMITIVE}_{KEY_BITS}bit"
    cases: List[_common.BenchCase] = []
    cases.append(_make_easy_stream_auth_encrypt_case(
        f"{base}_easy_stream_auth_io_encrypt_64mb"))
    cases.append(_make_easy_stream_auth_decrypt_case(
        f"{base}_easy_stream_auth_io_decrypt_64mb"))
    cases.append(_make_easy_user_loop_encrypt_case(
        f"{base}_easy_stream_user_loop_encrypt_64mb"))
    cases.append(_make_easy_user_loop_decrypt_case(
        f"{base}_easy_stream_user_loop_decrypt_64mb"))
    cases.append(_make_lowlevel_stream_auth_encrypt_case(
        f"{base}_lowlevel_stream_auth_io_encrypt_64mb"))
    cases.append(_make_lowlevel_stream_auth_decrypt_case(
        f"{base}_lowlevel_stream_auth_io_decrypt_64mb"))
    cases.append(_make_lowlevel_user_loop_encrypt_case(
        f"{base}_lowlevel_stream_user_loop_encrypt_64mb"))
    cases.append(_make_lowlevel_user_loop_decrypt_case(
        f"{base}_lowlevel_stream_user_loop_decrypt_64mb"))
    return cases


if __name__ == "__main__":
    main()
