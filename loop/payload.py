"""Plaintext content: the payload modes, the seeded per-worker
generator, and the buffer fill from the operating-system CSPRNG.
"""

from __future__ import annotations

import os

# Payload mode selector values for the --payload-mode flag.
#
#   - fixed: one CSPRNG-generated buffer per worker, held unchanged
#     for the whole run (the default).
#   - rotating: the buffer is regenerated before every iteration, so
#     no two encrypt calls see the same plaintext.
#   - pattern-zero / pattern-ff: degenerate constant fills (all 0x00 /
#     all 0xFF) probing minimum-entropy plaintext handling.
#   - pattern-ascii: a repeating 'A'..'Z' ramp probing low-entropy
#     structured text.
FIXED = 0
ROTATING = 1
PATTERN_ZERO = 2
PATTERN_FF = 3
PATTERN_ASCII = 4

PAYLOAD_NAMES: tuple[str, ...] = (
    "fixed",
    "rotating",
    "pattern-zero",
    "pattern-ff",
    "pattern-ascii",
)

_MASK64 = (1 << 64) - 1


def payload_mode_name(mode: int) -> str:
    return PAYLOAD_NAMES[mode]


def parse_payload_mode(s: str) -> int | None:
    try:
        return PAYLOAD_NAMES.index(s)
    except ValueError:
        return None


def seed_worker(seed: int, worker_id: int) -> int:
    """Seeded plaintext. The seed makes plaintext content reproducible
    so a failing iteration can be replayed with the same bytes; it
    governs nothing else — pipeline keys, nonces and masters stay
    CSPRNG-drawn, so a seeded run is a reproduction aid and never a
    security test. Each worker's stream is domain-separated by its id
    so seeded workers still hold pairwise-distinct buffers under the
    fixed and rotating modes. The generator is splitmix64: a few lines
    in any language, which is why it is the one every binding uses."""
    return (seed + worker_id + 1) & _MASK64


def _splitmix64(state: int) -> tuple[int, int]:
    """One splitmix64 draw; returns the advanced state and the output.

    Python-specific. Integers are arbitrary precision, so every step
    that would wrap in a 64-bit register is masked explicitly; without
    the masks the generator still produces bytes and still reproduces
    itself, but it is not splitmix64."""
    state = (state + 0x9E3779B97F4A7C15) & _MASK64
    z = state
    z = ((z ^ (z >> 30)) * 0xBF58476D1CE4E5B9) & _MASK64
    z = ((z ^ (z >> 27)) * 0x94D049BB133111EB) & _MASK64
    return state, z ^ (z >> 31)


def fill_random(n: int) -> bytes:
    """Draws n bytes from the operating-system CSPRNG."""
    return os.urandom(n)


def fill_payload(mode: int, seeded: bool, rng: int, n: int) -> tuple[bytes, int]:
    """Builds one plaintext buffer according to the payload mode and
    returns it with the advanced generator state. The fixed and rotating
    modes draw from the seeded generator when the run is seeded and from
    the OS CSPRNG otherwise; the pattern modes are deterministic
    regardless of the seed.

    Python-specific. The buffer is an immutable bytes object rather than
    a mutable one because the binding borrows bytes for an FFI input
    pointer and copies anything else; filling in place would buy a
    payload-sized copy on every call."""
    if mode in (FIXED, ROTATING):
        if not seeded:
            return fill_random(n), rng
        out = bytearray(n)
        for i in range(0, n, 8):
            rng, value = _splitmix64(rng)
            take = min(n - i, 8)
            out[i : i + take] = value.to_bytes(8, "little")[:take]
        return bytes(out), rng
    if mode == PATTERN_ZERO:
        return b"\x00" * n, rng
    if mode == PATTERN_FF:
        return b"\xff" * n, rng
    ramp = bytes(0x41 + (i % 26) for i in range(26))
    return (ramp * (n // 26 + 1))[:n], rng
