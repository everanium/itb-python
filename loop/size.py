"""Size and duration parsing, the monotonic clock, and the human
renderings of sizes, rates and durations. Every rendering here is part
of the output contract shared with the Go harness and the other
bindings' loop utilities, so the formats are fixed to the character,
not to taste.
"""

from __future__ import annotations

import re
import time

# Byte-size suffixes, longest first so "KIB" is matched before "K" and
# "B" never swallows the tail of another suffix. Every multiple is
# binary.
_SIZE_SUFFIXES: tuple[tuple[str, int], ...] = (
    ("KIB", 1 << 10),
    ("KB", 1 << 10),
    ("K", 1 << 10),
    ("MIB", 1 << 20),
    ("MB", 1 << 20),
    ("M", 1 << 20),
    ("GIB", 1 << 30),
    ("GB", 1 << 30),
    ("G", 1 << 30),
    ("B", 1),
)

# Duration units in the order the grammar probes them, so "ms" is
# taken before "m" and "s".
_DURATION_UNITS: tuple[tuple[str, float], ...] = (
    ("ns", 1.0),
    ("us", 1e3),
    ("ms", 1e6),
    ("s", 1e9),
    ("m", 60e9),
    ("h", 3600e9),
)

_DIGITS = re.compile(r"[0-9.]+")
_INT64_MAX = (1 << 63) - 1


def parse_size(s: str) -> int | None:
    """Parses a human byte-size string ("16MB", "1MiB", "512K",
    "1073741824") into a byte count. Every suffix is a binary multiple:
    K/KB/KiB = 1024, M/MB/MiB = 1024^2, G/GB/GiB = 1024^3, B or none =
    bytes; matching is case-insensitive and surrounding whitespace is
    trimmed. Returns None on a malformed or negative value."""
    upper = s.strip().upper()
    if not upper:
        return None
    mult = 1
    digits = upper
    for suffix, m in _SIZE_SUFFIXES:
        if upper.endswith(suffix):
            mult = m
            digits = upper[: len(upper) - len(suffix)]
            break
    digits = digits.rstrip()
    if not digits or not digits.isdigit() or not digits.isascii():
        return None
    n = int(digits)
    if mult > 1 and n > _INT64_MAX // mult:
        return None
    return n * mult


def parse_duration(s: str) -> int | None:
    """Parses the Go duration grammar — a sequence of decimal numbers
    each followed by a unit (h, m, s, ms, us, ns), such as "30s", "5m",
    "1h30m", "1.5s" — into nanoseconds. Returns None on a malformed
    string."""
    if not s:
        return None
    total = 0.0
    pos = 0
    while pos < len(s):
        m = _DIGITS.match(s, pos)
        if m is None:
            return None
        try:
            value = float(m.group(0))
        except ValueError:
            return None
        if value < 0.0:
            return None
        pos = m.end()
        mult = 0.0
        for unit, ns in _DURATION_UNITS:
            if s.startswith(unit, pos) and not s[pos + len(unit) : pos + len(unit) + 1].isalpha():
                mult = ns
                pos += len(unit)
                break
        if mult == 0.0:
            return None
        total += value * mult
    if total > 9.2e18:
        return None
    return int(total)


def now_ns() -> int:
    """Monotonic wall clock in nanoseconds."""
    return time.monotonic_ns()


def human_bytes(n: int) -> str:
    """Renders a byte count with a binary-unit suffix: "1.0GiB",
    "16.0MiB", "4.0KiB", "512B"."""
    if n >= 1 << 30:
        return f"{n / (1 << 30):.1f}GiB"
    if n >= 1 << 20:
        return f"{n / (1 << 20):.1f}MiB"
    if n >= 1 << 10:
        return f"{n / (1 << 10):.1f}KiB"
    return f"{n}B"


def human_bytes_signed(n: int) -> str:
    """Renders a possibly-negative byte delta with an explicit sign."""
    return f"-{human_bytes(-n)}" if n < 0 else f"+{human_bytes(n)}"


def mb_per_sec(byte_count: int, ns: int) -> float:
    """Binary MiB per second over a nanosecond window; 0 when the
    window is unmeasured."""
    if ns <= 0:
        return 0.0
    return byte_count / (1 << 20) / (ns / 1e9)


def human_rate(byte_count: int, ns: int) -> str:
    """Renders a throughput as "123.4MB/s" (binary MiB per second) or
    "n/a" for an unmeasured window."""
    if ns <= 0:
        return "n/a"
    return f"{mb_per_sec(byte_count, ns):.1f}MB/s"


def _fraction(frac_ns: int) -> str:
    """The fractional part of a nanosecond remainder (0 .. 1e9) as
    ".ddd" with trailing zeros removed; empty for zero."""
    if frac_ns == 0:
        return ""
    return "." + f"{frac_ns:09d}".rstrip("0")


def human_duration(ns: int) -> str:
    """Renders a duration the way Go's time.Duration prints: below one
    second as milliseconds ("900ms", "1.5ms"); otherwise "[Hh][Mm]Ss"
    where the hour part appears when non-zero, the minute part when the
    hour part appears or the minutes are non-zero, and the seconds
    carry their fraction with trailing zeros removed ("5s", "5.003s",
    "1m0s", "1m5.25s", "1h0m0s"). The caller rounds first."""
    ns = abs(ns)
    if ns == 0:
        return "0s"
    if ns < 1_000_000_000:
        # Scale the sub-millisecond remainder to nine digits so the
        # fraction renderer sees the same shape it does for seconds.
        return f"{ns // 1_000_000}{_fraction((ns % 1_000_000) * 1000)}ms"
    hours, rem = divmod(ns, 3_600_000_000_000)
    minutes, rem = divmod(rem, 60_000_000_000)
    seconds, frac = divmod(rem, 1_000_000_000)
    out = f"{hours}h" if hours > 0 else ""
    if hours > 0 or minutes > 0:
        out += f"{minutes}m"
    return f"{out}{seconds}{_fraction(frac)}s"
