"""Shared timing + reporting helpers for the Python binding
micro-benchmarks. Wall-clock via ``time.perf_counter``; output is a
fixed-width table::

    bench             size     mb_per_sec
    message           1 MiB    <n>
    ...

Configuration is driven by environment variables so a side-by-side
comparison with the root Go bench harness is straightforward:

=================== =========== =============================================
env var             default     notes
=================== =========== =============================================
ITB_NONCE_BITS      512         shipped secure default
ITB_KEY_BITS        1024        matches root Go BENCH3.md 1024-bit table
ITB_WITH_PARALLAX   false       root Go bench runs without parallax
ITB_WITH_WRAPPER    false       root Go bench runs without the wrapper
ITB_INNER_HASH      (profile)   opaque hash name
ITB_PROFILE         (per shape) opaque profile name
ITB_BENCH_MIN_SEC   5           per-case wall-clock budget (seconds)
=================== =========== =============================================
"""

from __future__ import annotations

import os
import sys
import time
from collections.abc import Callable
from pathlib import Path

# Make the itb package importable when the bench scripts are run by
# path (python3 benches/bench_<shape>.py).
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import itb  # noqa: E402

# Per-case iteration floor alongside the wall-clock budget.
BENCH_MIN_ITERS = 3

SIZES = [1 << 20, 16 << 20, 64 << 20]


def bench_min_seconds() -> float:
    raw = os.environ.get("ITB_BENCH_MIN_SEC", "")
    try:
        v = float(raw)
    except ValueError:
        return 5.0
    return v if v > 0.0 else 5.0


def build_opts() -> itb.Opts:
    """Reads the bench-shape env vars and builds an :class:`itb.Opts`.
    Defaults match root Go BENCH3.md so numbers are directly
    comparable."""
    opts = (
        itb.Opts()
        .with_nonce_bits(int(os.environ.get("ITB_NONCE_BITS") or 512))
        .with_key_bits(int(os.environ.get("ITB_KEY_BITS") or 1024))
        .with_parallax(os.environ.get("ITB_WITH_PARALLAX") in ("true", "1"))
        .with_wrapper(os.environ.get("ITB_WITH_WRAPPER") in ("true", "1"))
    )
    inner = os.environ.get("ITB_INNER_HASH", "")
    if inner:
        opts = opts.with_inner_hash(inner)
    mac_name = os.environ.get("ITB_MAC_NAME", "")
    if mac_name:
        opts = opts.with_mac_name(mac_name)
    return opts


def profile_name(fallback: str) -> str:
    return os.environ.get("ITB_PROFILE") or fallback


def bench_header() -> None:
    print(f"{'bench':<17} {'size':<8} mb_per_sec")


def size_label(size: int) -> str:
    if size >= 1 << 20:
        return f"{size >> 20} MiB"
    return f"{size >> 10} KiB"


def bench_case(name: str, size: int, fn: Callable[[], None]) -> None:
    """Runs ``fn`` until the wall-clock budget is spent (with an
    iteration floor + one untimed warm-up), then prints one table
    row."""
    fn()  # warm-up
    budget = bench_min_seconds()
    start = time.perf_counter()
    elapsed = 0.0
    iters = 0
    while elapsed < budget or iters < BENCH_MIN_ITERS:
        fn()
        iters += 1
        elapsed = time.perf_counter() - start
    mb = size * iters / (1024.0 * 1024.0)
    print(f"{name:<17} {size_label(size):<8} {mb / elapsed:.1f}")
