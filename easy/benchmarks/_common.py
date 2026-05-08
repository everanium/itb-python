"""Shared scaffolding for the Python Easy Mode benchmark scripts.

The harness mirrors the Go ``testing.B`` benchmark style on the
itb_ext_test.go / itb3_ext_test.go side: each bench function runs a
short warm-up batch to reach steady state, then a measured batch
whose total wall-clock time is divided by the iteration count to
produce the canonical ``ns/op`` throughput line. The output line
also carries an MB/s figure derived from the configured payload
size, matching the Go reporter's ``-benchmem``-less default.

Environment variables (mirrored from itb's bitbyte_test.go +
extended for Easy Mode):

* ``ITB_NONCE_BITS`` — process-wide nonce width override; valid
  values 128 / 256 / 512. Maps to :func:`itb.set_nonce_bits` before
  any encryptor is constructed. Default 128.
* ``ITB_LOCKSEED`` — when set to a non-empty / non-``0`` value, every
  Easy Mode encryptor in this run calls
  :meth:`itb.Encryptor.set_lock_seed(1)`. The Go side's
  auto-couple invariant then engages :meth:`set_bit_soup(1)` and
  :meth:`set_lock_soup(1)` automatically; no separate flags
  required for Easy Mode. Default off.

Worker count defaults to ``itb.set_max_workers(0)`` (auto-detect),
matching the Go bench default. Bench scripts may override before
calling :func:`run_all`.
"""

from __future__ import annotations

import os
import secrets
import sys
import time
from typing import Callable, List, Optional, Tuple


def env_nonce_bits(default: int = 128) -> int:
    """Read ``ITB_NONCE_BITS`` from the environment with the same
    128 / 256 / 512 validation as bitbyte_test.go's TestMain. Falls
    back to ``default`` on missing / invalid input (with a stderr
    diagnostic for the invalid case)."""
    v = os.environ.get("ITB_NONCE_BITS", "")
    if v == "":
        return default
    if v in ("128", "256", "512"):
        return int(v)
    print(
        f"ITB_NONCE_BITS={v!r} invalid (expected 128/256/512); using {default}",
        file=sys.stderr,
    )
    return default


def env_lock_seed() -> bool:
    """``True`` when ``ITB_LOCKSEED`` is set to a non-empty /
    non-``0`` value. Triggers :meth:`Encryptor.set_lock_seed(1)` on
    every encryptor; Easy Mode auto-couples BitSoup + LockSoup."""
    v = os.environ.get("ITB_LOCKSEED", "")
    return v not in ("", "0")


def env_filter() -> Optional[str]:
    """Optional substring filter for bench-function names, read from
    ``ITB_BENCH_FILTER``. Functions whose name does not contain the
    filter substring are skipped; used to scope a run down to a
    single primitive or operation during development."""
    v = os.environ.get("ITB_BENCH_FILTER", "")
    return v if v else None


def env_min_seconds() -> float:
    """Minimum wall-clock seconds the measured iter loop should
    take, read from ``ITB_BENCH_MIN_SEC`` (default 5.0). The runner
    keeps doubling iteration count until the measured run reaches
    this threshold, mirroring Go's ``-benchtime=Ns`` semantics. The
    5-second default is wide enough to absorb the cold-cache /
    warm-up transient that distorts shorter measurement windows on
    the 16 MiB encrypt / decrypt path."""
    v = os.environ.get("ITB_BENCH_MIN_SEC", "")
    if v == "":
        return 5.0
    try:
        f = float(v)
        if f <= 0:
            raise ValueError
        return f
    except ValueError:
        print(
            f"ITB_BENCH_MIN_SEC={v!r} invalid (expected positive float); using 5.0",
            file=sys.stderr,
        )
        return 5.0


def random_bytes(n: int) -> bytes:
    """Returns ``n`` random bytes from a CSPRNG. Matches the
    crypto/rand-fill pattern used by generateDataExt in
    itb_ext_test.go."""
    return secrets.token_bytes(n)


PAYLOAD_16MB = 16 << 20


# A bench case is a (name, callable) pair. The callable accepts an
# iteration count and runs the per-iter body that many times. The
# iteration callable returns nothing; the harness measures wall-clock
# time outside the callable.
BenchFn = Callable[[int], None]
BenchCase = Tuple[str, BenchFn, int]


def _measure(name: str, fn: BenchFn, payload_bytes: int, min_seconds: float) -> None:
    """Run a benchmark case to convergence and emit a single
    Go-bench-style report line.

    Convergence policy: warm up with one iteration, then double the
    iteration count until the measured wall-clock duration meets
    ``min_seconds``. The final ``ns/op`` figure is the measured
    duration of that final batch divided by its iteration count.
    """
    # Warm-up — one iteration to hit JIT / cache / cold-start
    # transients before the measured loop.
    try:
        fn(1)
    except Exception as e:
        print(f"{name}\tFAIL: {e}", flush=True)
        return

    iters = 1
    while True:
        t0 = time.perf_counter_ns()
        fn(iters)
        elapsed = time.perf_counter_ns() - t0
        if elapsed >= int(min_seconds * 1e9):
            break
        # Double up; cap growth so a very fast op doesn't escalate
        # past 1 << 24 iters for one batch.
        if iters >= (1 << 24):
            break
        iters *= 2

    ns_per_op = elapsed / iters
    mb_per_s = (payload_bytes / (ns_per_op / 1e9)) / (1 << 20) if ns_per_op > 0 else 0.0
    # Mirrors `BenchmarkX-8     N    ns/op    MB/s` Go format,
    # column-aligned for human reading.
    print(
        f"{name:<60s}\t{iters:>10d}\t{ns_per_op:>14.1f} ns/op\t{mb_per_s:>9.2f} MB/s",
        flush=True,
    )


def run_all(cases: List[BenchCase]) -> None:
    """Run every case in ``cases`` and print one Go-bench-style line
    per case to stdout. Honours ``ITB_BENCH_FILTER`` for substring
    scoping and ``ITB_BENCH_MIN_SEC`` for per-case wall-clock
    budget."""
    flt = env_filter()
    min_seconds = env_min_seconds()

    selected = cases if flt is None else [c for c in cases if flt in c[0]]
    if not selected:
        print(
            f"no bench cases match filter {flt!r}; "
            f"available: {[c[0] for c in cases]}",
            file=sys.stderr,
        )
        return

    print(
        f"# benchmarks={len(selected)} payload_bytes={selected[0][2]} "
        f"min_seconds={min_seconds}",
        flush=True,
    )
    for name, fn, payload_bytes in selected:
        _measure(name, fn, payload_bytes, min_seconds)
