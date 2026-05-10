"""Shared scaffolding for the Python wrapper benchmark scripts.

Mirrors :mod:`bindings.python.easy.benchmarks._common` — same Go
``testing.B`` style report line (name, iters, ns/op, MB/s) — adapted
for the wrapper sub-bench matrix.

Environment variables:

* ``ITB_BENCH_FILTER`` — substring filter on bench-function names.
* ``ITB_BENCH_MIN_SEC`` — minimum measured wall-clock seconds per
  case (default 5.0). Mirrors Go's ``-benchtime=Ns`` semantics.
"""

from __future__ import annotations

import os
import secrets
import sys
import time
from typing import Callable, List, Optional, Tuple


def env_filter() -> Optional[str]:
    v = os.environ.get("ITB_BENCH_FILTER", "")
    return v if v else None


def env_min_seconds() -> float:
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
    return secrets.token_bytes(n)


PAYLOAD_16MB = 16 << 20
PAYLOAD_64MB = 64 << 20


# A bench case is (name, callable, payload_bytes). The callable
# accepts an iteration count and runs the per-iter body that many
# times; the harness measures wall-clock time outside the callable.
BenchFn = Callable[[int], None]
BenchCase = Tuple[str, BenchFn, int]


def _measure(name: str, fn: BenchFn, payload_bytes: int, min_seconds: float) -> None:
    try:
        fn(1)
    except Exception as e:  # pragma: no cover (diagnostic path)
        print(f"{name}\tFAIL: {e}", flush=True)
        return

    iters = 1
    elapsed = 0
    while True:
        t0 = time.perf_counter_ns()
        fn(iters)
        elapsed = time.perf_counter_ns() - t0
        if elapsed >= int(min_seconds * 1e9):
            break
        if iters >= (1 << 24):
            break
        iters *= 2

    ns_per_op = elapsed / iters
    mb_per_s = (payload_bytes / (ns_per_op / 1e9)) / (1 << 20) if ns_per_op > 0 else 0.0
    print(
        f"{name:<70s}\t{iters:>10d}\t{ns_per_op:>14.1f} ns/op\t{mb_per_s:>9.2f} MB/s",
        flush=True,
    )


def run_all(cases: List[BenchCase]) -> None:
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
        f"# benchmarks={len(selected)} min_seconds={min_seconds}",
        flush=True,
    )
    for name, fn, payload_bytes in selected:
        _measure(name, fn, payload_bytes, min_seconds)
