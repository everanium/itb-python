"""Process-wide Go runtime knobs plus the library version string."""

from __future__ import annotations

import ctypes
import os

from . import _ffi
from .error import ItbError
from .status import Status, status_from


def set_memory_limit(limit_bytes: int) -> int:
    """Sets the Go runtime's soft heap limit in bytes and returns the
    previous limit. A negative value queries without changing."""
    return int(_ffi.syms().lib.ITB_SetMemoryLimit(limit_bytes))


def set_gc_percent(pct: int) -> int:
    """Sets the Go GC trigger percentage and returns the previous
    value. A negative value queries without changing."""
    return int(_ffi.syms().lib.ITB_SetGCPercent(pct))


def version() -> str:
    """Returns the libitb3 library version string."""
    s = _ffi.syms()
    need = ctypes.c_size_t(0)
    rc = int(s.lib.ITB_Version(None, 0, ctypes.byref(need)))
    if rc not in (int(Status.OK), int(Status.BUFFER_TOO_SMALL)):
        raise ItbError(_ffi.last_error(), status_from(rc))
    if need.value <= 1:
        return ""
    buf = ctypes.create_string_buffer(need.value)
    _ffi.check(int(s.lib.ITB_Version(buf, len(buf), ctypes.byref(need))))
    return buf.raw[: max(need.value - 1, 0)].decode("utf-8")


def drbg_auto_tier() -> str:
    """Returns the fill cipher the auto DRBG tier selected on this host
    (``"aes-256-ctr"`` or ``"chacha20"``): the tier a Pipeline uses when
    its ``drbg`` option is empty, resolved per host and recorded in no
    blob."""
    s = _ffi.syms()
    need = ctypes.c_size_t(0)
    rc = int(s.lib.ITB_DRBGAutoTier(None, 0, ctypes.byref(need)))
    if rc not in (int(Status.OK), int(Status.BUFFER_TOO_SMALL)):
        raise ItbError(_ffi.last_error(), status_from(rc))
    if need.value <= 1:
        return ""
    buf = ctypes.create_string_buffer(need.value)
    _ffi.check(int(s.lib.ITB_DRBGAutoTier(buf, len(buf), ctypes.byref(need))))
    return buf.raw[: max(need.value - 1, 0)].decode("utf-8")


def set_gomaxprocs(n: int) -> int:
    """Sets the Go runtime's GOMAXPROCS — the number of OS threads
    executing Go code simultaneously inside the library — and returns
    the previous value. ``n <= 0`` queries without changing."""
    return int(_ffi.syms().lib.ITB_SetGOMAXPROCS(n))


def write_heap_profile(path: str | os.PathLike[str]) -> None:
    """Writes a Go runtime heap profile (pprof format, readable with
    ``go tool pprof``) to ``path`` after one forced garbage
    collection. An empty path falls back to the ``ITB_MEMPROFILE``
    environment variable; a file-system failure raises
    :class:`~itb.error.ItbError` carrying the os diagnostic."""
    _ffi.check(int(_ffi.syms().lib.ITB_WriteHeapProfile(os.fsencode(os.fspath(path)))))


def pool_stats_len() -> int:
    """The number of ``int64`` slots :func:`pool_stats` fills. A
    caller sizes its buffer from this value rather than a constant:
    the slot count grows if the library adds a pool."""
    return int(_ffi.syms().lib.ITB_PoolStatsLen())


def pool_stats() -> list[int]:
    """The library's pool hit / miss counters, every one a
    monotonically increasing total since library load (a consumer
    differences two snapshots).

    Slot layout, with ``T`` the hash-array pool tier count in slot 0:
    for tier ``i`` the five slots at ``1 + 5*i`` hold the starter
    width (``0`` for an unused tier), checkouts, constructor misses,
    regrow replacements and bytes allocated by misses + regrows; the
    four slots at ``1 + 5*T`` hold the scratch byte pool's
    get / new / regrow / regrow-bytes and the four after them the
    parallax chunk pool's, in the same order."""
    s = _ffi.syms()
    # The capacity this entry takes is counted in int64 slots, not in
    # bytes, so the array is allocated by element count and the same
    # count is handed over.
    cap = int(s.lib.ITB_PoolStatsLen())
    if cap <= 0:
        return []
    buf = (ctypes.c_int64 * cap)()
    n = ctypes.c_size_t(0)
    _ffi.check(int(s.lib.ITB_PoolStats(buf, cap, ctypes.byref(n))))
    return [int(buf[i]) for i in range(min(n.value, cap))]
