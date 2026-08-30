"""Process-wide Go runtime knobs plus the library version string."""

from __future__ import annotations

import ctypes

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
    """Returns the libitb library version string."""
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
