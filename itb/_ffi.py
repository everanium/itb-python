"""Runtime symbol loading over the libitb shared library (ctypes).

The library is loaded once per process and never unloaded, so the
prototyped function attributes on the cached :class:`ctypes.CDLL`
stay valid for the process lifetime. Search order:

1. ``ITB_LIBITB_PATH`` environment variable (path to the shared
   library file).
2. ``<repo>/dist/<os>-<arch>/libitb.<ext>`` resolved by walking up
   from this file (in-repo builds).
3. The OS default loader path (``LD_LIBRARY_PATH``, ``ld.so.cache``,
   ``DYLD_LIBRARY_PATH``, ``PATH``).

A resolve failure surfaces as :class:`~itb.error.ItbError` at the
first FFI call rather than an import-time crash.
"""

from __future__ import annotations

import ctypes
import os
import platform
import sys
from pathlib import Path

from .error import ItbError
from .status import Status, status_from

# ctypes shorthands used in the prototype table below.
_c_int = ctypes.c_int
_c_int64 = ctypes.c_int64
_c_size_t = ctypes.c_size_t
_c_char_p = ctypes.c_char_p
_p_size_t = ctypes.POINTER(ctypes.c_size_t)
_p_int = ctypes.POINTER(ctypes.c_int)
# uintptr_t handles cross as c_size_t (same width on every supported
# platform); buffer pointers cross as c_char_p so both immutable
# ``bytes`` (inputs) and ``create_string_buffer`` arrays (outputs)
# are accepted.
_c_handle = ctypes.c_size_t
_p_handle = ctypes.POINTER(ctypes.c_size_t)

# name -> (argtypes, restype). Every prototype mirrors
# cmd/cshared/libitb.h.
_PROTOTYPES: dict[str, tuple[list[object], object]] = {
    "ITB_Version": ([_c_char_p, _c_size_t, _p_size_t], _c_int),
    "ITB_LastError": ([_c_char_p, _c_size_t, _p_size_t], _c_int),
    "ITB_SetMemoryLimit": ([_c_int64], _c_int64),
    "ITB_SetGCPercent": ([_c_int], _c_int),
    "ITB_Triple_Init": (
        [_c_char_p, _c_char_p, _c_char_p, _c_size_t, _p_size_t, _p_handle],
        _c_int,
    ),
    "ITB_Triple_Open": (
        [
            _c_char_p,
            _c_char_p,
            _c_size_t,
            _c_char_p,
            _c_char_p,
            _c_size_t,
            _c_char_p,
            _c_size_t,
            _c_size_t,
            _p_handle,
        ],
        _c_int,
    ),
    "ITB_Triple_Rekey": (
        [
            _c_handle,
            _c_char_p,
            _c_size_t,
            _c_char_p,
            _c_size_t,
            _c_char_p,
            _c_size_t,
            _p_size_t,
        ],
        _c_int,
    ),
    "ITB_Triple_Close": ([_c_handle], _c_int),
    "ITB_Triple_Free": ([_c_handle], _c_int),
    "ITB_Triple_EncryptStream": (
        [_c_handle, _c_char_p, _c_size_t, _c_char_p, _c_size_t, _p_size_t],
        _c_int,
    ),
    "ITB_Triple_DecryptStream": (
        [_c_handle, _c_char_p, _c_size_t, _c_char_p, _c_size_t, _p_size_t],
        _c_int,
    ),
    "ITB_Triple_EncryptMessage": (
        [_c_handle, _c_char_p, _c_size_t, _c_char_p, _c_size_t, _p_size_t],
        _c_int,
    ),
    "ITB_Triple_DecryptMessage": (
        [_c_handle, _c_char_p, _c_size_t, _c_char_p, _c_size_t, _p_size_t],
        _c_int,
    ),
    "ITB_Triple_RegisterProfile": ([_c_char_p, _c_char_p], _c_int),
    "ITB_Triple_EncryptStreamBegin": ([_c_handle, _p_handle], _c_int),
    "ITB_Triple_DecryptStreamBegin": ([_c_handle, _p_handle], _c_int),
    "ITB_Triple_StreamWrite": ([_c_handle, _c_char_p, _c_size_t], _c_int),
    "ITB_Triple_StreamEnd": ([_c_handle], _c_int),
    "ITB_Triple_StreamRead": (
        [_c_handle, _c_char_p, _c_size_t, _p_size_t, _p_int],
        _c_int,
    ),
    "ITB_Triple_StreamFree": ([_c_handle], _c_int),
}


def _lib_filename() -> str:
    if sys.platform.startswith("win"):
        return "libitb.dll"
    if sys.platform == "darwin":
        return "libitb.dylib"
    return "libitb.so"


def _dist_subdir() -> str:
    if sys.platform.startswith("win"):
        os_name = "windows"
    elif sys.platform == "darwin":
        os_name = "darwin"
    else:
        os_name = "linux"
    machine = platform.machine().lower()
    arch = {"x86_64": "amd64", "amd64": "amd64", "aarch64": "arm64", "arm64": "arm64"}.get(
        machine, machine
    )
    return f"{os_name}-{arch}"


def _resolve_library_path() -> str:
    env = os.environ.get("ITB_LIBITB_PATH", "")
    if env:
        return env
    # bindings/python/itb/_ffi.py -> repo root is three levels up.
    repo = Path(__file__).resolve().parents[3]
    cand = repo / "dist" / _dist_subdir() / _lib_filename()
    if cand.is_file():
        return str(cand)
    return _lib_filename()


class Syms:
    """The loaded shared library with every prototype declared."""

    def __init__(self) -> None:
        path = _resolve_library_path()
        try:
            self.lib = ctypes.CDLL(path)
        except OSError as exc:
            raise ItbError(f"failed to load libitb ({path}): {exc}") from exc
        for name, (argtypes, restype) in _PROTOTYPES.items():
            fn = getattr(self.lib, name)
            fn.argtypes = argtypes
            fn.restype = restype


_SYMS: Syms | None = None
_LOAD_ERROR: ItbError | None = None


def syms() -> Syms:
    """Returns the process-wide symbol bundle, loading the library on
    first use. Load failures are cached and re-reported on every call."""
    global _SYMS, _LOAD_ERROR
    if _SYMS is not None:
        return _SYMS
    if _LOAD_ERROR is not None:
        raise _LOAD_ERROR
    try:
        _SYMS = Syms()
    except ItbError as exc:
        _LOAD_ERROR = exc
        raise
    return _SYMS


def as_bytes(data: bytes | bytearray | memoryview) -> bytes:
    """Normalises the accepted buffer types to ``bytes`` for a
    borrowed FFI input pointer."""
    if isinstance(data, bytes):
        return data
    return bytes(data)


def last_error() -> str:
    """Reads the ``ITB_LastError`` diagnostic (NUL-stripped). Returns
    the empty string when no diagnostic is recorded or the library is
    unavailable."""
    try:
        s = syms()
    except ItbError:
        return ""
    need = ctypes.c_size_t(0)
    rc = int(s.lib.ITB_LastError(None, 0, ctypes.byref(need)))
    if rc not in (int(Status.OK), int(Status.BUFFER_TOO_SMALL)) or need.value <= 1:
        return ""
    buf = ctypes.create_string_buffer(need.value)
    rc = int(s.lib.ITB_LastError(buf, len(buf), ctypes.byref(need)))
    if rc != int(Status.OK):
        return ""
    return buf.raw[: max(need.value - 1, 0)].decode("utf-8", "replace")


def check(rc: int) -> None:
    """Maps a raw FFI return code onto ``None`` / :class:`ItbError`."""
    if rc == int(Status.OK):
        return
    raise ItbError(last_error(), status_from(rc))
