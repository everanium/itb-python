"""Handle-lifetime wrapper around the Triple Pipeline surface plus the
profile-catalogue entries (inspect / register / lookup / profiles)."""

from __future__ import annotations

import ctypes
import json
import os
from collections.abc import Callable
from types import TracebackType
from typing import Any, BinaryIO

from . import _ffi
from .error import ItbError
from .opts import Opts
from .status import Status
from .stream import DecryptStream, EncryptStream

Buffer = bytes | bytearray | memoryview

# Floor capacity for blob output buffers (Init / Save / Rekey).
_BLOB_CAP = 64 * 1024

# Floor capacity for profile-JSON output buffers (Inspect / Lookup /
# Profiles).
_JSON_CAP = 4 * 1024


def _out_cap(payload: int) -> int:
    """Pre-allocation formula for Message / one-shot stream outputs:
    ``max(131072, payload * 5/4 + 131072)``."""
    return max(payload + payload // 4 + 131_072, 131_072)


def _retry_once(
    cap: int, call: Callable[[ctypes.Array[ctypes.c_char], ctypes.c_size_t], int]
) -> bytes:
    """Single retry-once dispatch site for every variable-size output
    buffer: pre-allocate ``cap``, and on ``BUFFER_TOO_SMALL`` retry
    once with the exact size the FFI reported through the length
    out-param."""
    buf = ctypes.create_string_buffer(cap)
    n = ctypes.c_size_t(0)
    rc = call(buf, n)
    # Retry only when the reported length strictly exceeds the current
    # capacity.
    if rc == int(Status.BUFFER_TOO_SMALL) and n.value > cap:
        buf = ctypes.create_string_buffer(n.value)
        rc = call(buf, n)
    _ffi.check(rc)
    return buf.raw[: n.value]


def _masters(
    masters: tuple[Buffer, Buffer] | None,
) -> tuple[bytes, bytes, int]:
    """Folds the optional ``(perm, wrap)`` master pair into the
    ``(perm_master, wrap_master, masters_count)`` triple the Load
    entries take: count 0 selects the blob-embedded masters, count 2
    overrides them."""
    if masters is None:
        return b"", b"", 0
    return _ffi.as_bytes(masters[0]), _ffi.as_bytes(masters[1]), 2


def _fspath(path: str | os.PathLike[str]) -> bytes:
    return os.fsencode(os.fspath(path))


class Pipeline:
    """A Triple Pipeline session.

    :meth:`Pipeline.save` returns the serialised session blob the
    receiver feeds to :meth:`Pipeline.load`; :meth:`Pipeline.rekey`
    refreshes it. The Pipeline is a context manager; leaving the
    ``with`` block (or garbage collection via ``__del__``) frees the
    handle — libitb zeroes key material internally.

    Streaming-decrypt caveat: chunked Streaming AEAD verifies per
    chunk, so plaintext of verified chunks is released before a later
    chunk can fail authentication.
    """

    def __init__(self, handle: int) -> None:
        # Not part of the public API — use init() / load() / load_f().
        self._handle = handle

    @classmethod
    def init(cls, profile: str, opts: Opts | None = None) -> Pipeline:
        """Constructs a fresh Pipeline against the named profile. The
        session blob is available through :meth:`save`. On a
        blob-buffer retry the Init re-runs and yields a fresh session
        (the undersized attempt is closed by libitb before
        returning)."""
        s = _ffi.syms()
        profile_b = profile.encode("utf-8")
        opts_b = (opts or Opts()).build().encode("utf-8")
        handle = ctypes.c_size_t(0)

        def call(buf: ctypes.Array[ctypes.c_char], n: ctypes.c_size_t) -> int:
            return int(
                s.lib.ITB_Triple_Init(
                    profile_b,
                    opts_b,
                    buf,
                    len(buf),
                    ctypes.byref(n),
                    ctypes.byref(handle),
                )
            )

        _retry_once(_BLOB_CAP, call)
        return cls(handle.value)

    @classmethod
    def load(
        cls, blob: Buffer, masters: tuple[Buffer, Buffer] | None = None
    ) -> Pipeline:
        """Reconstructs a Pipeline from a blob produced by
        :meth:`Pipeline.save` or :meth:`Pipeline.rekey`. The blob's
        embedded profile record is the sole structural source — no
        profile name, no opts. ``masters`` is ``None`` to use the
        blob-embedded masters, or a ``(perm, wrap)`` pair to override
        them."""
        s = _ffi.syms()
        blob_b = _ffi.as_bytes(blob)
        pm, wm, count = _masters(masters)
        handle = ctypes.c_size_t(0)
        _ffi.check(
            int(
                s.lib.ITB_Triple_Load(
                    blob_b,
                    len(blob_b),
                    pm,
                    len(pm),
                    wm,
                    len(wm),
                    count,
                    ctypes.byref(handle),
                )
            )
        )
        return cls(handle.value)

    @classmethod
    def load_f(
        cls,
        path: str | os.PathLike[str],
        masters: tuple[Buffer, Buffer] | None = None,
    ) -> Pipeline:
        """:meth:`load` for a blob stored in a file. The file is read
        inside the library."""
        s = _ffi.syms()
        pm, wm, count = _masters(masters)
        handle = ctypes.c_size_t(0)
        _ffi.check(
            int(
                s.lib.ITB_Triple_LoadF(
                    _fspath(path),
                    pm,
                    len(pm),
                    wm,
                    len(wm),
                    count,
                    ctypes.byref(handle),
                )
            )
        )
        return cls(handle.value)

    def save(self) -> bytes:
        """The current serialised session blob — the bytes ``init``
        produced, the bytes ``load`` re-marshalled, or the bytes of
        the latest :meth:`rekey`."""
        s = _ffi.syms()

        def call(buf: ctypes.Array[ctypes.c_char], n: ctypes.c_size_t) -> int:
            return int(
                s.lib.ITB_Triple_Save(self._handle, buf, len(buf), ctypes.byref(n))
            )

        return _retry_once(_BLOB_CAP, call)

    def save_f(self, path: str | os.PathLike[str]) -> None:
        """Writes the current session blob to ``path`` inside the
        library (mode ``0600``; the containing directory must
        exist)."""
        _ffi.check(int(_ffi.syms().lib.ITB_Triple_SaveF(self._handle, _fspath(path))))

    def rekey(self, perm: Buffer, wrap: Buffer) -> bytes:
        """Rotates the parallax + wrapper masters and returns the
        refreshed session blob (also observable through :meth:`save`).
        Must not run concurrently with cipher calls or open stream
        sessions on the same Pipeline."""
        s = _ffi.syms()
        pm, wm = _ffi.as_bytes(perm), _ffi.as_bytes(wrap)

        def call(buf: ctypes.Array[ctypes.c_char], n: ctypes.c_size_t) -> int:
            return int(
                s.lib.ITB_Triple_Rekey(
                    self._handle,
                    pm,
                    len(pm),
                    wm,
                    len(wm),
                    buf,
                    len(buf),
                    ctypes.byref(n),
                )
            )

        return _retry_once(_BLOB_CAP, call)

    def max_workers(self, n: int) -> None:
        """Sets the worker cap for every subsequent cipher call. ``n``
        is clamped, never rejected: ``n <= 0`` selects auto
        (``runtime.NumCPU``), ``1..256`` pins the cap, larger values
        are treated as 256. The cap is per-machine tuning and is never
        written to the blob."""
        _ffi.check(int(_ffi.syms().lib.ITB_Triple_MaxWorkers(self._handle, n)))

    def close(self) -> None:
        """Zeroes the Pipeline's key material and marks it closed.
        Idempotent; subsequent cipher calls raise
        :class:`~itb.error.ItbError` with
        :attr:`~itb.status.Status.TRIPLE_CLOSED`."""
        _ffi.check(int(_ffi.syms().lib.ITB_Triple_Close(self._handle)))

    def encrypt_message(self, plain: Buffer) -> bytes:
        """Single Message encrypt: one call, one self-contained wire."""
        return self._cipher("ITB_Triple_EncryptMessage", plain)

    def decrypt_message(self, wire: Buffer) -> bytes:
        """Receive-side counterpart of :meth:`encrypt_message`."""
        return self._cipher("ITB_Triple_DecryptMessage", wire)

    def encrypt_stream_one_shot(self, plain: Buffer) -> bytes:
        """One-shot stream encrypt for callers holding the whole
        plaintext in memory. For bounded-memory streaming use
        :meth:`encrypt_stream` / :meth:`encrypt_stream_pump`."""
        return self._cipher("ITB_Triple_EncryptStream", plain)

    def decrypt_stream_one_shot(self, wire: Buffer) -> bytes:
        """Receive-side counterpart of :meth:`encrypt_stream_one_shot`."""
        return self._cipher("ITB_Triple_DecryptStream", wire)

    def encrypt_stream(self) -> EncryptStream:
        """Opens an incremental encrypt session (plaintext in, wire
        out)."""
        return EncryptStream(self, self._handle)

    def decrypt_stream(self) -> DecryptStream:
        """Opens an incremental decrypt session (wire in, plaintext
        out)."""
        return DecryptStream(self, self._handle)

    def encrypt_stream_pump(self, src: BinaryIO, dst: BinaryIO) -> None:
        """Pumps ``src`` through an encrypt session into ``dst`` with
        bounded memory: feed a slice, drain available wire, repeat;
        end + final drain on source EOF. The session is freed on
        return."""
        with self.encrypt_stream() as sess:
            sess.pump(src, dst)

    def decrypt_stream_pump(self, src: BinaryIO, dst: BinaryIO) -> None:
        """Receive-side counterpart of :meth:`encrypt_stream_pump`."""
        with self.decrypt_stream() as sess:
            sess.pump(src, dst)

    def _cipher(self, name: str, src: Buffer) -> bytes:
        """Shared body for the four buffer-in / buffer-out cipher
        entries."""
        fn = getattr(_ffi.syms().lib, name)
        src_b = _ffi.as_bytes(src)

        def call(buf: ctypes.Array[ctypes.c_char], n: ctypes.c_size_t) -> int:
            return int(
                fn(self._handle, src_b, len(src_b), buf, len(buf), ctypes.byref(n))
            )

        return _retry_once(_out_cap(len(src_b)), call)

    def free(self) -> None:
        """Releases the Pipeline handle (libitb closes and zeroes key
        material first). Safe to call more than once."""
        if self._handle == 0:
            return
        handle, self._handle = self._handle, 0
        try:
            s = _ffi.syms()
        except ItbError:
            return
        s.lib.ITB_Triple_Free(handle)

    def __enter__(self) -> Pipeline:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        self.free()

    def __del__(self) -> None:
        try:
            self.free()
        except Exception:
            # Interpreter shutdown may have torn down module state;
            # the OS reclaims the library either way.
            pass

    def __repr__(self) -> str:
        return f"Pipeline(handle={'open' if self._handle else 'freed'})"


# Profile record: the JSON object libitb emits from inspect / lookup
# and accepts in register, decoded with the standard-library json
# module. Key set: name, mode, width, hash, hashes, keybits, mac,
# tagstub, chunk, wrapper, outer, parallax, palette, segment.
Profile = dict[str, Any]


def _json_out(call: Callable[[ctypes.Array[ctypes.c_char], ctypes.c_size_t], int]) -> Any:
    return json.loads(_retry_once(_JSON_CAP, call).decode("utf-8"))


def inspect(blob: Buffer) -> Profile:
    """Decodes the blob's embedded profile record without opening a
    Pipeline. No registry read, no primitive probe — a primitive name
    the local build lacks is returned unchanged."""
    s = _ffi.syms()
    blob_b = _ffi.as_bytes(blob)

    def call(buf: ctypes.Array[ctypes.c_char], n: ctypes.c_size_t) -> int:
        return int(
            s.lib.ITB_Triple_Inspect(
                blob_b, len(blob_b), buf, len(buf), ctypes.byref(n)
            )
        )

    return _json_out(call)


def register(name: str, profile: Profile | str) -> None:
    """Registers a profile record under ``name`` so subsequent
    :meth:`Pipeline.init` / :func:`lookup` calls resolve it.
    ``profile`` is the record as a ``dict`` (the shape :func:`inspect`
    returns) or an already-encoded JSON string; a ``name`` key inside
    it, if present, must be empty or equal to ``name``. Validation
    (name pattern, reserved prefixes, field rules) is performed by
    libitb; a duplicate name fails with
    :attr:`~itb.status.Status.PROFILE_EXISTS`."""
    s = _ffi.syms()
    text = profile if isinstance(profile, str) else json.dumps(profile)
    _ffi.check(
        int(s.lib.ITB_Triple_Register(name.encode("utf-8"), text.encode("utf-8")))
    )


def lookup(name: str) -> Profile:
    """Returns the profile record registered under ``name`` (a shipped
    catalogue entry or a prior :func:`register`). An unknown name
    raises :class:`~itb.error.ItbError` with
    :attr:`~itb.status.Status.UNKNOWN_PROFILE`."""
    s = _ffi.syms()
    name_b = name.encode("utf-8")

    def call(buf: ctypes.Array[ctypes.c_char], n: ctypes.c_size_t) -> int:
        return int(s.lib.ITB_Triple_Lookup(name_b, buf, len(buf), ctypes.byref(n)))

    return _json_out(call)


def profiles() -> list[str]:
    """The sorted list of every registered profile name."""
    s = _ffi.syms()

    def call(buf: ctypes.Array[ctypes.c_char], n: ctypes.c_size_t) -> int:
        return int(s.lib.ITB_Triple_Profiles(buf, len(buf), ctypes.byref(n)))

    return list(_json_out(call))
