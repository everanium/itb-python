"""Incremental stream sessions over an open Pipeline.

A session is a dumb byte pump: :class:`EncryptStream` takes plaintext
in through ``write`` and yields wire through ``read`` / ``drain_all``;
:class:`DecryptStream` is the mirror (wire in, plaintext out). All
chunking, MAC, envelope, and wire-format decisions stay inside libitb.
Leaving the ``with`` block (or garbage collection) cancels the session
and frees the Go-side state; keep the parent Pipeline alive for the
session's lifetime.
"""

from __future__ import annotations

import ctypes
from types import TracebackType
from typing import BinaryIO, TypeVar

from . import _ffi
from .error import ItbError

_SessionT = TypeVar("_SessionT", bound="_Session")

# Feed / drain slice size used by the pump loops.
_PUMP_BUF = 1 << 20


class _Session:
    """Shared body for the two session directions."""

    _BEGIN = ""  # overridden per direction

    def __init__(self, pipe: object, pipe_handle: int) -> None:
        # Pin the parent Pipeline via a Python reference so it cannot
        # be garbage-collected (and its Go-side handle freed) while
        # this session is still live. The Go handle registry would
        # degrade a stale-pipe StreamWrite/Read to a bad-handle
        # status, but the nondeterminism is a correctness trap for
        # a caller that lets the parent go out of scope.
        self._pipe = pipe
        self._handle = 0
        self._ended = False
        s = _ffi.syms()
        handle = ctypes.c_size_t(0)
        begin = getattr(s.lib, self._BEGIN)
        _ffi.check(int(begin(pipe_handle, ctypes.byref(handle))))
        self._handle = handle.value

    def write(self, src: bytes | bytearray | memoryview) -> None:
        """Feeds ``src`` into the session. Blocks until the cipher
        chain accepts the bytes; errors are sticky."""
        s = _ffi.syms()
        src_b = _ffi.as_bytes(src)
        _ffi.check(int(s.lib.ITB_Triple_StreamWrite(self._handle, src_b, len(src_b))))

    def end(self) -> None:
        """Signals end-of-input. Idempotent; ``write`` after ``end``
        fails with ``BAD_INPUT``."""
        _ffi.check(int(_ffi.syms().lib.ITB_Triple_StreamEnd(self._handle)))
        self._ended = True

    def read(self, max_bytes: int = _PUMP_BUF) -> tuple[bytes, bool]:
        """Drains up to ``max_bytes`` produced bytes; returns
        ``(chunk, finished)``. Partial drains are normal. After
        ``end``, an empty-spool read blocks until the terminal bytes
        arrive or the session errors."""
        s = _ffi.syms()
        buf = ctypes.create_string_buffer(max_bytes)
        n = ctypes.c_size_t(0)
        fin = ctypes.c_int(0)
        _ffi.check(
            int(
                s.lib.ITB_Triple_StreamRead(
                    self._handle, buf, len(buf), ctypes.byref(n), ctypes.byref(fin)
                )
            )
        )
        return buf.raw[: n.value], fin.value != 0

    def drain_all(self) -> bytes:
        """Calls :meth:`end` (if not yet called) and returns every
        remaining output byte."""
        if not self._ended:
            self.end()
        out = bytearray()
        while True:
            chunk, finished = self.read()
            out += chunk
            if finished:
                return bytes(out)

    def pump(self, src: BinaryIO, dst: BinaryIO) -> None:
        """Moves ``src`` through the session into ``dst`` with bounded
        memory: feed a slice, drain available output, repeat; end +
        final drain on source EOF."""
        while True:
            piece = src.read(_PUMP_BUF)
            if not piece:
                break
            self.write(piece)
            # Drain whatever the chain has produced so far; a read
            # before end() never blocks.
            while True:
                chunk, _ = self.read()
                if not chunk:
                    break
                dst.write(chunk)
        self.end()
        while True:
            chunk, finished = self.read()
            if chunk:
                dst.write(chunk)
            if finished:
                break
        dst.flush()

    def free(self) -> None:
        """Cancels (if still running) and releases the session. Safe
        to call from any state and more than once."""
        if self._handle == 0:
            return
        handle, self._handle = self._handle, 0
        try:
            s = _ffi.syms()
        except ItbError:
            return
        s.lib.ITB_Triple_StreamFree(handle)

    def __enter__(self: _SessionT) -> _SessionT:
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


class EncryptStream(_Session):
    """Incremental encrypt session: plaintext in, wire out."""

    _BEGIN = "ITB_Triple_EncryptStreamBegin"


class DecryptStream(_Session):
    """Incremental decrypt session: wire in, plaintext out."""

    _BEGIN = "ITB_Triple_DecryptStreamBegin"
