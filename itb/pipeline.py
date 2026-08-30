"""Handle-lifetime wrapper around the Triple Pipeline surface."""

from __future__ import annotations

import ctypes
from collections.abc import Callable
from types import TracebackType
from typing import BinaryIO

from . import _ffi
from .error import ItbError
from .opts import Opts
from .status import Status
from .stream import DecryptStream, EncryptStream

Buffer = bytes | bytearray | memoryview

# Floor capacity for blob output buffers (Init / Rekey).
_BLOB_CAP = 64 * 1024


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
    # capacity — pattern P1 in the fleet audit.
    if rc == int(Status.BUFFER_TOO_SMALL) and n.value > cap:
        buf = ctypes.create_string_buffer(n.value)
        rc = call(buf, n)
    _ffi.check(rc)
    return buf.raw[: n.value]


class Pipeline:
    """A Triple Pipeline session plus its exported blob bytes.

    The blob carries the session bundle the receiver feeds to
    :meth:`Pipeline.open`; :meth:`Pipeline.rekey` refreshes it. The
    Pipeline is a context manager; leaving the ``with`` block (or
    garbage collection via ``__del__``) frees the handle — libitb
    zeroes key material internally.

    Streaming-decrypt caveat: chunked Streaming AEAD verifies per
    chunk, so plaintext of verified chunks is released before a later
    chunk can fail authentication.
    """

    def __init__(self, handle: int, blob: bytes) -> None:
        # Not part of the public API — use init() / open().
        self._handle = handle
        self._blob = blob

    @classmethod
    def init(cls, profile: str, opts: Opts | None = None) -> Pipeline:
        """Constructs a fresh Pipeline against the named profile. On a
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

        blob = _retry_once(_BLOB_CAP, call)
        return cls(handle.value, blob)

    @classmethod
    def open(
        cls,
        profile: str,
        blob: Buffer,
        opts: Opts | None = None,
        masters: tuple[Buffer, Buffer] | None = None,
    ) -> Pipeline:
        """Reconstructs a Pipeline from a blob produced by
        :meth:`Pipeline.init` or :meth:`Pipeline.rekey`. ``masters``
        is ``None`` to use the blob-embedded masters, or a
        ``(perm, wrap)`` pair to override them."""
        s = _ffi.syms()
        profile_b = profile.encode("utf-8")
        opts_b = (opts or Opts()).build().encode("utf-8")
        blob_b = _ffi.as_bytes(blob)
        if masters is None:
            pm, wm, count = b"", b"", 0
        else:
            pm, wm = _ffi.as_bytes(masters[0]), _ffi.as_bytes(masters[1])
            if not pm or not wm:
                raise ItbError("master override buffers must be non-empty")
            count = 2
        handle = ctypes.c_size_t(0)
        _ffi.check(
            int(
                s.lib.ITB_Triple_Open(
                    profile_b,
                    blob_b,
                    len(blob_b),
                    opts_b,
                    pm,
                    len(pm),
                    wm,
                    len(wm),
                    count,
                    ctypes.byref(handle),
                )
            )
        )
        return cls(handle.value, blob_b)

    @property
    def blob(self) -> bytes:
        """The exported session bundle bytes for the receiver side."""
        return self._blob

    def rekey(self, perm: Buffer, wrap: Buffer) -> None:
        """Rotates the parallax + wrapper masters and refreshes
        :attr:`blob`. Must not run concurrently with cipher calls or
        open stream sessions on the same Pipeline."""
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

        self._blob = _retry_once(max(_BLOB_CAP, len(self._blob)), call)

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
        # The blob bytes are elided — session-bundle material does not
        # belong in debug logs.
        return f"Pipeline(blob_len={len(self._blob)})"


def register_profile(name: str, opts: Opts) -> None:
    """Registers a user-defined Triple profile under ``name`` so
    subsequent :meth:`Pipeline.init` / :meth:`Pipeline.open` calls
    resolve it. The opts follow the register-profile grammar validated
    by Go (``mode``, ``width``, ``innerHash`` / ``innerHashes``,
    ``keyBits``, ``macName``, ``outerCipher``, ``parallaxPalette``,
    ``parallaxSegmentSize``, ``chunkSize``, ``parallaxOn``,
    ``wrapperOn``) — build them with :meth:`Opts.with_raw` plus the
    typed setters where key names coincide. A duplicate name fails
    with :attr:`~itb.status.Status.PROFILE_EXISTS`."""
    s = _ffi.syms()
    _ffi.check(
        int(
            s.lib.ITB_Triple_RegisterProfile(
                name.encode("utf-8"), opts.build().encode("utf-8")
            )
        )
    )
