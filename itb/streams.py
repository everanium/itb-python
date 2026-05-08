"""File-like streaming wrappers over the one-shot ITB encrypt/decrypt
API.

ITB ciphertexts cap at ~64 MB plaintext per chunk (the underlying
container size limit). Streaming larger payloads simply means
slicing the input into chunks at the binding layer, encrypting each
chunk through the regular FFI path, and concatenating the results.
The reverse operation walks a concatenated chunk stream by reading
the chunk header, calling :func:`itb.parse_chunk_len` to learn the
chunk's body length, reading that many bytes, and decrypting the
single chunk.

Both classes accept any binary file-like object for the ``fout`` /
``fin`` arguments (open files, ``io.BytesIO``, sockets wrapped in
``socket.makefile('wb')`` etc.). Memory peak per call is bounded
by ``chunk_size`` (default 16 MB), regardless of the total payload
length.

The Triple-Ouroboros (7-seed) variants share the same I/O contract
and only differ in the seed list passed to the constructor.
"""

from __future__ import annotations

import ctypes
from typing import IO, Optional

from . import _ffi
from ._ffi import (
    Seed,
    MAC,
    ITBError,
    STATUS_BAD_INPUT,
    STATUS_EASY_CLOSED,
    encrypt as _encrypt,
    decrypt as _decrypt,
    encrypt_triple as _encrypt_triple,
    decrypt_triple as _decrypt_triple,
    parse_chunk_len,
    header_size,
)

# Default chunk size matches itb.DefaultChunkSize on the Go side
# (16 MB) — the size at which ITB's barrier-encoded container
# layout stays well within the per-chunk pixel cap.
DEFAULT_CHUNK_SIZE = 16 * 1024 * 1024


class StreamEncryptor:
    """File-like writer that encrypts a stream of plaintext bytes
    chunk by chunk and writes each ciphertext chunk to an output
    binary file object.

    Usage:

        with itb.StreamEncryptor(ns, ds, ss, fout) as enc:
            while data := fin.read(1 << 20):
                enc.write(data)
        # closing the context flushes the trailing partial chunk

    The class accumulates `write()` input until at least
    ``chunk_size`` bytes are buffered, then encrypts and emits one
    chunk. ``close()`` flushes any tail < chunk_size as a final
    chunk (so the on-the-wire chunk count is `ceil(total / chunk)`).

    .. warning::
       Do not call :func:`itb.set_nonce_bits` between writes on the
       same stream. The chunks are encrypted under the active
       nonce-size at the moment each chunk is flushed; switching
       nonce-bits mid-stream produces a chunk header layout the
       paired :class:`StreamDecryptor` (which snapshots
       :func:`itb.header_size` at construction) cannot parse.
    """

    __slots__ = ("_seeds", "_fout", "_chunk_size", "_buf", "_closed")

    def __init__(
        self,
        noise: Seed,
        data: Seed,
        start: Seed,
        fout: IO[bytes],
        chunk_size: int = DEFAULT_CHUNK_SIZE,
    ):
        if chunk_size <= 0:
            raise ITBError(STATUS_BAD_INPUT, "chunk_size must be positive")
        self._seeds = (noise, data, start)
        self._fout = fout
        self._chunk_size = chunk_size
        self._buf = bytearray()
        self._closed = False

    def write(self, data: bytes) -> int:
        if self._closed:
            raise ITBError(STATUS_EASY_CLOSED, "write on closed StreamEncryptor")
        self._buf.extend(data)
        while len(self._buf) >= self._chunk_size:
            chunk = bytes(self._buf[: self._chunk_size])
            ct = _encrypt(*self._seeds, chunk)
            self._fout.write(ct)
            # Zero the consumed prefix in the source bytearray before
            # the slice-delete; del leaves the freed region in the
            # backing buffer otherwise.
            ctypes.memset(
                (ctypes.c_char * self._chunk_size).from_buffer(self._buf, 0),
                0,
                self._chunk_size,
            )
            del self._buf[: self._chunk_size]
        return len(data)

    def close(self) -> None:
        if self._closed:
            return
        if self._buf:
            ct = _encrypt(*self._seeds, bytes(self._buf))
            self._fout.write(ct)
            ctypes.memset(
                (ctypes.c_char * len(self._buf)).from_buffer(self._buf),
                0,
                len(self._buf),
            )
            self._buf.clear()
        self._closed = True

    def __enter__(self) -> "StreamEncryptor":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()


class StreamDecryptor:
    """File-like writer that decrypts a stream of ITB ciphertext
    chunks into the original plaintext, written to ``fout``.

    Usage:

        with itb.StreamDecryptor(ns, ds, ss, fout) as dec:
            while data := fin.read(1 << 20):
                dec.feed(data)

    The class accumulates `feed()` input until a full chunk
    (header + body) is available, then decrypts the chunk and
    writes the plaintext to ``fout``. Multiple full chunks in one
    feed call are processed sequentially.

    When :meth:`__exit__` is called during exception propagation,
    the partial-tail check is skipped so the original exception is
    not masked. Callers who need partial-tail detection during
    exception paths should call :meth:`close` explicitly.
    """

    __slots__ = ("_seeds", "_fout", "_buf", "_closed", "_header_size")

    def __init__(
        self,
        noise: Seed,
        data: Seed,
        start: Seed,
        fout: IO[bytes],
    ):
        self._seeds = (noise, data, start)
        self._fout = fout
        self._buf = bytearray()
        self._closed = False
        # Snapshot at construction so the decryptor uses the same
        # header layout the matching encryptor saw. Changing
        # SetNonceBits mid-stream would break decoding anyway.
        self._header_size = header_size()

    def feed(self, data: bytes) -> int:
        if self._closed:
            raise ITBError(STATUS_EASY_CLOSED, "feed on closed StreamDecryptor")
        self._buf.extend(data)
        self._drain()
        return len(data)

    def _drain(self) -> None:
        while True:
            if len(self._buf) < self._header_size:
                return
            chunk_len = parse_chunk_len(bytes(self._buf[: self._header_size]))
            if len(self._buf) < chunk_len:
                return
            chunk = bytes(self._buf[:chunk_len])
            pt = _decrypt(*self._seeds, chunk)
            self._fout.write(pt)
            del self._buf[:chunk_len]

    def close(self) -> None:
        if self._closed:
            return
        # Any leftover bytes that did not assemble into a full
        # chunk are a structural error: streaming ITB ciphertext
        # cannot have a half-chunk tail.
        if self._buf:
            raise ValueError(
                f"StreamDecryptor: trailing {len(self._buf)} bytes do not "
                "form a complete chunk"
            )
        self._closed = True

    def __enter__(self) -> "StreamDecryptor":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        # Suppress close-time errors only when an earlier exception
        # is propagating (otherwise close raises on partial input).
        if exc_type is None:
            self.close()
        else:
            self._closed = True


class StreamEncryptor3:
    """Triple-Ouroboros (7-seed) counterpart of :class:`StreamEncryptor`.

    .. warning::
       Do not call :func:`itb.set_nonce_bits` between writes on the
       same stream — see :class:`StreamEncryptor` for the rationale.
    """

    __slots__ = ("_seeds", "_fout", "_chunk_size", "_buf", "_closed")

    def __init__(
        self,
        noise: Seed,
        data1: Seed,
        data2: Seed,
        data3: Seed,
        start1: Seed,
        start2: Seed,
        start3: Seed,
        fout: IO[bytes],
        chunk_size: int = DEFAULT_CHUNK_SIZE,
    ):
        if chunk_size <= 0:
            raise ITBError(STATUS_BAD_INPUT, "chunk_size must be positive")
        self._seeds = (noise, data1, data2, data3, start1, start2, start3)
        self._fout = fout
        self._chunk_size = chunk_size
        self._buf = bytearray()
        self._closed = False

    def write(self, data: bytes) -> int:
        if self._closed:
            raise ITBError(STATUS_EASY_CLOSED, "write on closed StreamEncryptor3")
        self._buf.extend(data)
        while len(self._buf) >= self._chunk_size:
            chunk = bytes(self._buf[: self._chunk_size])
            ct = _encrypt_triple(*self._seeds, chunk)
            self._fout.write(ct)
            ctypes.memset(
                (ctypes.c_char * self._chunk_size).from_buffer(self._buf, 0),
                0,
                self._chunk_size,
            )
            del self._buf[: self._chunk_size]
        return len(data)

    def close(self) -> None:
        if self._closed:
            return
        if self._buf:
            ct = _encrypt_triple(*self._seeds, bytes(self._buf))
            self._fout.write(ct)
            ctypes.memset(
                (ctypes.c_char * len(self._buf)).from_buffer(self._buf),
                0,
                len(self._buf),
            )
            self._buf.clear()
        self._closed = True

    def __enter__(self) -> "StreamEncryptor3":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()


class StreamDecryptor3:
    """Triple-Ouroboros (7-seed) counterpart of :class:`StreamDecryptor`.

    When :meth:`__exit__` is called during exception propagation,
    the partial-tail check is skipped so the original exception is
    not masked. Callers who need partial-tail detection during
    exception paths should call :meth:`close` explicitly.
    """

    __slots__ = ("_seeds", "_fout", "_buf", "_closed", "_header_size")

    def __init__(
        self,
        noise: Seed,
        data1: Seed,
        data2: Seed,
        data3: Seed,
        start1: Seed,
        start2: Seed,
        start3: Seed,
        fout: IO[bytes],
    ):
        self._seeds = (noise, data1, data2, data3, start1, start2, start3)
        self._fout = fout
        self._buf = bytearray()
        self._closed = False
        self._header_size = header_size()

    def feed(self, data: bytes) -> int:
        if self._closed:
            raise ITBError(STATUS_EASY_CLOSED, "feed on closed StreamDecryptor3")
        self._buf.extend(data)
        self._drain()
        return len(data)

    def _drain(self) -> None:
        while True:
            if len(self._buf) < self._header_size:
                return
            chunk_len = parse_chunk_len(bytes(self._buf[: self._header_size]))
            if len(self._buf) < chunk_len:
                return
            chunk = bytes(self._buf[:chunk_len])
            pt = _decrypt_triple(*self._seeds, chunk)
            self._fout.write(pt)
            del self._buf[:chunk_len]

    def close(self) -> None:
        if self._closed:
            return
        if self._buf:
            raise ValueError(
                f"StreamDecryptor3: trailing {len(self._buf)} bytes do not "
                "form a complete chunk"
            )
        self._closed = True

    def __enter__(self) -> "StreamDecryptor3":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        if exc_type is None:
            self.close()
        else:
            self._closed = True


# ─── Functional convenience wrappers ───────────────────────────────────


def encrypt_stream(
    noise: Seed,
    data: Seed,
    start: Seed,
    fin: IO[bytes],
    fout: IO[bytes],
    chunk_size: int = DEFAULT_CHUNK_SIZE,
) -> None:
    """Reads plaintext from ``fin`` until EOF, encrypts in chunks of
    ``chunk_size``, and writes concatenated ITB chunks to ``fout``.
    """
    with StreamEncryptor(noise, data, start, fout, chunk_size) as enc:
        while True:
            buf = fin.read(chunk_size)
            if not buf:
                break
            enc.write(buf)


def decrypt_stream(
    noise: Seed,
    data: Seed,
    start: Seed,
    fin: IO[bytes],
    fout: IO[bytes],
    read_size: int = DEFAULT_CHUNK_SIZE,
) -> None:
    """Reads concatenated ITB chunks from ``fin`` until EOF and writes
    the recovered plaintext to ``fout``."""
    if read_size <= 0:
        raise ITBError(STATUS_BAD_INPUT, "read_size must be positive")
    with StreamDecryptor(noise, data, start, fout) as dec:
        while True:
            buf = fin.read(read_size)
            if not buf:
                break
            dec.feed(buf)


def encrypt_stream_triple(
    noise: Seed,
    data1: Seed,
    data2: Seed,
    data3: Seed,
    start1: Seed,
    start2: Seed,
    start3: Seed,
    fin: IO[bytes],
    fout: IO[bytes],
    chunk_size: int = DEFAULT_CHUNK_SIZE,
) -> None:
    """Triple-Ouroboros (7-seed) counterpart of :func:`encrypt_stream`."""
    with StreamEncryptor3(
        noise, data1, data2, data3, start1, start2, start3, fout, chunk_size
    ) as enc:
        while True:
            buf = fin.read(chunk_size)
            if not buf:
                break
            enc.write(buf)


def decrypt_stream_triple(
    noise: Seed,
    data1: Seed,
    data2: Seed,
    data3: Seed,
    start1: Seed,
    start2: Seed,
    start3: Seed,
    fin: IO[bytes],
    fout: IO[bytes],
    read_size: int = DEFAULT_CHUNK_SIZE,
) -> None:
    """Triple-Ouroboros (7-seed) counterpart of :func:`decrypt_stream`."""
    if read_size <= 0:
        raise ITBError(STATUS_BAD_INPUT, "read_size must be positive")
    with StreamDecryptor3(
        noise, data1, data2, data3, start1, start2, start3, fout
    ) as dec:
        while True:
            buf = fin.read(read_size)
            if not buf:
                break
            dec.feed(buf)


# ─── Authenticated streaming (Streaming AEAD) ───────────────────────────
#
# Streaming AEAD wrappers built on top of the per-chunk
# ITB_*StreamAuthenticated* ABI exports. The on-wire transcript carries
# a 32-byte CSPRNG ``stream_id`` prefix once at stream start, followed
# by a sequence of authenticated chunks each bound to the running
# ``(stream_id, cumulative_pixel_offset, final_flag)`` tuple inside
# the MAC closure. The encoder helper generates the prefix, emits it
# on the first ``write`` / ``close`` call, and tags the trailing chunk
# with ``final_flag = True``; the decoder helper reads the prefix once
# and verifies every chunk under the same anchor. Failure surfaces:
#
# - Chunk reorder / replay / cross-stream replay → ``ITBError`` with
#   :data:`STATUS_MAC_FAILURE`.
# - Truncate-tail (drop terminating chunk) → :class:`ItbStreamTruncatedError`.
# - Extra bytes past the terminating chunk →
#   :class:`ItbStreamAfterFinalError`.
# - Stream-prefix tamper → ``ITBError(STATUS_MAC_FAILURE)`` on chunk 0.
#
# The MAC handle (one per stream, allocated via :class:`itb.MAC`) is
# reused across every chunk; the helper does not free it. Closed-state
# preflight surfaces ``STATUS_EASY_CLOSED`` on any post-close call.

from ._ffi import (
    STREAM_ID_LEN as _STREAM_ID_LEN,
    STATUS_STREAM_TRUNCATED,
    STATUS_STREAM_AFTER_FINAL,
    ItbStreamTruncatedError,
    ItbStreamAfterFinalError,
    _generate_stream_id,
    _emit_chunk_auth_single,
    _emit_chunk_auth_triple,
    _consume_chunk_auth_single,
    _consume_chunk_auth_triple,
    _StreamAuthCache,
)


def _read_be16(buf, off: int) -> int:
    return (buf[off] << 8) | buf[off + 1]


class StreamEncryptorAuth:
    """Authenticated chunked-encrypt writer (Single Ouroboros + MAC).

    Buffers plaintext until at least ``chunk_size`` bytes are available,
    then drains one full chunk per FFI call. Each chunk is bound to
    the running ``(stream_id, cumulative_pixel_offset, final_flag)``
    tuple inside the MAC closure. The 32-byte CSPRNG ``stream_id``
    prefix is generated at construction and emitted to ``fout`` on the
    first :meth:`write` / :meth:`close` call; the prefix is not
    visible to the caller.

    Closed-state preflight: any :meth:`write` / :meth:`close` after
    :meth:`close` raises :class:`itb.ITBError` carrying
    :data:`itb._ffi.STATUS_EASY_CLOSED`.

    .. warning::
       Do not call :func:`itb.set_nonce_bits` between writes on the
       same stream. The chunks are encrypted under the active
       nonce-size at the moment each chunk is flushed; switching
       nonce-bits mid-stream produces a chunk header layout the
       paired :class:`StreamDecryptorAuth` cannot parse.
    """

    __slots__ = (
        "_seeds", "_mac", "_fout", "_chunk_size", "_buf", "_closed",
        "_stream_id", "_cum_pixels", "_header_size", "_width",
        "_prefix_emitted", "_out_cache",
    )

    def __init__(
        self,
        noise: Seed, data: Seed, start: Seed,
        mac,
        fout: IO[bytes],
        chunk_size: int = DEFAULT_CHUNK_SIZE,
    ):
        if chunk_size <= 0:
            raise ITBError(STATUS_BAD_INPUT, "chunk_size must be positive")
        self._seeds = (noise, data, start)
        self._mac = mac
        self._fout = fout
        self._chunk_size = chunk_size
        self._buf = bytearray()
        self._closed = False
        self._width = noise.width
        self._stream_id = _generate_stream_id()
        self._cum_pixels = 0
        self._header_size = header_size()
        self._prefix_emitted = False
        # Per-stream output buffer cache (Bonus 1b in .NEXTBIND.md
        # §7.1). Separate from the per-encryptor cache on
        # :class:`itb.easy.Encryptor` — the streaming class owns its
        # own cache because the helper free functions in :mod:`_ffi`
        # have no encryptor context to attach to.
        self._out_cache = _StreamAuthCache()

    def _emit_prefix(self) -> None:
        if not self._prefix_emitted:
            self._fout.write(self._stream_id)
            self._prefix_emitted = True

    def _emit_one(self, plaintext_len: int, final_flag: bool) -> None:
        chunk_pt = bytes(self._buf[:plaintext_len])
        # Wipe consumed prefix in source bytearray before slice-delete.
        if plaintext_len > 0:
            ctypes.memset(
                (ctypes.c_char * plaintext_len).from_buffer(self._buf, 0),
                0,
                plaintext_len,
            )
        del self._buf[:plaintext_len]
        ct = _emit_chunk_auth_single(
            self._width, *self._seeds, self._mac,
            chunk_pt, self._stream_id, self._cum_pixels, final_flag,
            cache=self._out_cache,
        )
        if len(ct) >= self._header_size:
            w = _read_be16(ct, self._header_size - 4)
            h = _read_be16(ct, self._header_size - 2)
            self._cum_pixels += w * h
        self._fout.write(ct)

    def write(self, data: bytes) -> int:
        if self._closed:
            raise ITBError(STATUS_EASY_CLOSED, "write on closed StreamEncryptorAuth")
        self._emit_prefix()
        self._buf.extend(data)
        # Keep at least one chunk's worth of bytes buffered until
        # close(): the deferred-final pattern needs end-of-input
        # signalled before a chunk can carry final_flag = True.
        while len(self._buf) > self._chunk_size:
            self._emit_one(self._chunk_size, False)
        return len(data)

    def close(self) -> None:
        if self._closed:
            # Idempotent — but still wipe cache on repeated close.
            self._out_cache.wipe()
            return
        self._emit_prefix()
        self._emit_one(len(self._buf), True)
        self._closed = True
        # Wipe per-stream cache so the last chunk's ciphertext does
        # not linger in heap memory.
        self._out_cache.wipe()

    def __enter__(self) -> "StreamEncryptorAuth":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()

    def __del__(self):
        # Best-effort GC release — wipe the per-stream cache even when
        # the consumer leaks the writer without calling close().
        try:
            self._out_cache.wipe()
        except Exception:
            pass


class StreamDecryptorAuth:
    """Authenticated chunked-decrypt writer (Single Ouroboros + MAC).

    Reads the 32-byte ``stream_id`` prefix once, then drains every
    complete chunk available in the internal buffer. Each chunk is
    verified under the running cumulative pixel offset and recovered
    ``final_flag``. An incomplete 32-byte prefix at :meth:`close`
    surfaces as :class:`itb.ITBError` carrying
    :data:`STATUS_BAD_INPUT` (wire-level malformation, header never
    finished arriving). Missing terminator after a fully observed
    prefix surfaces from :meth:`close` as
    :class:`ItbStreamTruncatedError`; trailing bytes after the
    terminator surface from :meth:`feed` / :meth:`close` as
    :class:`ItbStreamAfterFinalError`. Tampered transcript / wrong
    MAC key surface as :class:`itb.ITBError` carrying
    :data:`STATUS_MAC_FAILURE`.

    When :meth:`__exit__` is called during exception propagation,
    the partial-tail check is skipped so the original exception is
    not masked.
    """

    __slots__ = (
        "_seeds", "_mac", "_fout", "_buf", "_closed",
        "_stream_id", "_sid_have", "_cum_pixels", "_header_size",
        "_width", "_seen_final", "_out_cache",
    )

    def __init__(
        self,
        noise: Seed, data: Seed, start: Seed,
        mac,
        fout: IO[bytes],
    ):
        self._seeds = (noise, data, start)
        self._mac = mac
        self._fout = fout
        self._buf = bytearray()
        self._closed = False
        self._stream_id = bytearray(_STREAM_ID_LEN)
        self._sid_have = 0
        self._cum_pixels = 0
        self._header_size = header_size()
        self._width = noise.width
        self._seen_final = False
        # Per-stream output buffer cache (Bonus 1b in .NEXTBIND.md
        # §7.1). See :class:`StreamEncryptorAuth` for rationale.
        self._out_cache = _StreamAuthCache()

    def _drain(self) -> None:
        while True:
            if self._seen_final:
                if self._buf:
                    raise ItbStreamAfterFinalError(
                        "auth stream: trailing bytes after terminator")
                return
            if len(self._buf) < self._header_size:
                return
            chunk_len = parse_chunk_len(bytes(self._buf[: self._header_size]))
            if len(self._buf) < chunk_len:
                return
            w = _read_be16(self._buf, self._header_size - 4)
            h = _read_be16(self._buf, self._header_size - 2)
            pixels = w * h
            chunk = bytes(self._buf[:chunk_len])
            del self._buf[:chunk_len]
            pt, ff = _consume_chunk_auth_single(
                self._width, *self._seeds, self._mac,
                chunk, bytes(self._stream_id), self._cum_pixels,
                cache=self._out_cache,
            )
            self._fout.write(pt)
            self._cum_pixels += pixels
            if ff:
                self._seen_final = True

    def feed(self, data: bytes) -> int:
        if self._closed:
            raise ITBError(STATUS_EASY_CLOSED, "feed on closed StreamDecryptorAuth")
        off = 0
        if self._sid_have < _STREAM_ID_LEN:
            need = _STREAM_ID_LEN - self._sid_have
            take = min(need, len(data))
            self._stream_id[self._sid_have : self._sid_have + take] = data[:take]
            self._sid_have += take
            off = take
        if off < len(data):
            self._buf.extend(data[off:])
        if self._sid_have == _STREAM_ID_LEN:
            self._drain()
        return len(data)

    def close(self) -> None:
        if self._closed:
            self._out_cache.wipe()
            return
        if self._sid_have < _STREAM_ID_LEN:
            self._closed = True
            self._out_cache.wipe()
            # An incomplete 32-byte stream-id prefix is a wire-level
            # malformation (header never finished arriving), distinct
            # from "chunks observed but no terminator chunk among
            # them" which is the truncate-tail signal.
            raise ITBError(
                STATUS_BAD_INPUT,
                "auth stream: prefix never observed")
        self._drain()
        self._closed = True
        # Wipe per-stream cache after the last chunk has been
        # consumed so the recovered plaintext does not linger in
        # heap memory.
        self._out_cache.wipe()
        if not self._seen_final:
            raise ItbStreamTruncatedError(
                "auth stream: terminator never observed")

    def __enter__(self) -> "StreamDecryptorAuth":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        if exc_type is None:
            self.close()
        else:
            self._closed = True
            self._out_cache.wipe()

    def __del__(self):
        try:
            self._out_cache.wipe()
        except Exception:
            pass


class StreamEncryptorAuth3:
    """Triple-Ouroboros (7-seed) counterpart of
    :class:`StreamEncryptorAuth`."""

    __slots__ = (
        "_seeds", "_mac", "_fout", "_chunk_size", "_buf", "_closed",
        "_stream_id", "_cum_pixels", "_header_size", "_width",
        "_prefix_emitted", "_out_cache",
    )

    def __init__(
        self,
        noise: Seed,
        data1: Seed, data2: Seed, data3: Seed,
        start1: Seed, start2: Seed, start3: Seed,
        mac,
        fout: IO[bytes],
        chunk_size: int = DEFAULT_CHUNK_SIZE,
    ):
        if chunk_size <= 0:
            raise ITBError(STATUS_BAD_INPUT, "chunk_size must be positive")
        self._seeds = (noise, data1, data2, data3, start1, start2, start3)
        self._mac = mac
        self._fout = fout
        self._chunk_size = chunk_size
        self._buf = bytearray()
        self._closed = False
        self._width = noise.width
        self._stream_id = _generate_stream_id()
        self._cum_pixels = 0
        self._header_size = header_size()
        self._prefix_emitted = False
        # Per-stream output buffer cache (Bonus 1b in .NEXTBIND.md
        # §7.1). See :class:`StreamEncryptorAuth` for rationale.
        self._out_cache = _StreamAuthCache()

    def _emit_prefix(self) -> None:
        if not self._prefix_emitted:
            self._fout.write(self._stream_id)
            self._prefix_emitted = True

    def _emit_one(self, plaintext_len: int, final_flag: bool) -> None:
        chunk_pt = bytes(self._buf[:plaintext_len])
        if plaintext_len > 0:
            ctypes.memset(
                (ctypes.c_char * plaintext_len).from_buffer(self._buf, 0),
                0,
                plaintext_len,
            )
        del self._buf[:plaintext_len]
        ct = _emit_chunk_auth_triple(
            self._width, *self._seeds, self._mac,
            chunk_pt, self._stream_id, self._cum_pixels, final_flag,
            cache=self._out_cache,
        )
        if len(ct) >= self._header_size:
            w = _read_be16(ct, self._header_size - 4)
            h = _read_be16(ct, self._header_size - 2)
            self._cum_pixels += w * h
        self._fout.write(ct)

    def write(self, data: bytes) -> int:
        if self._closed:
            raise ITBError(STATUS_EASY_CLOSED, "write on closed StreamEncryptorAuth3")
        self._emit_prefix()
        self._buf.extend(data)
        while len(self._buf) > self._chunk_size:
            self._emit_one(self._chunk_size, False)
        return len(data)

    def close(self) -> None:
        if self._closed:
            self._out_cache.wipe()
            return
        self._emit_prefix()
        self._emit_one(len(self._buf), True)
        self._closed = True
        self._out_cache.wipe()

    def __enter__(self) -> "StreamEncryptorAuth3":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()

    def __del__(self):
        try:
            self._out_cache.wipe()
        except Exception:
            pass


class StreamDecryptorAuth3:
    """Triple-Ouroboros (7-seed) counterpart of
    :class:`StreamDecryptorAuth`."""

    __slots__ = (
        "_seeds", "_mac", "_fout", "_buf", "_closed",
        "_stream_id", "_sid_have", "_cum_pixels", "_header_size",
        "_width", "_seen_final", "_out_cache",
    )

    def __init__(
        self,
        noise: Seed,
        data1: Seed, data2: Seed, data3: Seed,
        start1: Seed, start2: Seed, start3: Seed,
        mac,
        fout: IO[bytes],
    ):
        self._seeds = (noise, data1, data2, data3, start1, start2, start3)
        self._mac = mac
        self._fout = fout
        self._buf = bytearray()
        self._closed = False
        self._stream_id = bytearray(_STREAM_ID_LEN)
        self._sid_have = 0
        self._cum_pixels = 0
        self._header_size = header_size()
        self._width = noise.width
        self._seen_final = False
        # Per-stream output buffer cache (Bonus 1b in .NEXTBIND.md
        # §7.1). See :class:`StreamEncryptorAuth` for rationale.
        self._out_cache = _StreamAuthCache()

    def _drain(self) -> None:
        while True:
            if self._seen_final:
                if self._buf:
                    raise ItbStreamAfterFinalError(
                        "auth stream: trailing bytes after terminator")
                return
            if len(self._buf) < self._header_size:
                return
            chunk_len = parse_chunk_len(bytes(self._buf[: self._header_size]))
            if len(self._buf) < chunk_len:
                return
            w = _read_be16(self._buf, self._header_size - 4)
            h = _read_be16(self._buf, self._header_size - 2)
            pixels = w * h
            chunk = bytes(self._buf[:chunk_len])
            del self._buf[:chunk_len]
            pt, ff = _consume_chunk_auth_triple(
                self._width, *self._seeds, self._mac,
                chunk, bytes(self._stream_id), self._cum_pixels,
                cache=self._out_cache,
            )
            self._fout.write(pt)
            self._cum_pixels += pixels
            if ff:
                self._seen_final = True

    def feed(self, data: bytes) -> int:
        if self._closed:
            raise ITBError(STATUS_EASY_CLOSED, "feed on closed StreamDecryptorAuth3")
        off = 0
        if self._sid_have < _STREAM_ID_LEN:
            need = _STREAM_ID_LEN - self._sid_have
            take = min(need, len(data))
            self._stream_id[self._sid_have : self._sid_have + take] = data[:take]
            self._sid_have += take
            off = take
        if off < len(data):
            self._buf.extend(data[off:])
        if self._sid_have == _STREAM_ID_LEN:
            self._drain()
        return len(data)

    def close(self) -> None:
        if self._closed:
            self._out_cache.wipe()
            return
        if self._sid_have < _STREAM_ID_LEN:
            self._closed = True
            self._out_cache.wipe()
            # An incomplete 32-byte stream-id prefix is a wire-level
            # malformation (header never finished arriving), distinct
            # from "chunks observed but no terminator chunk among
            # them" which is the truncate-tail signal.
            raise ITBError(
                STATUS_BAD_INPUT,
                "auth stream: prefix never observed")
        self._drain()
        self._closed = True
        self._out_cache.wipe()
        if not self._seen_final:
            raise ItbStreamTruncatedError(
                "auth stream: terminator never observed")

    def __enter__(self) -> "StreamDecryptorAuth3":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        if exc_type is None:
            self.close()
        else:
            self._closed = True
            self._out_cache.wipe()

    def __del__(self):
        try:
            self._out_cache.wipe()
        except Exception:
            pass


def encrypt_stream_auth(
    noise: Seed, data: Seed, start: Seed,
    mac,
    fin: IO[bytes],
    fout: IO[bytes],
    chunk_size: int = DEFAULT_CHUNK_SIZE,
) -> None:
    """Reads plaintext from ``fin`` until EOF, encrypts each chunk
    under the Streaming AEAD construction, and writes the
    concatenated ``stream_id || chunk_0 || chunk_1 || ...``
    transcript to ``fout``."""
    with StreamEncryptorAuth(noise, data, start, mac, fout, chunk_size) as enc:
        while True:
            buf = fin.read(chunk_size)
            if not buf:
                break
            enc.write(buf)


def decrypt_stream_auth(
    noise: Seed, data: Seed, start: Seed,
    mac,
    fin: IO[bytes],
    fout: IO[bytes],
    read_size: int = DEFAULT_CHUNK_SIZE,
) -> None:
    """Reads a Streaming AEAD transcript from ``fin`` until EOF and
    writes the recovered plaintext to ``fout``. Surfaces
    :class:`itb.ITBError` carrying :data:`STATUS_BAD_INPUT` when the
    input exhausts mid-prefix (incomplete 32-byte stream-id header),
    :class:`ItbStreamTruncatedError` when the prefix is fully observed
    but no terminating chunk arrives,
    :class:`ItbStreamAfterFinalError` when bytes follow the
    terminator, and :class:`itb.ITBError` carrying
    :data:`STATUS_MAC_FAILURE` on any per-chunk MAC mismatch."""
    if read_size <= 0:
        raise ITBError(STATUS_BAD_INPUT, "read_size must be positive")
    with StreamDecryptorAuth(noise, data, start, mac, fout) as dec:
        while True:
            buf = fin.read(read_size)
            if not buf:
                break
            dec.feed(buf)


def encrypt_stream_auth_triple(
    noise: Seed,
    data1: Seed, data2: Seed, data3: Seed,
    start1: Seed, start2: Seed, start3: Seed,
    mac,
    fin: IO[bytes],
    fout: IO[bytes],
    chunk_size: int = DEFAULT_CHUNK_SIZE,
) -> None:
    """Triple-Ouroboros (7-seed) counterpart of
    :func:`encrypt_stream_auth`."""
    with StreamEncryptorAuth3(
        noise, data1, data2, data3, start1, start2, start3, mac, fout, chunk_size,
    ) as enc:
        while True:
            buf = fin.read(chunk_size)
            if not buf:
                break
            enc.write(buf)


def decrypt_stream_auth_triple(
    noise: Seed,
    data1: Seed, data2: Seed, data3: Seed,
    start1: Seed, start2: Seed, start3: Seed,
    mac,
    fin: IO[bytes],
    fout: IO[bytes],
    read_size: int = DEFAULT_CHUNK_SIZE,
) -> None:
    """Triple-Ouroboros (7-seed) counterpart of
    :func:`decrypt_stream_auth`."""
    if read_size <= 0:
        raise ITBError(STATUS_BAD_INPUT, "read_size must be positive")
    with StreamDecryptorAuth3(
        noise, data1, data2, data3, start1, start2, start3, mac, fout,
    ) as dec:
        while True:
            buf = fin.read(read_size)
            if not buf:
                break
            dec.feed(buf)
