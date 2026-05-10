"""Format-deniability wrapper for ITB ciphertext.

Python-idiomatic surface over the 12 ``ITB_Wrap*`` / ``ITB_Unwrap*`` /
``ITB_WrapStream*`` / ``ITB_UnwrapStream*`` / ``ITB_WrapperKeySize`` /
``ITB_WrapperNonceSize`` exports in ``cmd/cshared/main.go``. Wraps an
ITB ciphertext under one of three outer keystream ciphers
(AES-128-CTR / ChaCha20 / SipHash-2-4 in CTR mode) so the on-wire
bytes carry no ITB-specific format pattern (W / H / container layout
for Non-AEAD; 32-byte streamID prefix + per-chunk metadata for
Streaming AEAD). The wrap exists for format-deniability ONLY — ITB
already provides content-deniability and the AEAD path already
provides integrity.

Quick start (Single Message Wrap / Unwrap):

    >>> from itb import wrapper
    >>> key = wrapper.generate_key(wrapper.CIPHER_AES128_CTR)
    >>> blob = b"...ITB ciphertext bytes..."
    >>> wire = wrapper.wrap(wrapper.CIPHER_AES128_CTR, key, blob)
    >>> recovered = wrapper.unwrap(wrapper.CIPHER_AES128_CTR, key, wire)
    >>> assert recovered == blob

Single Message in-place mutation (zero-allocation steady state):

    >>> mutable = bytearray(blob)
    >>> nonce = wrapper.wrap_in_place(wrapper.CIPHER_CHACHA20, key, mutable)
    >>> wire = bytes(nonce) + bytes(mutable)
    >>> # On the receive side:
    >>> mutable_wire = bytearray(wire)
    >>> body_view = wrapper.unwrap_in_place(
    ...     wrapper.CIPHER_CHACHA20, key, mutable_wire,
    ... )
    >>> assert bytes(body_view) == blob

Streaming wrap (caller-side framing through one keystream so length
prefixes also XOR through):

    >>> with wrapper.WrapStreamWriter(wrapper.CIPHER_SIPHASH24, key) as ww:
    ...     ww.update(b"chunk-1")
    ...     ww.update(b"chunk-2")
    ...     wire = ww.nonce + ww.update(b"...")  # accumulator pattern

The cipher_name argument selects one of three outer ciphers: "aes"
(AES-128-CTR — 16-byte key + 16-byte nonce, AES-NI accelerated),
"chacha" (ChaCha20 (RFC8439) — 32-byte key + 12-byte nonce), or
"siphash" (SipHash-2-4 in CTR mode — 16-byte key + 16-byte nonce,
custom CTR construction over the SipHash-2-4 PRF).

Threading. Each :class:`WrapStreamWriter` / :class:`UnwrapStreamReader`
instance owns one libitb stream handle and is single-writer by
construction; multiple instances run independently. The free
functions (:func:`wrap` / :func:`unwrap` / :func:`wrap_in_place` /
:func:`unwrap_in_place`) are thread-safe — each call allocates its
own outer cipher handle internally and the underlying libitb keystream
constructor draws a fresh CSPRNG nonce per call.
"""

from __future__ import annotations

import secrets
from typing import Optional

from ._ffi import (
    _ffi,
    _lib,
    _last_error,
    ITBError,
    STATUS_OK,
    STATUS_BAD_INPUT,
    STATUS_BAD_HANDLE,
    STATUS_BUFFER_TOO_SMALL,
)

# Canonical outer cipher names accepted by the wrap surface. Match
# the ``CipherAES128CTR`` / ``CipherChaCha20`` / ``CipherSipHash24``
# constants in github.com/everanium/itb/wrapper.
CIPHER_AES128_CTR = "aes"
CIPHER_CHACHA20 = "chacha"
CIPHER_SIPHASH24 = "siphash"

CIPHER_NAMES = (CIPHER_AES128_CTR, CIPHER_CHACHA20, CIPHER_SIPHASH24)


class WrapperError(ITBError):
    """Base class for every wrapper-side typed exception. Subclasses
    map a structural failure mode (unknown cipher name, key length
    mismatch, nonce length mismatch, exhausted handle) onto a
    ``STATUS_*`` code from :mod:`itb._ffi` so callers can branch on
    the failure kind without parsing the textual ``last_error``
    diagnostic."""


class InvalidCipherError(WrapperError):
    """Raised when ``cipher_name`` is not one of "aes" / "chacha" /
    "siphash". Carries :data:`itb.STATUS_BAD_INPUT`."""

    def __init__(self, cipher_name: str):
        super().__init__(
            STATUS_BAD_INPUT,
            f"unknown wrapper cipher {cipher_name!r} (expected one of {CIPHER_NAMES!r})",
        )


class InvalidKeyError(WrapperError):
    """Raised when the supplied key length does not match the
    cipher's expected key size. Carries :data:`itb.STATUS_BAD_INPUT`."""


class InvalidNonceError(WrapperError):
    """Raised when an internal nonce buffer cannot be sized for the
    selected cipher (e.g. a logic-level inconsistency between
    :func:`nonce_size` and the buffer caller passes through). Carries
    :data:`itb.STATUS_BAD_INPUT`."""


class WrapperHandleClosedError(WrapperError):
    """Raised when a streaming :meth:`WrapStreamWriter.update` /
    :meth:`UnwrapStreamReader.update` call follows
    :meth:`close`. Carries :data:`itb.STATUS_BAD_HANDLE`."""

    def __init__(self):
        super().__init__(STATUS_BAD_HANDLE, "stream handle has been closed")


def _validate_cipher_name(cipher_name: str) -> bytes:
    if cipher_name not in CIPHER_NAMES:
        raise InvalidCipherError(cipher_name)
    return cipher_name.encode("utf-8")


def _bytes_view(data) -> bytes:
    if isinstance(data, (bytes, bytearray, memoryview)):
        return bytes(data)
    raise TypeError("expected bytes-like input")


def _raise_wrapper(code: int) -> None:
    """Internal — re-raises an ITBError carrying the libitb LastError
    diagnostic. Used on every non-OK return from the wrapper FFI."""
    raise WrapperError(code, _last_error())


def key_size(cipher_name: str) -> int:
    """Returns the byte length of the keystream-cipher key for the
    named outer cipher (16 / 32 / 16 for "aes" / "chacha" /
    "siphash"). Raises :class:`InvalidCipherError` for any other
    name."""
    cn = _validate_cipher_name(cipher_name)
    out = _ffi.new("size_t*")
    rc = _lib.ITB_WrapperKeySize(cn, out)
    if rc != STATUS_OK:
        _raise_wrapper(rc)
    return int(out[0])


def nonce_size(cipher_name: str) -> int:
    """Returns the on-wire nonce length the named outer cipher emits
    per stream (16 / 12 / 16 for "aes" / "chacha" / "siphash").
    Raises :class:`InvalidCipherError` for any other name."""
    cn = _validate_cipher_name(cipher_name)
    out = _ffi.new("size_t*")
    rc = _lib.ITB_WrapperNonceSize(cn, out)
    if rc != STATUS_OK:
        _raise_wrapper(rc)
    return int(out[0])


def generate_key(cipher_name: str) -> bytes:
    """Returns a fresh CSPRNG key of the size required by
    ``cipher_name`` (16 / 32 / 16 bytes for "aes" / "chacha" /
    "siphash"). Uses Python's :func:`secrets.token_bytes`. The
    returned key is opaque bytes; the caller stores or shares it
    out-of-band.
    """
    return secrets.token_bytes(key_size(cipher_name))


def wrap(cipher_name: str, key: bytes, blob: bytes) -> bytes:
    """Single Message wrap. Seals ``blob`` under ``cipher_name`` with a
    fresh per-call CSPRNG nonce; returns the wire bytes
    ``nonce || keystream-XOR(blob)``.

    Allocates a fresh output buffer of size
    ``nonce_size(cipher_name) + len(blob)`` per call. For zero-
    allocation steady state on the hot path use :func:`wrap_in_place`.
    """
    cn = _validate_cipher_name(cipher_name)
    key_b = _bytes_view(key)
    if len(key_b) != key_size(cipher_name):
        raise InvalidKeyError(
            STATUS_BAD_INPUT,
            f"{cipher_name!r}: key must be {key_size(cipher_name)} bytes, got {len(key_b)}",
        )
    blob_b = _bytes_view(blob)
    cap = nonce_size(cipher_name) + len(blob_b)
    out_buf = _ffi.new("unsigned char[]", cap)
    out_len = _ffi.new("size_t*")
    in_blob = blob_b if blob_b else _ffi.NULL
    rc = _lib.ITB_Wrap(
        cn,
        key_b, len(key_b),
        in_blob, len(blob_b),
        out_buf, cap, out_len,
    )
    if rc != STATUS_OK:
        _raise_wrapper(rc)
    return bytes(_ffi.buffer(out_buf, int(out_len[0])))


def unwrap(cipher_name: str, key: bytes, wire: bytes) -> bytes:
    """Single Message unwrap. Reads the leading ``nonce_size(cipher_name)``
    bytes of ``wire`` as the per-stream nonce, XOR-decrypts the
    remainder under ``(key, nonce)`` and returns the recovered blob.

    Allocates a fresh output buffer of size
    ``len(wire) - nonce_size(cipher_name)`` per call. For zero-
    allocation steady state use :func:`unwrap_in_place`.
    """
    cn = _validate_cipher_name(cipher_name)
    key_b = _bytes_view(key)
    if len(key_b) != key_size(cipher_name):
        raise InvalidKeyError(
            STATUS_BAD_INPUT,
            f"{cipher_name!r}: key must be {key_size(cipher_name)} bytes, got {len(key_b)}",
        )
    wire_b = _bytes_view(wire)
    nlen = nonce_size(cipher_name)
    if len(wire_b) < nlen:
        raise InvalidNonceError(
            STATUS_BAD_INPUT,
            f"{cipher_name!r}: wire shorter than nonce ({len(wire_b)} < {nlen})",
        )
    cap = len(wire_b) - nlen
    out_buf = _ffi.new("unsigned char[]", max(cap, 1))
    out_len = _ffi.new("size_t*")
    rc = _lib.ITB_Unwrap(
        cn,
        key_b, len(key_b),
        wire_b, len(wire_b),
        out_buf, cap, out_len,
    )
    if rc != STATUS_OK:
        _raise_wrapper(rc)
    return bytes(_ffi.buffer(out_buf, int(out_len[0])))


def wrap_in_place(cipher_name: str, key: bytes, blob) -> bytes:
    """In-place Single Message wrap. XORs ``blob`` under a fresh per-
    call CSPRNG nonce; returns the per-stream nonce as ``bytes``.

    The input ``blob`` is **MUTATED**. Pass a :class:`bytearray` or
    a writable :class:`memoryview`; the caller is expected to emit
    ``nonce || blob`` to the wire (or compose a single buffer).

    Suitable for hot paths where the caller has just produced an
    ITB ciphertext and will not re-read it (the typical case for
    buffered write-to-wire). For an immutable plaintext path use
    :func:`wrap`.
    """
    cn = _validate_cipher_name(cipher_name)
    key_b = _bytes_view(key)
    if len(key_b) != key_size(cipher_name):
        raise InvalidKeyError(
            STATUS_BAD_INPUT,
            f"{cipher_name!r}: key must be {key_size(cipher_name)} bytes, got {len(key_b)}",
        )
    if not isinstance(blob, (bytearray, memoryview)):
        raise TypeError(
            "blob must be a writable bytes-like buffer (bytearray / memoryview); "
            "use wrap() for an immutable bytes input"
        )
    if isinstance(blob, memoryview) and blob.readonly:
        raise TypeError("blob memoryview must be writable")
    nlen = nonce_size(cipher_name)
    nonce_buf = _ffi.new("unsigned char[]", nlen)
    blob_view = _ffi.from_buffer("unsigned char[]", blob)
    blob_len = len(blob)
    in_arg = blob_view if blob_len > 0 else _ffi.NULL
    rc = _lib.ITB_WrapInPlace(
        cn,
        key_b, len(key_b),
        in_arg, blob_len,
        nonce_buf, nlen,
    )
    if rc != STATUS_OK:
        _raise_wrapper(rc)
    return bytes(_ffi.buffer(nonce_buf, nlen))


def unwrap_in_place(cipher_name: str, key: bytes, wire) -> memoryview:
    """In-place Single Message unwrap. Strips the leading
    ``nonce_size(cipher_name)`` bytes from ``wire`` and XOR-decrypts
    the remainder under ``(key, nonce)`` directly into the caller's
    buffer.

    The input ``wire`` is **MUTATED**. Pass a :class:`bytearray` or
    a writable :class:`memoryview`. The returned :class:`memoryview`
    aliases ``wire[nonce_size(cipher_name):]`` and contains the
    recovered blob; the leading nonce prefix is left unchanged.

    For an immutable wire input use :func:`unwrap`.
    """
    cn = _validate_cipher_name(cipher_name)
    key_b = _bytes_view(key)
    if len(key_b) != key_size(cipher_name):
        raise InvalidKeyError(
            STATUS_BAD_INPUT,
            f"{cipher_name!r}: key must be {key_size(cipher_name)} bytes, got {len(key_b)}",
        )
    if not isinstance(wire, (bytearray, memoryview)):
        raise TypeError(
            "wire must be a writable bytes-like buffer (bytearray / memoryview); "
            "use unwrap() for an immutable bytes input"
        )
    if isinstance(wire, memoryview) and wire.readonly:
        raise TypeError("wire memoryview must be writable")
    nlen = nonce_size(cipher_name)
    if len(wire) < nlen:
        raise InvalidNonceError(
            STATUS_BAD_INPUT,
            f"{cipher_name!r}: wire shorter than nonce ({len(wire)} < {nlen})",
        )
    wire_view = _ffi.from_buffer("unsigned char[]", wire)
    rc = _lib.ITB_UnwrapInPlace(
        cn,
        key_b, len(key_b),
        wire_view, len(wire),
    )
    if rc != STATUS_OK:
        _raise_wrapper(rc)
    # Return an aliased memoryview over the body section (post-nonce
    # bytes). Mirrors the Go-side return contract — Go returns
    # ``wire[NonceSize(name):]``.
    if isinstance(wire, bytearray):
        return memoryview(wire)[nlen:]
    return wire[nlen:]


class WrapStreamWriter:
    """Streaming wrap-encrypt handle.

    Allocated as a fresh-nonce / fresh-keystream session. The
    constructor draws a CSPRNG nonce, opens a libitb wrap-stream
    handle bound to ``(key, nonce)``, and exposes the nonce on the
    :attr:`nonce` attribute so the caller can emit it once at stream
    start (typically as the wire prefix). Subsequent
    :meth:`update` calls XOR caller plaintext through the keystream
    and return the encrypted bytes; the keystream counter advances
    monotonically across calls.

    Pair every :class:`WrapStreamWriter` with an
    :class:`UnwrapStreamReader` keyed by the same ``cipher_name`` /
    ``key`` and the nonce read off the wire.

    Thread-safety: the writer is single-feeder by construction. Do
    not interleave :meth:`update` calls from multiple threads on the
    same writer — the underlying libitb keystream is stateful.

    Use as a context manager (``with WrapStreamWriter(...) as ww:``)
    or call :meth:`close` explicitly when the stream ends. The
    handle is released back to libitb on close; subsequent
    :meth:`update` raises :class:`WrapperHandleClosedError`.
    """

    __slots__ = ("_handle", "_nonce", "_cipher_name", "_closed")

    def __init__(self, cipher_name: str, key: bytes):
        cn = _validate_cipher_name(cipher_name)
        key_b = _bytes_view(key)
        if len(key_b) != key_size(cipher_name):
            raise InvalidKeyError(
                STATUS_BAD_INPUT,
                f"{cipher_name!r}: key must be {key_size(cipher_name)} bytes, got {len(key_b)}",
            )
        nlen = nonce_size(cipher_name)
        nonce_buf = _ffi.new("unsigned char[]", nlen)
        h = _ffi.new("uintptr_t*")
        rc = _lib.ITB_WrapStreamWriter_Init(
            cn,
            key_b, len(key_b),
            nonce_buf, nlen,
            h,
        )
        if rc != STATUS_OK:
            _raise_wrapper(rc)
        self._handle = int(h[0])
        self._nonce = bytes(_ffi.buffer(nonce_buf, nlen))
        self._cipher_name = cipher_name
        self._closed = False

    @property
    def nonce(self) -> bytes:
        """The per-stream CSPRNG nonce. The caller emits this once at
        stream start (typically as the wire prefix) so the matching
        :class:`UnwrapStreamReader` can be constructed against it."""
        return self._nonce

    @property
    def cipher_name(self) -> str:
        """The outer cipher selected at construction."""
        return self._cipher_name

    @property
    def handle(self) -> int:
        """Opaque libitb handle id (uintptr). Useful for diagnostics."""
        return self._handle

    def update(self, src) -> bytes:
        """XOR-encrypts ``src`` through the keystream and returns the
        result as ``bytes``. ``src`` accepts any bytes-like input
        (immutable :class:`bytes`, :class:`bytearray`,
        :class:`memoryview`); the keystream counter advances by
        ``len(src)`` bytes regardless of input type.

        Raises :class:`WrapperHandleClosedError` if the writer has
        been closed.
        """
        if self._closed or not self._handle:
            raise WrapperHandleClosedError()
        src_b = _bytes_view(src)
        if not src_b:
            return b""
        out_buf = _ffi.new("unsigned char[]", len(src_b))
        rc = _lib.ITB_WrapStreamWriter_Update(
            self._handle,
            src_b, len(src_b),
            out_buf, len(src_b),
        )
        if rc != STATUS_OK:
            _raise_wrapper(rc)
        return bytes(_ffi.buffer(out_buf, len(src_b)))

    def close(self) -> None:
        """Releases the underlying libitb wrap-stream handle.
        Idempotent; second :meth:`close` is a no-op."""
        if self._closed or not self._handle:
            self._closed = True
            self._handle = 0
            return
        rc = _lib.ITB_WrapStreamWriter_Free(self._handle)
        self._handle = 0
        self._closed = True
        if rc != STATUS_OK:
            _raise_wrapper(rc)

    def __enter__(self) -> "WrapStreamWriter":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()

    def __del__(self):
        # Best-effort GC release.
        try:
            if self._handle and not self._closed:
                _lib.ITB_WrapStreamWriter_Free(self._handle)
                self._handle = 0
                self._closed = True
        except Exception:
            pass


class UnwrapStreamReader:
    """Streaming unwrap-decrypt handle. Counterpart of
    :class:`WrapStreamWriter`.

    Constructed against the per-stream nonce read off the wire
    (typically the leading ``nonce_size(cipher_name)`` bytes). The
    libitb wrap-stream handle is keyed by ``(cipher_name, key,
    wire_nonce)``; subsequent :meth:`update` calls XOR-decrypt
    caller-supplied wire bytes into recovered plaintext.

    Thread-safety: the reader is single-feeder by construction. Do
    not interleave :meth:`update` calls from multiple threads on the
    same reader.

    Use as a context manager (``with UnwrapStreamReader(...) as ur:``)
    or call :meth:`close` explicitly when the stream ends.
    """

    __slots__ = ("_handle", "_cipher_name", "_closed")

    def __init__(self, cipher_name: str, key: bytes, wire_nonce: bytes):
        cn = _validate_cipher_name(cipher_name)
        key_b = _bytes_view(key)
        if len(key_b) != key_size(cipher_name):
            raise InvalidKeyError(
                STATUS_BAD_INPUT,
                f"{cipher_name!r}: key must be {key_size(cipher_name)} bytes, got {len(key_b)}",
            )
        nonce_b = _bytes_view(wire_nonce)
        nlen = nonce_size(cipher_name)
        if len(nonce_b) != nlen:
            raise InvalidNonceError(
                STATUS_BAD_INPUT,
                f"{cipher_name!r}: nonce must be {nlen} bytes, got {len(nonce_b)}",
            )
        h = _ffi.new("uintptr_t*")
        rc = _lib.ITB_UnwrapStreamReader_Init(
            cn,
            key_b, len(key_b),
            nonce_b, len(nonce_b),
            h,
        )
        if rc != STATUS_OK:
            _raise_wrapper(rc)
        self._handle = int(h[0])
        self._cipher_name = cipher_name
        self._closed = False

    @property
    def cipher_name(self) -> str:
        """The outer cipher selected at construction."""
        return self._cipher_name

    @property
    def handle(self) -> int:
        """Opaque libitb handle id (uintptr). Useful for diagnostics."""
        return self._handle

    def update(self, src) -> bytes:
        """XOR-decrypts ``src`` through the keystream and returns the
        recovered plaintext bytes. ``src`` accepts any bytes-like
        input; the keystream counter advances by ``len(src)`` bytes.

        Raises :class:`WrapperHandleClosedError` if the reader has
        been closed.
        """
        if self._closed or not self._handle:
            raise WrapperHandleClosedError()
        src_b = _bytes_view(src)
        if not src_b:
            return b""
        out_buf = _ffi.new("unsigned char[]", len(src_b))
        rc = _lib.ITB_UnwrapStreamReader_Update(
            self._handle,
            src_b, len(src_b),
            out_buf, len(src_b),
        )
        if rc != STATUS_OK:
            _raise_wrapper(rc)
        return bytes(_ffi.buffer(out_buf, len(src_b)))

    def close(self) -> None:
        """Releases the underlying libitb wrap-stream handle.
        Idempotent; second :meth:`close` is a no-op."""
        if self._closed or not self._handle:
            self._closed = True
            self._handle = 0
            return
        rc = _lib.ITB_UnwrapStreamReader_Free(self._handle)
        self._handle = 0
        self._closed = True
        if rc != STATUS_OK:
            _raise_wrapper(rc)

    def __enter__(self) -> "UnwrapStreamReader":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()

    def __del__(self):
        # Best-effort GC release.
        try:
            if self._handle and not self._closed:
                _lib.ITB_UnwrapStreamReader_Free(self._handle)
                self._handle = 0
                self._closed = True
        except Exception:
            pass


__all__ = [
    "CIPHER_AES128_CTR",
    "CIPHER_CHACHA20",
    "CIPHER_SIPHASH24",
    "CIPHER_NAMES",
    "key_size",
    "nonce_size",
    "generate_key",
    "wrap",
    "unwrap",
    "wrap_in_place",
    "unwrap_in_place",
    "WrapStreamWriter",
    "UnwrapStreamReader",
    "WrapperError",
    "InvalidCipherError",
    "InvalidKeyError",
    "InvalidNonceError",
    "WrapperHandleClosedError",
]
