"""High-level Encryptor wrapper over the libitb C ABI.

Mirrors the github.com/everanium/itb/easy Go sub-package: one
constructor call replaces the lower-level seven-line setup ceremony
(hash factory, three or seven seeds, MAC closure, container-config
wiring) and returns an :class:`Encryptor` object that owns its own
per-instance configuration. Two encryptors with different settings
can be used in parallel without cross-contamination of the
process-wide ITB configuration.

Quick start (Single Ouroboros + HMAC-BLAKE3):

    >>> from itb import Encryptor
    >>> with Encryptor("blake3", 1024, "hmac-blake3") as enc:
    ...     ct = enc.encrypt_auth(b"hello world")
    ...     pt = enc.decrypt_auth(ct)
    ...     assert pt == b"hello world"

Triple Ouroboros (7 seeds, mode=3):

    >>> with Encryptor("areion512", 2048, "hmac-blake3", mode=3) as enc:
    ...     ct = enc.encrypt(b"large payload" * 1000)
    ...     pt = enc.decrypt(ct)

Cross-process persistence (encrypt today / decrypt tomorrow):

    >>> blob = enc.export()                # bytes (JSON-encoded)
    >>> # ... save blob to disk / KMS / wire ...
    >>> primitive, key_bits, mode, mac = peek_config(blob)
    >>> with Encryptor(primitive, key_bits, mac, mode=mode) as dec:
    ...     dec.import_state(blob)         # rebuild the seed material
    ...     pt = dec.decrypt_auth(ct)

Streaming. Chunking lives on the binding side (same pattern as
:class:`itb.StreamEncryptor`): slice the plaintext into chunks of
``chunk_size`` bytes and call :meth:`encrypt` per chunk; on the
decrypt side walk the concatenated stream by reading the chunk
header, calling :func:`itb.parse_chunk_len`, and feeding the chunk
to :meth:`decrypt`. The encryptor's chunk size knob (set via
:meth:`set_chunk_size`) is consumed only by the Go-side
EncryptStream entry point; one-shot :meth:`encrypt` honours the
container-cap heuristic in itb.ChunkSize.
"""

from __future__ import annotations

import ctypes
from typing import List, Optional, Tuple

from ._ffi import (
    _ffi,
    _lib,
    _last_error,
    _raise,
    ITBError,
    ItbStreamTruncatedError as _ItbStreamTruncatedError,
    ItbStreamAfterFinalError as _ItbStreamAfterFinalError,
    STATUS_OK,
    STATUS_BUFFER_TOO_SMALL,
    STATUS_BAD_INPUT,
    STATUS_EASY_CLOSED,
    STATUS_EASY_MALFORMED,
    STATUS_EASY_VERSION_TOO_NEW,
    STATUS_EASY_UNKNOWN_PRIMITIVE,
    STATUS_EASY_UNKNOWN_MAC,
    STATUS_EASY_BAD_KEY_BITS,
    STATUS_EASY_MISMATCH,
    STATUS_EASY_LOCKSEED_AFTER_ENCRYPT,
    STREAM_ID_LEN as _STREAM_ID_LEN,
    _generate_stream_id,
)
from .streams import DEFAULT_CHUNK_SIZE as _DEFAULT_CHUNK_SIZE


class EasyMismatchError(ITBError):
    """Raised when :meth:`Encryptor.import_state` rejects a state blob
    because one of the four bound dimensions (primitive / key_bits /
    mode / mac) disagrees with the receiver. The offending JSON field
    name is exposed on the ``.field`` attribute so callers can map
    onto a typed remediation path."""

    def __init__(self, code: int, message: str, field: str):
        super().__init__(code, message)
        self.field = field


def last_mismatch_field() -> str:
    """Reads the offending JSON field name from the most recent
    ITB_Easy_Import call that returned STATUS_EASY_MISMATCH on this
    thread. Empty string when the most recent failure was not a
    mismatch.

    The Encryptor.import_state method already attaches this name to
    the raised EasyMismatchError.field attribute; this free function
    is exposed for callers that need to read the field independently
    of the error path."""
    out_len = _ffi.new("size_t*")
    rc = _lib.ITB_Easy_LastMismatchField(_ffi.NULL, 0, out_len)
    if rc not in (STATUS_OK, STATUS_BUFFER_TOO_SMALL):
        return ""
    cap = int(out_len[0])
    if cap <= 1:
        return ""
    buf = _ffi.new("char[]", cap)
    rc = _lib.ITB_Easy_LastMismatchField(buf, cap, out_len)
    if rc != STATUS_OK:
        return ""
    return _ffi.string(buf, int(out_len[0]) - 1).decode("utf-8")


# Internal alias for backwards compatibility.
_last_mismatch_field = last_mismatch_field


def _raise_easy(code: int):
    """Raises the most specific exception subclass for a non-OK Easy
    status code. STATUS_EASY_MISMATCH attaches the offending field via
    EasyMismatchError; everything else falls through to ITBError with
    the LastError message."""
    if code == STATUS_EASY_MISMATCH:
        raise EasyMismatchError(code, _last_error(), _last_mismatch_field())
    raise ITBError(code, _last_error())


def peek_config(blob: bytes) -> Tuple[str, int, int, str]:
    """Parses a state blob's metadata (primitive, key_bits, mode, mac)
    without performing full validation, allowing a caller to inspect a
    saved blob before constructing a matching encryptor.

    Returns the four-tuple on success; raises ITBError(STATUS_EASY_MALFORMED)
    on JSON parse failure / kind mismatch / too-new version / unknown
    mode value."""
    if not isinstance(blob, (bytes, bytearray, memoryview)):
        raise TypeError("blob must be bytes-like")
    blob_bytes = bytes(blob)

    # Probe both string sizes first.
    prim_len = _ffi.new("size_t*")
    mac_len = _ffi.new("size_t*")
    kb_out = _ffi.new("int*")
    mode_out = _ffi.new("int*")
    rc = _lib.ITB_Easy_PeekConfig(
        blob_bytes, len(blob_bytes),
        _ffi.NULL, 0, prim_len,
        kb_out, mode_out,
        _ffi.NULL, 0, mac_len,
    )
    if rc != STATUS_OK and rc != STATUS_BUFFER_TOO_SMALL:
        _raise_easy(rc)

    prim_cap = int(prim_len[0])
    mac_cap = int(mac_len[0])
    prim_buf = _ffi.new("char[]", prim_cap)
    mac_buf = _ffi.new("char[]", mac_cap)
    rc = _lib.ITB_Easy_PeekConfig(
        blob_bytes, len(blob_bytes),
        prim_buf, prim_cap, prim_len,
        kb_out, mode_out,
        mac_buf, mac_cap, mac_len,
    )
    if rc != STATUS_OK:
        _raise_easy(rc)

    primitive = _ffi.string(prim_buf, int(prim_len[0]) - 1).decode("utf-8")
    mac_name = _ffi.string(mac_buf, int(mac_len[0]) - 1).decode("utf-8")
    return primitive, int(kb_out[0]), int(mode_out[0]), mac_name


class Encryptor:
    """High-level Encryptor over the libitb C ABI.

    Parameters
    ----------
    primitive:
        Canonical hash name from :func:`itb.list_hashes` —
        "areion256", "areion512", "siphash24", "aescmac",
        "blake2b256", "blake2b512", "blake2s", "blake3", "chacha20".
        Default ``None`` selects the package default ("areion512").
    key_bits:
        ITB key width in bits (512, 1024, 2048; multiple of the
        primitive's native hash width). Default ``None`` selects 1024.
    mac:
        Canonical MAC name from :func:`itb.list_macs` — "kmac256",
        "hmac-sha256", or "hmac-blake3". Default ``None`` selects
        "hmac-blake3".
    mode:
        1 = Single Ouroboros (3 seeds — noise, data, start);
        3 = Triple Ouroboros (7 seeds — noise + 3 pairs of data /
        start). Default 1.

    Construction is the heavy step — generates fresh PRF keys, fresh
    seed components, fresh MAC key from /dev/urandom. Reusing one
    Encryptor instance across many encrypt / decrypt calls amortises
    the cost across the lifetime of a session.

    Use as a context manager (``with Encryptor(...) as enc:``) or call
    :meth:`close` explicitly to zero PRF / MAC / seed material when
    the session ends. The :meth:`free` alias is kept for parity with
    the lower-level :class:`itb.Seed` / :class:`itb.MAC` lifecycle.

    Thread-safety contract.
        Cipher methods (:meth:`encrypt` / :meth:`decrypt` /
        :meth:`encrypt_auth` / :meth:`decrypt_auth`) write into the
        per-instance output-buffer cache and are **not safe** to
        invoke concurrently against the same encryptor. Sharing one
        :class:`Encryptor` across threads requires external
        synchronisation (e.g. a :class:`threading.Lock` held for the
        duration of every cipher call). Per-instance configuration
        setters (:meth:`set_nonce_bits` / :meth:`set_barrier_fill` /
        :meth:`set_bit_soup` / :meth:`set_lock_soup` /
        :meth:`set_lock_seed` / :meth:`set_chunk_size`) and
        state-serialisation methods (:meth:`export_state` /
        :meth:`import_state`) likewise require external
        synchronisation when called against the same encryptor from
        multiple threads. Distinct :class:`Encryptor` instances, each
        owned by one thread, run independently against the libitb
        worker pool.

    Output-buffer cache.
        The cipher methods reuse a per-encryptor cffi buffer to skip
        the per-call FFI size-probe round-trip; the buffer grows on
        demand and survives between calls. Each cipher call returns
        a fresh ``bytes`` copy of the result, so the cache is never
        exposed to the caller — but the cached bytes (the most recent
        ciphertext or plaintext) sit in heap memory until the next
        cipher call overwrites them or :meth:`close` / :meth:`free`
        zeroes them. Callers handling sensitive plaintext under a
        heap-scan threat model should call :meth:`close` immediately
        after the last decrypt rather than relying on garbage-
        collection-time zeroisation.
    """

    __slots__ = ("_handle", "_out_buf", "_out_cap", "_closed")

    def __init__(
        self,
        primitive: Optional[str] = None,
        key_bits: Optional[int] = None,
        mac: Optional[str] = None,
        mode: int = 1,
    ):
        prim_arg = (primitive.encode("utf-8") if primitive else _ffi.NULL)
        # Binding-side default override: when the caller passes
        # ``mac=None`` the binding picks ``hmac-blake3`` rather than
        # passing NULL through to libitb's own default. HMAC-BLAKE3
        # measures the lightest MAC overhead in the Easy Mode bench
        # surface; routing the default through it gives the
        # "constructor without arguments" path the lowest cost.
        mac_arg = (mac.encode("utf-8") if mac else b"hmac-blake3")
        kb_arg = int(key_bits) if key_bits else 0

        h = _ffi.new("uintptr_t*")
        rc = _lib.ITB_Easy_New(prim_arg, kb_arg, mac_arg, int(mode), h)
        if rc != STATUS_OK:
            _raise_easy(rc)
        self._handle = int(h[0])
        # Per-encryptor cffi output buffer cache. Grows on demand;
        # close() / free() / __del__ wipe it before drop.
        self._out_buf = _ffi.NULL
        self._out_cap = 0
        # Tracks the closed / freed state independently of the handle
        # field so the preflight in :meth:`_check_open` can surface
        # ``STATUS_EASY_CLOSED`` after :meth:`close` / :meth:`free`
        # without relying on the libitb-side handle-id lookup (which
        # would surface ``STATUS_BAD_HANDLE`` once :meth:`free` has
        # cleared the handle slot).
        self._closed = False

    # ─── Mixed-mode constructors ───────────────────────────────────

    @classmethod
    def mixed_single(
        cls,
        primitive_n: str,
        primitive_d: str,
        primitive_s: str,
        primitive_l: Optional[str],
        key_bits: int,
        mac: str,
    ) -> "Encryptor":
        """Construct a Single-Ouroboros :class:`Encryptor` with
        per-slot PRF primitive selection. ``primitive_n`` /
        ``primitive_d`` / ``primitive_s`` cover the noise / data /
        start slots; ``primitive_l`` (default ``None``) is the
        optional dedicated lockSeed primitive — when provided, a 4th
        seed slot is allocated under that primitive and BitSoup +
        LockSoup are auto-coupled on the on-direction.

        All four primitive names must resolve to the same native
        hash width via the libitb registry; mixed widths raise
        :class:`ITBError` with the panic message captured in
        :func:`itb._last_error`.
        """
        primL = primitive_l or ""
        h = _ffi.new("uintptr_t*")
        rc = _lib.ITB_Easy_NewMixed(
            primitive_n.encode("utf-8"),
            primitive_d.encode("utf-8"),
            primitive_s.encode("utf-8"),
            (primL.encode("utf-8") if primL else _ffi.NULL),
            int(key_bits),
            mac.encode("utf-8"),
            h,
        )
        if rc != STATUS_OK:
            _raise_easy(rc)
        obj = cls.__new__(cls)
        obj._handle = int(h[0])
        obj._out_buf = _ffi.NULL
        obj._out_cap = 0
        obj._closed = False
        return obj

    @classmethod
    def mixed_triple(
        cls,
        primitive_n: str,
        primitive_d1: str,
        primitive_d2: str,
        primitive_d3: str,
        primitive_s1: str,
        primitive_s2: str,
        primitive_s3: str,
        primitive_l: Optional[str],
        key_bits: int,
        mac: str,
    ) -> "Encryptor":
        """Triple-Ouroboros counterpart of :meth:`mixed_single`.
        Accepts seven per-slot primitive names (noise + 3 data +
        3 start) plus the optional ``primitive_l`` lockSeed
        primitive. See :meth:`mixed_single` for the construction
        contract."""
        primL = primitive_l or ""
        h = _ffi.new("uintptr_t*")
        rc = _lib.ITB_Easy_NewMixed3(
            primitive_n.encode("utf-8"),
            primitive_d1.encode("utf-8"),
            primitive_d2.encode("utf-8"),
            primitive_d3.encode("utf-8"),
            primitive_s1.encode("utf-8"),
            primitive_s2.encode("utf-8"),
            primitive_s3.encode("utf-8"),
            (primL.encode("utf-8") if primL else _ffi.NULL),
            int(key_bits),
            mac.encode("utf-8"),
            h,
        )
        if rc != STATUS_OK:
            _raise_easy(rc)
        obj = cls.__new__(cls)
        obj._handle = int(h[0])
        obj._out_buf = _ffi.NULL
        obj._out_cap = 0
        obj._closed = False
        return obj

    # ─── Internal preflight ────────────────────────────────────────

    def _check_open(self) -> None:
        """Preflight rejection for closed / freed encryptors. Surfaces
        :class:`ITBError` with code :data:`STATUS_EASY_CLOSED` before
        any libitb FFI call so callers see the canonical "encryptor
        has been closed" code regardless of whether the underlying
        handle slot has merely been zeroed (post-:meth:`close`) or has
        been released back to libitb (post-:meth:`free`)."""
        if self._closed or not self._handle:
            raise ITBError(STATUS_EASY_CLOSED, "encryptor has been closed")

    # ─── Per-slot primitive accessors ──────────────────────────────

    def primitive_at(self, slot: int) -> str:
        """Return the canonical hash primitive name bound to the
        given seed slot index. Slot ordering is canonical — 0 =
        noiseSeed, then dataSeed{,1..3}, then startSeed{,1..3},
        with the optional dedicated lockSeed at the trailing slot.
        For single-primitive encryptors every slot returns the same
        :attr:`primitive` value; for encryptors built via
        :meth:`mixed_single` / :meth:`mixed_triple` each slot
        returns its independently-chosen primitive name."""
        self._check_open()
        return _read_str(lambda buf, cap, ol:
                         _lib.ITB_Easy_PrimitiveAt(self._handle, int(slot), buf, cap, ol))

    @property
    def is_mixed(self) -> bool:
        """``True`` when the encryptor was constructed via
        :meth:`mixed_single` or :meth:`mixed_triple` (per-slot
        primitive selection); ``False`` for single-primitive
        encryptors built via the default :meth:`__init__`."""
        self._check_open()
        st = _ffi.new("int*")
        v = int(_lib.ITB_Easy_IsMixed(self._handle, st))
        if int(st[0]) != STATUS_OK:
            _raise_easy(int(st[0]))
        return v != 0

    # ─── Read-only field properties ────────────────────────────────

    @property
    def handle(self) -> int:
        """Opaque libitb handle id (uintptr). Useful for diagnostics
        and FFI-level interop; bindings should not rely on its
        numerical value."""
        return self._handle

    @property
    def primitive(self) -> str:
        """Returns the canonical primitive name bound at construction."""
        self._check_open()
        return _read_str(lambda buf, cap, ol:
                         _lib.ITB_Easy_Primitive(self._handle, buf, cap, ol))

    @property
    def key_bits(self) -> int:
        """Returns the ITB key width in bits."""
        self._check_open()
        st = _ffi.new("int*")
        v = int(_lib.ITB_Easy_KeyBits(self._handle, st))
        if int(st[0]) != STATUS_OK:
            _raise_easy(int(st[0]))
        return v

    @property
    def mode(self) -> int:
        """Returns 1 (Single Ouroboros) or 3 (Triple Ouroboros)."""
        self._check_open()
        st = _ffi.new("int*")
        v = int(_lib.ITB_Easy_Mode(self._handle, st))
        if int(st[0]) != STATUS_OK:
            _raise_easy(int(st[0]))
        return v

    @property
    def mac_name(self) -> str:
        """Returns the canonical MAC name bound at construction."""
        self._check_open()
        return _read_str(lambda buf, cap, ol:
                         _lib.ITB_Easy_MACName(self._handle, buf, cap, ol))

    @property
    def nonce_bits(self) -> int:
        """Returns the nonce size in bits configured for this
        encryptor — either the value from the most recent
        :meth:`set_nonce_bits` call, or the process-wide
        :func:`itb.get_nonce_bits` reading at construction time when
        no per-instance override has been issued. Reads the live
        cfg.NonceBits via ``ITB_Easy_NonceBits`` so a setter call on
        the Go side is reflected immediately."""
        self._check_open()
        st = _ffi.new("int*")
        v = int(_lib.ITB_Easy_NonceBits(self._handle, st))
        if int(st[0]) != STATUS_OK:
            _raise_easy(int(st[0]))
        return v

    @property
    def header_size(self) -> int:
        """Returns the per-instance ciphertext-chunk header size in
        bytes (nonce + 2-byte width + 2-byte height). Tracks this
        encryptor's own :attr:`nonce_bits`, NOT the process-wide
        :func:`itb.header_size` reading — important when the
        encryptor has called :meth:`set_nonce_bits` to override the
        default. Use this when slicing a chunk header off the front
        of a ciphertext stream produced by this encryptor or when
        sizing a tamper region for an authenticated-decrypt test."""
        self._check_open()
        st = _ffi.new("int*")
        v = int(_lib.ITB_Easy_HeaderSize(self._handle, st))
        if int(st[0]) != STATUS_OK:
            _raise_easy(int(st[0]))
        return v

    def parse_chunk_len(self, header: bytes) -> int:
        """Per-instance counterpart of :func:`itb.parse_chunk_len`.
        Inspects a chunk header (the fixed-size [nonce(N) ||
        width(2) || height(2)] prefix where N comes from this
        encryptor's :attr:`nonce_bits`) and returns the total chunk
        length on the wire.

        Use this when walking a concatenated chunk stream produced
        by this encryptor: read :attr:`header_size` bytes from the
        wire, call ``enc.parse_chunk_len(buf[:enc.header_size])``,
        read the remaining ``chunk_len - header_size`` bytes, and
        feed the full chunk to :meth:`decrypt` / :meth:`decrypt_auth`.

        The buffer must contain at least :attr:`header_size` bytes;
        only the header is consulted, the body bytes do not need to
        be present. Raises :class:`itb.ITBError` with code
        :data:`itb._ffi.STATUS_BAD_INPUT` on too-short buffer, zero
        dimensions, or width × height overflow against the
        container pixel cap."""
        self._check_open()
        if not isinstance(header, (bytes, bytearray, memoryview)):
            raise TypeError("header must be bytes-like")
        hdr = bytes(header)
        out = _ffi.new("size_t*")
        rc = _lib.ITB_Easy_ParseChunkLen(self._handle, hdr, len(hdr), out)
        if rc != STATUS_OK:
            _raise_easy(rc)
        return int(out[0])

    # ─── Cipher entry points ──────────────────────────────────────

    def encrypt(self, plaintext) -> bytes:
        """Encrypts plaintext using the encryptor's configured
        primitive / key_bits / mode and per-instance Config snapshot.
        Plain mode — does not attach a MAC tag; for authenticated
        encryption use :meth:`encrypt_auth`.

        Empty plaintext is rejected by libitb itself with
        :class:`ITBError` carrying
        :data:`itb._ffi.STATUS_ENCRYPT_FAILED` (the Go-side
        ``Encrypt128`` family returns ``"itb: empty data"`` before
        any work). Pass at least one byte."""
        if not isinstance(plaintext, (bytes, bytearray, memoryview)):
            raise TypeError("plaintext must be bytes-like")
        return self._cipher_call(_lib.ITB_Easy_Encrypt, plaintext)

    def decrypt(self, ciphertext) -> bytes:
        """Decrypts ciphertext produced by :meth:`encrypt` under the
        same encryptor.

        Empty ciphertext is rejected by libitb itself with
        :class:`ITBError` carrying
        :data:`itb._ffi.STATUS_ENCRYPT_FAILED`. Pass at least one
        byte."""
        if not isinstance(ciphertext, (bytes, bytearray, memoryview)):
            raise TypeError("ciphertext must be bytes-like")
        return self._cipher_call(_lib.ITB_Easy_Decrypt, ciphertext)

    def encrypt_auth(self, plaintext) -> bytes:
        """Encrypts plaintext and attaches a MAC tag using the
        encryptor's bound MAC closure.

        Empty plaintext is rejected by libitb itself with
        :class:`ITBError` carrying
        :data:`itb._ffi.STATUS_ENCRYPT_FAILED`. Pass at least one
        byte."""
        if not isinstance(plaintext, (bytes, bytearray, memoryview)):
            raise TypeError("plaintext must be bytes-like")
        return self._cipher_call(_lib.ITB_Easy_EncryptAuth, plaintext)

    def decrypt_auth(self, ciphertext) -> bytes:
        """Verifies and decrypts ciphertext produced by
        :meth:`encrypt_auth`. Raises :class:`itb.ITBError` with code
        :data:`itb._ffi.STATUS_MAC_FAILURE` on tampered ciphertext /
        wrong MAC key.

        Empty ciphertext is rejected by libitb itself with
        :class:`ITBError` carrying
        :data:`itb._ffi.STATUS_ENCRYPT_FAILED`. Pass at least one
        byte."""
        if not isinstance(ciphertext, (bytes, bytearray, memoryview)):
            raise TypeError("ciphertext must be bytes-like")
        return self._cipher_call(_lib.ITB_Easy_DecryptAuth, ciphertext)

    def _cipher_call(self, fn, payload) -> bytes:
        """Direct-call buffer-convention dispatcher with a per-encryptor
        output cache. Skips the size-probe round-trip that the lower-
        level _ffi helpers use: pre-allocates output capacity from a
        1.25× upper bound (the empirical ITB ciphertext-expansion
        factor measured at <= 1.155 across every primitive / mode /
        nonce / payload-size combination) and falls through to an
        explicit grow-and-retry only on the rare under-shoot. Reuses
        the cffi buffer across calls; close() / free() wipe it before
        drop. Input bytes are passed through directly; bytearray /
        memoryview wrap via ``_ffi.from_buffer`` to avoid the
        bytes()-copy that the previous implementation performed.

        The current Easy_Encrypt / Easy_Decrypt C ABI does the full
        crypto on every call regardless of out-buffer capacity (it
        computes the result internally, then returns BUFFER_TOO_SMALL
        without exposing the work) — so the pre-allocation here
        avoids paying for a duplicate encrypt / decrypt on each
        Python call.
        """
        self._check_open()
        payload_len = len(payload)
        # 1.25× + 128 KiB headroom comfortably exceeds the worst-case
        # expansion observed across the primitive / mode / nonce-bits /
        # barrier-fill matrix; bf=32 with payloads near 1 MiB pushes
        # the absolute ratio to ~1.346, leaving roughly 100 KiB of
        # residual margin over the 1.25× term that the constant pad
        # must absorb. The 128 KiB pad covers that worst case (and the
        # ratio tapers below 1.25× + small-K beyond a few MiB as the
        # bf-induced sqrt-shaped border overhead becomes asymptotically
        # negligible). Floor at 128 KiB so the very-small payload case
        # still gets a usable buffer that handles the Triple +
        # auth-MAC + bf=32 short-payload expansion (~35 KiB at
        # ptlen=1).
        cap = max(131072, (payload_len * 5) // 4 + 131072)
        if self._out_cap < cap:
            # Wipe previous bytes before reassignment — cffi's _ffi.new
            # discards the prior buffer without zeroing the heap region.
            if self._out_cap > 0 and self._out_buf != _ffi.NULL:
                _ffi.memmove(self._out_buf, b"\x00" * self._out_cap, self._out_cap)
            self._out_buf = _ffi.new("unsigned char[]", cap)
            self._out_cap = cap

        # cffi accepts bytes directly without a copy; bytearray and
        # memoryview need from_buffer to avoid the implicit
        # type-coercion copy.
        if isinstance(payload, bytes):
            in_arg = payload
        else:
            in_arg = _ffi.from_buffer("unsigned char[]", payload)

        out_len = _ffi.new("size_t*")
        rc = fn(self._handle, in_arg, payload_len,
                self._out_buf, self._out_cap, out_len)
        if rc == STATUS_BUFFER_TOO_SMALL:
            # Pre-allocation was too tight (extremely rare given the
            # 1.25× safety margin) — grow exactly to the required size
            # and retry. The first call already paid for the underlying
            # crypto via the current C ABI's full-encrypt-on-every-call
            # contract, so the retry runs the work again; this is
            # strictly the fallback path and not the hot loop.
            need = int(out_len[0])
            if self._out_cap > 0 and self._out_buf != _ffi.NULL:
                _ffi.memmove(self._out_buf, b"\x00" * self._out_cap, self._out_cap)
            self._out_buf = _ffi.new("unsigned char[]", need)
            self._out_cap = need
            rc = fn(self._handle, in_arg, payload_len,
                    self._out_buf, self._out_cap, out_len)
        if rc != STATUS_OK:
            _raise_easy(rc)
        return bytes(_ffi.buffer(self._out_buf, int(out_len[0])))

    # ─── Per-instance configuration setters ───────────────────────

    def set_nonce_bits(self, n: int) -> None:
        """Override the nonce size for this encryptor's subsequent
        encrypt / decrypt calls. Valid values: 128, 256, 512.
        Mutates only this encryptor's Config copy; process-wide
        :func:`itb.set_nonce_bits` is unaffected. The
        :attr:`nonce_bits` / :attr:`header_size` properties read
        through to the live Go-side cfg.NonceBits, so they reflect
        the new value automatically on the next access."""
        self._check_open()
        rc = _lib.ITB_Easy_SetNonceBits(self._handle, int(n))
        if rc != STATUS_OK:
            _raise_easy(rc)

    def set_barrier_fill(self, n: int) -> None:
        """Override the CSPRNG barrier-fill margin for this encryptor.
        Valid values: 1, 2, 4, 8, 16, 32. Asymmetric — receiver does
        not need the same value as sender."""
        self._check_open()
        rc = _lib.ITB_Easy_SetBarrierFill(self._handle, int(n))
        if rc != STATUS_OK:
            _raise_easy(rc)

    def set_bit_soup(self, mode: int) -> None:
        """0 = byte-level split (default); non-zero = bit-level Bit Soup
        split."""
        self._check_open()
        rc = _lib.ITB_Easy_SetBitSoup(self._handle, int(mode))
        if rc != STATUS_OK:
            _raise_easy(rc)

    def set_lock_soup(self, mode: int) -> None:
        """0 = off (default); non-zero = on. Auto-couples ``BitSoup=1``
        on this encryptor."""
        self._check_open()
        rc = _lib.ITB_Easy_SetLockSoup(self._handle, int(mode))
        if rc != STATUS_OK:
            _raise_easy(rc)

    def set_lock_seed(self, mode: int) -> None:
        """0 = off; 1 = on (allocates a dedicated lockSeed and routes
        the bit-permutation overlay through it; auto-couples
        ``LockSoup=1 + BitSoup=1`` on this encryptor). Calling after
        the first encrypt raises ITBError(STATUS_EASY_LOCKSEED_AFTER_ENCRYPT)."""
        self._check_open()
        rc = _lib.ITB_Easy_SetLockSeed(self._handle, int(mode))
        if rc != STATUS_OK:
            _raise_easy(rc)

    def set_chunk_size(self, n: int) -> None:
        """Per-instance streaming chunk-size override (0 = auto-detect
        via :data:`itb.ChunkSize` on the Go side)."""
        self._check_open()
        rc = _lib.ITB_Easy_SetChunkSize(self._handle, int(n))
        if rc != STATUS_OK:
            _raise_easy(rc)

    # ─── Material getters (defensive copies) ──────────────────────

    @property
    def seed_count(self) -> int:
        """Number of seed slots: 3 (Single without LockSeed),
        4 (Single with LockSeed), 7 (Triple without LockSeed),
        8 (Triple with LockSeed)."""
        self._check_open()
        st = _ffi.new("int*")
        v = int(_lib.ITB_Easy_SeedCount(self._handle, st))
        if int(st[0]) != STATUS_OK:
            _raise_easy(int(st[0]))
        return v

    def seed_components(self, slot: int) -> List[int]:
        """Returns the uint64 components of one seed slot (defensive
        copy). Slot index follows the canonical ordering:
        Single = ``[noise, data, start]``; Triple = ``[noise, data1,
        data2, data3, start1, start2, start3]``; the dedicated
        lockSeed slot, when present, is appended at the trailing
        index (index 3 for Single, index 7 for Triple). Bindings can
        consult :attr:`seed_count` to determine the valid slot
        range for the active mode + lockSeed configuration."""
        self._check_open()
        out_len = _ffi.new("int*")
        # Probe call — out=NULL / capCount=0 returns
        # STATUS_BUFFER_TOO_SMALL with the required size in *outLen.
        # STATUS_BAD_INPUT here would signal an out-of-range slot.
        rc = _lib.ITB_Easy_SeedComponents(self._handle, int(slot), _ffi.NULL, 0, out_len)
        if rc == STATUS_OK:
            return []
        if rc != STATUS_BUFFER_TOO_SMALL:
            _raise_easy(rc)
        n = int(out_len[0])
        buf = _ffi.new(f"unsigned long long[{n}]")
        rc = _lib.ITB_Easy_SeedComponents(self._handle, int(slot), buf, n, out_len)
        if rc != STATUS_OK:
            _raise_easy(rc)
        return [int(buf[i]) for i in range(int(out_len[0]))]

    @property
    def has_prf_keys(self) -> bool:
        """``True`` when the encryptor's primitive uses fixed PRF keys
        per seed slot (every shipped primitive except siphash24)."""
        self._check_open()
        st = _ffi.new("int*")
        v = int(_lib.ITB_Easy_HasPRFKeys(self._handle, st))
        if int(st[0]) != STATUS_OK:
            _raise_easy(int(st[0]))
        return v != 0

    def prf_key(self, slot: int) -> bytes:
        """Returns the fixed PRF key bytes for one seed slot
        (defensive copy). Raises ITBError(STATUS_BAD_INPUT) when the
        primitive has no fixed PRF keys (siphash24 — caller should
        consult :attr:`has_prf_keys` first) or when ``slot`` is out
        of range."""
        self._check_open()
        out_len = _ffi.new("size_t*")
        rc = _lib.ITB_Easy_PRFKey(self._handle, int(slot), _ffi.NULL, 0, out_len)
        # Probe pattern: zero-length key → STATUS_OK + outLen=0
        # (e.g. siphash24); non-zero length → STATUS_BUFFER_TOO_SMALL
        # with outLen carrying the required size. STATUS_BAD_INPUT
        # is reserved for out-of-range slot or no-fixed-key primitive.
        if rc == STATUS_OK and int(out_len[0]) == 0:
            return b""
        if rc != STATUS_BUFFER_TOO_SMALL:
            _raise_easy(rc)
        n = int(out_len[0])
        buf = _ffi.new(f"unsigned char[{n}]")
        rc = _lib.ITB_Easy_PRFKey(self._handle, int(slot), buf, n, out_len)
        if rc != STATUS_OK:
            _raise_easy(rc)
        return bytes(_ffi.buffer(buf, int(out_len[0])))

    @property
    def mac_key(self) -> bytes:
        """Returns a defensive copy of the encryptor's bound MAC fixed
        key. Save these bytes alongside the seed material for
        cross-process restore via :meth:`export` / :meth:`import_state`."""
        self._check_open()
        out_len = _ffi.new("size_t*")
        rc = _lib.ITB_Easy_MACKey(self._handle, _ffi.NULL, 0, out_len)
        if rc == STATUS_OK and int(out_len[0]) == 0:
            return b""
        if rc != STATUS_BUFFER_TOO_SMALL:
            _raise_easy(rc)
        n = int(out_len[0])
        buf = _ffi.new(f"unsigned char[{n}]")
        rc = _lib.ITB_Easy_MACKey(self._handle, buf, n, out_len)
        if rc != STATUS_OK:
            _raise_easy(rc)
        return bytes(_ffi.buffer(buf, int(out_len[0])))

    # ─── State serialization ──────────────────────────────────────

    def export(self) -> bytes:
        """Serialises the encryptor's full state (PRF keys, seed
        components, MAC key, dedicated lockSeed material when active)
        as a JSON blob. The caller saves the bytes as it sees fit
        (disk, KMS, wire) and later passes them back to
        :meth:`import_state` on a fresh encryptor to reconstruct the
        exact state.

        Per-instance configuration knobs (NonceBits, BarrierFill,
        BitSoup, LockSoup, ChunkSize) are NOT carried in the v1 blob
        — both sides communicate them via deployment config.
        LockSeed is carried because activating it changes the
        structural seed count."""
        self._check_open()
        out_len = _ffi.new("size_t*")
        rc = _lib.ITB_Easy_Export(self._handle, _ffi.NULL, 0, out_len)
        if rc != STATUS_BUFFER_TOO_SMALL:
            if rc == STATUS_OK:
                return b""
            _raise_easy(rc)
        need = int(out_len[0])
        buf = _ffi.new("unsigned char[]", need)
        rc = _lib.ITB_Easy_Export(self._handle, buf, need, out_len)
        if rc != STATUS_OK:
            _raise_easy(rc)
        return bytes(_ffi.buffer(buf, int(out_len[0])))

    def import_state(self, blob: bytes) -> None:
        """Replaces the encryptor's PRF keys, seed components, MAC
        key, and (optionally) dedicated lockSeed material with the
        values carried in a JSON blob produced by a prior
        :meth:`export` call.

        On any failure the encryptor's pre-import state is unchanged
        (the underlying Go-side Encryptor.Import is transactional).
        Mismatch on primitive / key_bits / mode / mac raises
        :class:`EasyMismatchError` carrying the offending field name
        in the ``.field`` attribute."""
        self._check_open()
        if not isinstance(blob, (bytes, bytearray, memoryview)):
            raise TypeError("blob must be bytes-like")
        blob_bytes = bytes(blob)
        rc = _lib.ITB_Easy_Import(self._handle, blob_bytes, len(blob_bytes))
        if rc != STATUS_OK:
            _raise_easy(rc)

    # ─── Streaming AEAD ──────────────────────────────────────────

    def encrypt_stream_auth(self, fin, fout, chunk_size: Optional[int] = None) -> None:
        """Reads plaintext from the binary file-like ``fin`` until EOF,
        encrypts each chunk under the Streaming AEAD construction
        bound to this encryptor's seeds + MAC closure, and writes the
        concatenated ``stream_id || chunk_0 || chunk_1 || ...``
        transcript to the binary file-like ``fout``.

        ``chunk_size`` defaults to :data:`itb.DEFAULT_CHUNK_SIZE`
        (16 MB) when not supplied; it must be positive. The 32-byte
        CSPRNG ``stream_id`` prefix is generated server-side per call;
        the running ``cumulative_pixel_offset`` and the terminating
        chunk's ``final_flag = True`` are managed internally.

        Empty stream is permitted — emits the 32-byte prefix followed
        by a single terminating chunk carrying zero plaintext bytes.

        Closed-state preflight: surfaces :class:`itb.ITBError` with
        code :data:`STATUS_EASY_CLOSED` after :meth:`close` /
        :meth:`free`."""
        self._check_open()
        cs = int(chunk_size) if chunk_size else _DEFAULT_CHUNK_SIZE
        if cs <= 0:
            raise ITBError(STATUS_BAD_INPUT, "chunk_size must be positive")
        stream_id = _generate_stream_id()
        fout.write(stream_id)
        cum_pixels = 0
        header_sz = self.header_size
        # Deferred-final pattern: keep at least one chunk's worth in
        # buf until end-of-input is signalled, so the terminal flag
        # can be set on the last chunk only.
        buf = bytearray()
        eof = False
        while not eof:
            while len(buf) <= cs and not eof:
                chunk = fin.read(cs)
                if not chunk:
                    eof = True
                    break
                buf.extend(chunk)
            if eof:
                # Final chunk carries final_flag = True. Empty stream
                # also passes through this branch with len(buf) == 0.
                ct = self._stream_auth_emit(
                    bytes(buf), stream_id, cum_pixels, True)
                # Wipe buffered plaintext after consumption.
                if len(buf) > 0:
                    ctypes.memset(
                        (ctypes.c_char * len(buf)).from_buffer(buf),
                        0,
                        len(buf),
                    )
                buf.clear()
                fout.write(ct)
                if len(ct) >= header_sz:
                    w = (ct[header_sz - 4] << 8) | ct[header_sz - 3]
                    h = (ct[header_sz - 2] << 8) | ct[header_sz - 1]
                    cum_pixels += w * h
                break
            # buf has > cs bytes; emit one non-terminal chunk and
            # keep the leftover for the next iteration.
            chunk_pt = bytes(buf[:cs])
            ctypes.memset(
                (ctypes.c_char * cs).from_buffer(buf, 0),
                0,
                cs,
            )
            del buf[:cs]
            ct = self._stream_auth_emit(
                chunk_pt, stream_id, cum_pixels, False)
            fout.write(ct)
            if len(ct) >= header_sz:
                w = (ct[header_sz - 4] << 8) | ct[header_sz - 3]
                h = (ct[header_sz - 2] << 8) | ct[header_sz - 1]
                cum_pixels += w * h

    def decrypt_stream_auth(self, fin, fout, read_size: Optional[int] = None) -> None:
        """Reads a Streaming AEAD transcript from the binary file-like
        ``fin`` until EOF and writes the recovered plaintext to
        ``fout``. Surfaces :class:`itb.ItbStreamTruncatedError` when
        the input exhausts without a terminating chunk,
        :class:`itb.ItbStreamAfterFinalError` when bytes follow the
        terminator, and :class:`itb.ITBError` carrying
        :data:`STATUS_MAC_FAILURE` on any per-chunk MAC mismatch.

        ``read_size`` defaults to :data:`itb.DEFAULT_CHUNK_SIZE`
        (16 MB) when not supplied; it must be positive."""
        self._check_open()
        rs = int(read_size) if read_size else _DEFAULT_CHUNK_SIZE
        if rs <= 0:
            raise ITBError(STATUS_BAD_INPUT, "read_size must be positive")
        header_sz = self.header_size
        accum = bytearray()
        sid_have = 0
        stream_id = bytearray(_STREAM_ID_LEN)
        cum_pixels = 0
        seen_final = False
        while True:
            chunk = fin.read(rs)
            if not chunk:
                # EOF — drain remainder.
                if sid_have < _STREAM_ID_LEN:
                    raise _ItbStreamTruncatedError(
                        "auth stream: prefix never observed")
                while not seen_final and len(accum) >= header_sz:
                    cl = self.parse_chunk_len(bytes(accum[:header_sz]))
                    if len(accum) < cl:
                        break
                    w = (accum[header_sz - 4] << 8) | accum[header_sz - 3]
                    h = (accum[header_sz - 2] << 8) | accum[header_sz - 1]
                    pixels = w * h
                    chunk_ct = bytes(accum[:cl])
                    del accum[:cl]
                    pt, ff = self._stream_auth_consume(
                        chunk_ct, bytes(stream_id), cum_pixels)
                    fout.write(pt)
                    cum_pixels += pixels
                    if ff:
                        seen_final = True
                if not seen_final:
                    raise _ItbStreamTruncatedError(
                        "auth stream: terminator never observed")
                if accum:
                    raise _ItbStreamAfterFinalError(
                        "auth stream: trailing bytes after terminator")
                return
            # Fill stream_id first.
            off = 0
            if sid_have < _STREAM_ID_LEN:
                need = _STREAM_ID_LEN - sid_have
                take = min(need, len(chunk))
                stream_id[sid_have : sid_have + take] = chunk[:take]
                sid_have += take
                off = take
            if off < len(chunk):
                accum.extend(chunk[off:])
            if sid_have < _STREAM_ID_LEN:
                continue
            # Drain whole chunks.
            while True:
                if seen_final:
                    if accum:
                        raise _ItbStreamAfterFinalError(
                            "auth stream: trailing bytes after terminator")
                    break
                if len(accum) < header_sz:
                    break
                cl = self.parse_chunk_len(bytes(accum[:header_sz]))
                if len(accum) < cl:
                    break
                w = (accum[header_sz - 4] << 8) | accum[header_sz - 3]
                h = (accum[header_sz - 2] << 8) | accum[header_sz - 1]
                pixels = w * h
                chunk_ct = bytes(accum[:cl])
                del accum[:cl]
                pt, ff = self._stream_auth_consume(
                    chunk_ct, bytes(stream_id), cum_pixels)
                fout.write(pt)
                cum_pixels += pixels
                if ff:
                    seen_final = True

    def _stream_auth_emit(
        self, plaintext: bytes, stream_id: bytes,
        cum_pixels: int, final_flag: bool,
    ) -> bytes:
        """Per-chunk encrypt dispatch via the Easy Mode Streaming AEAD
        ABI export. Pre-allocates from the 1.25× + 128 KiB envelope
        (mirror of :meth:`_cipher_call`); the C ABI runs the full
        crypto on every call regardless of out-buffer capacity, so a
        NULL/0 probe would double the work. The +32-byte tag and
        +1-byte flag inherent to the Streaming AEAD per-chunk wire
        layout are inside the 128 KiB pad's headroom even at
        chunk_size = 1. STATUS_BUFFER_TOO_SMALL retry stays as the
        safety net per .NEXTBIND.md §7.1.

        Reuses the per-encryptor ``_out_buf`` / ``_out_cap`` cache
        (Bonus 1 in §7.1) — same scope as the Single Message
        :meth:`_cipher_call` path — so the streaming hot loop
        amortises the cffi allocation across every chunk."""
        self._check_open()
        sid_buf = _ffi.new(f"unsigned char[{_STREAM_ID_LEN}]", stream_id)
        in_arg = plaintext if plaintext else _ffi.NULL
        payload_len = len(plaintext)
        cap = max(131072, (payload_len * 5) // 4 + 131072)
        if self._out_cap < cap:
            # Wipe previous bytes before reassignment — cffi's _ffi.new
            # discards the prior buffer without zeroing the heap region.
            if self._out_cap > 0 and self._out_buf != _ffi.NULL:
                _ffi.memmove(self._out_buf, b"\x00" * self._out_cap, self._out_cap)
            self._out_buf = _ffi.new("unsigned char[]", cap)
            self._out_cap = cap
        out_len = _ffi.new("size_t*")
        rc = _lib.ITB_Easy_EncryptStreamAuth(
            self._handle, in_arg, payload_len,
            sid_buf, int(cum_pixels), 1 if final_flag else 0,
            self._out_buf, self._out_cap, out_len)
        if rc == STATUS_BUFFER_TOO_SMALL:
            need = int(out_len[0])
            if need == 0:
                return b""
            if self._out_cap > 0 and self._out_buf != _ffi.NULL:
                _ffi.memmove(self._out_buf, b"\x00" * self._out_cap, self._out_cap)
            self._out_buf = _ffi.new("unsigned char[]", need)
            self._out_cap = need
            rc = _lib.ITB_Easy_EncryptStreamAuth(
                self._handle, in_arg, payload_len,
                sid_buf, int(cum_pixels), 1 if final_flag else 0,
                self._out_buf, self._out_cap, out_len)
        if rc != STATUS_OK:
            _raise_easy(rc)
        return bytes(_ffi.buffer(self._out_buf, int(out_len[0])))

    def _stream_auth_consume(
        self, ciphertext: bytes, stream_id: bytes, cum_pixels: int,
    ):
        """Per-chunk decrypt dispatch via the Easy Mode Streaming AEAD
        ABI export. Pre-allocates from the 1.25× + 128 KiB envelope
        (mirror of :meth:`_cipher_call`); see :meth:`_stream_auth_emit`
        for the rationale. STATUS_BUFFER_TOO_SMALL retry stays as the
        safety net per .NEXTBIND.md §7.1. Returns
        ``(plaintext, final_flag)``.

        Reuses the per-encryptor ``_out_buf`` / ``_out_cap`` cache
        (Bonus 1 in §7.1) — same scope as the Single Message
        :meth:`_cipher_call` path."""
        self._check_open()
        sid_buf = _ffi.new(f"unsigned char[{_STREAM_ID_LEN}]", stream_id)
        in_arg = ciphertext if ciphertext else _ffi.NULL
        payload_len = len(ciphertext)
        cap = max(131072, (payload_len * 5) // 4 + 131072)
        if self._out_cap < cap:
            if self._out_cap > 0 and self._out_buf != _ffi.NULL:
                _ffi.memmove(self._out_buf, b"\x00" * self._out_cap, self._out_cap)
            self._out_buf = _ffi.new("unsigned char[]", cap)
            self._out_cap = cap
        out_len = _ffi.new("size_t*")
        ff = _ffi.new("int*")
        rc = _lib.ITB_Easy_DecryptStreamAuth(
            self._handle, in_arg, payload_len,
            sid_buf, int(cum_pixels),
            self._out_buf, self._out_cap, out_len, ff)
        if rc == STATUS_BUFFER_TOO_SMALL:
            need = int(out_len[0])
            if need == 0:
                return b"", bool(int(ff[0]))
            if self._out_cap > 0 and self._out_buf != _ffi.NULL:
                _ffi.memmove(self._out_buf, b"\x00" * self._out_cap, self._out_cap)
            self._out_buf = _ffi.new("unsigned char[]", need)
            self._out_cap = need
            rc = _lib.ITB_Easy_DecryptStreamAuth(
                self._handle, in_arg, payload_len,
                sid_buf, int(cum_pixels),
                self._out_buf, self._out_cap, out_len, ff)
        if rc != STATUS_OK:
            _raise_easy(rc)
        return bytes(_ffi.buffer(self._out_buf, int(out_len[0]))), bool(int(ff[0]))

    # ─── Lifecycle ────────────────────────────────────────────────

    def close(self) -> None:
        """Zeroes the encryptor's PRF keys, MAC key, and seed
        components, and marks the encryptor as closed. Idempotent —
        multiple :meth:`close` calls return without raising. Also
        wipes the per-encryptor cffi output cache so the last
        ciphertext / plaintext does not linger in heap memory after
        the encryptor's working set has been zeroed on the Go side.

        Subsequent calls on a closed encryptor raise
        :class:`ITBError` with code :data:`STATUS_EASY_CLOSED`,
        regardless of whether the underlying handle slot has merely
        been closed (post-:meth:`close`) or fully released
        (post-:meth:`free`)."""
        # Always wipe the cached output buffer — repeated close calls
        # keep the cache wiped without racing the Go-side close.
        if self._out_cap > 0 and self._out_buf != _ffi.NULL:
            _ffi.memmove(self._out_buf, b"\x00" * self._out_cap, self._out_cap)
        self._out_buf = _ffi.NULL
        self._out_cap = 0
        if self._closed or not self._handle:
            # Idempotent — already closed.
            self._closed = True
            return
        rc = _lib.ITB_Easy_Close(self._handle)
        self._closed = True
        # Close is documented as idempotent on the Go side; treat
        # any non-OK return after close as a bug.
        if rc != STATUS_OK:
            _raise_easy(rc)

    def free(self) -> None:
        """Releases the underlying libitb handle slot. Wipes the
        per-encryptor cffi output cache (so key material does not
        linger in heap memory) and then releases the libitb handle
        slot. Idempotent — calling :meth:`free` on an already-freed
        encryptor returns silently. Subsequent method calls on the
        instance raise :class:`ITBError` with code
        :data:`STATUS_EASY_CLOSED`."""
        if self._out_cap > 0 and self._out_buf != _ffi.NULL:
            _ffi.memmove(self._out_buf, b"\x00" * self._out_cap, self._out_cap)
        self._out_buf = _ffi.NULL
        self._out_cap = 0
        h = self._handle
        self._handle = 0
        self._closed = True
        if h:
            rc = _lib.ITB_Easy_Free(h)
            if rc != STATUS_OK:
                _raise_easy(rc)

    def __enter__(self) -> "Encryptor":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.free()

    def __del__(self):
        # Best-effort GC release; ignore any error since interpreter
        # shutdown ordering is unpredictable.
        try:
            if self._out_cap > 0 and self._out_buf != _ffi.NULL:
                _ffi.memmove(self._out_buf, b"\x00" * self._out_cap, self._out_cap)
            self._out_buf = _ffi.NULL
            self._out_cap = 0
            if self._handle:
                _lib.ITB_Easy_Free(self._handle)
                self._handle = 0
                self._closed = True
        except Exception:
            pass


def _read_str(call) -> str:
    """Common idiom for size-out-param string accessors on the
    Encryptor: probe required length with NULL/0, allocate, retry.
    Mirrors the same helper in :mod:`itb._ffi` for the lower-level
    Seed / MAC accessors."""
    out_len = _ffi.new("size_t*")
    rc = call(_ffi.NULL, 0, out_len)
    if rc not in (STATUS_OK, STATUS_BUFFER_TOO_SMALL):
        _raise_easy(rc)
    cap = int(out_len[0])
    buf = _ffi.new("char[]", cap)
    rc = call(buf, cap, out_len)
    if rc != STATUS_OK:
        _raise_easy(rc)
    return _ffi.string(buf, int(out_len[0]) - 1).decode("utf-8")
