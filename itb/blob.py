"""Native-Blob wrapper over the libitb C ABI.

Mirrors the github.com/everanium/itb Blob128 / Blob256 / Blob512 Go
types: a width-specific container that packs the low-level encryptor
material (per-seed hash key + components + optional dedicated
lockSeed + optional MAC key + name) plus the captured process-wide
configuration into one self-describing JSON blob. Intended for the
low-level encrypt / decrypt path where each seed slot may carry a
different primitive — the high-level :class:`Encryptor` wraps a
narrower one-primitive-per-encryptor surface (see :mod:`itb.easy`).

Quick start (sender, Single Ouroboros + Areion-SoEM-512 + HMAC-BLAKE3):

    >>> from itb import Seed, Blob512, encrypt_auth, MAC
    >>> import os
    >>> ns = Seed("areion512", 2048)
    >>> ds = Seed("areion512", 2048)
    >>> ss = Seed("areion512", 2048)
    >>> mac_key = os.urandom(32)
    >>> mac = MAC("hmac-blake3", mac_key)
    >>> ct = encrypt_auth(ns, ds, ss, mac, b"payload")
    >>> b = Blob512()
    >>> b.set_key("n", ns.hash_key); b.set_components("n", ns.components)
    >>> b.set_key("d", ds.hash_key); b.set_components("d", ds.components)
    >>> b.set_key("s", ss.hash_key); b.set_components("s", ss.components)
    >>> b.set_mac_key(mac_key); b.set_mac_name("hmac-blake3")
    >>> blob_bytes = b.export(mac=True)
    >>> # ... persist blob_bytes ...

Receiver:

    >>> b2 = Blob512()
    >>> b2.import_blob(blob_bytes)
    >>> # Components and hash keys round-trip back into the receiver.
    >>> ns2 = Seed.from_components("areion512", b2.get_components("n"),
    ...                            hash_key=b2.get_key("n"))
    >>> # ... wire ds2, ss2 the same way; rebuild MAC; decrypt_auth ...

The blob is mode-discriminated: :meth:`export` packs Single material,
:meth:`export3` packs Triple material; :meth:`import_blob` and
:meth:`import_triple` are the corresponding receivers. A blob built
under one mode rejects the wrong importer with
:class:`BlobModeMismatchError`.

Globals (NonceBits / BarrierFill / BitSoup / LockSoup) are captured
into the blob at :meth:`export` / :meth:`export3` time and applied
process-wide on :meth:`import_blob` / :meth:`import_triple` via the
existing :func:`itb.set_nonce_bits` / :func:`itb.set_barrier_fill` /
:func:`itb.set_bit_soup` / :func:`itb.set_lock_soup` setters. The
worker count and the global LockSeed flag are not serialised — the
former is a deployment knob, the latter is irrelevant on the native
path which consults :meth:`Seed.attach_lock_seed` directly.
"""

from __future__ import annotations

from typing import List, Optional

from ._ffi import (
    _ffi,
    _lib,
    _last_error,
    ITBError,
    STATUS_OK,
    STATUS_BUFFER_TOO_SMALL,
    STATUS_BAD_INPUT,
    STATUS_BLOB_MODE_MISMATCH,
    STATUS_BLOB_MALFORMED,
    STATUS_BLOB_VERSION_TOO_NEW,
    STATUS_BLOB_TOO_MANY_OPTS,
)


# Slot identifiers — mirror the BlobSlot* constants in
# cmd/cshared/internal/capi/blob_handles.go.
SLOT_N = 0
SLOT_D = 1
SLOT_S = 2
SLOT_L = 3
SLOT_D1 = 4
SLOT_D2 = 5
SLOT_D3 = 6
SLOT_S1 = 7
SLOT_S2 = 8
SLOT_S3 = 9

# Aliased private names retained for backwards compatibility within
# the binding's internal helpers.
_SLOT_N = SLOT_N
_SLOT_D = SLOT_D
_SLOT_S = SLOT_S
_SLOT_L = SLOT_L
_SLOT_D1 = SLOT_D1
_SLOT_D2 = SLOT_D2
_SLOT_D3 = SLOT_D3
_SLOT_S1 = SLOT_S1
_SLOT_S2 = SLOT_S2
_SLOT_S3 = SLOT_S3

_SLOT_NAMES = {
    "n": SLOT_N,
    "d": SLOT_D,
    "s": SLOT_S,
    "l": SLOT_L,
    "d1": SLOT_D1,
    "d2": SLOT_D2,
    "d3": SLOT_D3,
    "s1": SLOT_S1,
    "s2": SLOT_S2,
    "s3": SLOT_S3,
}

# Export option bitmask — mirror BlobOpt* in blob_handles.go.
OPT_LOCKSEED = 1 << 0
OPT_MAC = 1 << 1

# Aliased private names retained for backwards compatibility.
_OPT_LOCKSEED = OPT_LOCKSEED
_OPT_MAC = OPT_MAC


class BlobModeMismatchError(ITBError):
    """Raised when :meth:`_BlobBase.import_blob` is called on a blob
    that carries Triple-mode material, or when :meth:`import_triple`
    is called on a Single-mode blob. The receiver picks the matching
    method explicitly; there is no automatic dispatch on the mode
    field of the parsed blob."""


class BlobMalformedError(ITBError):
    """Raised when the blob fails to parse as JSON or carries fields
    outside the documented shape (zero-length components, bad
    hex / decimal encoding, key_bits inconsistent with the components
    length, etc.)."""


class BlobVersionTooNewError(ITBError):
    """Raised when the blob's ``v`` field is greater than the highest
    schema version this build understands. Indicates the producer is
    a newer libitb than the consumer."""


def _raise_blob(code: int):
    """Raises the most specific Blob exception subclass for a non-OK
    status code; falls back to :class:`itb.ITBError` for codes that
    do not map to a typed Blob error."""
    if code == STATUS_BLOB_MODE_MISMATCH:
        raise BlobModeMismatchError(code, _last_error())
    if code == STATUS_BLOB_MALFORMED:
        raise BlobMalformedError(code, _last_error())
    if code == STATUS_BLOB_VERSION_TOO_NEW:
        raise BlobVersionTooNewError(code, _last_error())
    raise ITBError(code, _last_error())


def _slot(slot) -> int:
    """Resolves a slot identifier — accepts either an integer (already
    a BlobSlot* numeric constant) or a case-insensitive string from
    the canonical ``{"n","d","s","l","d1","d2","d3","s1","s2","s3"}``
    set."""
    if isinstance(slot, int):
        return slot
    if isinstance(slot, str):
        key = slot.lower()
        if key in _SLOT_NAMES:
            return _SLOT_NAMES[key]
    raise ValueError(f"invalid blob slot: {slot!r}")


class _BlobBase:
    """Width-agnostic Blob handle wrapper. Concrete subclasses
    :class:`Blob128`, :class:`Blob256`, :class:`Blob512` pin the
    width via :attr:`_WIDTH` and the corresponding constructor
    entry point.

    Slot identifiers may be passed as integers (0..9) or canonical
    strings (``"n"``, ``"d"``, ``"s"``, ``"l"``, ``"d1"``..``"d3"``,
    ``"s1"``..``"s3"``); both forms refer to the same underlying
    BlobSlot* constants from the C ABI.
    """

    __slots__ = ("_handle",)
    _WIDTH = 0  # overridden by subclasses

    def __init__(self):
        h = _ffi.new("uintptr_t*")
        rc = self._new(h)
        if rc != STATUS_OK:
            _raise_blob(rc)
        self._handle = int(h[0])

    @staticmethod
    def _new(h):
        raise NotImplementedError

    # ─── Lifecycle ─────────────────────────────────────────────────

    def free(self):
        """Releases the underlying libitb handle. Idempotent — the
        handle attribute is zeroed after the first call so a second
        :meth:`free` is a no-op rather than a double-free panic.
        Mirrors :meth:`itb.Seed.free` / :meth:`itb.MAC.free`: a non-OK
        status (typically ``STATUS_BAD_HANDLE`` if the handle was
        already invalidated by a sibling thread) is raised as
        :class:`ITBError` rather than silently swallowed."""
        if self._handle:
            rc = _lib.ITB_Blob_Free(self._handle)
            self._handle = 0
            if rc != STATUS_OK:
                _raise_blob(rc)

    close = free

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.free()

    def __del__(self):
        try:
            self.free()
        except Exception:
            pass

    # ─── Read-only meta ────────────────────────────────────────────

    @property
    def handle(self) -> int:
        """Opaque libitb handle id (uintptr). Useful for diagnostics;
        bindings should not rely on its numerical value."""
        return self._handle

    @property
    def width(self) -> int:
        """Native hash width — 128, 256, or 512. Pinned at
        construction time and stable for the lifetime of the handle."""
        st = _ffi.new("int*")
        v = int(_lib.ITB_Blob_Width(self._handle, st))
        if int(st[0]) != STATUS_OK:
            _raise_blob(int(st[0]))
        return v

    @property
    def mode(self) -> int:
        """Blob mode field — ``0`` = unset (freshly constructed
        handle), ``1`` = Single Ouroboros, ``3`` = Triple Ouroboros.
        Updated by :meth:`import_blob` / :meth:`import_triple` from
        the parsed blob's mode discriminator."""
        st = _ffi.new("int*")
        v = int(_lib.ITB_Blob_Mode(self._handle, st))
        if int(st[0]) != STATUS_OK:
            _raise_blob(int(st[0]))
        return v

    # ─── Slot setters ──────────────────────────────────────────────

    def set_key(self, slot, key: bytes):
        """Stores the hash key bytes for the given slot. The 256 /
        512 widths require exactly 32 / 64 bytes; the 128 width
        accepts variable lengths (empty for siphash24 — no internal
        fixed key — or 16 bytes for aescmac)."""
        if not isinstance(key, (bytes, bytearray, memoryview)):
            raise TypeError("key must be bytes-like")
        b = bytes(key)
        rc = _lib.ITB_Blob_SetKey(self._handle, _slot(slot), b, len(b))
        if rc != STATUS_OK:
            _raise_blob(rc)

    def set_components(self, slot, components):
        """Stores the seed components (sequence of unsigned 64-bit
        integers) for the given slot. Component count must satisfy
        the 8..MaxKeyBits/64 multiple-of-8 invariants — same rules
        as :meth:`itb.Seed.from_components`. Validation is deferred
        to :meth:`export` / :meth:`import_blob` time."""
        comps = list(components)
        n = len(comps)
        buf = _ffi.new(f"unsigned long long[{n if n > 0 else 1}]")
        for i, v in enumerate(comps):
            buf[i] = int(v)
        rc = _lib.ITB_Blob_SetComponents(self._handle, _slot(slot), buf, n)
        if rc != STATUS_OK:
            _raise_blob(rc)

    def set_mac_key(self, key: Optional[bytes]):
        """Stores the optional MAC key bytes. Pass ``None`` or an
        empty bytes object to clear a previously-set key. The MAC
        section is only emitted by :meth:`export` / :meth:`export3`
        when ``mac=True`` is passed AND the MAC key on the handle is
        non-empty."""
        if key is None:
            rc = _lib.ITB_Blob_SetMACKey(self._handle, _ffi.NULL, 0)
        else:
            if not isinstance(key, (bytes, bytearray, memoryview)):
                raise TypeError("MAC key must be bytes-like")
            b = bytes(key)
            rc = _lib.ITB_Blob_SetMACKey(self._handle, b, len(b))
        if rc != STATUS_OK:
            _raise_blob(rc)

    def set_mac_name(self, name: Optional[str]):
        """Stores the optional MAC name on the handle (e.g.
        ``"kmac256"``, ``"hmac-blake3"``). Pass ``None`` or an empty
        string to clear a previously-set name."""
        if not name:
            rc = _lib.ITB_Blob_SetMACName(self._handle, _ffi.NULL, 0)
        else:
            buf = name.encode("utf-8")
            rc = _lib.ITB_Blob_SetMACName(self._handle, buf, len(buf))
        if rc != STATUS_OK:
            _raise_blob(rc)

    # ─── Slot getters ──────────────────────────────────────────────

    def get_key(self, slot) -> bytes:
        """Returns a fresh copy of the hash key bytes from the given
        slot. Returns an empty bytes object for an unset slot or
        siphash24's no-internal-key path (callers distinguish by
        ``len(...) == 0`` and the slot they queried)."""
        sl = _slot(slot)
        out_len = _ffi.new("size_t*")
        rc = _lib.ITB_Blob_GetKey(self._handle, sl, _ffi.NULL, 0, out_len)
        if rc not in (STATUS_OK, STATUS_BUFFER_TOO_SMALL):
            _raise_blob(rc)
        n = int(out_len[0])
        if n == 0:
            return b""
        buf = _ffi.new("unsigned char[]", n)
        rc = _lib.ITB_Blob_GetKey(self._handle, sl, buf, n, out_len)
        if rc != STATUS_OK:
            _raise_blob(rc)
        return bytes(_ffi.buffer(buf, int(out_len[0])))

    def get_components(self, slot) -> List[int]:
        """Returns a list of unsigned 64-bit integers — the seed
        components stored at the given slot. Returns an empty list
        for an unset slot."""
        sl = _slot(slot)
        out_count = _ffi.new("size_t*")
        rc = _lib.ITB_Blob_GetComponents(self._handle, sl, _ffi.NULL, 0, out_count)
        if rc not in (STATUS_OK, STATUS_BUFFER_TOO_SMALL):
            _raise_blob(rc)
        n = int(out_count[0])
        if n == 0:
            return []
        buf = _ffi.new(f"unsigned long long[{n}]")
        rc = _lib.ITB_Blob_GetComponents(self._handle, sl, buf, n, out_count)
        if rc != STATUS_OK:
            _raise_blob(rc)
        return [int(buf[i]) for i in range(int(out_count[0]))]

    def get_mac_key(self) -> bytes:
        """Returns a fresh copy of the MAC key bytes from the handle,
        or empty bytes if no MAC is associated."""
        out_len = _ffi.new("size_t*")
        rc = _lib.ITB_Blob_GetMACKey(self._handle, _ffi.NULL, 0, out_len)
        if rc not in (STATUS_OK, STATUS_BUFFER_TOO_SMALL):
            _raise_blob(rc)
        n = int(out_len[0])
        if n == 0:
            return b""
        buf = _ffi.new("unsigned char[]", n)
        rc = _lib.ITB_Blob_GetMACKey(self._handle, buf, n, out_len)
        if rc != STATUS_OK:
            _raise_blob(rc)
        return bytes(_ffi.buffer(buf, int(out_len[0])))

    def get_mac_name(self) -> str:
        """Returns the MAC name from the handle, or an empty string
        if no MAC is associated."""
        out_len = _ffi.new("size_t*")
        rc = _lib.ITB_Blob_GetMACName(self._handle, _ffi.NULL, 0, out_len)
        if rc not in (STATUS_OK, STATUS_BUFFER_TOO_SMALL):
            _raise_blob(rc)
        cap = int(out_len[0])
        if cap <= 1:
            return ""
        buf = _ffi.new("char[]", cap)
        rc = _lib.ITB_Blob_GetMACName(self._handle, buf, cap, out_len)
        if rc != STATUS_OK:
            _raise_blob(rc)
        return _ffi.string(buf, int(out_len[0]) - 1).decode("utf-8")

    # ─── Export / Import ───────────────────────────────────────────

    def export(self, lockseed: bool = False, mac: bool = False) -> bytes:
        """Serialises the handle's Single-Ouroboros state into a JSON
        blob. The optional ``lockseed`` and ``mac`` keyword flags
        opt the matching sections in: when ``lockseed=True`` the
        ``l`` slot's KeyL + components are emitted; when ``mac=True``
        the MAC key + name are emitted (both must be non-empty on
        the handle)."""
        return self._export(self._opts(lockseed, mac), triple=False)

    def export3(self, lockseed: bool = False, mac: bool = False) -> bytes:
        """Serialises the handle's Triple-Ouroboros state into a
        JSON blob. See :meth:`export` for the ``lockseed`` / ``mac``
        bitmask semantics."""
        return self._export(self._opts(lockseed, mac), triple=True)

    def import_blob(self, blob: bytes):
        """Parses a Single-Ouroboros JSON blob, populates the
        handle's slots, and applies the captured globals via the
        process-wide setters.

        Raises :class:`BlobModeMismatchError` when the blob is
        Triple-mode, :class:`BlobMalformedError` on parse / shape
        failure, :class:`BlobVersionTooNewError` on a version field
        higher than this build supports."""
        if not isinstance(blob, (bytes, bytearray, memoryview)):
            raise TypeError("blob must be bytes-like")
        b = bytes(blob)
        rc = _lib.ITB_Blob_Import(self._handle, b, len(b))
        if rc != STATUS_OK:
            _raise_blob(rc)

    def import_triple(self, blob: bytes):
        """Triple-Ouroboros counterpart of :meth:`import_blob`. Same
        error contract."""
        if not isinstance(blob, (bytes, bytearray, memoryview)):
            raise TypeError("blob must be bytes-like")
        b = bytes(blob)
        rc = _lib.ITB_Blob_Import3(self._handle, b, len(b))
        if rc != STATUS_OK:
            _raise_blob(rc)

    # ─── Helpers ───────────────────────────────────────────────────

    @staticmethod
    def _opts(lockseed: bool, mac: bool) -> int:
        m = 0
        if lockseed:
            m |= _OPT_LOCKSEED
        if mac:
            m |= _OPT_MAC
        return m

    def _export(self, opts: int, triple: bool) -> bytes:
        # Two-phase probe-then-retry buffer convention.
        out_len = _ffi.new("size_t*")
        fn = _lib.ITB_Blob_Export3 if triple else _lib.ITB_Blob_Export
        rc = fn(self._handle, opts, _ffi.NULL, 0, out_len)
        if rc not in (STATUS_OK, STATUS_BUFFER_TOO_SMALL):
            _raise_blob(rc)
        cap = int(out_len[0])
        if cap == 0:
            return b""
        buf = _ffi.new("unsigned char[]", cap)
        rc = fn(self._handle, opts, buf, cap, out_len)
        if rc != STATUS_OK:
            _raise_blob(rc)
        return bytes(_ffi.buffer(buf, int(out_len[0])))


class Blob128(_BlobBase):
    """128-bit width Blob — covers ``siphash24`` and ``aescmac``
    primitives. Hash key length is variable: empty for siphash24
    (no internal fixed key), 16 bytes for aescmac. The 128-bit width
    is reserved for testing and below-spec stress controls; for
    production traffic prefer :class:`Blob256` or :class:`Blob512`.
    """

    __slots__ = ()
    _WIDTH = 128

    @staticmethod
    def _new(h):
        return _lib.ITB_Blob128_New(h)


class Blob256(_BlobBase):
    """256-bit width Blob — covers ``areion256``, ``blake2s``,
    ``blake2b256``, ``blake3``, ``chacha20``. Hash key length is
    fixed at 32 bytes."""

    __slots__ = ()
    _WIDTH = 256

    @staticmethod
    def _new(h):
        return _lib.ITB_Blob256_New(h)


class Blob512(_BlobBase):
    """512-bit width Blob — covers ``areion512`` (via the SoEM-512
    construction) and ``blake2b512``. Hash key length is fixed at
    64 bytes."""

    __slots__ = ()
    _WIDTH = 512

    @staticmethod
    def _new(h):
        return _lib.ITB_Blob512_New(h)
