"""Status codes mirrored from the libitb C ABI
(``cmd/cshared/internal/capi/errors.go``). Numeric values are stable
across releases.
"""

from __future__ import annotations

import enum


class Status(enum.IntEnum):
    """Integer status code returned by every libitb entry point."""

    OK = 0
    BAD_HASH = 1
    BAD_KEY_BITS = 2
    BAD_HANDLE = 3
    BAD_INPUT = 4
    BUFFER_TOO_SMALL = 5
    ENCRYPT_FAILED = 6
    DECRYPT_FAILED = 7
    SEED_WIDTH_MIX = 8
    BAD_MAC = 9
    MAC_FAILURE = 10
    BLOB_MALFORMED_RECIPE = 11
    RECIPE_PRIMITIVE_UNKNOWN = 12
    UNKNOWN_PROFILE = 13
    RESERVED_14 = 14
    RESERVED_15 = 15
    RESERVED_16 = 16
    RESERVED_17 = 17
    BLOB_MODE_MISMATCH = 19
    BLOB_MALFORMED = 20
    BLOB_VERSION_TOO_NEW = 21
    BLOB_TOO_MANY_OPTS = 22
    STREAM_TRUNCATED = 23
    STREAM_AFTER_FINAL = 24
    TRIPLE_CLOSED = 25
    PROFILE_EXISTS = 26
    INTERNAL = 99

    def label(self) -> str:
        """Short human-readable label for the status code."""
        return _LABELS.get(self, "unknown status")


_LABELS: dict[Status, str] = {
    Status.OK: "ok",
    Status.BAD_HASH: "unknown hash name",
    Status.BAD_KEY_BITS: "invalid key bits",
    Status.BAD_HANDLE: "invalid handle",
    Status.BAD_INPUT: "invalid input",
    Status.BUFFER_TOO_SMALL: "output buffer too small",
    Status.ENCRYPT_FAILED: "encrypt failed",
    Status.DECRYPT_FAILED: "decrypt failed",
    Status.SEED_WIDTH_MIX: "seed width mismatch",
    Status.BAD_MAC: "unknown MAC name or invalid MAC handle",
    Status.MAC_FAILURE: "MAC verification failed",
    Status.BLOB_MALFORMED_RECIPE: "blob profile record invalid",
    Status.RECIPE_PRIMITIVE_UNKNOWN: (
        "blob profile record names a primitive absent from the local registries"
    ),
    Status.UNKNOWN_PROFILE: "unknown profile name",
    Status.RESERVED_14: "reserved status",
    Status.RESERVED_15: "reserved status",
    Status.RESERVED_16: "reserved status",
    Status.RESERVED_17: "reserved status",
    Status.BLOB_MODE_MISMATCH: "blob mode mismatch",
    Status.BLOB_MALFORMED: "malformed state blob",
    Status.BLOB_VERSION_TOO_NEW: "blob version too new",
    Status.BLOB_TOO_MANY_OPTS: "too many blob export opts",
    Status.STREAM_TRUNCATED: "stream truncated before terminator",
    Status.STREAM_AFTER_FINAL: "stream chunk after terminator",
    Status.TRIPLE_CLOSED: "Triple Pipeline is closed",
    Status.PROFILE_EXISTS: "profile name already registered",
    Status.INTERNAL: "internal error",
}


def status_from(code: int) -> Status:
    """Maps a raw return code onto :class:`Status`; unknown codes
    collapse to :attr:`Status.INTERNAL`."""
    try:
        return Status(code)
    except ValueError:
        return Status.INTERNAL
