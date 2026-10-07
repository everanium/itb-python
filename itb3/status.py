"""Status codes mirrored from the libitb3 C ABI
(``cmd/cshared/internal/capi/errors.go``). Numeric values are stable
across releases.
"""

from __future__ import annotations

import enum


class Status(enum.IntEnum):
    """Integer status code returned by every libitb3 entry point."""

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


def status_from(code: int) -> Status:
    """Maps a raw return code onto :class:`Status`; unknown codes
    collapse to :attr:`Status.INTERNAL`."""
    try:
        return Status(code)
    except ValueError:
        return Status.INTERNAL
