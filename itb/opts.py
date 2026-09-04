"""URL-query builder for the opts pass-through string.

The builder performs no validation — every key and value is rendered
into a percent-encoded query string and passed through to Go
verbatim; libitb rejects unknown keys or bad values with a diagnostic
surfaced via :class:`~itb.error.ItbError`. Primitive / MAC / cipher /
palette names are opaque strings.
"""

from __future__ import annotations

from collections.abc import Sequence
from urllib.parse import quote


class Opts:
    """Builder producing the URL-query-encoded opts string consumed by
    :meth:`itb.Pipeline.init`. Every setter returns ``self`` for
    fluent chaining. (Profile registration takes a JSON record — see
    :func:`itb.register` — not an ``Opts``.)"""

    def __init__(self) -> None:
        self._pairs: list[tuple[str, str]] = []

    def with_perm_master(self, master: bytes | bytearray | memoryview) -> Opts:
        """Hex-encodes the parallax master override (``pm``)."""
        return self.with_raw("pm", bytes(master).hex())

    def with_wrap_master(self, master: bytes | bytearray | memoryview) -> Opts:
        """Hex-encodes the wrapper master override (``wm``)."""
        return self.with_raw("wm", bytes(master).hex())

    def with_parallax(self, on: bool) -> Opts:
        return self.with_raw("withParallax", "true" if on else "false")

    def with_wrapper(self, on: bool) -> Opts:
        return self.with_raw("withWrapper", "true" if on else "false")

    def with_max_workers(self, n: int) -> Opts:
        """Init-time worker cap; ``n <= 0`` selects auto. The live cap
        is adjustable later through :meth:`itb.Pipeline.max_workers`."""
        return self.with_raw("maxWorkers", str(n))

    def with_nonce_bits(self, n: int) -> Opts:
        return self.with_raw("nonceBits", str(n))

    def with_barrier_fill(self, n: int) -> Opts:
        return self.with_raw("barrierFill", str(n))

    def with_chunk_size(self, n: int) -> Opts:
        return self.with_raw("chunkSize", str(n))

    def with_key_bits(self, n: int) -> Opts:
        return self.with_raw("keyBits", str(n))

    def with_parallax_segment_size(self, n: int) -> Opts:
        return self.with_raw("parallaxSegmentSize", str(n))

    def with_mac_name(self, name: str) -> Opts:
        return self.with_raw("macName", name)

    def with_inner_hash(self, name: str) -> Opts:
        return self.with_raw("innerHash", name)

    def with_inner_hashes(self, names: Sequence[str]) -> Opts:
        """Comma-joins an 8-slot per-call inner-hash constellation into
        the ``innerHashes`` opts key. Parallel to the Go-side
        ``Opts.MixedHashes [8]string`` per-call override; slot ordering
        is ``[noise, lock, data1, data2, data3, start1, start2,
        start3]``.

        Fail-fast validation surfaces at Init on the Go side; a typo'd
        slot or width mismatch surfaces with an error naming the
        offending slot. When both this and :meth:`with_inner_hash` are
        set, the mixed override wins on the Go side."""
        return self.with_raw("innerHashes", ",".join(names))

    def with_outer_cipher(self, name: str) -> Opts:
        return self.with_raw("outerCipher", name)

    def with_parallax_palette(self, names: Sequence[str]) -> Opts:
        """Comma-joins the palette names (``parallaxPalette``)."""
        return self.with_raw("parallaxPalette", ",".join(names))

    def with_raw(self, key: str, value: str) -> Opts:
        """Escape hatch appending a raw ``key=value`` pair. Covers
        every key the Go side accepts."""
        self._pairs.append((key, value))
        return self

    def build(self) -> str:
        """Renders the accumulated pairs as a query string. The
        accepted values are ASCII names, decimal integers,
        ``true`` / ``false``, hex, and comma-separated lists, so
        everything outside the URL-safe subset (plus ``,``) is
        percent-escaped byte-wise."""
        return "&".join(f"{_enc(k)}={_enc(v)}" for k, v in self._pairs)

    def __repr__(self) -> str:
        return f"Opts({self.build()!r})"


def _enc(s: str) -> str:
    return quote(s, safe=",")
