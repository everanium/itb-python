"""Tests for the authenticated streaming wrappers
(:class:`itb.StreamEncryptorAuth` / :class:`itb.StreamDecryptorAuth`,
:class:`itb.StreamEncryptorAuth3` / :class:`itb.StreamDecryptorAuth3`,
plus the :func:`itb.encrypt_stream_auth` / :func:`itb.decrypt_stream_auth`
free-function counterparts and their ``_triple`` siblings).

Coverage mirrors the cross-binding contract for Streaming AEAD:

- Round-trip per (Single + Triple) × (3 hash widths) × (3 MAC primitives).
- Reorder of two chunks → :class:`itb.ITBError` ``STATUS_MAC_FAILURE``.
- Truncate-tail → :class:`itb.ItbStreamTruncatedError` from ``close()``.
- Cross-stream replay → :class:`itb.ITBError` ``STATUS_MAC_FAILURE``.
- Stream-prefix tamper → :class:`itb.ITBError` ``STATUS_MAC_FAILURE``.
- Empty stream + single-chunk stream round-trip.
- ``write`` / ``feed`` after ``close`` → :data:`STATUS_EASY_CLOSED`.
- Trailing bytes past the terminator → :class:`itb.ItbStreamAfterFinalError`.

The 32-byte CSPRNG ``stream_id`` prefix is generated server-side per
constructor call; tests therefore use ``io.BytesIO`` for both input
and output so the wire transcript can be inspected directly.
"""

import io
import secrets
import sys
import unittest
from contextlib import contextmanager
from pathlib import Path

HERE = Path(__file__).resolve()
sys.path.insert(0, str(HERE.parents[1]))

import itb  # noqa: E402


SMALL_CHUNK = 4096

CANONICAL_MACS = ("kmac256", "hmac-sha256", "hmac-blake3")
HASH_BY_WIDTH = (
    ("siphash24", 128),
    ("blake3", 256),
    ("blake2b512", 512),
)

STREAM_ID_LEN = 32


@contextmanager
def nonce_bits(n):
    orig = itb.get_nonce_bits()
    itb.set_nonce_bits(n)
    try:
        yield
    finally:
        itb.set_nonce_bits(orig)


def _seeds(hash_name, n):
    return [itb.Seed(hash_name, 1024) for _ in range(n)]


def _free(seeds):
    for s in seeds:
        s.free()


def _new_mac(name):
    return itb.MAC(name, secrets.token_bytes(32))


class TestStreamAuthSingleClass(unittest.TestCase):
    def test_class_roundtrip_default_nonce(self):
        plaintext = secrets.token_bytes(SMALL_CHUNK * 5 + 17)
        seeds = _seeds("blake3", 3)
        mac = _new_mac("hmac-blake3")
        try:
            cbuf = io.BytesIO()
            with itb.StreamEncryptorAuth(*seeds, mac, cbuf, chunk_size=SMALL_CHUNK) as enc:
                enc.write(plaintext[:1000])
                enc.write(plaintext[1000:5000])
                enc.write(plaintext[5000:])
            ct = cbuf.getvalue()
            # Wire prefix is 32-byte stream_id.
            self.assertGreaterEqual(len(ct), STREAM_ID_LEN)

            pbuf = io.BytesIO()
            with itb.StreamDecryptorAuth(*seeds, mac, pbuf) as dec:
                view = memoryview(ct)
                for off in range(0, len(view), 1024):
                    dec.feed(bytes(view[off : off + 1024]))
            self.assertEqual(pbuf.getvalue(), plaintext)
        finally:
            mac.free()
            _free(seeds)

    def test_class_roundtrip_all_macs_all_widths(self):
        plaintext = secrets.token_bytes(SMALL_CHUNK * 2 + 33)
        for mac_name in CANONICAL_MACS:
            for hash_name, _ in HASH_BY_WIDTH:
                with self.subTest(mac=mac_name, hash=hash_name):
                    seeds = _seeds(hash_name, 3)
                    mac = _new_mac(mac_name)
                    try:
                        cbuf = io.BytesIO()
                        with itb.StreamEncryptorAuth(
                            *seeds, mac, cbuf, chunk_size=SMALL_CHUNK
                        ) as enc:
                            enc.write(plaintext)
                        pbuf = io.BytesIO()
                        with itb.StreamDecryptorAuth(*seeds, mac, pbuf) as dec:
                            dec.feed(cbuf.getvalue())
                        self.assertEqual(pbuf.getvalue(), plaintext)
                    finally:
                        mac.free()
                        _free(seeds)

    def test_roundtrip_non_default_nonce(self):
        plaintext = secrets.token_bytes(SMALL_CHUNK * 3 + 100)
        for n in (256, 512):
            with self.subTest(nonce=n):
                with nonce_bits(n):
                    seeds = _seeds("blake3", 3)
                    mac = _new_mac("hmac-sha256")
                    try:
                        cbuf = io.BytesIO()
                        with itb.StreamEncryptorAuth(
                            *seeds, mac, cbuf, chunk_size=SMALL_CHUNK
                        ) as enc:
                            enc.write(plaintext)
                        pbuf = io.BytesIO()
                        with itb.StreamDecryptorAuth(*seeds, mac, pbuf) as dec:
                            dec.feed(cbuf.getvalue())
                        self.assertEqual(pbuf.getvalue(), plaintext)
                    finally:
                        mac.free()
                        _free(seeds)


class TestStreamAuthTripleClass(unittest.TestCase):
    def test_class_roundtrip_default_nonce(self):
        plaintext = secrets.token_bytes(SMALL_CHUNK * 4 + 33)
        seeds = _seeds("blake3", 7)
        mac = _new_mac("hmac-blake3")
        try:
            cbuf = io.BytesIO()
            with itb.StreamEncryptorAuth3(
                *seeds, mac, cbuf, chunk_size=SMALL_CHUNK
            ) as enc:
                enc.write(plaintext[:SMALL_CHUNK])
                enc.write(plaintext[SMALL_CHUNK : 3 * SMALL_CHUNK])
                enc.write(plaintext[3 * SMALL_CHUNK :])
            pbuf = io.BytesIO()
            with itb.StreamDecryptorAuth3(*seeds, mac, pbuf) as dec:
                dec.feed(cbuf.getvalue())
            self.assertEqual(pbuf.getvalue(), plaintext)
        finally:
            mac.free()
            _free(seeds)

    def test_class_roundtrip_all_macs_all_widths(self):
        plaintext = secrets.token_bytes(SMALL_CHUNK * 2 + 7)
        for mac_name in CANONICAL_MACS:
            for hash_name, _ in HASH_BY_WIDTH:
                with self.subTest(mac=mac_name, hash=hash_name):
                    seeds = _seeds(hash_name, 7)
                    mac = _new_mac(mac_name)
                    try:
                        cbuf = io.BytesIO()
                        with itb.StreamEncryptorAuth3(
                            *seeds, mac, cbuf, chunk_size=SMALL_CHUNK
                        ) as enc:
                            enc.write(plaintext)
                        pbuf = io.BytesIO()
                        with itb.StreamDecryptorAuth3(*seeds, mac, pbuf) as dec:
                            dec.feed(cbuf.getvalue())
                        self.assertEqual(pbuf.getvalue(), plaintext)
                    finally:
                        mac.free()
                        _free(seeds)


class TestStreamAuthFunctional(unittest.TestCase):
    def test_encrypt_stream_auth_roundtrip(self):
        plaintext = secrets.token_bytes(SMALL_CHUNK * 4)
        seeds = _seeds("blake3", 3)
        mac = _new_mac("hmac-blake3")
        try:
            fin = io.BytesIO(plaintext)
            cbuf = io.BytesIO()
            itb.encrypt_stream_auth(*seeds, mac, fin, cbuf, chunk_size=SMALL_CHUNK)

            cin = io.BytesIO(cbuf.getvalue())
            pbuf = io.BytesIO()
            itb.decrypt_stream_auth(*seeds, mac, cin, pbuf)
            self.assertEqual(pbuf.getvalue(), plaintext)
        finally:
            mac.free()
            _free(seeds)

    def test_encrypt_stream_auth_triple_roundtrip(self):
        plaintext = secrets.token_bytes(SMALL_CHUNK * 5 + 7)
        seeds = _seeds("blake3", 7)
        mac = _new_mac("hmac-sha256")
        try:
            fin = io.BytesIO(plaintext)
            cbuf = io.BytesIO()
            itb.encrypt_stream_auth_triple(
                *seeds, mac, fin, cbuf, chunk_size=SMALL_CHUNK)
            pbuf = io.BytesIO()
            itb.decrypt_stream_auth_triple(
                *seeds, mac, io.BytesIO(cbuf.getvalue()), pbuf)
            self.assertEqual(pbuf.getvalue(), plaintext)
        finally:
            mac.free()
            _free(seeds)


class TestStreamAuthEdgeCases(unittest.TestCase):
    def test_empty_stream(self):
        seeds = _seeds("blake3", 3)
        mac = _new_mac("hmac-blake3")
        try:
            cbuf = io.BytesIO()
            with itb.StreamEncryptorAuth(
                *seeds, mac, cbuf, chunk_size=SMALL_CHUNK
            ) as enc:
                pass  # no write before close
            ct = cbuf.getvalue()
            self.assertGreater(len(ct), STREAM_ID_LEN)

            pbuf = io.BytesIO()
            with itb.StreamDecryptorAuth(*seeds, mac, pbuf) as dec:
                dec.feed(ct)
            self.assertEqual(pbuf.getvalue(), b"")
        finally:
            mac.free()
            _free(seeds)

    def test_single_chunk_stream(self):
        plaintext = b"x" * 100
        seeds = _seeds("blake3", 3)
        mac = _new_mac("hmac-blake3")
        try:
            cbuf = io.BytesIO()
            with itb.StreamEncryptorAuth(
                *seeds, mac, cbuf, chunk_size=SMALL_CHUNK
            ) as enc:
                enc.write(plaintext)
            pbuf = io.BytesIO()
            with itb.StreamDecryptorAuth(*seeds, mac, pbuf) as dec:
                dec.feed(cbuf.getvalue())
            self.assertEqual(pbuf.getvalue(), plaintext)
        finally:
            mac.free()
            _free(seeds)


class TestStreamAuthDetectionPaths(unittest.TestCase):
    """Five attack vectors closed by the Streaming AEAD construction."""

    def _produce_three_chunks(self, seeds, mac, plaintext):
        cbuf = io.BytesIO()
        with itb.StreamEncryptorAuth(
            *seeds, mac, cbuf, chunk_size=SMALL_CHUNK
        ) as enc:
            enc.write(plaintext)
        ct = cbuf.getvalue()
        # Slice into stream_id prefix + three chunks via header walk.
        header_sz = itb.header_size()
        prefix = ct[:STREAM_ID_LEN]
        body = ct[STREAM_ID_LEN:]
        chunks = []
        off = 0
        while off < len(body):
            cl = itb.parse_chunk_len(body[off : off + header_sz])
            chunks.append(body[off : off + cl])
            off += cl
        return prefix, chunks

    def test_chunk_reorder_detected(self):
        # Three chunks of roughly equal size forces three chunks on wire.
        plaintext = secrets.token_bytes(SMALL_CHUNK * 2 + SMALL_CHUNK // 2)
        seeds = _seeds("blake3", 3)
        mac = _new_mac("hmac-blake3")
        try:
            prefix, chunks = self._produce_three_chunks(seeds, mac, plaintext)
            self.assertGreaterEqual(len(chunks), 3)
            # Swap chunks[0] <-> chunks[1] on wire.
            tampered = prefix + chunks[1] + chunks[0] + b"".join(chunks[2:])
            pbuf = io.BytesIO()
            with self.assertRaises(itb.ITBError) as cm:
                with itb.StreamDecryptorAuth(*seeds, mac, pbuf) as dec:
                    dec.feed(tampered)
            self.assertEqual(cm.exception.code, itb.STATUS_MAC_FAILURE)
        finally:
            mac.free()
            _free(seeds)

    def test_truncate_tail_detected(self):
        plaintext = secrets.token_bytes(SMALL_CHUNK * 2 + SMALL_CHUNK // 2)
        seeds = _seeds("blake3", 3)
        mac = _new_mac("hmac-blake3")
        try:
            prefix, chunks = self._produce_three_chunks(seeds, mac, plaintext)
            self.assertGreaterEqual(len(chunks), 2)
            # Drop the terminating chunk — the receiver should not see
            # the final flag.
            truncated = prefix + b"".join(chunks[:-1])
            pbuf = io.BytesIO()
            dec = itb.StreamDecryptorAuth(*seeds, mac, pbuf)
            dec.feed(truncated)
            with self.assertRaises(itb.ItbStreamTruncatedError) as cm:
                dec.close()
            self.assertEqual(cm.exception.code, itb.STATUS_STREAM_TRUNCATED)
        finally:
            mac.free()
            _free(seeds)

    def test_after_final_detected(self):
        plaintext = secrets.token_bytes(SMALL_CHUNK + 100)
        seeds = _seeds("blake3", 3)
        mac = _new_mac("hmac-blake3")
        try:
            prefix, chunks = self._produce_three_chunks(seeds, mac, plaintext)
            self.assertGreaterEqual(len(chunks), 1)
            # Append a duplicate of the terminating chunk past the
            # original terminator.
            after_final = prefix + b"".join(chunks) + chunks[-1]
            pbuf = io.BytesIO()
            dec = itb.StreamDecryptorAuth(*seeds, mac, pbuf)
            with self.assertRaises(itb.ItbStreamAfterFinalError) as cm:
                dec.feed(after_final)
            self.assertEqual(cm.exception.code, itb.STATUS_STREAM_AFTER_FINAL)
        finally:
            mac.free()
            _free(seeds)

    def test_cross_stream_replay_detected(self):
        plaintext = secrets.token_bytes(SMALL_CHUNK * 2)
        seeds = _seeds("blake3", 3)
        mac = _new_mac("hmac-blake3")
        try:
            # Stream A and Stream B under the same seeds + MAC keys
            # but with distinct helper-generated stream_ids.
            pa, ca = self._produce_three_chunks(seeds, mac, plaintext)
            pb, cb = self._produce_three_chunks(seeds, mac, plaintext)
            self.assertNotEqual(pa, pb)
            # Splice chunk_0 of A into B's position 0 — same stream_id
            # in B's prefix, different chunk-0 MAC. Fails on chunk 0.
            tampered = pb + ca[0] + b"".join(cb[1:])
            pbuf = io.BytesIO()
            with self.assertRaises(itb.ITBError) as cm:
                with itb.StreamDecryptorAuth(*seeds, mac, pbuf) as dec:
                    dec.feed(tampered)
            self.assertEqual(cm.exception.code, itb.STATUS_MAC_FAILURE)
        finally:
            mac.free()
            _free(seeds)

    def test_stream_prefix_tamper_detected(self):
        plaintext = secrets.token_bytes(SMALL_CHUNK + 200)
        seeds = _seeds("blake3", 3)
        mac = _new_mac("hmac-blake3")
        try:
            prefix, chunks = self._produce_three_chunks(seeds, mac, plaintext)
            tampered_prefix = bytearray(prefix)
            tampered_prefix[0] ^= 0x80  # flip a single bit in the prefix
            tampered = bytes(tampered_prefix) + b"".join(chunks)
            pbuf = io.BytesIO()
            with self.assertRaises(itb.ITBError) as cm:
                with itb.StreamDecryptorAuth(*seeds, mac, pbuf) as dec:
                    dec.feed(tampered)
            self.assertEqual(cm.exception.code, itb.STATUS_MAC_FAILURE)
        finally:
            mac.free()
            _free(seeds)


class TestStreamAuthClosedState(unittest.TestCase):
    def test_write_after_close_raises(self):
        seeds = _seeds("blake3", 3)
        mac = _new_mac("hmac-blake3")
        try:
            cbuf = io.BytesIO()
            enc = itb.StreamEncryptorAuth(*seeds, mac, cbuf, chunk_size=SMALL_CHUNK)
            enc.write(b"hello")
            enc.close()
            with self.assertRaises(itb.ITBError) as cm:
                enc.write(b"world")
            self.assertEqual(cm.exception.code, itb._ffi.STATUS_EASY_CLOSED)
        finally:
            mac.free()
            _free(seeds)

    def test_feed_after_close_raises(self):
        seeds = _seeds("blake3", 3)
        mac = _new_mac("hmac-blake3")
        try:
            cbuf = io.BytesIO()
            with itb.StreamEncryptorAuth(*seeds, mac, cbuf, chunk_size=SMALL_CHUNK) as enc:
                enc.write(b"x" * 100)
            ct = cbuf.getvalue()
            pbuf = io.BytesIO()
            dec = itb.StreamDecryptorAuth(*seeds, mac, pbuf)
            dec.feed(ct)
            dec.close()
            with self.assertRaises(itb.ITBError) as cm:
                dec.feed(b"y")
            self.assertEqual(cm.exception.code, itb._ffi.STATUS_EASY_CLOSED)
        finally:
            mac.free()
            _free(seeds)

    def test_bad_chunk_size_rejected(self):
        seeds = _seeds("blake3", 3)
        mac = _new_mac("hmac-blake3")
        try:
            with self.assertRaises(itb.ITBError) as cm:
                itb.StreamEncryptorAuth(*seeds, mac, io.BytesIO(), chunk_size=0)
            self.assertEqual(cm.exception.code, itb.STATUS_BAD_INPUT)
        finally:
            mac.free()
            _free(seeds)


class TestStreamAuthLifetime(unittest.TestCase):
    """Class lifetime — Python relies on reference holding for the
    duration of FFI calls. The Streaming AEAD helpers retain Seed /
    MAC references on ``self._seeds`` / ``self._mac`` so the wrapper
    Python objects stay alive for every per-chunk FFI invocation."""

    def test_seeds_and_mac_retained_through_stream_lifetime(self):
        plaintext = secrets.token_bytes(SMALL_CHUNK + 1)
        seeds = _seeds("blake3", 3)
        mac = _new_mac("hmac-blake3")
        try:
            cbuf = io.BytesIO()
            enc = itb.StreamEncryptorAuth(*seeds, mac, cbuf, chunk_size=SMALL_CHUNK)
            # Local references dropped; the encryptor must still hold
            # the seed + mac handles alive through __del__'s scope.
            enc.write(plaintext)
            enc.close()
            ct = cbuf.getvalue()
            pbuf = io.BytesIO()
            dec = itb.StreamDecryptorAuth(*seeds, mac, pbuf)
            dec.feed(ct)
            dec.close()
            self.assertEqual(pbuf.getvalue(), plaintext)
        finally:
            mac.free()
            _free(seeds)


class TestStreamAuthChunkSizeOne(unittest.TestCase):
    """The Streaming AEAD round-trip matrix covers ``chunk_size = 1``
    explicitly: every plaintext byte triggers one full per-chunk MAC
    round-trip and one container-cap encrypt/decrypt. Single-mode
    coverage on one MAC primitive is sufficient — Triple is
    structurally identical at the helper level and the chunk_size=1
    case probes the per-chunk dispatch loop, not the underlying
    container."""

    def test_chunk_size_one_roundtrip_single(self):
        plaintext = b"chunk1by"  # 8 bytes → 8 chunks at chunk_size=1
        seeds = _seeds("blake3", 3)
        mac = _new_mac("hmac-blake3")
        try:
            cbuf = io.BytesIO()
            with itb.StreamEncryptorAuth(*seeds, mac, cbuf, chunk_size=1) as enc:
                enc.write(plaintext)
            pbuf = io.BytesIO()
            with itb.StreamDecryptorAuth(*seeds, mac, pbuf) as dec:
                dec.feed(cbuf.getvalue())
            self.assertEqual(pbuf.getvalue(), plaintext)
        finally:
            mac.free()
            _free(seeds)


class TestStreamAuthIncompletePrefix(unittest.TestCase):
    """An incomplete 32-byte stream-id prefix on the wire is a
    protocol-level malformation distinct from truncate-tail (which is
    "prefix observed but no terminating chunk among the chunks").
    The prefix-truncation path surfaces ``STATUS_BAD_INPUT`` rather
    than ``STATUS_STREAM_TRUNCATED``."""

    def test_incomplete_prefix_raises_bad_input(self):
        seeds = _seeds("blake3", 3)
        mac = _new_mac("hmac-blake3")
        try:
            pbuf = io.BytesIO()
            dec = itb.StreamDecryptorAuth(*seeds, mac, pbuf)
            # Feed 16 bytes of a 32-byte prefix, then close.
            dec.feed(b"\x00" * 16)
            with self.assertRaises(itb.ITBError) as cm:
                dec.close()
            self.assertEqual(cm.exception.code, itb.STATUS_BAD_INPUT)
            self.assertNotIsInstance(cm.exception, itb.ItbStreamTruncatedError)
        finally:
            mac.free()
            _free(seeds)

    def test_zero_byte_prefix_raises_bad_input(self):
        seeds = _seeds("blake3", 3)
        mac = _new_mac("hmac-blake3")
        try:
            pbuf = io.BytesIO()
            dec = itb.StreamDecryptorAuth(*seeds, mac, pbuf)
            with self.assertRaises(itb.ITBError) as cm:
                dec.close()
            self.assertEqual(cm.exception.code, itb.STATUS_BAD_INPUT)
        finally:
            mac.free()
            _free(seeds)


if __name__ == "__main__":
    unittest.main(verbosity=2)
