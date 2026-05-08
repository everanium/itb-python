"""Tests for the authenticated streaming methods on the high-level
:class:`itb.Encryptor` (``encrypt_stream_auth`` / ``decrypt_stream_auth``).

Reuses the existing Easy Mode encryptor surface — one constructor
call covers the seed material and MAC closure — and exercises the
Easy Mode Streaming AEAD ABI export. Coverage parallels
``test_streams_auth.py`` at the per-encryptor entry point:

- Round-trip across the canonical MAC × hash-width matrix.
- Truncate-tail / cross-stream replay / prefix-tamper detection.
- Empty + single-chunk streams.
- Closed-state preflight after :meth:`Encryptor.close` /
  :meth:`Encryptor.free`.
"""

import io
import secrets
import sys
import unittest
from pathlib import Path

HERE = Path(__file__).resolve()
sys.path.insert(0, str(HERE.parents[1]))

import itb  # noqa: E402


SMALL_CHUNK = 4096
STREAM_ID_LEN = 32

CANONICAL_MACS = ("kmac256", "hmac-sha256", "hmac-blake3")
HASH_BY_WIDTH = (
    ("siphash24", 128),
    ("blake3", 256),
    ("blake2b512", 512),
)


def _split_chunks(ct: bytes, header_size: int):
    """Split a Streaming AEAD wire transcript into the 32-byte
    stream_id prefix plus the on-wire chunk byte slices."""
    prefix = ct[:STREAM_ID_LEN]
    body = ct[STREAM_ID_LEN:]
    chunks = []
    off = 0
    while off < len(body):
        cl = itb.parse_chunk_len(body[off : off + header_size])
        chunks.append(body[off : off + cl])
        off += cl
    return prefix, chunks


class TestEasyStreamAuthRoundtrip(unittest.TestCase):
    def test_default_constructor_roundtrip(self):
        plaintext = secrets.token_bytes(SMALL_CHUNK * 3 + 17)
        with itb.Encryptor("blake3", 1024, "hmac-blake3") as enc:
            cbuf = io.BytesIO()
            enc.encrypt_stream_auth(io.BytesIO(plaintext), cbuf, chunk_size=SMALL_CHUNK)
            ct = cbuf.getvalue()
            self.assertGreater(len(ct), STREAM_ID_LEN)

            pbuf = io.BytesIO()
            enc.decrypt_stream_auth(io.BytesIO(ct), pbuf, read_size=SMALL_CHUNK)
            self.assertEqual(pbuf.getvalue(), plaintext)

    def test_all_mac_hash_combinations_single(self):
        plaintext = secrets.token_bytes(SMALL_CHUNK * 2 + 9)
        for mac_name in CANONICAL_MACS:
            for hash_name, _ in HASH_BY_WIDTH:
                with self.subTest(mac=mac_name, hash=hash_name):
                    with itb.Encryptor(hash_name, 1024, mac_name) as enc:
                        cbuf = io.BytesIO()
                        enc.encrypt_stream_auth(
                            io.BytesIO(plaintext), cbuf, chunk_size=SMALL_CHUNK)
                        pbuf = io.BytesIO()
                        enc.decrypt_stream_auth(
                            io.BytesIO(cbuf.getvalue()), pbuf,
                            read_size=SMALL_CHUNK)
                        self.assertEqual(pbuf.getvalue(), plaintext)

    def test_all_mac_hash_combinations_triple(self):
        plaintext = secrets.token_bytes(SMALL_CHUNK + 100)
        for mac_name in CANONICAL_MACS:
            for hash_name, _ in HASH_BY_WIDTH:
                with self.subTest(mac=mac_name, hash=hash_name):
                    with itb.Encryptor(hash_name, 1024, mac_name, mode=3) as enc:
                        cbuf = io.BytesIO()
                        enc.encrypt_stream_auth(
                            io.BytesIO(plaintext), cbuf, chunk_size=SMALL_CHUNK)
                        pbuf = io.BytesIO()
                        enc.decrypt_stream_auth(
                            io.BytesIO(cbuf.getvalue()), pbuf,
                            read_size=SMALL_CHUNK)
                        self.assertEqual(pbuf.getvalue(), plaintext)

    def test_default_chunk_size(self):
        # When chunk_size is None / 0, the binding picks
        # itb.DEFAULT_CHUNK_SIZE (16 MB) — short payload still works.
        plaintext = b"hello streaming world"
        with itb.Encryptor("blake3", 1024, "hmac-blake3") as enc:
            cbuf = io.BytesIO()
            enc.encrypt_stream_auth(io.BytesIO(plaintext), cbuf)
            pbuf = io.BytesIO()
            enc.decrypt_stream_auth(io.BytesIO(cbuf.getvalue()), pbuf)
            self.assertEqual(pbuf.getvalue(), plaintext)


class TestEasyStreamAuthEdgeCases(unittest.TestCase):
    def test_empty_stream(self):
        with itb.Encryptor("blake3", 1024, "hmac-blake3") as enc:
            cbuf = io.BytesIO()
            enc.encrypt_stream_auth(io.BytesIO(b""), cbuf, chunk_size=SMALL_CHUNK)
            ct = cbuf.getvalue()
            self.assertGreater(len(ct), STREAM_ID_LEN)
            pbuf = io.BytesIO()
            enc.decrypt_stream_auth(
                io.BytesIO(ct), pbuf, read_size=SMALL_CHUNK)
            self.assertEqual(pbuf.getvalue(), b"")

    def test_single_chunk_stream(self):
        plaintext = b"x" * 100
        with itb.Encryptor("blake3", 1024, "hmac-blake3") as enc:
            cbuf = io.BytesIO()
            enc.encrypt_stream_auth(io.BytesIO(plaintext), cbuf, chunk_size=SMALL_CHUNK)
            pbuf = io.BytesIO()
            enc.decrypt_stream_auth(
                io.BytesIO(cbuf.getvalue()), pbuf, read_size=SMALL_CHUNK)
            self.assertEqual(pbuf.getvalue(), plaintext)


class TestEasyStreamAuthDetectionPaths(unittest.TestCase):
    def test_truncate_tail_detected(self):
        plaintext = secrets.token_bytes(SMALL_CHUNK * 2 + SMALL_CHUNK // 2)
        with itb.Encryptor("blake3", 1024, "hmac-blake3") as enc:
            cbuf = io.BytesIO()
            enc.encrypt_stream_auth(io.BytesIO(plaintext), cbuf, chunk_size=SMALL_CHUNK)
            ct = cbuf.getvalue()
            prefix, chunks = _split_chunks(ct, enc.header_size)
            self.assertGreaterEqual(len(chunks), 2)
            truncated = prefix + b"".join(chunks[:-1])
            pbuf = io.BytesIO()
            with self.assertRaises(itb.ItbStreamTruncatedError) as cm:
                enc.decrypt_stream_auth(
                    io.BytesIO(truncated), pbuf, read_size=SMALL_CHUNK)
            self.assertEqual(cm.exception.code, itb.STATUS_STREAM_TRUNCATED)

    def test_after_final_detected(self):
        plaintext = secrets.token_bytes(SMALL_CHUNK + 100)
        with itb.Encryptor("blake3", 1024, "hmac-blake3") as enc:
            cbuf = io.BytesIO()
            enc.encrypt_stream_auth(io.BytesIO(plaintext), cbuf, chunk_size=SMALL_CHUNK)
            ct = cbuf.getvalue()
            prefix, chunks = _split_chunks(ct, enc.header_size)
            after_final = prefix + b"".join(chunks) + chunks[-1]
            pbuf = io.BytesIO()
            with self.assertRaises(itb.ItbStreamAfterFinalError) as cm:
                enc.decrypt_stream_auth(
                    io.BytesIO(after_final), pbuf, read_size=SMALL_CHUNK)
            self.assertEqual(cm.exception.code, itb.STATUS_STREAM_AFTER_FINAL)

    def test_chunk_reorder_detected(self):
        plaintext = secrets.token_bytes(SMALL_CHUNK * 2 + SMALL_CHUNK // 2)
        with itb.Encryptor("blake3", 1024, "hmac-blake3") as enc:
            cbuf = io.BytesIO()
            enc.encrypt_stream_auth(io.BytesIO(plaintext), cbuf, chunk_size=SMALL_CHUNK)
            ct = cbuf.getvalue()
            prefix, chunks = _split_chunks(ct, enc.header_size)
            self.assertGreaterEqual(len(chunks), 3)
            tampered = prefix + chunks[1] + chunks[0] + b"".join(chunks[2:])
            pbuf = io.BytesIO()
            with self.assertRaises(itb.ITBError) as cm:
                enc.decrypt_stream_auth(
                    io.BytesIO(tampered), pbuf, read_size=SMALL_CHUNK)
            self.assertEqual(cm.exception.code, itb.STATUS_MAC_FAILURE)

    def test_stream_prefix_tamper_detected(self):
        plaintext = secrets.token_bytes(SMALL_CHUNK + 200)
        with itb.Encryptor("blake3", 1024, "hmac-blake3") as enc:
            cbuf = io.BytesIO()
            enc.encrypt_stream_auth(io.BytesIO(plaintext), cbuf, chunk_size=SMALL_CHUNK)
            ct = cbuf.getvalue()
            prefix, chunks = _split_chunks(ct, enc.header_size)
            tampered_prefix = bytearray(prefix)
            tampered_prefix[0] ^= 0x80
            tampered = bytes(tampered_prefix) + b"".join(chunks)
            pbuf = io.BytesIO()
            with self.assertRaises(itb.ITBError) as cm:
                enc.decrypt_stream_auth(
                    io.BytesIO(tampered), pbuf, read_size=SMALL_CHUNK)
            self.assertEqual(cm.exception.code, itb.STATUS_MAC_FAILURE)


class TestEasyStreamAuthClosedState(unittest.TestCase):
    def test_call_after_close_raises(self):
        enc = itb.Encryptor("blake3", 1024, "hmac-blake3")
        enc.encrypt_stream_auth(
            io.BytesIO(b"hello"), io.BytesIO(), chunk_size=SMALL_CHUNK)
        enc.close()
        with self.assertRaises(itb.ITBError) as cm:
            enc.encrypt_stream_auth(
                io.BytesIO(b"world"), io.BytesIO(), chunk_size=SMALL_CHUNK)
        self.assertEqual(cm.exception.code, itb._ffi.STATUS_EASY_CLOSED)

    def test_call_after_free_raises(self):
        enc = itb.Encryptor("blake3", 1024, "hmac-blake3")
        enc.encrypt_stream_auth(
            io.BytesIO(b"hello"), io.BytesIO(), chunk_size=SMALL_CHUNK)
        enc.free()
        with self.assertRaises(itb.ITBError) as cm:
            enc.decrypt_stream_auth(
                io.BytesIO(b""), io.BytesIO(), read_size=SMALL_CHUNK)
        self.assertEqual(cm.exception.code, itb._ffi.STATUS_EASY_CLOSED)

    def test_bad_chunk_size_rejected(self):
        with itb.Encryptor("blake3", 1024, "hmac-blake3") as enc:
            with self.assertRaises(itb.ITBError) as cm:
                enc.encrypt_stream_auth(io.BytesIO(b"x"), io.BytesIO(), chunk_size=-1)
            self.assertEqual(cm.exception.code, itb.STATUS_BAD_INPUT)

    def test_bad_read_size_rejected(self):
        with itb.Encryptor("blake3", 1024, "hmac-blake3") as enc:
            with self.assertRaises(itb.ITBError) as cm:
                enc.decrypt_stream_auth(io.BytesIO(b"x"), io.BytesIO(), read_size=-1)
            self.assertEqual(cm.exception.code, itb.STATUS_BAD_INPUT)


class TestEasyStreamAuthLifetime(unittest.TestCase):
    """Class lifetime — the encryptor wrapper retains its handle for
    every per-chunk FFI call. Verifies the post-stream encryptor is
    still usable for a follow-up encrypt + decrypt."""

    def test_subsequent_calls_after_stream(self):
        with itb.Encryptor("blake3", 1024, "hmac-blake3") as enc:
            cbuf = io.BytesIO()
            enc.encrypt_stream_auth(
                io.BytesIO(b"first stream"), cbuf, chunk_size=SMALL_CHUNK)
            # Second stream on the same encryptor.
            cbuf2 = io.BytesIO()
            enc.encrypt_stream_auth(
                io.BytesIO(b"second stream"), cbuf2, chunk_size=SMALL_CHUNK)
            pbuf = io.BytesIO()
            enc.decrypt_stream_auth(
                io.BytesIO(cbuf2.getvalue()), pbuf, read_size=SMALL_CHUNK)
            self.assertEqual(pbuf.getvalue(), b"second stream")


if __name__ == "__main__":
    unittest.main(verbosity=2)
