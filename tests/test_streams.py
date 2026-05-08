"""Tests for the Python streaming wrappers (StreamEncryptor /
StreamDecryptor + StreamEncryptor3 / StreamDecryptor3 + the
encrypt_stream / decrypt_stream / *_triple convenience functions).

Each test uses io.BytesIO as both input and output so we exercise
the file-like contract without touching disk. Multi-chunk inputs
are constructed by calling .write() multiple times with sub-chunk
buffers, ensuring the encryptor's accumulator + flush logic
processes more than one chunk per stream.

Triple-Ouroboros and non-default nonce-bits configurations are
covered explicitly so a regression in the dynamic header_size()
path or in the seed-list plumbing is caught here.
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


@contextmanager
def nonce_bits(n):
    orig = itb.get_nonce_bits()
    itb.set_nonce_bits(n)
    try:
        yield
    finally:
        itb.set_nonce_bits(orig)


# Small chunk size to force multiple chunks for short inputs and
# exercise the accumulator-flush path. ITB still accepts these
# sizes; only the wire-format chunk count is amplified.
SMALL_CHUNK = 4096


def _seeds(hash_name, n):
    return [itb.Seed(hash_name, 1024) for _ in range(n)]


def _free(seeds):
    for s in seeds:
        s.free()


class TestStreamEncryptorSingleClass(unittest.TestCase):
    def test_class_roundtrip_default_nonce(self):
        plaintext = secrets.token_bytes(SMALL_CHUNK * 5 + 17)
        seeds = _seeds("blake3", 3)
        try:
            cbuf = io.BytesIO()
            with itb.StreamEncryptor(*seeds, cbuf, chunk_size=SMALL_CHUNK) as enc:
                # Push data in three irregular slices, forcing the
                # accumulator path to handle partial chunks.
                enc.write(plaintext[:1000])
                enc.write(plaintext[1000:5000])
                enc.write(plaintext[5000:])
            ct = cbuf.getvalue()

            pbuf = io.BytesIO()
            with itb.StreamDecryptor(*seeds, pbuf) as dec:
                # Feed ciphertext in 1-KB shards.
                view = memoryview(ct)
                for off in range(0, len(view), 1024):
                    dec.feed(bytes(view[off : off + 1024]))
            self.assertEqual(pbuf.getvalue(), plaintext)
        finally:
            _free(seeds)

    def test_class_roundtrip_non_default_nonce(self):
        plaintext = secrets.token_bytes(SMALL_CHUNK * 3 + 100)
        for n in (256, 512):
            with self.subTest(nonce=n):
                with nonce_bits(n):
                    seeds = _seeds("blake3", 3)
                    try:
                        cbuf = io.BytesIO()
                        with itb.StreamEncryptor(
                            *seeds, cbuf, chunk_size=SMALL_CHUNK
                        ) as enc:
                            enc.write(plaintext)
                        pbuf = io.BytesIO()
                        with itb.StreamDecryptor(*seeds, pbuf) as dec:
                            dec.feed(cbuf.getvalue())
                        self.assertEqual(pbuf.getvalue(), plaintext)
                    finally:
                        _free(seeds)


class TestStreamFunctional(unittest.TestCase):
    def test_encrypt_stream_decrypt_stream(self):
        plaintext = secrets.token_bytes(SMALL_CHUNK * 4)
        seeds = _seeds("blake3", 3)
        try:
            fin = io.BytesIO(plaintext)
            cbuf = io.BytesIO()
            itb.encrypt_stream(*seeds, fin, cbuf, chunk_size=SMALL_CHUNK)

            cin = io.BytesIO(cbuf.getvalue())
            pbuf = io.BytesIO()
            itb.decrypt_stream(*seeds, cin, pbuf)
            self.assertEqual(pbuf.getvalue(), plaintext)
        finally:
            _free(seeds)

    def test_encrypt_stream_across_nonce_sizes(self):
        plaintext = secrets.token_bytes(SMALL_CHUNK * 3 + 256)
        for n in (128, 256, 512):
            with self.subTest(nonce=n):
                with nonce_bits(n):
                    seeds = _seeds("blake3", 3)
                    try:
                        fin = io.BytesIO(plaintext)
                        cbuf = io.BytesIO()
                        itb.encrypt_stream(
                            *seeds, fin, cbuf, chunk_size=SMALL_CHUNK
                        )
                        pbuf = io.BytesIO()
                        itb.decrypt_stream(
                            *seeds, io.BytesIO(cbuf.getvalue()), pbuf
                        )
                        self.assertEqual(pbuf.getvalue(), plaintext)
                    finally:
                        _free(seeds)


class TestStreamEncryptorTripleClass(unittest.TestCase):
    def test_class_roundtrip_default_nonce(self):
        plaintext = secrets.token_bytes(SMALL_CHUNK * 4 + 33)
        seeds = _seeds("blake3", 7)
        try:
            cbuf = io.BytesIO()
            with itb.StreamEncryptor3(
                *seeds, cbuf, chunk_size=SMALL_CHUNK
            ) as enc:
                enc.write(plaintext[: SMALL_CHUNK])
                enc.write(plaintext[SMALL_CHUNK : 3 * SMALL_CHUNK])
                enc.write(plaintext[3 * SMALL_CHUNK :])
            ct = cbuf.getvalue()

            pbuf = io.BytesIO()
            with itb.StreamDecryptor3(*seeds, pbuf) as dec:
                dec.feed(ct)
            self.assertEqual(pbuf.getvalue(), plaintext)
        finally:
            _free(seeds)

    def test_class_roundtrip_non_default_nonce(self):
        plaintext = secrets.token_bytes(SMALL_CHUNK * 3)
        for n in (256, 512):
            with self.subTest(nonce=n):
                with nonce_bits(n):
                    seeds = _seeds("blake3", 7)
                    try:
                        cbuf = io.BytesIO()
                        with itb.StreamEncryptor3(
                            *seeds, cbuf, chunk_size=SMALL_CHUNK
                        ) as enc:
                            enc.write(plaintext)
                        pbuf = io.BytesIO()
                        with itb.StreamDecryptor3(*seeds, pbuf) as dec:
                            dec.feed(cbuf.getvalue())
                        self.assertEqual(pbuf.getvalue(), plaintext)
                    finally:
                        _free(seeds)


class TestStreamFunctionalTriple(unittest.TestCase):
    def test_encrypt_stream_triple_decrypt_stream_triple(self):
        plaintext = secrets.token_bytes(SMALL_CHUNK * 5 + 7)
        seeds = _seeds("blake3", 7)
        try:
            fin = io.BytesIO(plaintext)
            cbuf = io.BytesIO()
            itb.encrypt_stream_triple(
                *seeds, fin, cbuf, chunk_size=SMALL_CHUNK
            )
            cin = io.BytesIO(cbuf.getvalue())
            pbuf = io.BytesIO()
            itb.decrypt_stream_triple(*seeds, cin, pbuf)
            self.assertEqual(pbuf.getvalue(), plaintext)
        finally:
            _free(seeds)

    def test_encrypt_stream_triple_across_nonce_sizes(self):
        plaintext = secrets.token_bytes(SMALL_CHUNK * 3 + 100)
        for n in (128, 256, 512):
            with self.subTest(nonce=n):
                with nonce_bits(n):
                    seeds = _seeds("blake3", 7)
                    try:
                        fin = io.BytesIO(plaintext)
                        cbuf = io.BytesIO()
                        itb.encrypt_stream_triple(
                            *seeds, fin, cbuf, chunk_size=SMALL_CHUNK
                        )
                        pbuf = io.BytesIO()
                        itb.decrypt_stream_triple(
                            *seeds, io.BytesIO(cbuf.getvalue()), pbuf
                        )
                        self.assertEqual(pbuf.getvalue(), plaintext)
                    finally:
                        _free(seeds)


class TestStreamErrors(unittest.TestCase):
    def test_write_after_close_raises(self):
        seeds = _seeds("blake3", 3)
        try:
            cbuf = io.BytesIO()
            enc = itb.StreamEncryptor(*seeds, cbuf, chunk_size=SMALL_CHUNK)
            enc.write(b"hello")
            enc.close()
            with self.assertRaises(itb.ITBError) as cm:
                enc.write(b"world")
            self.assertEqual(cm.exception.code, itb._ffi.STATUS_EASY_CLOSED)
        finally:
            _free(seeds)

    def test_partial_chunk_at_close_raises(self):
        seeds = _seeds("blake3", 3)
        try:
            cbuf = io.BytesIO()
            with itb.StreamEncryptor(
                *seeds, cbuf, chunk_size=SMALL_CHUNK
            ) as enc:
                enc.write(b"x" * 100)
            ct = cbuf.getvalue()

            pbuf = io.BytesIO()
            dec = itb.StreamDecryptor(*seeds, pbuf)
            # Feed only the first 30 bytes — header complete (≥20) but
            # body truncated. close() must raise on the trailing
            # incomplete chunk.
            dec.feed(ct[:30])
            with self.assertRaises(ValueError):
                dec.close()
        finally:
            _free(seeds)


if __name__ == "__main__":
    unittest.main(verbosity=2)
