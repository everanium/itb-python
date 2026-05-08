"""Tests for streaming use of the high-level :class:`itb.Encryptor`.

Streaming over the Encryptor surface lives entirely on the binding
side (no separate StreamEncryptor / StreamDecryptor classes) — the
Python consumer slices the plaintext into chunks of the desired
size and calls :meth:`Encryptor.encrypt` per chunk; the decrypt
side walks the concatenated chunk stream by reading
:attr:`Encryptor.header_size` bytes, calling
:meth:`Encryptor.parse_chunk_len`, reading the remaining body, and
feeding the full chunk to :meth:`Encryptor.decrypt`. This is the
same pattern that :class:`itb.StreamEncryptor` / :class:`itb.StreamDecryptor`
follow internally over the legacy Seed / encrypt / decrypt path —
only the per-call surface differs.

Triple-Ouroboros (mode=3) and non-default nonce-bits configurations
are covered explicitly so a regression in the per-instance
:attr:`Encryptor.header_size` / :meth:`Encryptor.parse_chunk_len`
path or in the seed plumbing surfaces here.
"""

import io
import secrets
import sys
import unittest
from pathlib import Path

HERE = Path(__file__).resolve()
sys.path.insert(0, str(HERE.parents[2]))

import itb  # noqa: E402


SMALL_CHUNK = 4096


def _stream_encrypt(enc, fin, fout, chunk_size):
    """Read plaintext from fin until EOF, encrypt in chunks of
    chunk_size, write concatenated ciphertext chunks to fout."""
    while True:
        buf = fin.read(chunk_size)
        if not buf:
            break
        fout.write(enc.encrypt(buf))


def _stream_decrypt(enc, fin, fout):
    """Read concatenated ciphertext chunks from fin and write the
    recovered plaintext to fout. Walks the stream by reading the
    fixed-size header, parsing the chunk length, reading the body,
    and decrypting each chunk."""
    accumulator = bytearray()
    while True:
        buf = fin.read(SMALL_CHUNK)
        if not buf:
            break
        accumulator.extend(buf)
        # Drain any complete chunks already in the accumulator.
        while True:
            if len(accumulator) < enc.header_size:
                break
            chunk_len = enc.parse_chunk_len(bytes(accumulator[: enc.header_size]))
            if len(accumulator) < chunk_len:
                break
            chunk = bytes(accumulator[:chunk_len])
            fout.write(enc.decrypt(chunk))
            del accumulator[:chunk_len]
    if accumulator:
        raise ValueError(
            f"trailing {len(accumulator)} bytes do not form a complete chunk"
        )


class TestEasyStreamRoundtripDefaultNonce(unittest.TestCase):
    def test_class_roundtrip(self):
        plaintext = secrets.token_bytes(SMALL_CHUNK * 5 + 17)
        with itb.Encryptor("blake3", 1024, "kmac256", mode=1) as enc:
            cbuf = io.BytesIO()
            _stream_encrypt(enc, io.BytesIO(plaintext), cbuf, SMALL_CHUNK)
            pbuf = io.BytesIO()
            _stream_decrypt(enc, io.BytesIO(cbuf.getvalue()), pbuf)
            self.assertEqual(pbuf.getvalue(), plaintext)


class TestEasyStreamRoundtripNonDefaultNonce(unittest.TestCase):
    def test_class_roundtrip_non_default_nonce(self):
        plaintext = secrets.token_bytes(SMALL_CHUNK * 3 + 100)
        for n in (256, 512):
            with self.subTest(nonce=n):
                with itb.Encryptor("blake3", 1024, "kmac256", mode=1) as enc:
                    enc.set_nonce_bits(n)
                    cbuf = io.BytesIO()
                    _stream_encrypt(enc, io.BytesIO(plaintext), cbuf, SMALL_CHUNK)
                    pbuf = io.BytesIO()
                    _stream_decrypt(enc, io.BytesIO(cbuf.getvalue()), pbuf)
                    self.assertEqual(pbuf.getvalue(), plaintext)


class TestEasyStreamTripleRoundtripDefaultNonce(unittest.TestCase):
    def test_class_roundtrip(self):
        plaintext = secrets.token_bytes(SMALL_CHUNK * 4 + 33)
        with itb.Encryptor("blake3", 1024, "kmac256", mode=3) as enc:
            cbuf = io.BytesIO()
            _stream_encrypt(enc, io.BytesIO(plaintext), cbuf, SMALL_CHUNK)
            pbuf = io.BytesIO()
            _stream_decrypt(enc, io.BytesIO(cbuf.getvalue()), pbuf)
            self.assertEqual(pbuf.getvalue(), plaintext)


class TestEasyStreamTripleRoundtripNonDefaultNonce(unittest.TestCase):
    def test_class_roundtrip_non_default_nonce(self):
        plaintext = secrets.token_bytes(SMALL_CHUNK * 3)
        for n in (256, 512):
            with self.subTest(nonce=n):
                with itb.Encryptor("blake3", 1024, "kmac256", mode=3) as enc:
                    enc.set_nonce_bits(n)
                    cbuf = io.BytesIO()
                    _stream_encrypt(enc, io.BytesIO(plaintext), cbuf, SMALL_CHUNK)
                    pbuf = io.BytesIO()
                    _stream_decrypt(enc, io.BytesIO(cbuf.getvalue()), pbuf)
                    self.assertEqual(pbuf.getvalue(), plaintext)


class TestEasyStreamErrors(unittest.TestCase):
    def test_partial_chunk_raises(self):
        """Feeding only a partial chunk to the streaming decoder
        surfaces a ValueError on close — same plausible-failure
        contract as :class:`itb.StreamDecryptor`."""
        plaintext = b"x" * 100
        with itb.Encryptor("blake3", 1024, "kmac256", mode=1) as enc:
            cbuf = io.BytesIO()
            _stream_encrypt(enc, io.BytesIO(plaintext), cbuf, SMALL_CHUNK)
            ct = cbuf.getvalue()
            # Feed only 30 bytes — header complete (>= 20) but body
            # truncated. The drain loop must reject the trailing
            # incomplete chunk on close.
            with self.assertRaises(ValueError):
                _stream_decrypt(enc, io.BytesIO(ct[:30]), io.BytesIO())

    def test_parse_chunk_len_short_buffer(self):
        with itb.Encryptor("blake3", 1024, "kmac256") as enc:
            with self.assertRaises(itb.ITBError) as cm:
                enc.parse_chunk_len(b"\x00" * (enc.header_size - 1))
            self.assertEqual(cm.exception.code, itb._ffi.STATUS_BAD_INPUT)

    def test_parse_chunk_len_zero_dim(self):
        with itb.Encryptor("blake3", 1024, "kmac256") as enc:
            # header_size bytes, but width == 0.
            hdr = b"\x00" * enc.header_size
            with self.assertRaises(itb.ITBError):
                enc.parse_chunk_len(hdr)


if __name__ == "__main__":
    unittest.main(verbosity=2)
