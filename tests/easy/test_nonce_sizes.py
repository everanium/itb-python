"""Round-trip tests across all per-instance nonce-size configurations.

Symmetric counterpart to bindings/python/tests/test_nonce_sizes.py.
The Encryptor surface exposes nonce_bits as a per-instance setter
(:meth:`Encryptor.set_nonce_bits`) rather than a process-wide
config — each encryptor's :attr:`Encryptor.header_size` and
:meth:`Encryptor.parse_chunk_len` track its own nonce_bits state
without touching the global :func:`itb.set_nonce_bits` /
:func:`itb.get_nonce_bits` accessors.

This file exhaustively covers the Encryptor surface under each
nonce configuration:
  - one-shot encrypt / decrypt (Single mode + Triple mode);
  - authenticated encrypt / decrypt (Single + Triple), including
    tamper rejection at the per-instance header offset;
  - parse_chunk_len reporting the right chunk length.
"""

import secrets
import sys
import unittest
from pathlib import Path

HERE = Path(__file__).resolve()
sys.path.insert(0, str(HERE.parents[2]))

import itb  # noqa: E402


NONCE_SIZES = (128, 256, 512)


class TestEasyHeaderSizeTracksNonceBits(unittest.TestCase):
    def test_default_is_20(self):
        with itb.Encryptor("blake3", 1024, "kmac256") as enc:
            self.assertEqual(enc.header_size, 20)
            self.assertEqual(enc.nonce_bits, 128)

    def test_dynamic(self):
        for n in NONCE_SIZES:
            with self.subTest(nonce=n):
                with itb.Encryptor("blake3", 1024, "kmac256") as enc:
                    enc.set_nonce_bits(n)
                    self.assertEqual(enc.nonce_bits, n)
                    self.assertEqual(enc.header_size, n // 8 + 4)


class TestEasyEncryptDecryptAcrossNonceSizes(unittest.TestCase):
    """Single mode one-shot encrypt/decrypt over all three nonce
    sizes via per-instance setter."""

    def test_all(self):
        plaintext = secrets.token_bytes(1024)
        for n in NONCE_SIZES:
            for hash_name in ("siphash24", "blake3", "blake2b512"):
                with self.subTest(nonce=n, hash=hash_name):
                    with itb.Encryptor(hash_name, 1024, "kmac256", mode=1) as enc:
                        enc.set_nonce_bits(n)
                        ct = enc.encrypt(plaintext)
                        pt = enc.decrypt(ct)
                        self.assertEqual(pt, plaintext)
                        # parse_chunk_len must report the full chunk.
                        self.assertEqual(
                            enc.parse_chunk_len(ct[: enc.header_size]),
                            len(ct),
                        )


class TestEasyTripleEncryptDecryptAcrossNonceSizes(unittest.TestCase):
    """Triple mode (mode=3) one-shot encrypt/decrypt over all three
    nonce sizes via per-instance setter."""

    def test_all(self):
        plaintext = secrets.token_bytes(1024)
        for n in NONCE_SIZES:
            for hash_name in ("siphash24", "blake3", "blake2b512"):
                with self.subTest(nonce=n, hash=hash_name):
                    with itb.Encryptor(hash_name, 1024, "kmac256", mode=3) as enc:
                        enc.set_nonce_bits(n)
                        ct = enc.encrypt(plaintext)
                        pt = enc.decrypt(ct)
                        self.assertEqual(pt, plaintext)
                        self.assertEqual(
                            enc.parse_chunk_len(ct[: enc.header_size]),
                            len(ct),
                        )


class TestEasyAuthAcrossNonceSizes(unittest.TestCase):
    """Single + Auth round trip + tamper rejection at the
    per-instance header offset."""

    def test_all(self):
        plaintext = secrets.token_bytes(1024)
        for n in NONCE_SIZES:
            for mac_name in ("kmac256", "hmac-sha256", "hmac-blake3"):
                with self.subTest(nonce=n, mac=mac_name):
                    with itb.Encryptor("blake3", 1024, mac_name, mode=1) as enc:
                        enc.set_nonce_bits(n)
                        ct = enc.encrypt_auth(plaintext)
                        pt = enc.decrypt_auth(ct)
                        self.assertEqual(pt, plaintext)
                        tampered = bytearray(ct)
                        h = enc.header_size
                        for i in range(h, min(h + 256, len(tampered))):
                            tampered[i] ^= 0x01
                        with self.assertRaises(itb.ITBError) as cm:
                            enc.decrypt_auth(bytes(tampered))
                        self.assertEqual(
                            cm.exception.code, itb._ffi.STATUS_MAC_FAILURE,
                        )


class TestEasyTripleAuthAcrossNonceSizes(unittest.TestCase):
    """Triple + Auth round trip + tamper rejection at the
    per-instance header offset."""

    def test_all(self):
        plaintext = secrets.token_bytes(1024)
        for n in NONCE_SIZES:
            for mac_name in ("kmac256", "hmac-sha256", "hmac-blake3"):
                with self.subTest(nonce=n, mac=mac_name):
                    with itb.Encryptor("blake3", 1024, mac_name, mode=3) as enc:
                        enc.set_nonce_bits(n)
                        ct = enc.encrypt_auth(plaintext)
                        pt = enc.decrypt_auth(ct)
                        self.assertEqual(pt, plaintext)
                        tampered = bytearray(ct)
                        h = enc.header_size
                        for i in range(h, min(h + 256, len(tampered))):
                            tampered[i] ^= 0x01
                        with self.assertRaises(itb.ITBError) as cm:
                            enc.decrypt_auth(bytes(tampered))
                        self.assertEqual(
                            cm.exception.code, itb._ffi.STATUS_MAC_FAILURE,
                        )


class TestEasyTwoEncryptorsIndependentNonceBits(unittest.TestCase):
    """Per-instance nonce_bits are isolated: one encryptor's
    set_nonce_bits(256) does not affect another encryptor that uses
    the default."""

    def test_isolation(self):
        plaintext = b"isolation test"
        with itb.Encryptor("blake3", 1024, "kmac256") as a, \
             itb.Encryptor("blake3", 1024, "kmac256") as b:
            a.set_nonce_bits(512)
            self.assertEqual(a.nonce_bits, 512)
            self.assertEqual(a.header_size, 68)
            self.assertEqual(b.nonce_bits, 128)
            self.assertEqual(b.header_size, 20)
            # Round-trip works on both with their own nonce sizes.
            self.assertEqual(a.decrypt(a.encrypt(plaintext)), plaintext)
            self.assertEqual(b.decrypt(b.encrypt(plaintext)), plaintext)


if __name__ == "__main__":
    unittest.main(verbosity=2)
