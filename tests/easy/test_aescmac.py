"""AES-CMAC-focused Encryptor coverage.

Symmetric counterpart to bindings/python/tests/test_aescmac.py
applied to the high-level :class:`itb.Encryptor` surface. AES-CMAC
ships only at -128 (the AES block size).
"""

import secrets
import sys
import unittest
from pathlib import Path

HERE = Path(__file__).resolve()
sys.path.insert(0, str(HERE.parents[2]))

import itb  # noqa: E402


AESCMAC_HASHES = [
    ("aescmac", 128),
]

EXPECTED_KEY_LEN = {
    "aescmac": 16,
}

NONCE_SIZES = (128, 256, 512)


def _key_bits_for(width: int):
    return [k for k in (512, 1024, 2048) if k % width == 0]


class TestAESCMACEasyRoundtripAcrossNonceSizes(unittest.TestCase):
    def test_all(self):
        plaintext = secrets.token_bytes(1024)
        for n in NONCE_SIZES:
            for hash_name, _ in AESCMAC_HASHES:
                with self.subTest(nonce=n, hash=hash_name):
                    with itb.Encryptor(hash_name, 1024, "kmac256", mode=1) as enc:
                        enc.set_nonce_bits(n)
                        ct = enc.encrypt(plaintext)
                        pt = enc.decrypt(ct)
                        self.assertEqual(pt, plaintext)


class TestAESCMACEasyTripleRoundtripAcrossNonceSizes(unittest.TestCase):
    def test_all(self):
        plaintext = secrets.token_bytes(1024)
        for n in NONCE_SIZES:
            for hash_name, _ in AESCMAC_HASHES:
                with self.subTest(nonce=n, hash=hash_name):
                    with itb.Encryptor(hash_name, 1024, "kmac256", mode=3) as enc:
                        enc.set_nonce_bits(n)
                        ct = enc.encrypt(plaintext)
                        pt = enc.decrypt(ct)
                        self.assertEqual(pt, plaintext)


class TestAESCMACEasyAuthAcrossNonceSizes(unittest.TestCase):
    def test_all(self):
        plaintext = secrets.token_bytes(1024)
        for n in NONCE_SIZES:
            for mac_name in ("kmac256", "hmac-sha256", "hmac-blake3"):
                for hash_name, _ in AESCMAC_HASHES:
                    with self.subTest(nonce=n, mac=mac_name, hash=hash_name):
                        with itb.Encryptor(hash_name, 1024, mac_name, mode=1) as enc:
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
                                cm.exception.code,
                                itb._ffi.STATUS_MAC_FAILURE,
                            )


class TestAESCMACEasyTripleAuthAcrossNonceSizes(unittest.TestCase):
    def test_all(self):
        plaintext = secrets.token_bytes(1024)
        for n in NONCE_SIZES:
            for mac_name in ("kmac256", "hmac-sha256", "hmac-blake3"):
                for hash_name, _ in AESCMAC_HASHES:
                    with self.subTest(nonce=n, mac=mac_name, hash=hash_name):
                        with itb.Encryptor(hash_name, 1024, mac_name, mode=3) as enc:
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
                                cm.exception.code,
                                itb._ffi.STATUS_MAC_FAILURE,
                            )


class TestAESCMACEasyPersistenceAcrossNonceSizes(unittest.TestCase):
    def test_roundtrip(self):
        plaintext = b"persistence payload " + secrets.token_bytes(1024)

        for hash_name, width in AESCMAC_HASHES:
            for key_bits in _key_bits_for(width):
                for n in NONCE_SIZES:
                    with self.subTest(hash=hash_name, key_bits=key_bits, nonce=n):
                        src = itb.Encryptor(hash_name, key_bits, "kmac256", mode=1)
                        src.set_nonce_bits(n)
                        self.assertEqual(
                            len(src.prf_key(0)), EXPECTED_KEY_LEN[hash_name],
                        )
                        self.assertEqual(
                            len(src.seed_components(0)) * 64, key_bits,
                        )
                        blob = src.export()
                        ct = src.encrypt(plaintext)
                        src.free()

                        dst = itb.Encryptor(hash_name, key_bits, "kmac256", mode=1)
                        dst.set_nonce_bits(n)
                        dst.import_state(blob)
                        pt = dst.decrypt(ct)
                        self.assertEqual(pt, plaintext)
                        dst.free()


class TestAESCMACEasyRoundtripSizes(unittest.TestCase):
    def test_sizes(self):
        for hash_name, _ in AESCMAC_HASHES:
            for n in NONCE_SIZES:
                for sz in (1, 17, 4096, 65536, 1 << 20):
                    with self.subTest(hash=hash_name, nonce=n, size=sz):
                        plaintext = secrets.token_bytes(sz)
                        with itb.Encryptor(hash_name, 1024, "kmac256") as enc:
                            enc.set_nonce_bits(n)
                            ct = enc.encrypt(plaintext)
                            pt = enc.decrypt(ct)
                            self.assertEqual(pt, plaintext)


if __name__ == "__main__":
    unittest.main(verbosity=2)
