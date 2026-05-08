"""Round-trip tests across all nonce-size configurations.

ITB exposes a runtime-configurable nonce size (set_nonce_bits) that
takes one of {128, 256, 512}. The on-the-wire chunk header therefore
varies between 20, 36, and 68 bytes; every consumer that walks
ciphertext on the byte level (chunk parsers, tampering tests,
streaming decoders) must use itb.header_size() rather than a
hardcoded constant.

This file exhaustively covers the FFI surface under each nonce
configuration:
  - one-shot encrypt / decrypt (single + triple);
  - authenticated encrypt / decrypt (single + triple), including
    tamper rejection at the dynamic header offset;
  - parse_chunk_len reporting the right chunk length.

Each test snapshots the original nonce setting on entry and
restores it on exit so subsequent suites run unaffected.
"""

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


NONCE_SIZES = (128, 256, 512)


class TestHeaderSizeTracksNonceBits(unittest.TestCase):
    def test_default_is_20(self):
        self.assertEqual(itb.header_size(), 20)
        self.assertEqual(itb.get_nonce_bits(), 128)

    def test_dynamic(self):
        for n in NONCE_SIZES:
            with self.subTest(nonce=n):
                with nonce_bits(n):
                    self.assertEqual(itb.header_size(), n // 8 + 4)


class TestEncryptDecryptAcrossNonceSizes(unittest.TestCase):
    """Single one-shot encrypt/decrypt over all three nonce sizes."""

    def test_all(self):
        plaintext = secrets.token_bytes(1024)
        for n in NONCE_SIZES:
            for hash_name in ("siphash24", "blake3", "blake2b512"):
                with self.subTest(nonce=n, hash=hash_name):
                    with nonce_bits(n):
                        seeds = [itb.Seed(hash_name, 1024) for _ in range(3)]
                        try:
                            ct = itb.encrypt(*seeds, plaintext)
                            pt = itb.decrypt(*seeds, ct)
                            self.assertEqual(pt, plaintext)
                            # parse_chunk_len must report the full chunk.
                            self.assertEqual(
                                itb.parse_chunk_len(ct[: itb.header_size()]),
                                len(ct),
                            )
                        finally:
                            for s in seeds:
                                s.free()


class TestTripleEncryptDecryptAcrossNonceSizes(unittest.TestCase):
    """Triple one-shot (7-seed) encrypt/decrypt over all three nonces."""

    def test_all(self):
        plaintext = secrets.token_bytes(1024)
        for n in NONCE_SIZES:
            for hash_name in ("siphash24", "blake3", "blake2b512"):
                with self.subTest(nonce=n, hash=hash_name):
                    with nonce_bits(n):
                        seeds = [itb.Seed(hash_name, 1024) for _ in range(7)]
                        try:
                            ct = itb.encrypt_triple(*seeds, plaintext)
                            pt = itb.decrypt_triple(*seeds, ct)
                            self.assertEqual(pt, plaintext)
                        finally:
                            for s in seeds:
                                s.free()


class TestAuthAcrossNonceSizes(unittest.TestCase):
    """Single + Auth round trip + tamper rejection at dynamic header."""

    def test_all(self):
        plaintext = secrets.token_bytes(1024)
        for n in NONCE_SIZES:
            for mac_name in ("kmac256", "hmac-sha256", "hmac-blake3"):
                with self.subTest(nonce=n, mac=mac_name):
                    with nonce_bits(n):
                        mac = itb.MAC(mac_name, secrets.token_bytes(32))
                        seeds = [itb.Seed("blake3", 1024) for _ in range(3)]
                        try:
                            ct = itb.encrypt_auth(*seeds, mac, plaintext)
                            pt = itb.decrypt_auth(*seeds, mac, ct)
                            self.assertEqual(pt, plaintext)
                            # Tamper at the dynamic header offset.
                            tampered = bytearray(ct)
                            h = itb.header_size()
                            for i in range(h, min(h + 256, len(tampered))):
                                tampered[i] ^= 0x01
                            with self.assertRaises(itb.ITBError) as cm:
                                itb.decrypt_auth(*seeds, mac, bytes(tampered))
                            self.assertEqual(
                                cm.exception.code, itb._ffi.STATUS_MAC_FAILURE
                            )
                        finally:
                            mac.free()
                            for s in seeds:
                                s.free()


class TestTripleAuthAcrossNonceSizes(unittest.TestCase):
    """Triple + Auth round trip + tamper rejection at dynamic header."""

    def test_all(self):
        plaintext = secrets.token_bytes(1024)
        for n in NONCE_SIZES:
            for mac_name in ("kmac256", "hmac-sha256", "hmac-blake3"):
                with self.subTest(nonce=n, mac=mac_name):
                    with nonce_bits(n):
                        mac = itb.MAC(mac_name, secrets.token_bytes(32))
                        seeds = [itb.Seed("blake3", 1024) for _ in range(7)]
                        try:
                            ct = itb.encrypt_auth_triple(*seeds, mac, plaintext)
                            pt = itb.decrypt_auth_triple(*seeds, mac, ct)
                            self.assertEqual(pt, plaintext)
                            tampered = bytearray(ct)
                            h = itb.header_size()
                            for i in range(h, min(h + 256, len(tampered))):
                                tampered[i] ^= 0x01
                            with self.assertRaises(itb.ITBError) as cm:
                                itb.decrypt_auth_triple(
                                    *seeds, mac, bytes(tampered)
                                )
                            self.assertEqual(
                                cm.exception.code, itb._ffi.STATUS_MAC_FAILURE
                            )
                        finally:
                            mac.free()
                            for s in seeds:
                                s.free()


if __name__ == "__main__":
    unittest.main(verbosity=2)
