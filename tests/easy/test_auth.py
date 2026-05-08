"""End-to-end Encryptor tests for Authenticated Encryption.

Symmetric counterpart to bindings/python/tests/test_auth.py. Same
matrix (3 MACs × 3 hash widths × {Single, Triple} round trip plus
tamper rejection) applied to the high-level :class:`itb.Encryptor`
surface.

The cross-MAC rejection cases (different MAC primitive or different
MAC key on encrypt vs decrypt) are realised here by Export-ing the
sender's state and Import-ing it into a receiver constructed with
the wrong MAC primitive — but Import enforces matching primitive /
key_bits / mode / mac and refuses the swap with EasyMismatchError,
so the cross-MAC case becomes a structural-rejection test instead
of a runtime MAC verification miss. The same security guarantee is
covered by tampering the MAC bytes inside the ciphertext (header-
adjacent flip) which is the Encryptor-level analogue.
"""

import secrets
import sys
import unittest
from pathlib import Path

HERE = Path(__file__).resolve()
sys.path.insert(0, str(HERE.parents[2]))

import itb  # noqa: E402


CANONICAL_MACS = [
    ("kmac256", 32, 32, 16),
    ("hmac-sha256", 32, 32, 16),
    ("hmac-blake3", 32, 32, 32),
]

HASH_BY_WIDTH = [
    ("siphash24", 128),
    ("blake3", 256),
    ("blake2b512", 512),
]


class TestAuthEasyRoundtrip(unittest.TestCase):
    """Single Ouroboros (mode=1) + Auth: 3 MACs × 3 hash widths."""

    def test_all_macs_all_widths(self):
        plaintext = secrets.token_bytes(4096)
        for mac_name, _, _, _ in CANONICAL_MACS:
            for hash_name, _ in HASH_BY_WIDTH:
                with self.subTest(mac=mac_name, hash=hash_name):
                    with itb.Encryptor(hash_name, 1024, mac_name, mode=1) as enc:
                        ct = enc.encrypt_auth(plaintext)
                        pt = enc.decrypt_auth(ct)
                        self.assertEqual(pt, plaintext)

                        # Tamper: flip 256 bytes past the dynamic header.
                        tampered = bytearray(ct)
                        h = enc.header_size
                        for i in range(h, min(h + 256, len(tampered))):
                            tampered[i] ^= 0x01
                        with self.assertRaises(itb.ITBError) as cm:
                            enc.decrypt_auth(bytes(tampered))
                        self.assertEqual(
                            cm.exception.code, itb._ffi.STATUS_MAC_FAILURE,
                        )


class TestAuthEasyTripleRoundtrip(unittest.TestCase):
    """Triple Ouroboros (mode=3) + Auth: 3 MACs × 3 hash widths."""

    def test_all_macs_all_widths(self):
        plaintext = secrets.token_bytes(4096)
        for mac_name, _, _, _ in CANONICAL_MACS:
            for hash_name, _ in HASH_BY_WIDTH:
                with self.subTest(mac=mac_name, hash=hash_name):
                    with itb.Encryptor(hash_name, 1024, mac_name, mode=3) as enc:
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


class TestAuthEasyCrossMACRejection(unittest.TestCase):
    """Cross-MAC rejection at the structural level: an exported
    state blob carries the encryptor's MAC primitive name; Import
    on a receiver constructed with a different MAC primitive
    surfaces :class:`itb.EasyMismatchError` with field='mac' rather
    than a runtime MAC verification miss.

    For runtime MAC failure on the same MAC primitive / different
    key, see :class:`TestAuthEasyDifferentKeyRejection` below."""

    def test_different_primitive(self):
        with itb.Encryptor("blake3", 1024, "kmac256", mode=1) as src:
            blob = src.export()
        # Receiver with hmac-sha256 — Import must reject on field=mac.
        with itb.Encryptor("blake3", 1024, "hmac-sha256", mode=1) as dst:
            with self.assertRaises(itb.EasyMismatchError) as cm:
                dst.import_state(blob)
            self.assertEqual(cm.exception.field, "mac")
            self.assertEqual(cm.exception.code, itb._ffi.STATUS_EASY_MISMATCH)


class TestAuthEasyDifferentKeyRejection(unittest.TestCase):
    """Same-primitive different-key MAC failure at the runtime level.
    Encrypt with one encryptor, attempt decrypt with a separately
    constructed encryptor (same primitive / key_bits / mode / mac
    but with its own random MAC key) — STATUS_MAC_FAILURE rather
    than a corrupted plaintext."""

    def test_same_primitive_different_key(self):
        plaintext = b"authenticated payload"
        with itb.Encryptor("blake3", 1024, "hmac-sha256", mode=1) as enc1, \
             itb.Encryptor("blake3", 1024, "hmac-sha256", mode=1) as enc2:
            # Day 1: encrypt with enc1's seeds and MAC key.
            blob1 = enc1.export()
            ct = enc1.encrypt_auth(plaintext)
            # Day 2: enc2 has its own (different) seed/MAC keys.
            # Decrypt the ct under enc2 — same primitive matrix but
            # different keying material → MAC verification failure.
            with self.assertRaises(itb.ITBError) as cm:
                enc2.decrypt_auth(ct)
            # Without restoring blob1 into enc2, decrypt_auth fails
            # at MAC verification (the keys differ on every dimension).
            self.assertEqual(
                cm.exception.code, itb._ffi.STATUS_MAC_FAILURE,
            )


if __name__ == "__main__":
    unittest.main(verbosity=2)
