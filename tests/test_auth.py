"""End-to-end Python binding tests for Authenticated Encryption.

Exercises the same matrix as cmd/cshared/ctest/test_smoke.c
auth section: 3 MACs × 3 hash widths × {Single, Triple} round trip
plus tamper rejection. Run from repo root after building libitb.so:

    go build -trimpath -buildmode=c-shared -o dist/linux-amd64/libitb.so ./cmd/cshared
    python -m unittest discover bindings/python/tests
"""

import secrets
import sys
import unittest
from pathlib import Path

HERE = Path(__file__).resolve()
sys.path.insert(0, str(HERE.parents[1]))

import itb  # noqa: E402


CANONICAL_MACS = [
    ("kmac256", 32, 32, 16),
    ("hmac-sha256", 32, 32, 16),
    ("hmac-blake3", 32, 32, 32),
]

# (hash, width) representatives one per ITB key-width axis.
HASH_BY_WIDTH = [
    ("siphash24", 128),
    ("blake3", 256),
    ("blake2b512", 512),
]


class TestMACIntrospection(unittest.TestCase):
    def test_list_macs(self):
        self.assertEqual(itb.list_macs(), CANONICAL_MACS)


class TestMACLifecycle(unittest.TestCase):
    def test_create_and_free(self):
        for name, _, _, _ in CANONICAL_MACS:
            with self.subTest(mac=name):
                key_size = 32
                mac = itb.MAC(name, secrets.token_bytes(key_size))
                self.assertNotEqual(mac.handle, 0)
                self.assertEqual(mac.name, name)
                mac.free()
                self.assertEqual(mac.handle, 0)

    def test_context_manager(self):
        with itb.MAC("hmac-sha256", secrets.token_bytes(32)) as m:
            self.assertNotEqual(m.handle, 0)
        self.assertEqual(m.handle, 0)

    def test_bad_name(self):
        with self.assertRaises(itb.ITBError) as cm:
            itb.MAC("nonsense-mac", secrets.token_bytes(32))
        self.assertEqual(cm.exception.code, itb._ffi.STATUS_BAD_MAC)

    def test_short_key(self):
        for name, _, _, min_key in CANONICAL_MACS:
            with self.subTest(mac=name):
                with self.assertRaises(itb.ITBError) as cm:
                    itb.MAC(name, secrets.token_bytes(min_key - 1))
                self.assertEqual(cm.exception.code, itb._ffi.STATUS_BAD_INPUT)


class TestAuthRoundtrip(unittest.TestCase):
    """Single-Ouroboros + Auth: 3 MACs × 3 hash widths."""

    def test_all_macs_all_widths(self):
        plaintext = secrets.token_bytes(4096)
        for mac_name, _, _, _ in CANONICAL_MACS:
            for hash_name, _ in HASH_BY_WIDTH:
                with self.subTest(mac=mac_name, hash=hash_name):
                    mac = itb.MAC(mac_name, secrets.token_bytes(32))
                    seeds = [itb.Seed(hash_name, 1024) for _ in range(3)]
                    try:
                        ct = itb.encrypt_auth(*seeds, mac, plaintext)
                        pt = itb.decrypt_auth(*seeds, mac, ct)
                        self.assertEqual(pt, plaintext)

                        # Tamper: flip 256 bytes after the dynamic header.
                        tampered = bytearray(ct)
                        h = itb.header_size()
                        for i in range(h, min(h + 256, len(tampered))):
                            tampered[i] ^= 0x01
                        with self.assertRaises(itb.ITBError) as cm:
                            itb.decrypt_auth(*seeds, mac, bytes(tampered))
                        self.assertEqual(cm.exception.code, itb._ffi.STATUS_MAC_FAILURE)
                    finally:
                        mac.free()
                        for s in seeds:
                            s.free()


class TestAuthTripleRoundtrip(unittest.TestCase):
    """Triple Ouroboros + Auth: 3 MACs × 3 hash widths × 7 seeds."""

    def test_all_macs_all_widths(self):
        plaintext = secrets.token_bytes(4096)
        for mac_name, _, _, _ in CANONICAL_MACS:
            for hash_name, _ in HASH_BY_WIDTH:
                with self.subTest(mac=mac_name, hash=hash_name):
                    mac = itb.MAC(mac_name, secrets.token_bytes(32))
                    seeds = [itb.Seed(hash_name, 1024) for _ in range(7)]
                    try:
                        ct = itb.encrypt_auth_triple(*seeds, mac, plaintext)
                        pt = itb.decrypt_auth_triple(*seeds, mac, ct)
                        self.assertEqual(pt, plaintext)

                        tampered = bytearray(ct)
                        h = itb.header_size()
                        for i in range(h, min(h + 256, len(tampered))):
                            tampered[i] ^= 0x01
                        with self.assertRaises(itb.ITBError) as cm:
                            itb.decrypt_auth_triple(*seeds, mac, bytes(tampered))
                        self.assertEqual(cm.exception.code, itb._ffi.STATUS_MAC_FAILURE)
                    finally:
                        mac.free()
                        for s in seeds:
                            s.free()


class TestAuthCrossMACRejection(unittest.TestCase):
    """Encrypt under one MAC, attempt decrypt with a different MAC
    handle (different primitive or different key) — must surface
    STATUS_MAC_FAILURE rather than corrupting the plaintext."""

    def test_different_primitive(self):
        seeds = [itb.Seed("blake3", 1024) for _ in range(3)]
        enc_mac = itb.MAC("kmac256", secrets.token_bytes(32))
        dec_mac = itb.MAC("hmac-sha256", secrets.token_bytes(32))
        try:
            ct = itb.encrypt_auth(*seeds, enc_mac, b"authenticated payload")
            with self.assertRaises(itb.ITBError) as cm:
                itb.decrypt_auth(*seeds, dec_mac, ct)
            self.assertEqual(cm.exception.code, itb._ffi.STATUS_MAC_FAILURE)
        finally:
            enc_mac.free()
            dec_mac.free()
            for s in seeds:
                s.free()

    def test_same_primitive_different_key(self):
        seeds = [itb.Seed("blake3", 1024) for _ in range(3)]
        enc_mac = itb.MAC("hmac-sha256", secrets.token_bytes(32))
        dec_mac = itb.MAC("hmac-sha256", secrets.token_bytes(32))
        try:
            ct = itb.encrypt_auth(*seeds, enc_mac, b"authenticated payload")
            with self.assertRaises(itb.ITBError) as cm:
                itb.decrypt_auth(*seeds, dec_mac, ct)
            self.assertEqual(cm.exception.code, itb._ffi.STATUS_MAC_FAILURE)
        finally:
            enc_mac.free()
            dec_mac.free()
            for s in seeds:
                s.free()


if __name__ == "__main__":
    unittest.main(verbosity=2)
