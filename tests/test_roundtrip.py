"""End-to-end Python binding tests over libitb.so.

Run from repo root after building the shared library:

    go build -trimpath -buildmode=c-shared -o dist/linux-amd64/libitb.so ./cmd/cshared
    python -m pytest bindings/python/tests/

The tests exercise the same surface as cmd/cshared/ctest/test_smoke.c
plus a few Python-level idioms (context manager, exception classes,
bytearray / memoryview inputs).
"""

import os
import secrets
import sys
import unittest
from pathlib import Path

# Allow running from repo root without `pip install -e bindings/python`.
HERE = Path(__file__).resolve()
sys.path.insert(0, str(HERE.parents[1]))

import itb  # noqa: E402


CANONICAL_HASHES = [
    ("areion256", 256),
    ("areion512", 512),
    ("siphash24", 128),
    ("aescmac", 128),
    ("blake2b256", 256),
    ("blake2b512", 512),
    ("blake2s", 256),
    ("blake3", 256),
    ("chacha20", 256),
]


class TestIntrospection(unittest.TestCase):
    def test_version(self):
        v = itb.version()
        self.assertTrue(v)
        self.assertRegex(v, r"^\d+\.\d+\.\d+")

    def test_list_hashes(self):
        got = itb.list_hashes()
        self.assertEqual(got, CANONICAL_HASHES)

    def test_constants(self):
        self.assertEqual(itb.max_key_bits(), 2048)
        self.assertEqual(itb.channels(), 8)


class TestSeedLifecycle(unittest.TestCase):
    def test_new_and_free(self):
        s = itb.Seed("blake3", 1024)
        self.assertNotEqual(s.handle, 0)
        self.assertEqual(s.hash_name, "blake3")
        self.assertEqual(s.width, 256)
        s.free()
        self.assertEqual(s.handle, 0)

    def test_context_manager(self):
        with itb.Seed("areion256", 1024) as s:
            self.assertNotEqual(s.handle, 0)
        self.assertEqual(s.handle, 0)

    def test_double_free_idempotent(self):
        # Python wrapper deliberately makes Seed.free() idempotent:
        # it zeros the internal handle on the first call, so a second
        # call is a no-op rather than an error.
        s = itb.Seed("blake3", 1024)
        s.free()
        s.free()  # must not raise
        self.assertEqual(s.handle, 0)

    def test_bad_hash(self):
        with self.assertRaises(itb.ITBError) as cm:
            itb.Seed("nonsense-hash", 1024)
        self.assertEqual(cm.exception.code, itb._ffi.STATUS_BAD_HASH)

    def test_bad_key_bits(self):
        for bits in (0, 256, 511, 2049):
            with self.subTest(bits=bits):
                with self.assertRaises(itb.ITBError) as cm:
                    itb.Seed("blake3", bits)
                self.assertEqual(cm.exception.code, itb._ffi.STATUS_BAD_KEY_BITS)


class TestRoundtrip(unittest.TestCase):
    def test_all_hashes_all_widths(self):
        plaintext = secrets.token_bytes(4096)
        for name, _ in CANONICAL_HASHES:
            for key_bits in (512, 1024, 2048):
                with self.subTest(hash=name, bits=key_bits):
                    with (
                        itb.Seed(name, key_bits) as ns,
                        itb.Seed(name, key_bits) as ds,
                        itb.Seed(name, key_bits) as ss,
                    ):
                        ct = itb.encrypt(ns, ds, ss, plaintext)
                        self.assertGreater(len(ct), len(plaintext))
                        pt = itb.decrypt(ns, ds, ss, ct)
                        self.assertEqual(pt, plaintext)

    def test_bytearray_input(self):
        with (
            itb.Seed("blake3", 1024) as ns,
            itb.Seed("blake3", 1024) as ds,
            itb.Seed("blake3", 1024) as ss,
        ):
            payload = bytearray(b"hello bytearray")
            ct = itb.encrypt(ns, ds, ss, payload)
            pt = itb.decrypt(ns, ds, ss, ct)
            self.assertEqual(pt, bytes(payload))

    def test_memoryview_input(self):
        with (
            itb.Seed("blake3", 1024) as ns,
            itb.Seed("blake3", 1024) as ds,
            itb.Seed("blake3", 1024) as ss,
        ):
            payload = memoryview(b"hello memoryview view view view")
            ct = itb.encrypt(ns, ds, ss, payload)
            pt = itb.decrypt(ns, ds, ss, ct)
            self.assertEqual(pt, bytes(payload))

    def test_seed_width_mismatch(self):
        with (
            itb.Seed("siphash24", 1024) as ns,   # width 128
            itb.Seed("blake3", 1024) as ds,      # width 256
            itb.Seed("blake3", 1024) as ss,      # width 256
        ):
            with self.assertRaises(itb.ITBError) as cm:
                itb.encrypt(ns, ds, ss, b"hello")
            self.assertEqual(cm.exception.code, itb._ffi.STATUS_SEED_WIDTH_MIX)


class TestTripleRoundtrip(unittest.TestCase):
    """Triple Ouroboros end-to-end via ITB_Encrypt3 / ITB_Decrypt3."""

    def _seven(self, name, key_bits):
        return [itb.Seed(name, key_bits) for _ in range(7)]

    def _free(self, seeds):
        for s in seeds:
            s.free()

    def test_all_hashes_all_widths(self):
        plaintext = secrets.token_bytes(4096)
        for name, _ in CANONICAL_HASHES:
            for key_bits in (512, 1024, 2048):
                with self.subTest(hash=name, bits=key_bits):
                    seeds = self._seven(name, key_bits)
                    try:
                        ct = itb.encrypt_triple(*seeds, plaintext)
                        self.assertGreater(len(ct), len(plaintext))
                        pt = itb.decrypt_triple(*seeds, ct)
                        self.assertEqual(pt, plaintext)
                    finally:
                        self._free(seeds)

    def test_triple_seed_width_mismatch(self):
        # Mix one width-128 seed with six width-256 seeds — must
        # be rejected with STATUS_SEED_WIDTH_MIX.
        odd = itb.Seed("siphash24", 1024)
        rest = [itb.Seed("blake3", 1024) for _ in range(6)]
        try:
            with self.assertRaises(itb.ITBError) as cm:
                itb.encrypt_triple(odd, *rest, b"hello")
            self.assertEqual(cm.exception.code, itb._ffi.STATUS_SEED_WIDTH_MIX)
        finally:
            odd.free()
            for s in rest:
                s.free()


class TestConfig(unittest.TestCase):
    def test_bit_soup_roundtrip(self):
        orig = itb.get_bit_soup()
        try:
            itb.set_bit_soup(1)
            self.assertEqual(itb.get_bit_soup(), 1)
            itb.set_bit_soup(0)
            self.assertEqual(itb.get_bit_soup(), 0)
        finally:
            itb.set_bit_soup(orig)

    def test_lock_soup_roundtrip(self):
        orig = itb.get_lock_soup()
        try:
            itb.set_lock_soup(1)
            self.assertEqual(itb.get_lock_soup(), 1)
        finally:
            itb.set_lock_soup(orig)

    def test_max_workers_roundtrip(self):
        orig = itb.get_max_workers()
        try:
            itb.set_max_workers(4)
            self.assertEqual(itb.get_max_workers(), 4)
        finally:
            itb.set_max_workers(orig)

    def test_nonce_bits_validation(self):
        orig = itb.get_nonce_bits()
        try:
            for valid in (128, 256, 512):
                itb.set_nonce_bits(valid)
                self.assertEqual(itb.get_nonce_bits(), valid)
            for bad in (0, 1, 192, 1024):
                with self.subTest(bad=bad):
                    with self.assertRaises(itb.ITBError) as cm:
                        itb.set_nonce_bits(bad)
                    self.assertEqual(cm.exception.code, itb._ffi.STATUS_BAD_INPUT)
        finally:
            itb.set_nonce_bits(orig)

    def test_barrier_fill_validation(self):
        orig = itb.get_barrier_fill()
        try:
            for valid in (1, 2, 4, 8, 16, 32):
                itb.set_barrier_fill(valid)
                self.assertEqual(itb.get_barrier_fill(), valid)
            for bad in (0, 3, 5, 7, 64):
                with self.subTest(bad=bad):
                    with self.assertRaises(itb.ITBError) as cm:
                        itb.set_barrier_fill(bad)
                    self.assertEqual(cm.exception.code, itb._ffi.STATUS_BAD_INPUT)
        finally:
            itb.set_barrier_fill(orig)


if __name__ == "__main__":
    unittest.main(verbosity=2)
