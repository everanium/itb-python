"""Native-Blob round-trip tests for the itb Python binding.

Mirror of blob_test.go (Go-side) and capi_blob_test.go (capi-side):
exercises the same Single / Triple × LockSeed × MAC × non-default
globals matrix through the ITB_Blob_* C ABI surface, plus the three
typed error paths (mode mismatch, malformed JSON, version too new).

The blob captures the sender's process-wide configuration (NonceBits
/ BarrierFill / BitSoup / LockSoup) at export time and applies it
unconditionally on import, so each test case toggles the four globals
to non-default values, exports, resets to defaults, imports, and
verifies the restored state — same shape as the Go-side tests.
"""

import json
import os
import sys
import unittest
from pathlib import Path

HERE = Path(__file__).resolve()
sys.path.insert(0, str(HERE.parents[1]))

import itb  # noqa: E402
from itb import (  # noqa: E402
    Blob128,
    Blob256,
    Blob512,
    BlobMalformedError,
    BlobModeMismatchError,
    BlobVersionTooNewError,
    Seed,
    MAC,
)


def _with_globals(test):
    """Decorator: snapshot the four globals on entry, set non-default
    values for the test body, restore on exit. Mirrors withGlobals
    from blob_test.go."""

    def wrapper(self, *args, **kwargs):
        prev = (
            itb.get_nonce_bits(),
            itb.get_barrier_fill(),
            itb.get_bit_soup(),
            itb.get_lock_soup(),
        )
        itb.set_nonce_bits(512)
        itb.set_barrier_fill(4)
        itb.set_bit_soup(1)
        itb.set_lock_soup(1)
        try:
            return test(self, *args, **kwargs)
        finally:
            itb.set_nonce_bits(prev[0])
            itb.set_barrier_fill(prev[1])
            itb.set_bit_soup(prev[2])
            itb.set_lock_soup(prev[3])

    return wrapper


def _reset_globals():
    """Forces all four globals to their defaults so an Import-applied
    snapshot can be detected via post-Import reads."""
    itb.set_nonce_bits(128)
    itb.set_barrier_fill(1)
    itb.set_bit_soup(0)
    itb.set_lock_soup(0)


def _assert_globals_restored(self, nonce, barrier, bit_soup, lock_soup):
    self.assertEqual(itb.get_nonce_bits(), nonce, "NonceBits not restored")
    self.assertEqual(itb.get_barrier_fill(), barrier, "BarrierFill not restored")
    self.assertEqual(itb.get_bit_soup(), bit_soup, "BitSoup not restored")
    self.assertEqual(itb.get_lock_soup(), lock_soup, "LockSoup not restored")


class TestBlobBasics(unittest.TestCase):
    """Smoke tests — construction, properties, free/double-free."""

    def test_construct_each_width(self):
        for cls, expected_width in [
            (Blob128, 128),
            (Blob256, 256),
            (Blob512, 512),
        ]:
            with self.subTest(cls=cls.__name__):
                b = cls()
                self.assertEqual(b.width, expected_width)
                self.assertEqual(b.mode, 0)
                self.assertNotEqual(b.handle, 0)
                b.free()

    def test_double_free_idempotent(self):
        b = Blob512()
        b.free()
        b.free()  # must not raise

    def test_context_manager(self):
        with Blob512() as b:
            self.assertEqual(b.width, 512)
        # The handle is freed; further use would raise BadHandle.
        with self.assertRaises(itb.ITBError):
            b.width


# ───────────────────────────────────────────────────────────────────
# Blob512 — Areion-SoEM-512 round-trip via Python wrapper
# ───────────────────────────────────────────────────────────────────


class TestBlob512SingleRoundtripFullMatrix(unittest.TestCase):
    """Single Ouroboros — 4 cases (lockseed × mac), each restoring
    a working decrypt path from the imported state."""

    @_with_globals
    def test_full_matrix(self):
        plaintext = b"py blob512 single round-trip payload"
        for with_ls in (False, True):
            for with_mac in (False, True):
                with self.subTest(lockseed=with_ls, mac=with_mac):
                    self._roundtrip("areion512", 2048, plaintext, with_ls, with_mac)

    def _roundtrip(self, primitive, key_bits, plaintext, with_ls, with_mac):
        ns = Seed(primitive, key_bits)
        ds = Seed(primitive, key_bits)
        ss = Seed(primitive, key_bits)

        ls = None
        if with_ls:
            ls = Seed(primitive, key_bits)
            ns.attach_lock_seed(ls)

        mac_key = os.urandom(32) if with_mac else None
        mac = MAC("kmac256", mac_key) if with_mac else None

        if with_mac:
            ct = itb.encrypt_auth(ns, ds, ss, mac, plaintext)
        else:
            ct = itb.encrypt(ns, ds, ss, plaintext)

        # Sender — populate handle + export.
        with Blob512() as src:
            src.set_key("n", ns.hash_key)
            src.set_key("d", ds.hash_key)
            src.set_key("s", ss.hash_key)
            src.set_components("n", ns.components)
            src.set_components("d", ds.components)
            src.set_components("s", ss.components)
            if with_ls:
                src.set_key("l", ls.hash_key)
                src.set_components("l", ls.components)
            if with_mac:
                src.set_mac_key(mac_key)
                src.set_mac_name("kmac256")

            blob = src.export(lockseed=with_ls, mac=with_mac)

        # Receiver — reset globals, import, rebuild seeds, decrypt.
        _reset_globals()
        with Blob512() as dst:
            dst.import_blob(blob)
            self.assertEqual(dst.mode, 1)
            _assert_globals_restored(self, 512, 4, 1, 1)

            ns2 = Seed.from_components(primitive, dst.get_components("n"),
                                       hash_key=dst.get_key("n"))
            ds2 = Seed.from_components(primitive, dst.get_components("d"),
                                       hash_key=dst.get_key("d"))
            ss2 = Seed.from_components(primitive, dst.get_components("s"),
                                       hash_key=dst.get_key("s"))
            if with_ls:
                ls2 = Seed.from_components(primitive, dst.get_components("l"),
                                           hash_key=dst.get_key("l"))
                ns2.attach_lock_seed(ls2)

            mac2 = None
            if with_mac:
                self.assertEqual(dst.get_mac_name(), "kmac256")
                self.assertEqual(dst.get_mac_key(), mac_key)
                mac2 = MAC("kmac256", dst.get_mac_key())

            if with_mac:
                pt = itb.decrypt_auth(ns2, ds2, ss2, mac2, ct)
            else:
                pt = itb.decrypt(ns2, ds2, ss2, ct)
            self.assertEqual(pt, plaintext)


class TestBlob512TripleRoundtripFullMatrix(unittest.TestCase):
    """Triple Ouroboros — same matrix, decrypt_triple path."""

    @_with_globals
    def test_full_matrix(self):
        plaintext = b"py blob512 triple round-trip payload"
        for with_ls in (False, True):
            for with_mac in (False, True):
                with self.subTest(lockseed=with_ls, mac=with_mac):
                    self._roundtrip(plaintext, with_ls, with_mac)

    def _roundtrip(self, plaintext, with_ls, with_mac):
        primitive, key_bits = "areion512", 2048
        ns = Seed(primitive, key_bits)
        ds1 = Seed(primitive, key_bits)
        ds2 = Seed(primitive, key_bits)
        ds3 = Seed(primitive, key_bits)
        ss1 = Seed(primitive, key_bits)
        ss2 = Seed(primitive, key_bits)
        ss3 = Seed(primitive, key_bits)

        ls = None
        if with_ls:
            ls = Seed(primitive, key_bits)
            ns.attach_lock_seed(ls)

        mac_key = os.urandom(32) if with_mac else None
        mac = MAC("kmac256", mac_key) if with_mac else None

        if with_mac:
            ct = itb.encrypt_auth_triple(ns, ds1, ds2, ds3, ss1, ss2, ss3, mac, plaintext)
        else:
            ct = itb.encrypt_triple(ns, ds1, ds2, ds3, ss1, ss2, ss3, plaintext)

        with Blob512() as src:
            for slot, seed in (("n", ns), ("d1", ds1), ("d2", ds2), ("d3", ds3),
                               ("s1", ss1), ("s2", ss2), ("s3", ss3)):
                src.set_key(slot, seed.hash_key)
                src.set_components(slot, seed.components)
            if with_ls:
                src.set_key("l", ls.hash_key)
                src.set_components("l", ls.components)
            if with_mac:
                src.set_mac_key(mac_key)
                src.set_mac_name("kmac256")
            blob = src.export3(lockseed=with_ls, mac=with_mac)

        _reset_globals()
        with Blob512() as dst:
            dst.import_triple(blob)
            self.assertEqual(dst.mode, 3)
            _assert_globals_restored(self, 512, 4, 1, 1)

            seeds = {}
            for slot in ("n", "d1", "d2", "d3", "s1", "s2", "s3"):
                seeds[slot] = Seed.from_components(
                    primitive, dst.get_components(slot),
                    hash_key=dst.get_key(slot))
            if with_ls:
                ls2 = Seed.from_components(primitive, dst.get_components("l"),
                                           hash_key=dst.get_key("l"))
                seeds["n"].attach_lock_seed(ls2)

            mac2 = MAC("kmac256", dst.get_mac_key()) if with_mac else None

            if with_mac:
                pt = itb.decrypt_auth_triple(
                    seeds["n"], seeds["d1"], seeds["d2"], seeds["d3"],
                    seeds["s1"], seeds["s2"], seeds["s3"], mac2, ct)
            else:
                pt = itb.decrypt_triple(
                    seeds["n"], seeds["d1"], seeds["d2"], seeds["d3"],
                    seeds["s1"], seeds["s2"], seeds["s3"], ct)
            self.assertEqual(pt, plaintext)


# ───────────────────────────────────────────────────────────────────
# Blob256 — BLAKE3 round-trip
# ───────────────────────────────────────────────────────────────────


class TestBlob256Roundtrip(unittest.TestCase):
    @_with_globals
    def test_single(self):
        plaintext = b"py blob256 single round-trip"
        ns = Seed("blake3", 1024)
        ds = Seed("blake3", 1024)
        ss = Seed("blake3", 1024)
        ct = itb.encrypt(ns, ds, ss, plaintext)

        with Blob256() as src:
            for slot, seed in (("n", ns), ("d", ds), ("s", ss)):
                src.set_key(slot, seed.hash_key)
                src.set_components(slot, seed.components)
            blob = src.export()

        _reset_globals()
        with Blob256() as dst:
            dst.import_blob(blob)
            self.assertEqual(dst.mode, 1)
            ns2 = Seed.from_components("blake3", dst.get_components("n"),
                                       hash_key=dst.get_key("n"))
            ds2 = Seed.from_components("blake3", dst.get_components("d"),
                                       hash_key=dst.get_key("d"))
            ss2 = Seed.from_components("blake3", dst.get_components("s"),
                                       hash_key=dst.get_key("s"))
            self.assertEqual(itb.decrypt(ns2, ds2, ss2, ct), plaintext)

    @_with_globals
    def test_triple(self):
        plaintext = b"py blob256 triple round-trip"
        seeds = [Seed("blake3", 1024) for _ in range(7)]
        ct = itb.encrypt_triple(*seeds, plaintext)

        slot_names = ("n", "d1", "d2", "d3", "s1", "s2", "s3")
        with Blob256() as src:
            for slot, seed in zip(slot_names, seeds):
                src.set_key(slot, seed.hash_key)
                src.set_components(slot, seed.components)
            blob = src.export3()

        _reset_globals()
        with Blob256() as dst:
            dst.import_triple(blob)
            self.assertEqual(dst.mode, 3)
            seeds2 = [
                Seed.from_components("blake3", dst.get_components(slot),
                                     hash_key=dst.get_key(slot))
                for slot in slot_names
            ]
            self.assertEqual(itb.decrypt_triple(*seeds2, ct), plaintext)


# ───────────────────────────────────────────────────────────────────
# Blob128 — siphash24 (no key) and aescmac (16-byte key)
# ───────────────────────────────────────────────────────────────────


class TestBlob128Roundtrip(unittest.TestCase):
    @_with_globals
    def test_siphash_single(self):
        plaintext = b"py blob128 siphash round-trip"
        ns = Seed("siphash24", 512)
        ds = Seed("siphash24", 512)
        ss = Seed("siphash24", 512)
        ct = itb.encrypt(ns, ds, ss, plaintext)

        with Blob128() as src:
            for slot, seed in (("n", ns), ("d", ds), ("s", ss)):
                src.set_key(slot, seed.hash_key)  # empty bytes
                src.set_components(slot, seed.components)
            blob = src.export()

        _reset_globals()
        with Blob128() as dst:
            dst.import_blob(blob)
            ns2 = Seed.from_components("siphash24", dst.get_components("n"))
            ds2 = Seed.from_components("siphash24", dst.get_components("d"))
            ss2 = Seed.from_components("siphash24", dst.get_components("s"))
            self.assertEqual(itb.decrypt(ns2, ds2, ss2, ct), plaintext)

    @_with_globals
    def test_aescmac_single(self):
        plaintext = b"py blob128 aescmac round-trip"
        ns = Seed("aescmac", 512)
        ds = Seed("aescmac", 512)
        ss = Seed("aescmac", 512)
        ct = itb.encrypt(ns, ds, ss, plaintext)

        with Blob128() as src:
            for slot, seed in (("n", ns), ("d", ds), ("s", ss)):
                src.set_key(slot, seed.hash_key)
                src.set_components(slot, seed.components)
            blob = src.export()

        _reset_globals()
        with Blob128() as dst:
            dst.import_blob(blob)
            ns2 = Seed.from_components("aescmac", dst.get_components("n"),
                                       hash_key=dst.get_key("n"))
            ds2 = Seed.from_components("aescmac", dst.get_components("d"),
                                       hash_key=dst.get_key("d"))
            ss2 = Seed.from_components("aescmac", dst.get_components("s"),
                                       hash_key=dst.get_key("s"))
            self.assertEqual(itb.decrypt(ns2, ds2, ss2, ct), plaintext)


# ───────────────────────────────────────────────────────────────────
# Slot-naming surface (string / int parity)
# ───────────────────────────────────────────────────────────────────


class TestBlobSlotIdentifiers(unittest.TestCase):
    def test_string_and_int_slots_equivalent(self):
        b = Blob512()
        try:
            key = os.urandom(64)
            comps = [0xDEADBEEFCAFEBABE] * 8
            b.set_key("n", key)
            b.set_components("n", comps)
            self.assertEqual(b.get_key(0), key)  # 0 == BlobSlotN
            self.assertEqual(b.get_components(0), comps)
        finally:
            b.free()

    def test_invalid_slot_name(self):
        b = Blob512()
        try:
            with self.assertRaises(ValueError):
                b.set_key("nope", b"\x00" * 64)
        finally:
            b.free()


# ───────────────────────────────────────────────────────────────────
# Error paths — mode mismatch, malformed, version too new
# ───────────────────────────────────────────────────────────────────


class TestBlobErrors(unittest.TestCase):
    @_with_globals
    def test_mode_mismatch(self):
        ns = Seed("areion512", 1024)
        ds = Seed("areion512", 1024)
        ss = Seed("areion512", 1024)
        with Blob512() as src:
            for slot, seed in (("n", ns), ("d", ds), ("s", ss)):
                src.set_key(slot, seed.hash_key)
                src.set_components(slot, seed.components)
            blob = src.export()

        with Blob512() as dst:
            with self.assertRaises(BlobModeMismatchError):
                dst.import_triple(blob)

    def test_malformed(self):
        with Blob512() as b:
            with self.assertRaises(BlobMalformedError):
                b.import_blob(b"{not json")

    def test_version_too_new(self):
        doc = {
            "v": 99,
            "mode": 1,
            "key_bits": 512,
            "key_n": "00" * 64,
            "key_d": "00" * 64,
            "key_s": "00" * 64,
            "ns": ["0"] * 8,
            "ds": ["0"] * 8,
            "ss": ["0"] * 8,
            "globals": {
                "nonce_bits": 128,
                "barrier_fill": 1,
                "bit_soup": 0,
                "lock_soup": 0,
            },
        }
        data = json.dumps(doc).encode("utf-8")
        with Blob512() as b:
            with self.assertRaises(BlobVersionTooNewError):
                b.import_blob(data)


if __name__ == "__main__":
    unittest.main()
