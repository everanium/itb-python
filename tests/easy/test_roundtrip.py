"""End-to-end Python binding tests for the high-level
:class:`itb.Encryptor` surface (the github.com/everanium/itb/easy
sub-package wrapper).

Run from repo root after building the shared library:

    go build -trimpath -buildmode=c-shared -o dist/linux-amd64/libitb.so ./cmd/cshared
    python -m pytest bindings/python/tests/easy/

Mirrors the structure of bindings/python/tests/test_roundtrip.py (the
low-level ``itb.Seed`` / ``itb.encrypt`` / ``itb.decrypt`` path)
adapted to the one-handle, per-instance-config Encryptor API.
"""

import secrets
import sys
import unittest
from pathlib import Path

# Allow running from repo root without `pip install -e bindings/python`.
HERE = Path(__file__).resolve()
sys.path.insert(0, str(HERE.parents[2]))

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


def _key_bits_for(width: int):
    """Iterates over the three ITB key-bit widths that are valid for
    a given native hash width — multiples of width in [512, 2048]."""
    return [k for k in (512, 1024, 2048) if k % width == 0]


class TestEncryptorLifecycle(unittest.TestCase):
    def test_new_and_free(self):
        enc = itb.Encryptor("blake3", 1024, "kmac256")
        self.assertNotEqual(enc.handle, 0)
        self.assertEqual(enc.primitive, "blake3")
        self.assertEqual(enc.key_bits, 1024)
        self.assertEqual(enc.mode, 1)
        self.assertEqual(enc.mac_name, "kmac256")
        enc.free()
        self.assertEqual(enc.handle, 0)

    def test_context_manager(self):
        with itb.Encryptor("areion256", 1024, "kmac256") as enc:
            self.assertNotEqual(enc.handle, 0)
        self.assertEqual(enc.handle, 0)

    def test_double_free_idempotent(self):
        enc = itb.Encryptor("blake3", 1024, "kmac256")
        enc.free()
        enc.free()  # must not raise
        self.assertEqual(enc.handle, 0)

    def test_close_then_method_raises(self):
        enc = itb.Encryptor("blake3", 1024, "kmac256")
        enc.close()
        with self.assertRaises(itb.ITBError) as cm:
            enc.encrypt(b"after close")
        self.assertEqual(cm.exception.code, itb._ffi.STATUS_EASY_CLOSED)
        enc.free()

    def test_defaults(self):
        # Empty primitive / 0 keyBits / empty mac select package
        # defaults: areion512 / 1024 / hmac-blake3 (the latter via the
        # binding-side override that maps ``mac=None`` to the
        # lightest-overhead MAC available in the Easy Mode surface).
        with itb.Encryptor() as enc:
            self.assertEqual(enc.primitive, "areion512")
            self.assertEqual(enc.key_bits, 1024)
            self.assertEqual(enc.mode, 1)
            self.assertEqual(enc.mac_name, "hmac-blake3")

    def test_bad_primitive(self):
        with self.assertRaises(itb.ITBError):
            itb.Encryptor("nonsense-hash", 1024, "kmac256")

    def test_bad_mac(self):
        with self.assertRaises(itb.ITBError):
            itb.Encryptor("blake3", 1024, "nonsense-mac")

    def test_bad_key_bits(self):
        for bits in (256, 511, 999, 2049):
            with self.subTest(bits=bits):
                with self.assertRaises(itb.ITBError):
                    itb.Encryptor("blake3", bits, "kmac256")

    def test_bad_mode(self):
        with self.assertRaises(itb.ITBError):
            itb.Encryptor("blake3", 1024, "kmac256", mode=2)


class TestRoundtripSingle(unittest.TestCase):
    """Single Ouroboros (mode=1, 3 seeds) end-to-end across every
    primitive at every supported ITB key width."""

    def test_all_hashes_all_widths(self):
        plaintext = secrets.token_bytes(4096)
        for name, width in CANONICAL_HASHES:
            for key_bits in _key_bits_for(width):
                with self.subTest(hash=name, bits=key_bits):
                    with itb.Encryptor(name, key_bits, "kmac256", mode=1) as enc:
                        ct = enc.encrypt(plaintext)
                        self.assertGreater(len(ct), len(plaintext))
                        pt = enc.decrypt(ct)
                        self.assertEqual(pt, plaintext)

    def test_all_hashes_all_widths_auth(self):
        plaintext = secrets.token_bytes(4096)
        for name, width in CANONICAL_HASHES:
            for key_bits in _key_bits_for(width):
                with self.subTest(hash=name, bits=key_bits):
                    with itb.Encryptor(name, key_bits, "kmac256", mode=1) as enc:
                        ct = enc.encrypt_auth(plaintext)
                        pt = enc.decrypt_auth(ct)
                        self.assertEqual(pt, plaintext)

    def test_bytearray_input(self):
        with itb.Encryptor("blake3", 1024, "kmac256") as enc:
            payload = bytearray(b"hello bytearray")
            ct = enc.encrypt(payload)
            pt = enc.decrypt(ct)
            self.assertEqual(pt, bytes(payload))

    def test_memoryview_input(self):
        with itb.Encryptor("blake3", 1024, "kmac256") as enc:
            payload = memoryview(b"hello memoryview view view view")
            ct = enc.encrypt(payload)
            pt = enc.decrypt(ct)
            self.assertEqual(pt, bytes(payload))

class TestRoundtripTriple(unittest.TestCase):
    """Triple Ouroboros (mode=3, 7 seeds) end-to-end across every
    primitive at every supported ITB key width."""

    def test_all_hashes_all_widths(self):
        plaintext = secrets.token_bytes(4096)
        for name, width in CANONICAL_HASHES:
            for key_bits in _key_bits_for(width):
                with self.subTest(hash=name, bits=key_bits):
                    with itb.Encryptor(name, key_bits, "kmac256", mode=3) as enc:
                        ct = enc.encrypt(plaintext)
                        self.assertGreater(len(ct), len(plaintext))
                        pt = enc.decrypt(ct)
                        self.assertEqual(pt, plaintext)

    def test_all_hashes_all_widths_auth(self):
        plaintext = secrets.token_bytes(4096)
        for name, width in CANONICAL_HASHES:
            for key_bits in _key_bits_for(width):
                with self.subTest(hash=name, bits=key_bits):
                    with itb.Encryptor(name, key_bits, "kmac256", mode=3) as enc:
                        ct = enc.encrypt_auth(plaintext)
                        pt = enc.decrypt_auth(ct)
                        self.assertEqual(pt, plaintext)

    def test_seed_count_reflects_mode(self):
        with itb.Encryptor("blake3", 1024, "kmac256", mode=1) as enc:
            self.assertEqual(enc.seed_count, 3)
        with itb.Encryptor("blake3", 1024, "kmac256", mode=3) as enc:
            self.assertEqual(enc.seed_count, 7)


class TestConfigPerInstance(unittest.TestCase):
    """Per-instance configuration setters mutate only the specific
    encryptor's Config copy; process-wide setters are unaffected."""

    def test_set_bit_soup(self):
        with itb.Encryptor("blake3", 1024, "kmac256") as enc:
            # No exception means accepted; behavioural verification
            # is downstream (round-trip still works).
            enc.set_bit_soup(1)
            ct = enc.encrypt(b"bit-soup payload")
            pt = enc.decrypt(ct)
            self.assertEqual(pt, b"bit-soup payload")

    def test_set_lock_soup_couples_bit_soup(self):
        # Activating LockSoup auto-couples BitSoup=1 on the same
        # encryptor; verify by round-tripping a known plaintext.
        with itb.Encryptor("blake3", 1024, "kmac256") as enc:
            enc.set_lock_soup(1)
            ct = enc.encrypt(b"lock-soup payload")
            pt = enc.decrypt(ct)
            self.assertEqual(pt, b"lock-soup payload")

    def test_set_lock_seed_grows_seed_count(self):
        with itb.Encryptor("blake3", 1024, "kmac256", mode=1) as enc:
            self.assertEqual(enc.seed_count, 3)
            enc.set_lock_seed(1)
            self.assertEqual(enc.seed_count, 4)
            ct = enc.encrypt(b"lockseed payload")
            pt = enc.decrypt(ct)
            self.assertEqual(pt, b"lockseed payload")

    def test_set_lock_seed_after_encrypt_rejected(self):
        with itb.Encryptor("blake3", 1024, "kmac256") as enc:
            enc.encrypt(b"first")
            with self.assertRaises(itb.ITBError) as cm:
                enc.set_lock_seed(1)
            self.assertEqual(
                cm.exception.code,
                itb._ffi.STATUS_EASY_LOCKSEED_AFTER_ENCRYPT,
            )

    def test_set_nonce_bits_validation(self):
        with itb.Encryptor("blake3", 1024, "kmac256") as enc:
            for valid in (128, 256, 512):
                enc.set_nonce_bits(valid)  # must not raise
            for bad in (0, 1, 192, 1024):
                with self.subTest(bad=bad):
                    with self.assertRaises(itb.ITBError) as cm:
                        enc.set_nonce_bits(bad)
                    self.assertEqual(cm.exception.code, itb._ffi.STATUS_BAD_INPUT)

    def test_set_barrier_fill_validation(self):
        with itb.Encryptor("blake3", 1024, "kmac256") as enc:
            for valid in (1, 2, 4, 8, 16, 32):
                enc.set_barrier_fill(valid)  # must not raise
            for bad in (0, 3, 5, 7, 64):
                with self.subTest(bad=bad):
                    with self.assertRaises(itb.ITBError) as cm:
                        enc.set_barrier_fill(bad)
                    self.assertEqual(cm.exception.code, itb._ffi.STATUS_BAD_INPUT)

    def test_set_chunk_size_accepted(self):
        with itb.Encryptor("blake3", 1024, "kmac256") as enc:
            enc.set_chunk_size(1024)  # must not raise
            enc.set_chunk_size(0)     # auto-detect

    def test_two_encryptors_isolated(self):
        # Setting LockSoup on one encryptor must not bleed into
        # another encryptor; per-instance Config snapshots are
        # independent.
        with itb.Encryptor("blake3", 1024, "kmac256") as a, \
             itb.Encryptor("blake3", 1024, "kmac256") as b:
            a.set_lock_soup(1)
            # Round-trip works on both, with different overlay state.
            self.assertEqual(a.decrypt(a.encrypt(b"a")), b"a")
            self.assertEqual(b.decrypt(b.encrypt(b"b")), b"b")


if __name__ == "__main__":
    unittest.main(verbosity=2)
