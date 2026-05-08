"""Cross-process persistence round-trip tests for ITB Python bindings.

The shipped Python API exposes:

    seed.components -> List[int]  (8..32 uint64 elements)
    seed.hash_key   -> bytes      (16 / 32 / 64 bytes; empty for siphash24)
    Seed.from_components(name, components, hash_key=b"") -> Seed

These are the persistence surface required for any deployment where
encrypt and decrypt run in different processes (network, storage,
backup, microservices). Without both ``components`` and ``hash_key``
captured at encrypt-side and re-supplied at decrypt-side, the seed
state cannot be reconstructed and the ciphertext is unreadable.

The tests below simulate that flow end-to-end across every primitive
in the registry × three key-bit widths.
"""

import sys
import unittest
from pathlib import Path

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

EXPECTED_HASH_KEY_LEN = {
    "areion256": 32,
    "areion512": 64,
    "siphash24": 0,  # no internal fixed key — keyed by seed components
    "aescmac": 16,
    "blake2b256": 32,
    "blake2b512": 64,
    "blake2s": 32,
    "blake3": 32,
    "chacha20": 32,
}


def _key_bits_for(width: int):
    """Iterates over the three ITB key-bit widths that are valid for
    a given native hash width — multiples of width in [512, 2048]."""
    return [k for k in (512, 1024, 2048) if k % width == 0]


class TestPersistenceRoundtrip(unittest.TestCase):
    """Encrypt → snapshot (components + hash_key) → free seeds →
    rebuild seeds via Seed.from_components → decrypt successfully.

    Mirrors capi.TestNewSeedFromComponentsRoundtrip on the Go side."""

    def test_roundtrip_all_hashes(self):
        plaintext = b"any binary data, including 0x00 bytes -- " + bytes(range(256))

        for name, width in CANONICAL_HASHES:
            for key_bits in _key_bits_for(width):
                with self.subTest(hash=name, key_bits=key_bits):
                    # Day 1 — random seeds.
                    ns = itb.Seed(name, key_bits)
                    ds = itb.Seed(name, key_bits)
                    ss = itb.Seed(name, key_bits)
                    ns_comps, ns_key = ns.components, ns.hash_key
                    ds_comps, ds_key = ds.components, ds.hash_key
                    ss_comps, ss_key = ss.components, ss.hash_key

                    self.assertEqual(len(ns_comps) * 64, key_bits)
                    self.assertEqual(len(ns_key), EXPECTED_HASH_KEY_LEN[name])

                    ciphertext = itb.encrypt(ns, ds, ss, plaintext)
                    ns.free(); ds.free(); ss.free()

                    # Day 2 — restore from saved material.
                    ns2 = itb.Seed.from_components(name, ns_comps, ns_key)
                    ds2 = itb.Seed.from_components(name, ds_comps, ds_key)
                    ss2 = itb.Seed.from_components(name, ss_comps, ss_key)
                    decrypted = itb.decrypt(ns2, ds2, ss2, ciphertext)
                    self.assertEqual(decrypted, plaintext)

                    # Restored seeds report the same key + components.
                    self.assertEqual(ns2.components, ns_comps)
                    self.assertEqual(ns2.hash_key, ns_key)
                    ns2.free(); ds2.free(); ss2.free()

    def test_random_key_path(self):
        """Pass an empty hash_key — Seed.from_components must generate
        a fresh random key (and report a non-empty hash_key for every
        primitive except SipHash-2-4)."""
        components = [0] * 8  # 512-bit zero key — sufficient for non-SipHash
        for name, _ in CANONICAL_HASHES:
            with self.subTest(hash=name):
                seed = itb.Seed.from_components(name, components, b"")
                key = seed.hash_key
                if name == "siphash24":
                    self.assertEqual(key, b"")
                else:
                    self.assertEqual(len(key), EXPECTED_HASH_KEY_LEN[name])
                seed.free()

    def test_explicit_key_preserved(self):
        """The hash_key bytes returned by from_components(...) match
        the supplied key bit-exact."""
        # Use blake3 — symmetric 32-byte key, easy to assert.
        explicit = bytes(range(32))
        components = [0xCAFEBABE_DEADBEEF] * 8
        seed = itb.Seed.from_components("blake3", components, explicit)
        self.assertEqual(seed.hash_key, explicit)
        seed.free()

    def test_bad_key_size(self):
        """Wrong-size hash_key for a primitive that expects fixed-key
        bytes returns a clean ITBError (no panic across the FFI)."""
        components = [0] * 16  # 1024-bit
        with self.assertRaises(itb.ITBError):
            itb.Seed.from_components("blake3", components, b"\x00" * 7)

    def test_siphash_rejects_hash_key(self):
        """SipHash-2-4 takes no internal fixed key; passing one must
        be rejected (not silently ignored)."""
        components = [0] * 8
        with self.assertRaises(itb.ITBError):
            itb.Seed.from_components("siphash24", components, b"\x00" * 16)


if __name__ == "__main__":
    unittest.main()
