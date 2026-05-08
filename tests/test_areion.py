"""Areion-SoEM-focused Python binding coverage.

Symmetric counterpart to test_blake2b.py: the same coverage shape
(nonce-size sweep, single + triple roundtrip, single + triple auth
with tamper rejection, persistence sweep, plaintext-size sweep)
applied to areion256 / areion512. Areion's batched arm has been
shipped longer than BLAKE2b's, but the sibling test_nonce_sizes /
test_auth files happened to pick non-Areion representatives for the
width-256 / width-512 buckets, so dedicated Areion coverage at those
axes did not exist until now.

What this file adds beyond the parametrised iterators in the sibling
test files:

  * areion256 + areion512 coverage across all three SetNonceBits
    values (sibling test_nonce_sizes iterates blake3 + blake2b512 +
    siphash24).
  * areion256 + areion512 authenticated round-trip including tamper
    rejection at the dynamic header offset (sibling test_auth picks
    blake3 + blake2b512 + siphash24).
  * areion256 + areion512 persistence round-trip cycling nonce_bits
    across all three values inside a single test — the Areion-SoEM
    ASM kernels are length-specialised at 20 / 36 / 68 byte buf
    shapes, so the full sweep surfaces any drift between encrypt-time
    and decrypt-time nonce_bits configuration.

Run from repo root after building libitb.so:

    go build -trimpath -buildmode=c-shared -o dist/linux-amd64/libitb.so ./cmd/cshared
    python -m pytest bindings/python/tests/test_areion.py
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
    """Process-wide nonce_bits brackets — restored on exit."""
    orig = itb.get_nonce_bits()
    itb.set_nonce_bits(n)
    try:
        yield
    finally:
        itb.set_nonce_bits(orig)


# (hash, ITB_seed_width) — both Areion-SoEM widths. The width feeds
# into Seed.from_components key-validation later in this file.
AREION_HASHES = [
    ("areion256", 256),
    ("areion512", 512),
]

# Hash-key length (bytes) per primitive — locks in the FFI-surfaced
# contract that Areion-SoEM-256 carries a 32-byte fixed key and
# Areion-SoEM-512 carries a 64-byte fixed key. Mirrors
# EXPECTED_HASH_KEY_LEN in test_persistence.py.
EXPECTED_KEY_LEN = {
    "areion256": 32,
    "areion512": 64,
}

NONCE_SIZES = (128, 256, 512)


class TestAreionRoundtripAcrossNonceSizes(unittest.TestCase):
    """Single-Ouroboros encrypt/decrypt over areion256 + areion512
    × all three nonce sizes. The four-pixel-batched VAES kernel runs
    a length-specialised path at 20 / 36 / 68 bytes; the loop below
    drives every shape through the FFI surface."""

    def test_all(self):
        plaintext = secrets.token_bytes(1024)
        for n in NONCE_SIZES:
            for hash_name, _ in AREION_HASHES:
                with self.subTest(nonce=n, hash=hash_name):
                    with nonce_bits(n):
                        seeds = [itb.Seed(hash_name, 1024) for _ in range(3)]
                        try:
                            ct = itb.encrypt(*seeds, plaintext)
                            pt = itb.decrypt(*seeds, ct)
                            self.assertEqual(pt, plaintext)
                            self.assertEqual(
                                itb.parse_chunk_len(ct[: itb.header_size()]),
                                len(ct),
                            )
                        finally:
                            for s in seeds:
                                s.free()


class TestAreionTripleRoundtripAcrossNonceSizes(unittest.TestCase):
    """Triple-Ouroboros (7 seeds) encrypt/decrypt over areion256 +
    areion512 × all three nonce sizes."""

    def test_all(self):
        plaintext = secrets.token_bytes(1024)
        for n in NONCE_SIZES:
            for hash_name, _ in AREION_HASHES:
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


class TestAreionAuthAcrossNonceSizes(unittest.TestCase):
    """Single + Auth round trip + tamper rejection over areion256 +
    areion512 × all three nonce sizes. Each MAC primitive is paired
    with each Areion width to confirm the auth scaffolding is
    width-agnostic."""

    def test_all(self):
        plaintext = secrets.token_bytes(1024)
        for n in NONCE_SIZES:
            for mac_name in ("kmac256", "hmac-sha256", "hmac-blake3"):
                for hash_name, _ in AREION_HASHES:
                    with self.subTest(nonce=n, mac=mac_name, hash=hash_name):
                        with nonce_bits(n):
                            mac = itb.MAC(mac_name, secrets.token_bytes(32))
                            seeds = [itb.Seed(hash_name, 1024) for _ in range(3)]
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
                                    itb.decrypt_auth(
                                        *seeds, mac, bytes(tampered)
                                    )
                                self.assertEqual(
                                    cm.exception.code,
                                    itb._ffi.STATUS_MAC_FAILURE,
                                )
                            finally:
                                mac.free()
                                for s in seeds:
                                    s.free()


class TestAreionTripleAuthAcrossNonceSizes(unittest.TestCase):
    """Triple + Auth (7 seeds) round trip + tamper rejection over
    areion256 + areion512 × all three nonce sizes."""

    def test_all(self):
        plaintext = secrets.token_bytes(1024)
        for n in NONCE_SIZES:
            for mac_name in ("kmac256", "hmac-sha256", "hmac-blake3"):
                for hash_name, _ in AREION_HASHES:
                    with self.subTest(nonce=n, mac=mac_name, hash=hash_name):
                        with nonce_bits(n):
                            mac = itb.MAC(mac_name, secrets.token_bytes(32))
                            seeds = [itb.Seed(hash_name, 1024) for _ in range(7)]
                            try:
                                ct = itb.encrypt_auth_triple(
                                    *seeds, mac, plaintext
                                )
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
                                    cm.exception.code,
                                    itb._ffi.STATUS_MAC_FAILURE,
                                )
                            finally:
                                mac.free()
                                for s in seeds:
                                    s.free()


class TestAreionPersistenceAcrossNonceSizes(unittest.TestCase):
    """Encrypt with areion → snapshot (components + hash_key) → free
    seeds → reconstruct via Seed.from_components → decrypt → verify
    plaintext is bit-identical. Each (hash, key_bits, nonce_bits)
    combination must roundtrip — a regression in the Areion-SoEM ASM
    kernel that drifts between original and restored seeds (e.g. a
    mis-seeded fixedKey broadcast) would surface as a decrypt
    mismatch on the day-2 path while leaving the day-1 encrypt path
    silent.
    """

    def test_roundtrip(self):
        plaintext = b"persistence payload " + secrets.token_bytes(1024)

        for hash_name, width in AREION_HASHES:
            valid_key_bits = [k for k in (512, 1024, 2048) if k % width == 0]
            for key_bits in valid_key_bits:
                for n in NONCE_SIZES:
                    with self.subTest(hash=hash_name, key_bits=key_bits, nonce=n):
                        with nonce_bits(n):
                            # Day 1 — random seeds.
                            ns = itb.Seed(hash_name, key_bits)
                            ds = itb.Seed(hash_name, key_bits)
                            ss = itb.Seed(hash_name, key_bits)
                            try:
                                ns_comps, ns_key = ns.components, ns.hash_key
                                ds_comps, ds_key = ds.components, ds.hash_key
                                ss_comps, ss_key = ss.components, ss.hash_key

                                self.assertEqual(
                                    len(ns_key), EXPECTED_KEY_LEN[hash_name]
                                )
                                self.assertEqual(len(ns_comps) * 64, key_bits)

                                ciphertext = itb.encrypt(ns, ds, ss, plaintext)
                            finally:
                                ns.free(); ds.free(); ss.free()

                            # Day 2 — restore from saved material.
                            ns2 = itb.Seed.from_components(
                                hash_name, ns_comps, ns_key
                            )
                            ds2 = itb.Seed.from_components(
                                hash_name, ds_comps, ds_key
                            )
                            ss2 = itb.Seed.from_components(
                                hash_name, ss_comps, ss_key
                            )
                            try:
                                decrypted = itb.decrypt(
                                    ns2, ds2, ss2, ciphertext
                                )
                                self.assertEqual(decrypted, plaintext)
                            finally:
                                ns2.free(); ds2.free(); ss2.free()


class TestAreionRoundtripSizes(unittest.TestCase):
    """Roundtrip areion256/areion512 on plaintext sizes that span
    multiple chunk boundaries. ITB's processChunk batches 4 pixels
    per BatchHash call; trailing partial batches must dispatch via
    the per-lane fallback, and the test surfaces any boundary bug
    where the batched arm runs on incomplete lane data."""

    def test_sizes(self):
        for hash_name, _ in AREION_HASHES:
            for n in NONCE_SIZES:
                for sz in (1, 17, 4096, 65536, 1 << 20):
                    with self.subTest(hash=hash_name, nonce=n, size=sz):
                        with nonce_bits(n):
                            plaintext = secrets.token_bytes(sz)
                            ns = itb.Seed(hash_name, 1024)
                            ds = itb.Seed(hash_name, 1024)
                            ss = itb.Seed(hash_name, 1024)
                            try:
                                ct = itb.encrypt(ns, ds, ss, plaintext)
                                pt = itb.decrypt(ns, ds, ss, ct)
                                self.assertEqual(pt, plaintext)
                            finally:
                                ns.free(); ds.free(); ss.free()


if __name__ == "__main__":
    unittest.main(verbosity=2)
