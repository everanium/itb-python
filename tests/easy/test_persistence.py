"""Cross-process persistence round-trip tests for the high-level
:class:`itb.Encryptor` surface.

The :meth:`Encryptor.export` / :meth:`Encryptor.import_state` /
:func:`itb.peek_config` triplet is the persistence surface required
for any deployment where encrypt and decrypt run in different
processes (network, storage, backup, microservices). Without the
JSON-encoded blob captured at encrypt-side and re-supplied at
decrypt-side, the encryptor state cannot be reconstructed and the
ciphertext is unreadable.

Mirrors the structure of bindings/python/tests/test_persistence.py
(the low-level ``Seed.from_components`` / ``hash_key`` /
``components`` path) adapted to the one-handle, JSON-blob-state
Encryptor API. The Encryptor blob carries strictly more state than
the low-level path — PRF keys for every seed slot, MAC key, optional
dedicated lockSeed material, plus the structural metadata
(primitive / key_bits / mode / mac).
"""

import sys
import unittest
from pathlib import Path

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

EXPECTED_PRF_KEY_LEN = {
    "areion256": 32,
    "areion512": 64,
    "siphash24": 0,
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
    """Encrypt → export → free → fresh Encryptor → import → decrypt
    successfully. Mirrors capi.TestEasyExportImportRoundtrip on the
    Go side and bindings/python/tests/test_persistence.py on the
    low-level binding side."""

    def test_roundtrip_all_hashes_single(self):
        plaintext = b"any binary data, including 0x00 bytes -- " + bytes(range(256))

        for name, width in CANONICAL_HASHES:
            for key_bits in _key_bits_for(width):
                with self.subTest(hash=name, key_bits=key_bits):
                    # Day 1 — random encryptor.
                    src = itb.Encryptor(name, key_bits, "kmac256", mode=1)
                    blob = src.export()
                    ct = src.encrypt_auth(plaintext)
                    src.free()

                    # Day 2 — restore from saved blob.
                    dst = itb.Encryptor(name, key_bits, "kmac256", mode=1)
                    dst.import_state(blob)
                    pt = dst.decrypt_auth(ct)
                    self.assertEqual(pt, plaintext)
                    dst.free()

    def test_roundtrip_all_hashes_triple(self):
        plaintext = b"triple-mode persistence payload " + bytes(range(64))

        for name, width in CANONICAL_HASHES:
            for key_bits in _key_bits_for(width):
                with self.subTest(hash=name, key_bits=key_bits):
                    src = itb.Encryptor(name, key_bits, "kmac256", mode=3)
                    blob = src.export()
                    ct = src.encrypt_auth(plaintext)
                    src.free()

                    dst = itb.Encryptor(name, key_bits, "kmac256", mode=3)
                    dst.import_state(blob)
                    pt = dst.decrypt_auth(ct)
                    self.assertEqual(pt, plaintext)
                    dst.free()

    def test_roundtrip_with_lock_seed(self):
        """Activating LockSeed grows the encryptor to 4 (Single) or 8
        (Triple) seed slots; the exported blob carries the dedicated
        lockSeed material via the lock_seed:true field, and
        :meth:`Encryptor.import_state` on a fresh encryptor restores
        the seed slot AND auto-couples LockSoup + BitSoup overlays
        (mirroring :meth:`set_lock_seed`'s on-direction coupling).
        Transparent for the binding consumer — no manual overlay
        setter required on the receiver side."""
        plaintext = b"lockseed payload " + bytes(range(32))

        for mode, expected_count in ((1, 4), (3, 8)):
            with self.subTest(mode=mode):
                src = itb.Encryptor("blake3", 1024, "kmac256", mode=mode)
                src.set_lock_seed(1)
                self.assertEqual(src.seed_count, expected_count)
                blob = src.export()
                ct = src.encrypt_auth(plaintext)
                src.free()

                dst = itb.Encryptor("blake3", 1024, "kmac256", mode=mode)
                self.assertEqual(dst.seed_count, expected_count - 1)
                dst.import_state(blob)
                self.assertEqual(dst.seed_count, expected_count)
                pt = dst.decrypt_auth(ct)
                self.assertEqual(pt, plaintext)
                dst.free()

    def test_roundtrip_with_full_config(self):
        """Per-instance configuration knobs (NonceBits, BarrierFill,
        BitSoup, LockSoup) round-trip through the state blob along
        with the seed material — no manual mirror set_*() calls
        required on the receiver. The blob carries the fields that
        the sender explicitly set; the receiver's :meth:`import_state`
        restores them transparently."""
        plaintext = b"full-config persistence " + bytes(range(64))

        src = itb.Encryptor("blake3", 1024, "kmac256")
        src.set_nonce_bits(512)
        src.set_barrier_fill(4)
        src.set_bit_soup(1)
        src.set_lock_soup(1)
        blob = src.export()
        ct = src.encrypt_auth(plaintext)
        src.free()

        # Receiver — fresh encryptor without any mirror set_*() calls.
        dst = itb.Encryptor("blake3", 1024, "kmac256")
        self.assertEqual(dst.nonce_bits, 128)  # default before Import
        dst.import_state(blob)
        self.assertEqual(dst.nonce_bits, 512)  # restored from blob
        self.assertEqual(dst.header_size, 68)  # follows nonce_bits

        pt = dst.decrypt_auth(ct)
        self.assertEqual(pt, plaintext)
        dst.free()

    def test_roundtrip_barrier_fill_receiver_priority(self):
        """BarrierFill is asymmetric — the receiver does not need the
        same margin as the sender. When the receiver explicitly
        installs a non-default BarrierFill (> 1) before Import, that
        choice takes priority over the blob's barrier_fill, mirroring
        the asymmetric semantics documented on
        :func:`itb.set_barrier_fill`. The receiver round-trips the
        plaintext under its own margin regardless of which value the
        sender used."""
        plaintext = b"barrier-fill priority"

        src = itb.Encryptor("blake3", 1024, "kmac256")
        src.set_barrier_fill(4)
        blob = src.export()
        ct = src.encrypt_auth(plaintext)
        src.free()

        # Receiver pre-sets BarrierFill=8; Import must NOT downgrade
        # it to the blob's 4.
        dst = itb.Encryptor("blake3", 1024, "kmac256")
        dst.set_barrier_fill(8)
        dst.import_state(blob)
        pt = dst.decrypt_auth(ct)
        self.assertEqual(pt, plaintext)
        dst.free()

        # A receiver that did NOT pre-set BarrierFill picks up the
        # blob value transparently.
        dst2 = itb.Encryptor("blake3", 1024, "kmac256")
        dst2.import_state(blob)
        pt2 = dst2.decrypt_auth(ct)
        self.assertEqual(pt2, plaintext)
        dst2.free()


class TestPeekConfig(unittest.TestCase):
    """:func:`itb.peek_config` parses a state blob's metadata
    without performing full validation — the four-tuple
    (primitive, key_bits, mode, mac) lets callers construct a matching
    Encryptor before attempting the full Import."""

    def test_peek_recovers_metadata(self):
        for primitive, _ in CANONICAL_HASHES:
            for key_bits in _key_bits_for(dict(CANONICAL_HASHES)[primitive]):
                for mode in (1, 3):
                    for mac in ("kmac256", "hmac-sha256", "hmac-blake3"):
                        with self.subTest(p=primitive, kb=key_bits, m=mode, mac=mac):
                            with itb.Encryptor(primitive, key_bits, mac, mode=mode) as enc:
                                blob = enc.export()
                            p2, kb2, mode2, mac2 = itb.peek_config(blob)
                            self.assertEqual(p2, primitive)
                            self.assertEqual(kb2, key_bits)
                            self.assertEqual(mode2, mode)
                            self.assertEqual(mac2, mac)

    def test_peek_malformed_blob(self):
        for blob in (b"not json", b"", b"{}", b'{"v":1}'):
            with self.subTest(blob=blob):
                with self.assertRaises(itb.ITBError) as cm:
                    itb.peek_config(blob)
                self.assertEqual(cm.exception.code, itb._ffi.STATUS_EASY_MALFORMED)

    def test_peek_too_new_version(self):
        # Hand-craft a blob with v=99; PeekConfig must reject as
        # too-new rather than silently parsing.
        blob = b'{"v":99,"kind":"itb-easy"}'
        with self.assertRaises(itb.ITBError):
            itb.peek_config(blob)


class TestImportMismatch(unittest.TestCase):
    """Importing a blob whose primitive / key_bits / mode / mac
    disagrees with the receiver Encryptor raises EasyMismatchError
    with the offending field name on .field, NOT generic ITBError."""

    def setUp(self):
        with itb.Encryptor("blake3", 1024, "kmac256", mode=1) as src:
            self.blob = src.export()

    def _expect_mismatch(self, dst: itb.Encryptor, field: str):
        with self.assertRaises(itb.EasyMismatchError) as cm:
            dst.import_state(self.blob)
        self.assertEqual(cm.exception.field, field)
        self.assertEqual(cm.exception.code, itb._ffi.STATUS_EASY_MISMATCH)

    def test_primitive_mismatch(self):
        with itb.Encryptor("blake2s", 1024, "kmac256", mode=1) as dst:
            self._expect_mismatch(dst, "primitive")

    def test_key_bits_mismatch(self):
        with itb.Encryptor("blake3", 2048, "kmac256", mode=1) as dst:
            self._expect_mismatch(dst, "key_bits")

    def test_mode_mismatch(self):
        with itb.Encryptor("blake3", 1024, "kmac256", mode=3) as dst:
            self._expect_mismatch(dst, "mode")

    def test_mac_mismatch(self):
        with itb.Encryptor("blake3", 1024, "hmac-sha256", mode=1) as dst:
            self._expect_mismatch(dst, "mac")


class TestImportMalformed(unittest.TestCase):
    """Distinct status codes for the structural failure modes:
    malformed JSON, too-new version, unknown primitive / MAC, bad
    key_bits."""

    def test_malformed_json(self):
        with itb.Encryptor("blake3", 1024, "kmac256") as enc:
            with self.assertRaises(itb.ITBError) as cm:
                enc.import_state(b"this is not json")
            self.assertEqual(cm.exception.code, itb._ffi.STATUS_EASY_MALFORMED)

    def test_too_new_version(self):
        with itb.Encryptor("blake3", 1024, "kmac256") as enc:
            blob = b'{"v":99,"kind":"itb-easy"}'
            with self.assertRaises(itb.ITBError) as cm:
                enc.import_state(blob)
            self.assertEqual(
                cm.exception.code, itb._ffi.STATUS_EASY_VERSION_TOO_NEW,
            )

    def test_wrong_kind(self):
        with itb.Encryptor("blake3", 1024, "kmac256") as enc:
            blob = b'{"v":1,"kind":"not-itb-easy"}'
            with self.assertRaises(itb.ITBError) as cm:
                enc.import_state(blob)
            self.assertEqual(cm.exception.code, itb._ffi.STATUS_EASY_MALFORMED)


class TestMaterialGetters(unittest.TestCase):
    """The low-level test_persistence.py exercises ``seed.components``
    and ``seed.hash_key`` as the two persistence-relevant accessors;
    the Encryptor surface exposes the same material via
    :meth:`Encryptor.seed_components` (per slot), :meth:`prf_key`
    (per slot), and :attr:`mac_key`. The full state blob is the
    one-shot wrapper, but binding consumers may still want to inspect
    individual slots."""

    def test_prf_key_lengths_per_primitive(self):
        for name, width in CANONICAL_HASHES:
            for key_bits in _key_bits_for(width):
                with self.subTest(hash=name, key_bits=key_bits):
                    with itb.Encryptor(name, key_bits, "kmac256") as enc:
                        if name == "siphash24":
                            self.assertFalse(enc.has_prf_keys)
                            with self.assertRaises(itb.ITBError):
                                enc.prf_key(0)
                        else:
                            self.assertTrue(enc.has_prf_keys)
                            for slot in range(enc.seed_count):
                                key = enc.prf_key(slot)
                                self.assertEqual(
                                    len(key), EXPECTED_PRF_KEY_LEN[name],
                                )

    def test_seed_components_lengths_per_key_bits(self):
        for name, width in CANONICAL_HASHES:
            for key_bits in _key_bits_for(width):
                with self.subTest(hash=name, key_bits=key_bits):
                    with itb.Encryptor(name, key_bits, "kmac256") as enc:
                        for slot in range(enc.seed_count):
                            comps = enc.seed_components(slot)
                            self.assertEqual(len(comps) * 64, key_bits)

    def test_mac_key_present(self):
        # Every shipped MAC primitive returns a non-empty fixed key.
        for mac in ("kmac256", "hmac-sha256", "hmac-blake3"):
            with self.subTest(mac=mac):
                with itb.Encryptor("blake3", 1024, mac) as enc:
                    self.assertGreater(len(enc.mac_key), 0)

    def test_seed_components_out_of_range(self):
        with itb.Encryptor("blake3", 1024, "kmac256", mode=1) as enc:
            self.assertEqual(enc.seed_count, 3)
            with self.assertRaises(itb.ITBError) as cm:
                enc.seed_components(3)
            self.assertEqual(cm.exception.code, itb._ffi.STATUS_BAD_INPUT)
            with self.assertRaises(itb.ITBError) as cm:
                enc.seed_components(-1)
            self.assertEqual(cm.exception.code, itb._ffi.STATUS_BAD_INPUT)


if __name__ == "__main__":
    unittest.main(verbosity=2)
