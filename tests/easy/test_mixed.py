"""Mixed-mode Encryptor (per-slot PRF primitive selection) tests for
the itb Python binding. Mirrors the Go-side easy.NewMixed /
easy.NewMixed3 coverage: round-trip on Single + Triple, optional
dedicated lockSeed under its own primitive, state-blob
Export / Import, mixed-width rejection through the cgo boundary,
and the per-slot introspection accessors (primitive_at, is_mixed).
"""

import os
import sys
import unittest
from pathlib import Path

HERE = Path(__file__).resolve()
sys.path.insert(0, str(HERE.parents[2]))

import itb  # noqa: E402


class TestMixedSingle(unittest.TestCase):
    """Single Ouroboros mixed-mode round-trips."""

    def test_basic_roundtrip(self):
        enc = itb.Encryptor.mixed_single(
            primitive_n="blake3",
            primitive_d="blake2s",
            primitive_s="areion256",
            primitive_l=None,
            key_bits=1024,
            mac="kmac256",
        )
        try:
            self.assertTrue(enc.is_mixed)
            self.assertEqual(enc.primitive, "mixed")
            self.assertEqual(enc.primitive_at(0), "blake3")
            self.assertEqual(enc.primitive_at(1), "blake2s")
            self.assertEqual(enc.primitive_at(2), "areion256")

            plaintext = b"py mixed Single roundtrip payload"
            ct = enc.encrypt(plaintext)
            self.assertEqual(enc.decrypt(ct), plaintext)
        finally:
            enc.close()

    def test_with_dedicated_lockseed(self):
        enc = itb.Encryptor.mixed_single(
            primitive_n="blake3",
            primitive_d="blake2s",
            primitive_s="blake3",
            primitive_l="areion256",
            key_bits=1024,
            mac="kmac256",
        )
        try:
            self.assertEqual(enc.primitive_at(3), "areion256")
            plaintext = b"py mixed Single + dedicated lockSeed payload"
            ct = enc.encrypt_auth(plaintext)
            self.assertEqual(enc.decrypt_auth(ct), plaintext)
        finally:
            enc.close()

    def test_aescmac_siphash_mix_128bit(self):
        """SipHash24 in one slot + AES-CMAC in others — 128-bit
        width with mixed key shapes (siphash carries no fixed key
        bytes, aescmac carries 16). Exercises the per-slot empty
        / non-empty PRF-key validation in Export / Import."""
        enc = itb.Encryptor.mixed_single(
            primitive_n="aescmac",
            primitive_d="siphash24",
            primitive_s="aescmac",
            primitive_l=None,
            key_bits=512,
            mac="hmac-sha256",
        )
        try:
            plaintext = b"py mixed 128-bit aescmac+siphash24 mix"
            ct = enc.encrypt(plaintext)
            self.assertEqual(enc.decrypt(ct), plaintext)
        finally:
            enc.close()


class TestMixedTriple(unittest.TestCase):
    """Triple Ouroboros mixed-mode round-trips."""

    def test_basic_roundtrip(self):
        enc = itb.Encryptor.mixed_triple(
            primitive_n="areion256",
            primitive_d1="blake3",
            primitive_d2="blake2s",
            primitive_d3="chacha20",
            primitive_s1="blake2b256",
            primitive_s2="blake3",
            primitive_s3="blake2s",
            primitive_l=None,
            key_bits=1024,
            mac="kmac256",
        )
        try:
            wants = ["areion256", "blake3", "blake2s", "chacha20",
                     "blake2b256", "blake3", "blake2s"]
            for i, w in enumerate(wants):
                self.assertEqual(enc.primitive_at(i), w)
            plaintext = b"py mixed Triple roundtrip payload"
            ct = enc.encrypt(plaintext)
            self.assertEqual(enc.decrypt(ct), plaintext)
        finally:
            enc.close()

    def test_with_dedicated_lockseed(self):
        enc = itb.Encryptor.mixed_triple(
            primitive_n="blake3",
            primitive_d1="blake2s",
            primitive_d2="blake3",
            primitive_d3="blake2s",
            primitive_s1="blake3",
            primitive_s2="blake2s",
            primitive_s3="blake3",
            primitive_l="areion256",
            key_bits=1024,
            mac="kmac256",
        )
        try:
            self.assertEqual(enc.primitive_at(7), "areion256")
            plaintext = b"py mixed Triple + lockSeed payload" * 16
            ct = enc.encrypt_auth(plaintext)
            self.assertEqual(enc.decrypt_auth(ct), plaintext)
        finally:
            enc.close()


class TestMixedExportImport(unittest.TestCase):
    """State-blob Export / Import round-trips on mixed-mode
    encryptors. The per-slot primitive list rides through the
    blob's ``primitives`` array; receiver constructs a matching
    encryptor first, then Imports."""

    def test_single_export_import(self):
        kwargs = dict(
            primitive_n="blake3",
            primitive_d="blake2s",
            primitive_s="areion256",
            primitive_l=None,
            key_bits=1024,
            mac="kmac256",
        )
        sender = itb.Encryptor.mixed_single(**kwargs)
        try:
            plaintext = os.urandom(2048)
            ct = sender.encrypt_auth(plaintext)
            blob = sender.export()
            self.assertGreater(len(blob), 0)
        finally:
            sender.close()

        receiver = itb.Encryptor.mixed_single(**kwargs)
        try:
            receiver.import_state(blob)
            self.assertEqual(receiver.decrypt_auth(ct), plaintext)
        finally:
            receiver.close()

    def test_triple_export_import_with_lockseed(self):
        kwargs = dict(
            primitive_n="areion256",
            primitive_d1="blake3",
            primitive_d2="blake2s",
            primitive_d3="chacha20",
            primitive_s1="blake2b256",
            primitive_s2="blake3",
            primitive_s3="blake2s",
            primitive_l="areion256",
            key_bits=1024,
            mac="kmac256",
        )
        sender = itb.Encryptor.mixed_triple(**kwargs)
        try:
            plaintext = b"py mixed Triple + lockSeed Export/Import" * 16
            ct = sender.encrypt_auth(plaintext)
            blob = sender.export()
        finally:
            sender.close()

        receiver = itb.Encryptor.mixed_triple(**kwargs)
        try:
            receiver.import_state(blob)
            self.assertEqual(receiver.decrypt_auth(ct), plaintext)
        finally:
            receiver.close()

    def test_shape_mismatch(self):
        """Mixed blob landing on a single-primitive receiver — and
        the reverse — must be rejected as a primitive mismatch."""
        mixed_kwargs = dict(
            primitive_n="blake3",
            primitive_d="blake2s",
            primitive_s="blake3",
            primitive_l=None,
            key_bits=1024,
            mac="kmac256",
        )
        mixed_sender = itb.Encryptor.mixed_single(**mixed_kwargs)
        try:
            mixed_blob = mixed_sender.export()
        finally:
            mixed_sender.close()

        single_recv = itb.Encryptor("blake3", 1024, "kmac256")
        try:
            with self.assertRaises(itb.ITBError):
                single_recv.import_state(mixed_blob)
        finally:
            single_recv.close()


class TestMixedRejection(unittest.TestCase):
    """Validation paths through the cgo boundary."""

    def test_reject_mixed_width(self):
        """Mixing a 256-bit primitive with a 512-bit primitive
        surfaces as ITBError (panic-to-Status path on the Go side)."""
        with self.assertRaises(itb.ITBError):
            _ = itb.Encryptor.mixed_single(
                primitive_n="blake3",      # 256-bit
                primitive_d="areion512",   # 512-bit ← width mismatch
                primitive_s="blake3",
                primitive_l=None,
                key_bits=1024,
                mac="kmac256",
            )

    def test_reject_unknown_primitive(self):
        with self.assertRaises(itb.ITBError):
            _ = itb.Encryptor.mixed_single(
                primitive_n="no-such-primitive",
                primitive_d="blake3",
                primitive_s="blake3",
                primitive_l=None,
                key_bits=1024,
                mac="kmac256",
            )


class TestMixedNonMixed(unittest.TestCase):
    """Single-primitive [Encryptor] still reports is_mixed = False
    and uniform primitive_at across slots."""

    def test_default_constructor_is_not_mixed(self):
        enc = itb.Encryptor("blake3", 1024, "kmac256")
        try:
            self.assertFalse(enc.is_mixed)
            for i in range(3):
                self.assertEqual(enc.primitive_at(i), "blake3")
        finally:
            enc.close()


if __name__ == "__main__":
    unittest.main()
