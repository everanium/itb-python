"""BLAKE3-focused Encryptor coverage.

Symmetric counterpart to bindings/python/tests/test_blake3.py — same
coverage shape (nonce-size sweep, single + triple roundtrip, single
+ triple auth with tamper rejection, persistence sweep, plaintext-
size sweep) applied to the high-level :class:`itb.Encryptor` surface
instead of the lower-level Seed / encrypt / decrypt path.

BLAKE3 ships at a single width (-256) — there is no -512 BLAKE3 in
the registry — so this file iterates the single primitive across
the same axes test_blake2{b,s}.py cover.

Persistence here rides on :meth:`Encryptor.export` /
:meth:`Encryptor.import_state` (JSON blob, single round-trip)
instead of the legacy ``components`` + ``hash_key`` pair captured
per seed slot. The blob captures the strictly larger encryptor
state (PRF keys for every slot, MAC key, optional dedicated
lockSeed material) so the day-2 decrypt path exercises the full
restore.

Run from repo root after building libitb.so:

    go build -trimpath -buildmode=c-shared -o dist/linux-amd64/libitb.so ./cmd/cshared
    python -m pytest bindings/python/tests/easy/test_blake3.py
"""

import secrets
import sys
import unittest
from pathlib import Path

HERE = Path(__file__).resolve()
sys.path.insert(0, str(HERE.parents[2]))

import itb  # noqa: E402


# (hash, ITB_seed_width) — BLAKE3 ships only at -256.
BLAKE3_HASHES = [
    ("blake3", 256),
]

# Hash-key length (bytes) per primitive.
EXPECTED_KEY_LEN = {
    "blake3": 32,
}

NONCE_SIZES = (128, 256, 512)


class TestBLAKE3EasyRoundtripAcrossNonceSizes(unittest.TestCase):
    """Single Ouroboros round-trip via Encryptor over blake3 × all
    three nonce sizes. set_nonce_bits is per-instance on the
    Encryptor surface, so the brackets that bracket the legacy
    process-wide setter become a single setter call on the encryptor
    after construction."""

    def test_all(self):
        plaintext = secrets.token_bytes(1024)
        for n in NONCE_SIZES:
            for hash_name, _ in BLAKE3_HASHES:
                with self.subTest(nonce=n, hash=hash_name):
                    with itb.Encryptor(hash_name, 1024, "kmac256", mode=1) as enc:
                        enc.set_nonce_bits(n)
                        ct = enc.encrypt(plaintext)
                        pt = enc.decrypt(ct)
                        self.assertEqual(pt, plaintext)


class TestBLAKE3EasyTripleRoundtripAcrossNonceSizes(unittest.TestCase):
    """Triple Ouroboros (mode=3) round-trip via Encryptor."""

    def test_all(self):
        plaintext = secrets.token_bytes(1024)
        for n in NONCE_SIZES:
            for hash_name, _ in BLAKE3_HASHES:
                with self.subTest(nonce=n, hash=hash_name):
                    with itb.Encryptor(hash_name, 1024, "kmac256", mode=3) as enc:
                        enc.set_nonce_bits(n)
                        ct = enc.encrypt(plaintext)
                        pt = enc.decrypt(ct)
                        self.assertEqual(pt, plaintext)


class TestBLAKE3EasyAuthAcrossNonceSizes(unittest.TestCase):
    """Single Ouroboros + Auth + tamper rejection via Encryptor.

    Tamper region starts past the chunk header (nonce + 2-byte width
    + 2-byte height) so the body bytes get bit-flipped, not the
    header dimensions. Encryptor's nonce_bits is per-instance, so
    the header size is computed from n directly rather than via the
    process-wide :func:`itb.header_size` (which would read the
    global nonce setting and miss the per-instance override)."""

    def test_all(self):
        plaintext = secrets.token_bytes(1024)
        for n in NONCE_SIZES:
            for mac_name in ("kmac256", "hmac-sha256", "hmac-blake3"):
                for hash_name, _ in BLAKE3_HASHES:
                    with self.subTest(nonce=n, mac=mac_name, hash=hash_name):
                        with itb.Encryptor(hash_name, 1024, mac_name, mode=1) as enc:
                            enc.set_nonce_bits(n)
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
                                cm.exception.code,
                                itb._ffi.STATUS_MAC_FAILURE,
                            )


class TestBLAKE3EasyTripleAuthAcrossNonceSizes(unittest.TestCase):
    """Triple Ouroboros (mode=3) + Auth + tamper rejection. Header
    size computed per-instance from the encryptor's nonce_bits."""

    def test_all(self):
        plaintext = secrets.token_bytes(1024)
        for n in NONCE_SIZES:
            for mac_name in ("kmac256", "hmac-sha256", "hmac-blake3"):
                for hash_name, _ in BLAKE3_HASHES:
                    with self.subTest(nonce=n, mac=mac_name, hash=hash_name):
                        with itb.Encryptor(hash_name, 1024, mac_name, mode=3) as enc:
                            enc.set_nonce_bits(n)
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
                                cm.exception.code,
                                itb._ffi.STATUS_MAC_FAILURE,
                            )


class TestBLAKE3EasyPersistenceAcrossNonceSizes(unittest.TestCase):
    """Encrypt → export blob → free encryptor → fresh encryptor →
    import blob → decrypt → verify plaintext bit-identical. The
    encryptor's set_nonce_bits state is per-instance and not carried
    in the blob (deployment config), so the receiver mirrors it via
    a matching set_nonce_bits call."""

    def test_roundtrip(self):
        plaintext = b"persistence payload " + secrets.token_bytes(1024)

        for hash_name, width in BLAKE3_HASHES:
            valid_key_bits = [k for k in (512, 1024, 2048) if k % width == 0]
            for key_bits in valid_key_bits:
                for n in NONCE_SIZES:
                    with self.subTest(hash=hash_name, key_bits=key_bits, nonce=n):
                        # Day 1.
                        src = itb.Encryptor(hash_name, key_bits, "kmac256", mode=1)
                        src.set_nonce_bits(n)
                        self.assertEqual(
                            len(src.prf_key(0)), EXPECTED_KEY_LEN[hash_name],
                        )
                        self.assertEqual(
                            len(src.seed_components(0)) * 64, key_bits,
                        )
                        blob = src.export()
                        ct = src.encrypt(plaintext)
                        src.free()

                        # Day 2.
                        dst = itb.Encryptor(hash_name, key_bits, "kmac256", mode=1)
                        dst.set_nonce_bits(n)
                        dst.import_state(blob)
                        pt = dst.decrypt(ct)
                        self.assertEqual(pt, plaintext)
                        dst.free()


class TestBLAKE3EasyRoundtripSizes(unittest.TestCase):
    """Round-trip across plaintext sizes that span multiple chunk
    boundaries. ITB's processChunk batches 4 pixels per BatchHash
    call; trailing partial batches must dispatch via the per-lane
    fallback."""

    def test_sizes(self):
        for hash_name, _ in BLAKE3_HASHES:
            for n in NONCE_SIZES:
                for sz in (1, 17, 4096, 65536, 1 << 20):
                    with self.subTest(hash=hash_name, nonce=n, size=sz):
                        plaintext = secrets.token_bytes(sz)
                        with itb.Encryptor(hash_name, 1024, "kmac256") as enc:
                            enc.set_nonce_bits(n)
                            ct = enc.encrypt(plaintext)
                            pt = enc.decrypt(ct)
                            self.assertEqual(pt, plaintext)


if __name__ == "__main__":
    unittest.main(verbosity=2)
