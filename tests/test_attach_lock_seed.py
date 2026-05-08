"""Python binding tests for the low-level :meth:`itb.Seed.attach_lock_seed`
mutator. The dedicated lockSeed routes the bit-permutation derivation
through its own state instead of the noiseSeed: the per-chunk PRF
closure captures BOTH the lockSeed's components AND its hash function,
so the lockSeed primitive may legitimately differ from the noiseSeed
primitive within the same native hash width — keying-material isolation
plus algorithm diversity for defence-in-depth on the bit-permutation
channel, without changing the public encrypt / decrypt signatures.

The bit-permutation overlay must be engaged via :func:`itb.set_bit_soup`
or :func:`itb.set_lock_soup` before any encrypt call — without the
overlay, the dedicated lockSeed has no observable effect on the wire
output, and the Go-side build-PRF guard panics on encrypt-time. These
tests exercise both the round-trip path with overlay engaged and the
attach-time misuse rejections (self-attach, post-Encrypt switching,
width mismatch).
"""

import sys
import unittest
from contextlib import contextmanager
from pathlib import Path

HERE = Path(__file__).resolve()
sys.path.insert(0, str(HERE.parents[1]))

import itb  # noqa: E402


@contextmanager
def lock_soup_on():
    """Brackets a test region with set_lock_soup(1) — auto-couples
    BitSoup=1 — and restores both flags on exit."""
    prev_bs = itb.get_bit_soup()
    prev_ls = itb.get_lock_soup()
    itb.set_lock_soup(1)
    try:
        yield
    finally:
        itb.set_bit_soup(prev_bs)
        itb.set_lock_soup(prev_ls)


class TestAttachLockSeedRoundtrip(unittest.TestCase):
    """Standard happy path: attach a fresh lockSeed onto noiseSeed,
    engage the overlay, encrypt → decrypt round-trip succeeds."""

    def test_roundtrip(self):
        plaintext = b"attach_lock_seed roundtrip payload"
        with lock_soup_on():
            ns = itb.Seed("blake3", 1024)
            ds = itb.Seed("blake3", 1024)
            ss = itb.Seed("blake3", 1024)
            ls = itb.Seed("blake3", 1024)
            try:
                ns.attach_lock_seed(ls)
                ct = itb.encrypt(ns, ds, ss, plaintext)
                pt = itb.decrypt(ns, ds, ss, ct)
                self.assertEqual(pt, plaintext)
            finally:
                ns.free(); ds.free(); ss.free(); ls.free()


class TestAttachLockSeedCrossProcess(unittest.TestCase):
    """Cross-process persistence: attach + export seed material
    on the sender, restore via :meth:`itb.Seed.from_components` on
    the receiver, attach the restored lockSeed, decrypt successfully."""

    def test_persistence(self):
        plaintext = b"cross-process attach lockseed roundtrip"
        with lock_soup_on():
            # Day 1 — sender.
            ns = itb.Seed("blake3", 1024)
            ds = itb.Seed("blake3", 1024)
            ss = itb.Seed("blake3", 1024)
            ls = itb.Seed("blake3", 1024)
            ns.attach_lock_seed(ls)
            comps = (ns.components, ds.components, ss.components, ls.components)
            keys = (ns.hash_key, ds.hash_key, ss.hash_key, ls.hash_key)
            ct = itb.encrypt(ns, ds, ss, plaintext)
            ns.free(); ds.free(); ss.free(); ls.free()

            # Day 2 — receiver.
            ns2 = itb.Seed.from_components("blake3", comps[0], keys[0])
            ds2 = itb.Seed.from_components("blake3", comps[1], keys[1])
            ss2 = itb.Seed.from_components("blake3", comps[2], keys[2])
            ls2 = itb.Seed.from_components("blake3", comps[3], keys[3])
            try:
                ns2.attach_lock_seed(ls2)
                pt = itb.decrypt(ns2, ds2, ss2, ct)
                self.assertEqual(pt, plaintext)
            finally:
                ns2.free(); ds2.free(); ss2.free(); ls2.free()


class TestAttachLockSeedRejections(unittest.TestCase):
    """Misuse paths surface as ITBError: self-attach, post-encrypt
    switching, and width mismatch."""

    def test_self_attach_rejected(self):
        ns = itb.Seed("blake3", 1024)
        try:
            with self.assertRaises(itb.ITBError) as cm:
                ns.attach_lock_seed(ns)
            self.assertEqual(cm.exception.code, itb._ffi.STATUS_BAD_INPUT)
        finally:
            ns.free()

    def test_width_mismatch_rejected(self):
        ns_256 = itb.Seed("blake3", 1024)      # width 256
        ls_128 = itb.Seed("siphash24", 1024)   # width 128
        try:
            with self.assertRaises(itb.ITBError) as cm:
                ns_256.attach_lock_seed(ls_128)
            self.assertEqual(
                cm.exception.code, itb._ffi.STATUS_SEED_WIDTH_MIX,
            )
        finally:
            ns_256.free(); ls_128.free()

    def test_post_encrypt_attach_rejected(self):
        with lock_soup_on():
            ns = itb.Seed("blake3", 1024)
            ds = itb.Seed("blake3", 1024)
            ss = itb.Seed("blake3", 1024)
            ls = itb.Seed("blake3", 1024)
            ns.attach_lock_seed(ls)
            # Encrypt once — locks future AttachLockSeed calls.
            itb.encrypt(ns, ds, ss, b"pre-switch")
            ls2 = itb.Seed("blake3", 1024)
            try:
                with self.assertRaises(itb.ITBError) as cm:
                    ns.attach_lock_seed(ls2)
                self.assertEqual(
                    cm.exception.code, itb._ffi.STATUS_BAD_INPUT,
                )
            finally:
                ns.free(); ds.free(); ss.free()
                ls.free(); ls2.free()

    def test_type_check(self):
        ns = itb.Seed("blake3", 1024)
        try:
            with self.assertRaises(TypeError):
                ns.attach_lock_seed("not a seed")
        finally:
            ns.free()


class TestAttachLockSeedOverlayOff(unittest.TestCase):
    """Without the bit-permutation overlay engaged, the build-PRF
    guard inside the Go-side dispatch panics on encrypt-time
    surfacing as ITBError. This is the regression-pin for the
    overlay-off action-at-a-distance bug — silent no-op is replaced
    by a loud failure."""

    def test_overlay_off_panics_on_encrypt(self):
        # Ensure both flags are off.
        prev_bs = itb.get_bit_soup()
        prev_ls = itb.get_lock_soup()
        itb.set_bit_soup(0)
        itb.set_lock_soup(0)
        try:
            ns = itb.Seed("blake3", 1024)
            ds = itb.Seed("blake3", 1024)
            ss = itb.Seed("blake3", 1024)
            ls = itb.Seed("blake3", 1024)
            ns.attach_lock_seed(ls)
            with self.assertRaises(itb.ITBError):
                itb.encrypt(ns, ds, ss, b"overlay off - should panic")
            ns.free(); ds.free(); ss.free(); ls.free()
        finally:
            itb.set_bit_soup(prev_bs)
            itb.set_lock_soup(prev_ls)


if __name__ == "__main__":
    unittest.main(verbosity=2)
