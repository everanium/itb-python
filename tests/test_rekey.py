"""Init -> Rekey -> Load receiver with the rotated blob -> round
trip."""

from __future__ import annotations

import unittest

import itb


class RekeyTest(unittest.TestCase):
    def test_rekey_round_trip(self) -> None:
        with itb.Pipeline.init("singlemsg-triple-mac-v1") as sender:
            blob_before = sender.save()

            rotated = sender.rekey(b"\x11" * 32, b"\x22" * 32)
            self.assertNotEqual(rotated, blob_before, "rekey must refresh the blob")
            self.assertEqual(rotated, sender.save(), "save must observe the rekey")

            with itb.Pipeline.load(rotated) as receiver:
                plain = b"post-rekey payload"
                wire = sender.encrypt_message(plain)
                self.assertEqual(receiver.decrypt_message(wire), plain)


if __name__ == "__main__":
    unittest.main()
