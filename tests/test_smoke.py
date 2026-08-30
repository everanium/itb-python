"""Init -> blob -> Open -> encrypt_message -> decrypt_message round
trip."""

from __future__ import annotations

import unittest

import itb


class SmokeTest(unittest.TestCase):
    def test_smoke_round_trip(self) -> None:
        with itb.Pipeline.init("singlemsg-triple-mac-v1") as sender:
            self.assertTrue(sender.blob)
            with itb.Pipeline.open("singlemsg-triple-mac-v1", sender.blob) as receiver:
                plain = b"smoke round-trip payload"
                wire = sender.encrypt_message(plain)
                self.assertNotEqual(wire, plain)
                self.assertEqual(receiver.decrypt_message(wire), plain)


if __name__ == "__main__":
    unittest.main()
