"""Freeing an encrypt session mid-flight cleans up and leaves the
Pipeline usable."""

from __future__ import annotations

import unittest

import itb


class StreamCancelTest(unittest.TestCase):
    def test_free_mid_flight_then_reuse_pipeline(self) -> None:
        with itb.Pipeline.init("streaming-aead-triple-mac-v1") as sender:
            sess = sender.encrypt_stream()
            sess.write(b"\xa5" * 100_000)
            # Freed here without end() — free() cancels and releases
            # the session; the test passing (process not hanging) is
            # the assertion.
            sess.free()

            # The Pipeline stays usable after the cancelled session.
            with itb.Pipeline.open(
                "streaming-aead-triple-mac-v1", sender.blob
            ) as receiver:
                wire = sender.encrypt_message(b"after cancel")
                self.assertEqual(receiver.decrypt_message(wire), b"after cancel")


if __name__ == "__main__":
    unittest.main()
