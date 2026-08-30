"""Round trip through the stream pumps on a Streaming AEAD profile."""

from __future__ import annotations

import io
import unittest

import itb


class StreamPumpTest(unittest.TestCase):
    def test_pump_round_trip_1mib(self) -> None:
        with itb.Pipeline.init("streaming-aead-triple-mac-v1") as sender:
            with itb.Pipeline.open(
                "streaming-aead-triple-mac-v1", sender.blob
            ) as receiver:
                plain = bytes(i % 251 for i in range(1 << 20))

                wire_buf = io.BytesIO()
                sender.encrypt_stream_pump(io.BytesIO(plain), wire_buf)
                wire = wire_buf.getvalue()
                self.assertTrue(wire)

                back_buf = io.BytesIO()
                receiver.decrypt_stream_pump(io.BytesIO(wire), back_buf)
                self.assertEqual(back_buf.getvalue(), plain)

    def test_pump_matches_one_shot(self) -> None:
        with itb.Pipeline.init("streaming-aead-triple-mac-v1") as sender:
            with itb.Pipeline.open(
                "streaming-aead-triple-mac-v1", sender.blob
            ) as receiver:
                plain = bytes(i % 199 for i in range(65_536))
                wire = sender.encrypt_stream_one_shot(plain)

                back_buf = io.BytesIO()
                receiver.decrypt_stream_pump(io.BytesIO(wire), back_buf)
                self.assertEqual(back_buf.getvalue(), plain)

                back2 = receiver.decrypt_stream_one_shot(wire)
                self.assertEqual(back2, plain)


if __name__ == "__main__":
    unittest.main()
