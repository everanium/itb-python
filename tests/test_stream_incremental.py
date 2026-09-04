"""Explicit write / end / read round trip with pathological batch
sizes (17-byte feed, 23-byte drain) across multiple chunks."""

from __future__ import annotations

import unittest

import itb


class StreamIncrementalTest(unittest.TestCase):
    def test_incremental_tiny_batches(self) -> None:
        # Small chunk size so the 64 KiB payload spans many chunks.
        opts = itb.Opts().with_chunk_size(4096)
        with itb.Pipeline.init("streaming-aead-triple-mac-v1", opts) as sender:
            with itb.Pipeline.load(sender.save()) as receiver:
                plain = bytes(i % 241 for i in range(65_536))

                # Encrypt: 17-byte writes, then end + 23-byte drains.
                wire = bytearray()
                with sender.encrypt_stream() as sess:
                    for off in range(0, len(plain), 17):
                        sess.write(plain[off : off + 17])
                    sess.end()
                    while True:
                        chunk, finished = sess.read(23)
                        wire += chunk
                        if finished:
                            break
                self.assertTrue(wire)

                # Decrypt with the same pathological batch sizes.
                back = bytearray()
                with receiver.decrypt_stream() as sess:
                    for off in range(0, len(wire), 17):
                        sess.write(bytes(wire[off : off + 17]))
                    sess.end()
                    while True:
                        chunk, finished = sess.read(23)
                        back += chunk
                        if finished:
                            break
                self.assertEqual(bytes(back), plain)


if __name__ == "__main__":
    unittest.main()
