"""Single Message round trip across every shipped cipher profile at
small (4 KiB) and medium (256 KiB) payloads. The blob-only profile has
no cipher surface and is exercised in test_errors.py instead."""

from __future__ import annotations

import unittest

import itb


def payload(n: int, seed: int) -> bytes:
    """Deterministic non-trivial payload (xorshift fill)."""
    x = seed | 1
    out = bytearray(n)
    for i in range(n):
        x ^= (x << 13) & 0xFFFFFFFFFFFFFFFF
        x ^= x >> 7
        x ^= (x << 17) & 0xFFFFFFFFFFFFFFFF
        out[i] = x & 0xFF
    return bytes(out)


PROFILES = [
    "streaming-aead-triple-mac-v1",
    "streaming-noaead-triple-v1",
    "singlemsg-triple-mac-v1",
    "singlemsg-triple-nomac-v1",
    "streaming-aead-triple-mac-mixed-v1",
    "streaming-noaead-triple-mixed-v1",
    "singlemsg-triple-mac-mixed-v1",
    "singlemsg-triple-nomac-mixed-v1",
]


class MessageTest(unittest.TestCase):
    def test_message_round_trip_every_profile(self) -> None:
        for profile in PROFILES:
            with self.subTest(profile=profile):
                with itb.Pipeline.init(profile) as sender:
                    with itb.Pipeline.open(profile, sender.blob) as receiver:
                        for size in (4 * 1024, 256 * 1024):
                            plain = payload(size, size)
                            wire = sender.encrypt_message(plain)
                            back = receiver.decrypt_message(wire)
                            self.assertEqual(back, plain, f"{profile} @{size}")


if __name__ == "__main__":
    unittest.main()
