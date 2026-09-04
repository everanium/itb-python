"""A decrypt session fed a tampered wire fails with a sticky MAC
failure. Uses a position probe rather than a single bit flip because
the over-sized container carries CSPRNG residue in the non-payload
area — a flip that lands inside the residue is architecturally inert
(residue is not payload) and the session finishes clean. Probing 32
evenly-spaced positions makes the all-residue probability negligible;
the first position that surfaces an error must give
``Status.MAC_FAILURE`` and remain sticky on subsequent reads."""

from __future__ import annotations

import unittest

import itb


class StreamStickyTest(unittest.TestCase):
    def test_tampered_wire_sticky_failure(self) -> None:
        with itb.Pipeline.init("streaming-aead-triple-mac-v1") as sender:
            with itb.Pipeline.load(sender.save()) as receiver:
                plain = bytes(i % 227 for i in range(65_536))
                base_wire = sender.encrypt_stream_one_shot(plain)
                self.assertGreater(
                    len(base_wire),
                    128,
                    "wire too short to place a distributed probe",
                )

                probes = 32
                # Evenly spread through the wire body; skip the first /
                # last 16 bytes so a hit against the outer envelope
                # framing does not muddy the observation.
                body_start = 16
                body_end = len(base_wire) - 16
                stride = (body_end - body_start) // probes

                for probe in range(probes):
                    idx = body_start + probe * stride
                    wire = bytearray(base_wire)
                    wire[idx] ^= 0x01

                    with receiver.decrypt_stream() as sess:
                        # Ignore Write / End status — the failure may
                        # surface on either side or only on the drain
                        # that follows.
                        try:
                            sess.write(bytes(wire))
                            sess.end()
                        except itb.ItbError:
                            pass

                        first_err: itb.ItbError | None = None
                        finished_clean = False
                        while True:
                            try:
                                _, finished = sess.read(4096)
                            except itb.ItbError as e:
                                first_err = e
                                break
                            if finished:
                                finished_clean = True
                                break
                        if finished_clean:
                            # Residue hit at this offset — try the
                            # next probe.
                            continue
                        assert first_err is not None
                        self.assertEqual(
                            first_err.status,
                            itb.Status.MAC_FAILURE,
                            f"expected MAC failure on tampered wire at "
                            f"probe {probe} (byte {idx}), got {first_err}",
                        )

                        # Sticky: a subsequent read reports the same
                        # status.
                        with self.assertRaises(itb.ItbError) as ctx:
                            sess.read(4096)
                        self.assertEqual(ctx.exception.status, first_err.status)
                        return

                self.fail(
                    f"no probe among {probes} evenly-spaced positions "
                    "surfaced a MAC failure — either the probe pattern is "
                    "degenerate or authentication is not covering the "
                    "wire body it should"
                )


if __name__ == "__main__":
    unittest.main()
