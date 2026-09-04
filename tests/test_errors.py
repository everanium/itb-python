"""Error-mapping surface: opaque-string relay, unknown profile, closed
Pipeline, profile registration from a JSON record (with an 8-entry
``hashes`` constellation), duplicate registration."""

from __future__ import annotations

import unittest

import itb


class ErrorsTest(unittest.TestCase):
    def test_unknown_profile_is_unknown_profile_with_diagnostic(self) -> None:
        with self.assertRaises(itb.ItbError) as ctx:
            itb.Pipeline.init("no-such-profile")
        self.assertEqual(ctx.exception.status, itb.Status.UNKNOWN_PROFILE)
        self.assertTrue(str(ctx.exception))

    def test_unknown_opts_key_is_bad_input(self) -> None:
        # Typoed key (lowercase s) — Go rejects unknown keys.
        opts = itb.Opts().with_raw("chunksize", "4096")
        with self.assertRaises(itb.ItbError) as ctx:
            itb.Pipeline.init("singlemsg-triple-mac-v1", opts)
        self.assertEqual(ctx.exception.status, itb.Status.BAD_INPUT)

    def test_closed_pipeline_reports_triple_closed(self) -> None:
        with itb.Pipeline.init("singlemsg-triple-mac-v1") as pipe:
            pipe.close()
            pipe.close()  # idempotent
            with self.assertRaises(itb.ItbError) as ctx:
                pipe.encrypt_message(b"payload")
            self.assertEqual(ctx.exception.status, itb.Status.TRIPLE_CLOSED)

    def test_register_mixed_then_duplicate(self) -> None:
        # 8-entry width-256 hashes constellation, layers off.
        profile = {
            "mode": "singlemsg-nomac",
            "width": 256,
            "hashes": [
                "blake3", "blake2s", "areion256", "blake2b256",
                "chacha20", "blake3", "blake2s", "areion256",
            ],
            "keybits": 1024,
            "parallax": False,
            "wrapper": False,
        }
        itb.register("python-binding-test-mixed", profile)

        # The registered profile round-trips and is visible in the
        # catalogue.
        self.assertIn("python-binding-test-mixed", itb.profiles())
        self.assertEqual(itb.lookup("python-binding-test-mixed")["hashes"], profile["hashes"])
        with itb.Pipeline.init("python-binding-test-mixed") as sender:
            with itb.Pipeline.load(sender.save()) as receiver:
                wire = sender.encrypt_message(b"custom profile")
                self.assertEqual(receiver.decrypt_message(wire), b"custom profile")

        # Duplicate name is a distinct status.
        with self.assertRaises(itb.ItbError) as ctx:
            itb.register("python-binding-test-mixed", profile)
        self.assertEqual(ctx.exception.status, itb.Status.PROFILE_EXISTS)

    def test_register_rejects_unknown_key(self) -> None:
        # Strict record decode on the Go side — the binding performs no
        # JSON validation of its own.
        with self.assertRaises(itb.ItbError) as ctx:
            itb.register("python-binding-test-badkey", {"mode": "singlemsg-nomac", "bogus": 1})
        self.assertEqual(ctx.exception.status, itb.Status.BAD_INPUT)

    def test_opaque_primitive_name_relay(self) -> None:
        # An unknown inner-hash name is relayed to Go and rejected
        # there — the binding performs no name validation of its own.
        opts = itb.Opts().with_inner_hash("no-such-hash")
        with self.assertRaises(itb.ItbError) as ctx:
            itb.Pipeline.init("singlemsg-triple-mac-v1", opts)
        self.assertIsNotNone(ctx.exception.status)
        self.assertNotEqual(ctx.exception.status, itb.Status.OK)

    def test_per_call_inner_hashes_override_round_trips(self) -> None:
        # The single-primitive width-512 base profile takes an 8-slot
        # per-call MixedHashes override (Go-side Opts.MixedHashes,
        # wired through the innerHashes= opts key). The override lands
        # in the blob's profile record, so the receiver loads with no
        # opts of its own.
        mix = [
            "areion512", "blake2b512", "areion512", "blake2b512",
            "areion512", "blake2b512", "areion512", "blake2b512",
        ]
        sender_opts = itb.Opts().with_inner_hashes(mix)
        with itb.Pipeline.init("singlemsg-triple-mac-v1", sender_opts) as sender:
            blob = sender.save()
            self.assertEqual(itb.inspect(blob)["hashes"], mix)
            with itb.Pipeline.load(blob) as receiver:
                plain = b"per-call inner-hashes override round-trip payload"
                wire = sender.encrypt_message(plain)
                self.assertEqual(receiver.decrypt_message(wire), plain)


if __name__ == "__main__":
    unittest.main()
