"""Error-mapping surface: opaque-string relay, closed Pipeline,
duplicate profile registration (with an 8-entry ``innerHashes``
constellation)."""

from __future__ import annotations

import unittest

import itb


class ErrorsTest(unittest.TestCase):
    def test_unknown_profile_is_bad_input_with_diagnostic(self) -> None:
        with self.assertRaises(itb.ItbError) as ctx:
            itb.Pipeline.init("no-such-profile")
        self.assertEqual(ctx.exception.status, itb.Status.BAD_INPUT)
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

    def test_register_profile_mixed_then_duplicate(self) -> None:
        # 8-entry width-256 innerHashes constellation, layers off.
        opts = (
            itb.Opts()
            .with_raw("mode", "singlemsg-nomac")
            .with_raw("width", "256")
            .with_raw(
                "innerHashes",
                "blake3,blake2s,areion256,blake2b256,chacha20,blake3,blake2s,areion256",
            )
            .with_raw("keyBits", "1024")
            .with_raw("parallaxOn", "false")
            .with_raw("wrapperOn", "false")
        )
        itb.register_profile("python-binding-test-mixed", opts)

        # The registered profile round-trips.
        with itb.Pipeline.init("python-binding-test-mixed") as sender:
            with itb.Pipeline.open(
                "python-binding-test-mixed", sender.blob
            ) as receiver:
                wire = sender.encrypt_message(b"custom profile")
                self.assertEqual(receiver.decrypt_message(wire), b"custom profile")

        # Duplicate name is a distinct status.
        with self.assertRaises(itb.ItbError) as ctx:
            itb.register_profile("python-binding-test-mixed", opts)
        self.assertEqual(ctx.exception.status, itb.Status.PROFILE_EXISTS)

    def test_opaque_primitive_name_relay(self) -> None:
        # An unknown inner-hash name is relayed to Go and rejected
        # there — the binding performs no name validation of its own.
        opts = itb.Opts().with_inner_hash("no-such-hash")
        with self.assertRaises(itb.ItbError) as ctx:
            itb.Pipeline.init("singlemsg-triple-mac-v1", opts)
        self.assertIsNotNone(ctx.exception.status)
        self.assertNotEqual(ctx.exception.status, itb.Status.OK)


if __name__ == "__main__":
    unittest.main()
