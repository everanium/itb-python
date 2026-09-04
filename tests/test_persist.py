"""Session persistence: save / load in memory, save_f / load_f through
a temp file (mode 0600), inspect, lookup / profiles, max_workers."""

from __future__ import annotations

import os
import stat
import tempfile
import unittest

import itb

PROFILE = "singlemsg-triple-mac-v1"


class PersistTest(unittest.TestCase):
    def test_save_load_round_trip(self) -> None:
        with itb.Pipeline.init(PROFILE) as sender:
            blob = sender.save()
            self.assertTrue(blob)
            self.assertEqual(sender.save(), blob, "save is stable between calls")
            with itb.Pipeline.load(blob) as receiver:
                self.assertEqual(receiver.save(), blob, "load retains the blob")
                wire = sender.encrypt_message(b"in-memory persist")
                self.assertEqual(receiver.decrypt_message(wire), b"in-memory persist")

    def test_save_f_load_f_round_trip(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "session.blob")
            with itb.Pipeline.init(PROFILE) as sender:
                sender.save_f(path)
                mode = stat.S_IMODE(os.stat(path).st_mode)
                self.assertEqual(mode, 0o600, f"blob file mode {mode:o}")
                with itb.Pipeline.load_f(path) as receiver:
                    self.assertEqual(receiver.save(), sender.save())
                    wire = sender.encrypt_message(b"file persist")
                    self.assertEqual(receiver.decrypt_message(wire), b"file persist")

    def test_load_f_missing_file_is_bad_input(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(itb.ItbError) as ctx:
                itb.Pipeline.load_f(os.path.join(tmp, "absent.blob"))
            self.assertEqual(ctx.exception.status, itb.Status.BAD_INPUT)

    def test_load_with_master_override(self) -> None:
        with itb.Pipeline.init(PROFILE) as sender:
            rotated = sender.rekey(b"\x31" * 32, b"\x32" * 32)
            with itb.Pipeline.load(sender.save(), (b"\x31" * 32, b"\x32" * 32)) as receiver:
                self.assertEqual(receiver.save(), rotated)
                wire = sender.encrypt_message(b"master override")
                self.assertEqual(receiver.decrypt_message(wire), b"master override")

    def test_inspect_matches_lookup(self) -> None:
        with itb.Pipeline.init(PROFILE) as pipe:
            record = itb.inspect(pipe.save())
        self.assertEqual(record["name"], PROFILE)
        self.assertEqual(record["mode"], "singlemsg-mac")
        self.assertIn("keybits", record)
        self.assertEqual(record, itb.lookup(PROFILE))

    def test_inspect_rejects_garbage(self) -> None:
        with self.assertRaises(itb.ItbError) as ctx:
            itb.inspect(b"not a blob")
        self.assertEqual(ctx.exception.status, itb.Status.BAD_INPUT)

    def test_profiles_and_lookup(self) -> None:
        names = itb.profiles()
        self.assertIn(PROFILE, names)
        self.assertEqual(names, sorted(names))
        with self.assertRaises(itb.ItbError) as ctx:
            itb.lookup("no-such-profile")
        self.assertEqual(ctx.exception.status, itb.Status.UNKNOWN_PROFILE)

    def test_max_workers(self) -> None:
        with itb.Pipeline.init(PROFILE) as pipe:
            pipe.max_workers(2)
            pipe.max_workers(-1)  # clamped to auto, never rejected
            pipe.max_workers(10_000)  # clamped to 256
            wire = pipe.encrypt_message(b"after cap change")
            self.assertEqual(pipe.decrypt_message(wire), b"after cap change")
            pipe.close()
            with self.assertRaises(itb.ItbError) as ctx:
                pipe.max_workers(2)
            self.assertEqual(ctx.exception.status, itb.Status.TRIPLE_CLOSED)

    def test_init_max_workers_negative_is_clamped(self) -> None:
        with itb.Pipeline.init(PROFILE, itb.Opts().with_max_workers(-1)) as pipe:
            wire = pipe.encrypt_message(b"negative cap")
            self.assertEqual(pipe.decrypt_message(wire), b"negative cap")


if __name__ == "__main__":
    unittest.main()
