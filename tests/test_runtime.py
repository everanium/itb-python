"""Runtime surface: the process-wide Go knobs (heap limit, GC
percentage, GOMAXPROCS, heap profile, pool counters) and the shipped
inner-hash registry enumeration."""

from __future__ import annotations

import os
import tempfile
import unittest

import itb3 as itb


class RuntimeTest(unittest.TestCase):
    def test_set_gomaxprocs_queries_then_restores(self) -> None:
        # A non-positive argument queries without changing; the setter
        # returns the value that was in force before it.
        before = itb.set_gomaxprocs(0)
        self.assertGreater(before, 0)
        self.assertEqual(itb.set_gomaxprocs(2), before)
        self.assertEqual(itb.set_gomaxprocs(0), 2)
        itb.set_gomaxprocs(before)
        self.assertEqual(itb.set_gomaxprocs(0), before)

    def test_write_heap_profile_writes_a_readable_profile(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "heap.prof")
            itb.write_heap_profile(path)
            self.assertGreater(os.path.getsize(path), 0)
            with open(path, "rb") as f:
                # pprof profiles are gzip-wrapped protobuf.
                self.assertEqual(f.read(2), b"\x1f\x8b")

    def test_write_heap_profile_reports_the_os_diagnostic(self) -> None:
        with self.assertRaises(itb.ItbError) as ctx:
            itb.write_heap_profile("/no-such-directory-itb3-test/heap.prof")
        self.assertEqual(ctx.exception.status, itb.Status.BAD_INPUT)
        self.assertIn("heap.prof", ctx.exception.message)

    def test_pool_stats_length_matches_the_declared_layout(self) -> None:
        length = itb.pool_stats_len()
        self.assertGreater(length, 0)
        stats = itb.pool_stats()
        self.assertEqual(len(stats), length)
        tiers = stats[0]
        # Slot 0 carries the tier count T; the vector is 1 + 5*T + 8.
        self.assertGreater(tiers, 0)
        self.assertEqual(length, 1 + 5 * tiers + 8)

    def test_pool_stats_counters_are_monotonic_across_work(self) -> None:
        before = itb.pool_stats()
        with itb.Pipeline.init("singlemsg-triple-mac-v1") as pipe:
            pipe.decrypt_message(pipe.encrypt_message(b"x" * 4096))
        after = itb.pool_stats()
        self.assertEqual(len(after), len(before))
        for i in range(1, len(after)):
            self.assertGreaterEqual(after[i], before[i])
        self.assertGreater(sum(after[1:]), sum(before[1:]))

    def test_memory_limit_and_gc_percent_query_without_changing(self) -> None:
        limit = itb.set_memory_limit(-1)
        self.assertEqual(itb.set_memory_limit(-1), limit)
        pct = itb.set_gc_percent(-1)
        self.assertEqual(itb.set_gc_percent(-1), pct)


class HashRegistryTest(unittest.TestCase):
    def test_hash_names_enumerates_the_shipped_registry(self) -> None:
        names = itb.hash_names()
        self.assertGreater(len(names), 1)
        self.assertEqual(len(names), len(set(names)))
        for name in names:
            self.assertIsInstance(name, str)
            self.assertTrue(name)
        # The enumeration is what a caller validates a primitive name
        # against, so a shipped name resolves and a typo does not.
        self.assertIn("areion512", names)
        self.assertNotIn("areion512-nope", names)

    def test_every_enumerated_name_constructs_a_pipeline(self) -> None:
        for name in itb.hash_names():
            opts = itb.Opts().with_inner_hash(name).with_parallax(False)
            with itb.Pipeline.init("singlemsg-triple-nomac-v1", opts) as pipe:
                self.assertEqual(
                    pipe.decrypt_message(pipe.encrypt_message(b"registry probe")),
                    b"registry probe",
                )

    def test_drbg_auto_tier_names_a_fill_cipher(self) -> None:
        self.assertIn(itb.drbg_auto_tier(), ("aes-256-ctr", "chacha20"))


if __name__ == "__main__":
    unittest.main()
