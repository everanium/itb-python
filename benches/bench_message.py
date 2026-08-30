"""encrypt_message throughput vs plaintext size (Single Message
profile) at 1 MiB / 16 MiB / 64 MiB."""

from __future__ import annotations

import secrets

import bench_util
import itb


def main() -> None:
    # Bench-scale allocation churn leaks Go scratch heap unboundedly
    # without a soft memory cap + aggressive GC; the return values
    # report the previous settings, not an error.
    itb.set_memory_limit(512 << 20)
    itb.set_gc_percent(20)

    pipe = itb.Pipeline.init(
        bench_util.profile_name("singlemsg-triple-nomac-v1"), bench_util.build_opts()
    )
    bench_util.bench_header()
    for size in bench_util.SIZES:
        # CSPRNG-fill so plaintext content matches the root Go bench
        # (crypto/rand). Not in the timing loop.
        plain = secrets.token_bytes(size)

        def run(p: bytes = plain) -> None:
            pipe.encrypt_message(p)

        bench_util.bench_case("message", size, run)

        # Pre-encrypt one wire outside the decrypt timing loop.
        dec_wire = pipe.encrypt_message(plain)

        def run_dec(w: bytes = dec_wire) -> None:
            pipe.decrypt_message(w)

        bench_util.bench_case("message-dec", size, run_dec)
    pipe.free()


if __name__ == "__main__":
    main()
