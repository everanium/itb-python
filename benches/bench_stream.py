"""encrypt_stream_pump throughput vs plaintext size (Streaming
Non-AEAD profile) at 1 MiB / 16 MiB / 64 MiB."""

from __future__ import annotations

import io
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
        bench_util.profile_name("streaming-noaead-triple-v1"), bench_util.build_opts()
    )
    bench_util.bench_header()
    for size in bench_util.SIZES:
        # CSPRNG-fill so plaintext content matches the root Go bench
        # (crypto/rand). Not in the timing loop.
        plain = secrets.token_bytes(size)

        def run(p: bytes = plain) -> None:
            pipe.encrypt_stream_pump(io.BytesIO(p), io.BytesIO())

        bench_util.bench_case("stream_pump", size, run)

        # Pre-encrypt one wire outside the decrypt timing loop.
        enc_buf = io.BytesIO()
        pipe.encrypt_stream_pump(io.BytesIO(plain), enc_buf)
        dec_wire = enc_buf.getvalue()

        def run_dec(w: bytes = dec_wire) -> None:
            pipe.decrypt_stream_pump(io.BytesIO(w), io.BytesIO())

        bench_util.bench_case("stream_pump-dec", size, run_dec)
    pipe.free()


if __name__ == "__main__":
    main()
