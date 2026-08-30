# ITB Python Binding

> **Security notice.** ITB is an experimental symmetric cipher construction without prior peer review, independent cryptanalysis, or formal certification. The construction's security properties have **not been verified** by independent cryptographers or mathematicians.
>
> PRF-grade hash functions are **required**. No warranty is provided.

**No bespoke cryptography.** ITB introduces no cryptographic primitive of its own — no custom S-box, permutation, or round function. It is a construction over existing primitives, much as PGP composes standard ciphers rather than defining one. Such constructions are not the object of algorithm-level cryptographic certification: national regimes (NIST CAVP/FIPS in the US, GOST/FSB in Russia, OSCCA's SM-series in China, IC3S in India, SOG-IS/EUCC and national lists in the EU, ASD's ISM in Australia, CRYPTREC in Japan, KCMVP in South Korea) certify **primitives** and the **modules** built on them, not compositional schemes. Eligibility for regulated use is therefore inherited from the primitives ITB is configured with, not conferred by ITB itself.

Thin proxy over the libitb shared library's `ITB_Triple_*` surface
(`cmd/cshared`). Runtime FFI via the standard-library `ctypes` module
— no C compiler at install time, no compile-time link, no third-party
dependencies; the `.so` / `.dylib` / `.dll` is resolved and dispatched
at first use. Every hash-name / MAC-name / cipher-name / profile-name
is an opaque string passed through to Go for validation; the binding
carries no ITB construction logic. The public surface is one
`Pipeline` class (init / open / rekey / close, Single Message encrypt
/ decrypt, one-shot and incremental stream sessions with file-object
pumps), an `Opts` query-string builder, `register_profile`, and the
Go runtime knobs.

## Prerequisites (Arch Linux)

```bash
sudo pacman -S go python
```

Generic Linux / macOS: a Go toolchain plus Python 3.10+. Windows: the
same; libitb builds as `libitb.dll`.

## Build the shared library

The convenience driver builds `libitb.so` and compile-checks the
Python sources in one step:

```bash
./bindings/python/build.sh
```

Equivalent manual invocation:

```bash
go build -trimpath -buildmode=c-shared \
    -o dist/linux-amd64/libitb.so ./cmd/cshared
```

The package is importable directly from `bindings/python/` (no build
step — `ctypes` loads the shared library at runtime); an editable
install into a virtualenv is `pip install -e bindings/python`.

## Library lookup order

1. `ITB_LIBITB_PATH` environment variable (path to the shared
   library file).
2. `<repo>/dist/<os>-<arch>/libitb.<ext>` resolved from the package
   directory (in-repo builds).
3. The OS default loader path (`LD_LIBRARY_PATH`, `ld.so.cache`,
   `DYLD_LIBRARY_PATH`, `PATH`).

## Usage example

```python
import itb

sender = itb.Pipeline.init("singlemsg-triple-mac-v1")
receiver = itb.Pipeline.open("singlemsg-triple-mac-v1", sender.blob)

wire = sender.encrypt_message(b"any text or binary data")
plain = receiver.decrypt_message(wire)
assert plain == b"any text or binary data"
```

The `Opts` builder overrides the profile default per call (chunk
size, outer cipher, parallax on/off, wrapper on/off, MAC name,
palette):

```python
opts = itb.Opts().with_chunk_size(65536).with_wrapper(False)
sender = itb.Pipeline.init("singlemsg-triple-mac-v1", opts)
receiver = itb.Pipeline.open("singlemsg-triple-mac-v1", sender.blob, opts)
```

`Pipeline.rekey` rotates the parallax + wrapper masters mid-session
(the eight ITB seeds and MAC key are fixed for the session lifetime
by design); the receiver picks up the new masters through a fresh
`sender.blob` handshake:

```python
sender.rekey(b"\x11" * 32, b"\x22" * 32)
receiver = itb.Pipeline.open("singlemsg-triple-mac-v1", sender.blob)
```

`Pipeline` and the stream sessions are context managers, so a `with`
block frees the Go-side handle deterministically (garbage collection
via `__del__` covers the non-`with` path). For bounded-memory
streaming, `encrypt_stream_pump` / `decrypt_stream_pump` move any
readable file object into any writable one through an incremental
session; the explicit `encrypt_stream()` / `decrypt_stream()`
sessions expose `write` / `end` / `read` / `drain_all` for
caller-driven loops. Byte inputs accept `bytes`, `bytearray`, and
`memoryview`.

Profile names, opts keys, and every primitive name are validated by
the Go side; a rejected string raises `itb.ItbError` carrying the
status code (`itb.Status`) plus the `ITB_LastError` diagnostic.

## Memory

Two process-wide knobs constrain Go runtime arena pacing, readable at
libitb load time via env vars (`ITB_GOMEMLIMIT`, `ITB_GOGC`) and
adjustable at any time programmatically. Pass `-1` to query without
changing:

```python
itb.set_memory_limit(512 << 20)
itb.set_gc_percent(20)
```

## Testing

```bash
./bindings/python/run_tests.sh
```

The harness builds `libitb.so`, exports `ITB_LIBITB_PATH`, and
invokes `python -m unittest discover` against `tests/`. Positional
arguments are forwarded to unittest (e.g.
`./run_tests.sh tests.test_smoke`). The suite covers Single Message
round trips per shipped profile, stream pumps, incremental sessions
with pathological batch sizes, tampered-wire failure stickiness,
mid-flight cancellation, rekey, profile registration, and error
mapping — surface parity checks; the deep suite lives in Go under the
shipped tree.

## Benchmarking

```bash
./bindings/python/run_bench.sh
```

Micro-benches: `encrypt_message` and `encrypt_stream_pump` throughput
at 1 MiB / 16 MiB / 64 MiB. Shape and budget are driven by env vars
(`ITB_PROFILE`, `ITB_INNER_HASH`, `ITB_KEY_BITS`, `ITB_NONCE_BITS`,
`ITB_WITH_PARALLAX`, `ITB_WITH_WRAPPER`, `ITB_BENCH_MIN_SEC`); the
script pins the same defaults as the root Go BENCH3.md table.

## eitb utility

A small CLI under `bindings/python/eitb/` mirrors the shipped Go
`tools/eitb` scope for shell smoke tests:

```bash
python3 bindings/python/eitb/eitb.py version
python3 bindings/python/eitb/eitb.py hashes
python3 bindings/python/eitb/eitb.py encrypt singlemsg-triple-mac-v1 in.bin out.bin  # blob hex on stderr
python3 bindings/python/eitb/eitb.py decrypt singlemsg-triple-mac-v1 <blob-hex> out.bin back.bin
```

## Limitations

- The binding wraps the Triple Pipeline surface only. The Low-Level
  seed / MAC / blob / wrapper / parallax APIs are not exposed — use
  the shipped Go core for those.
- Streaming-decrypt caveat: chunked Streaming AEAD verifies per
  chunk, so plaintext of verified chunks is released before a later
  chunk can fail authentication.
- `ITB_LastError` is process-global last-write-wins; the textual
  diagnostic attached to an `ItbError` may belong to a different call
  under concurrent FFI use. The status code is always attributable.
- `rekey` must not run concurrently with cipher calls or open stream
  sessions on the same `Pipeline`.
- Input `bytearray` / `memoryview` buffers are copied to `bytes` at
  the FFI boundary; outputs are freshly-allocated `bytes`.
- libitb must be reachable at runtime through the lookup order above.
