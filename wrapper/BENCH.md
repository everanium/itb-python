# ITB Python Binding — Format-Deniability Wrapper Benchmark Results

The wrapper layer prefixes a fresh CSPRNG nonce and XORs every byte of an ITB ciphertext under one of three outer keystream ciphers — AES-128-CTR (libitb-side stdlib AES-NI path), ChaCha20 (RFC8439) (`golang.org/x/crypto/chacha20`), or SipHash-2-4 in CTR mode (`dchest/siphash` PRF + custom counter loop). The wire format becomes `nonce || keystream-XOR(bytestream)`, indistinguishable from any generic stream-cipher payload by surface pattern; ITB's own content-deniability is unchanged.

The numbers below isolate the **outer cipher cost** that the wrapper layer adds on top of ITB. Two test scopes:

* **Wrapper Only** — 16 MiB random buffer, no ITB call. Pure outer cipher round-trip throughput. The `WrapInPlace` row mutates the caller's `bytearray` (zero-allocation steady state); the `Wrap` row allocates a fresh output buffer per call.
* **Full ITB + wrapper** — encrypt and decrypt are timed **separately** (split sub-benches `…/encrypt` and `…/decrypt`) so the per-direction breakdown is visible. Both Single Ouroboros and Triple Ouroboros are reported. Single-message benches process a 16 MiB plaintext under one encrypt / wrap call (or one unwrap / decrypt call). Streaming benches process a 64 MiB plaintext through 16 MiB chunks via either ITB's streaming AEAD entry points or a User-Driven Loop emitting framed chunks through the wrapped writer.

Outer-cipher overhead on a 16 HT host with hardware AES-NI is effectively zero — the AES-CTR keystream finishes well ahead of every ITB-encrypt slot, and the `WrapInPlace` path adds no allocation pressure. **On larger Triple Ouroboros hosts (e.g. AMD EPYC 9655P, 192 HT) the picture inverts for the non-AES outer ciphers**: ITB's per-pixel hashing scales across all available HT, while the wrapper's keystream XOR runs single-threaded on one core. ChaCha20 (~700 MB/s peak on a single core via `x/crypto/chacha20`) and SipHash-CTR (~250-280 MB/s peak via the `dchest/siphash` PRF + 8-byte refill loop) become the bottleneck once ITB's Triple decrypt path approaches ~1 GB/s on big-iron. AES-128-CTR retains hardware acceleration on every HT thread the goroutine lands on and stays out of the critical path even there.

The Python binding adds the per-call cffi crossing and a `bytes` materialisation on the helper return path. The wrapper only row therefore reads slightly under the matching Go-native row at 16 MiB; the gap closes on the full ITB + wrapper rows, where the ITB encrypt / decrypt time dominates over the keystream XOR + cffi overhead.

## Binding asymmetry note

The Python binding's Streaming No MAC arm covers the User-Driven Loop variant only — there is no IO-Driven Streaming No MAC writer / reader pair. The Streaming AEAD path covers IO-Driven for both Easy and Low-Level. See the "Binding asymmetry" section in [README.md](README.md).

## Reproduction

```sh
# Build libitb.so:
go build -trimpath -buildmode=c-shared -o dist/linux-amd64/libitb.so ./cmd/cshared

# Run the full 102-case sub-bench matrix:
PYTHONPATH=bindings/python python3 -m bindings.python.wrapper.benchmarks.bench_wrapper
```

Filter examples:

```sh
ITB_BENCH_FILTER=BenchmarkWrapperOnly \
    PYTHONPATH=bindings/python python3 -m bindings.python.wrapper.benchmarks.bench_wrapper

ITB_BENCH_FILTER=BenchmarkMessageSingle/easy-nomac \
    PYTHONPATH=bindings/python python3 -m bindings.python.wrapper.benchmarks.bench_wrapper

ITB_BENCH_FILTER=BenchmarkStreamingTriple \
    PYTHONPATH=bindings/python python3 -m bindings.python.wrapper.benchmarks.bench_wrapper
```

## Configuration

* Outer cipher path: AES-128-CTR / ChaCha20 (RFC8439) / SipHash-2-4 in CTR mode (libitb-side).
* ITB primitive: Areion-SoEM-512.
* ITB seed width: 1024 bits.
* ITB cipher config: `nonce_bits=128`, `barrier_fill=1`, `bit_soup=0`, `lock_soup=0` (minimum config so the outer cipher delta is not masked by per-pixel feature cost).
* `itb.set_max_workers(0)` (use every available HT for the per-pixel hash kernels).
* MAC factory: HMAC-BLAKE3, 32-byte CSPRNG key (where applicable).
* Single-message plaintext: 16 MiB random.
* Streaming plaintext: 64 MiB random; chunk size 16 MiB.
* Decrypt-only sub-benches refresh the working wire from a pristine copy each iteration via `bytes()`; the memcpy is included in the timed total. This overhead is small relative to ITB's Decrypt cost on this hardware.

### Wrapper only round-trip (16 MiB plaintext, encrypt + decrypt timed together)

| Outer cipher | `Wrap` (alloc) MB/s | `WrapInPlace` (zero alloc) MB/s |
|---|---|---|
| **AES-128-CTR** | 1814 | **1492** |
| **ChaCha20** | 307 | **291** |
| **SipHash-CTR** | 258 | **245** |

### Single Message — Single Ouroboros (16 MiB plaintext)

| Mode | AES Enc | AES Dec | ChaCha Enc | ChaCha Dec | SipHash Enc | SipHash Dec |
|---|---|---|---|---|---|---|
| **Easy** No MAC | 156 | 263 | 130 | 185 | 124 | 174 |
| **Easy** MAC Authenticated | 152 | 244 | 124 | 176 | 117 | 167 |
| **Low-Level** No MAC | 164 | 265 | 129 | 186 | 125 | 175 |
| **Low-Level** MAC Authenticated | 154 | 247 | 124 | 176 | 118 | 169 |

### Single Message — Triple Ouroboros (16 MiB plaintext)

| Mode | AES Enc | AES Dec | ChaCha Enc | ChaCha Dec | SipHash Enc | SipHash Dec |
|---|---|---|---|---|---|---|
| **Easy** No MAC | 215 | 308 | 162 | 209 | 153 | 195 |
| **Easy** MAC Authenticated | 197 | 286 | 152 | 200 | 143 | 186 |
| **Low-Level** No MAC | 218 | 309 | 163 | 211 | 153 | 195 |
| **Low-Level** MAC Authenticated | 193 | 287 | 151 | 201 | 143 | 185 |

### Streaming — Single Ouroboros (64 MiB plaintext, 16 MiB chunk size)

| Mode | AES Enc | AES Dec | ChaCha Enc | ChaCha Dec | SipHash Enc | SipHash Dec |
|---|---|---|---|---|---|---|
| **Streaming AEAD Easy** IO-Driven | 106 | 126 | 90 | 103 | 86 | 104 |
| **Streaming AEAD Low-Level** IO-Driven | 105 | 121 | 89 | 108 | 87 | 99 |
| **Streaming Easy** No MAC, User-Driven Loop | 146 | 167 | 130 | 131 | 110 | 126 |
| **Streaming Low-Level** No MAC, User-Driven Loop | 137 | 158 | 113 | 132 | 109 | 126 |

### Streaming — Triple Ouroboros (64 MiB plaintext, 16 MiB chunk size)

| Mode | AES Enc | AES Dec | ChaCha Enc | ChaCha Dec | SipHash Enc | SipHash Dec |
|---|---|---|---|---|---|---|
| **Streaming AEAD Easy** IO-Driven | 121 | 157 | 107 | 115 | 98 | 120 |
| **Streaming AEAD Low-Level** IO-Driven | 129 | 141 | 101 | 126 | 103 | 110 |
| **Streaming Easy** No MAC, User-Driven Loop | 175 | 183 | 137 | 138 | 131 | 134 |
| **Streaming Low-Level** No MAC, User-Driven Loop | 174 | 181 | 136 | 141 | 131 | 135 |

This file is updated by re-running the reproduction command and pasting the bench output into the tables. Numbers above are rounded to MB/s.
