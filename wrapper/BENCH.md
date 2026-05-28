# ITB Python Binding — Format-Deniability Wrapper Benchmark Results

> **Security notice.** ITB is an experimental symmetric cipher construction without prior peer review, independent cryptanalysis, or formal certification. The construction's security properties have **not been verified** by independent cryptographers or mathematicians.
>
> PRF-grade hash functions are **required**. No warranty is provided.

**No bespoke cryptography.** ITB introduces no cryptographic primitive of its own — no custom S-box, permutation, or round function. It is a construction over existing primitives, much as PGP composes standard ciphers rather than defining one. Such constructions are not the object of algorithm-level cryptographic certification: national regimes (NIST CAVP/FIPS in the US, GOST/FSB in Russia, KCMVP in South Korea, OSCCA's SM-series in China, SOG-IS/EUCC and national lists in the EU, ASD's ISM in Australia) certify **primitives** and the **modules** built on them, not compositional schemes. Eligibility for regulated use is therefore inherited from the primitives ITB is configured with, not conferred by ITB itself.

The wrapper layer prefixes a fresh CSPRNG nonce and XORs every byte of an ITB ciphertext under one of outer keystream ciphers, one per PRF-grade ITB registry primitive in CTR mode. The keystream construction is delegated libitb-side to the `ctr` package. The wire format becomes `nonce || keystream-XOR(bytestream)`, indistinguishable from any generic stream-cipher payload by surface pattern; ITB's own content-deniability is unchanged.

The numbers below isolate the **outer cipher cost** that the wrapper layer adds on top of ITB. Two test scopes:

* **Wrapper Only** — 16 MiB random buffer, no ITB call. Pure outer cipher round-trip throughput. The `wrap_in_place` row mutates the caller's `bytearray` (no output-buffer allocation); the `wrap` row allocates a fresh output buffer per call.
* **Full ITB + wrapper** — encrypt and decrypt are timed **separately** (split sub-benches `…/encrypt` and `…/decrypt`) so the per-direction breakdown is visible. Both Single Ouroboros and Triple Ouroboros are reported. Single-message benches process a 16 MiB plaintext under one encrypt / wrap call (or one unwrap / decrypt call). Streaming benches process a 64 MiB plaintext through 16 MiB chunks via either ITB's streaming AEAD entry points or a User-Driven Loop emitting framed chunks through the wrapped writer.

The wrapper bench covers all outer ciphers — each in CTR mode.

Outer-cipher overhead on a 16 HT host with hardware AES-NI is effectively zero — the AES-CTR keystream finishes well ahead of every ITB-encrypt slot, and the `wrap_in_place` path avoids output-buffer allocation. **On larger Triple Ouroboros hosts (e.g. AMD EPYC 9655P, 192 HT) the picture inverts for the non-AES outer ciphers**: ITB's per-pixel hashing scales across all available HT, while the wrapper's keystream XOR splits across up to 32 worker goroutines (`min(32, GOMAXPROCS, chunks)`) inside libitb for buffers at or above the 256 KiB threshold, each worker seeking its own keystream to its chunk offset via `ctr.NewAt`; buffers below the threshold run serially.

The Python binding adds the per-call cffi crossing and a `bytes` materialisation on the helper return path. The wrapper only row therefore reads slightly under the matching Go-native row at 16 MiB; the gap closes on the full ITB + wrapper rows, where the ITB encrypt / decrypt time dominates over the keystream XOR + cffi overhead.

## Binding asymmetry note

The Python binding's Streaming No MAC arm covers the User-Driven Loop variant only — there is no IO-Driven Streaming No MAC writer / reader pair. The Streaming AEAD path covers IO-Driven for both Easy and Low-Level.

## Reproduction

```sh
# Build libitb.so:
go build -trimpath -buildmode=c-shared -o dist/linux-amd64/libitb.so ./cmd/cshared

# Run the full 306-case sub-bench matrix:
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

* Outer cipher path: all PRF-grade registry primitives, keystream built libitb-side via the `ctr` package.
* ITB primitive: Areion-SoEM-512.
* ITB seed width: 1024 bits.
* ITB cipher config: `nonce_bits=128`, `barrier_fill=1`, `bit_soup=0`, `lock_soup=0` (minimum config so the outer cipher delta is not masked by per-pixel feature cost).
* `itb.set_max_workers(0)` (use every available HT for the per-pixel hash kernels).
* MAC factory: HMAC-BLAKE3, 32-byte CSPRNG key (where applicable).
* Single-message plaintext: 16 MiB random.
* Streaming plaintext: 64 MiB random; chunk size 16 MiB.
* Decrypt-only sub-benches refresh the working wire from a pristine copy each iteration via `bytes()`; the memcpy is included in the timed total. This overhead is small relative to ITB's Decrypt cost on this hardware.

Column abbreviations in the Full ITB + wrapper tables: **LL** = Low-Level, **Loop** = User-Driven Loop, **IO** = IO-Driven, **NoMAC** = No MAC, **MAC** = MAC Authenticated, **Enc** / **Dec** = encrypt / decrypt direction. All throughput is MB/s, rounded.

### Wrapper only round-trip (16 MiB plaintext, encrypt + decrypt timed together)

| Outer cipher | `Wrap` (alloc) MB/s | `wrap_in_place` (no output-buffer alloc) MB/s |
|---|---|---|
| **Areion-SoEM-256** | 1391 | 701 |
| **Areion-SoEM-512** | 1404 | 717 |
| **BLAKE2b-256** | 561 | 410 |
| **BLAKE2b-512** | 905 | 558 |
| **BLAKE2s** | 598 | 431 |
| **BLAKE3** | 999 | 604 |
| **AES-128-CTR** | 2091 | 931 |
| **SipHash-2-4** | 1679 | 792 |
| **ChaCha20** | 1643 | 788 |

### Single Message — Single Ouroboros (16 MiB plaintext)

| Cipher | Easy NoMAC Enc | Easy NoMAC Dec | Easy MAC Enc | Easy MAC Dec | LL NoMAC Enc | LL NoMAC Dec | LL MAC Enc | LL MAC Dec |
|---|---|---|---|---|---|---|---|---|
| **Areion-SoEM-256** | 144 | 261 | 161 | 254 | 173 | 274 | 159 | 255 |
| **Areion-SoEM-512** | 171 | 276 | 161 | 251 | 173 | 274 | 160 | 254 |
| **BLAKE2b-256** | 157 | 234 | 147 | 220 | 158 | 232 | 147 | 219 |
| **BLAKE2b-512** | 167 | 259 | 155 | 240 | 166 | 256 | 156 | 240 |
| **BLAKE2s** | 158 | 239 | 149 | 223 | 161 | 236 | 148 | 221 |
| **BLAKE3** | 169 | 265 | 158 | 248 | 168 | 262 | 158 | 246 |
| **AES-128-CTR** | 178 | 285 | 164 | 262 | 177 | 285 | 164 | 263 |
| **SipHash-2-4** | 174 | 282 | 162 | 257 | 175 | 280 | 160 | 260 |
| **ChaCha20** | 175 | 277 | 161 | 259 | 175 | 280 | 162 | 259 |

### Single Message — Triple Ouroboros (16 MiB plaintext)

| Cipher | Easy NoMAC Enc | Easy NoMAC Dec | Easy MAC Enc | Easy MAC Dec | LL NoMAC Enc | LL NoMAC Dec | LL MAC Enc | LL MAC Dec |
|---|---|---|---|---|---|---|---|---|
| **Areion-SoEM-256** | 223 | 302 | 199 | 279 | 226 | 296 | 202 | 280 |
| **Areion-SoEM-512** | 223 | 299 | 205 | 282 | 225 | 298 | 205 | 281 |
| **BLAKE2b-256** | 195 | 252 | 182 | 237 | 194 | 251 | 182 | 238 |
| **BLAKE2b-512** | 210 | 277 | 191 | 262 | 214 | 280 | 196 | 264 |
| **BLAKE2s** | 197 | 256 | 185 | 243 | 199 | 256 | 183 | 243 |
| **BLAKE3** | 215 | 285 | 200 | 271 | 216 | 285 | 199 | 271 |
| **AES-128-CTR** | 230 | 309 | 213 | 289 | 233 | 313 | 212 | 293 |
| **SipHash-2-4** | 226 | 306 | 208 | 290 | 225 | 305 | 208 | 290 |
| **ChaCha20** | 225 | 302 | 208 | 287 | 225 | 306 | 207 | 286 |

### Streaming — Single Ouroboros (64 MiB plaintext, 16 MiB chunk size) — AEAD

| Cipher | AEAD Easy IO Enc | AEAD Easy IO Dec | AEAD LL IO Enc | AEAD LL IO Dec |
|---|---|---|---|---|
| **Areion-SoEM-256** | 109 | 130 | 105 | 131 |
| **Areion-SoEM-512** | 105 | 132 | 105 | 130 |
| **BLAKE2b-256** | 100 | 123 | 100 | 122 |
| **BLAKE2b-512** | 103 | 128 | 103 | 128 |
| **BLAKE2s** | 101 | 123 | 98 | 124 |
| **BLAKE3** | 104 | 128 | 103 | 128 |
| **AES-128-CTR** | 107 | 133 | 107 | 133 |
| **SipHash-2-4** | 106 | 132 | 105 | 131 |
| **ChaCha20** | 105 | 131 | 105 | 131 |

### Streaming — Single Ouroboros (64 MiB plaintext, 16 MiB chunk size) — Non-AEAD (User-Driven Loop)

| Cipher | Easy Loop Enc | Easy Loop Dec | LL Loop Enc | LL Loop Dec |
|---|---|---|---|---|
| **Areion-SoEM-256** | 143 | 183 | 142 | 182 |
| **Areion-SoEM-512** | 142 | 183 | 142 | 184 |
| **BLAKE2b-256** | 132 | 166 | 132 | 166 |
| **BLAKE2b-512** | 138 | 177 | 138 | 176 |
| **BLAKE2s** | 133 | 167 | 133 | 167 |
| **BLAKE3** | 139 | 178 | 140 | 178 |
| **AES-128-CTR** | 146 | 191 | 146 | 187 |
| **SipHash-2-4** | 143 | 186 | 144 | 183 |
| **ChaCha20** | 142 | 186 | 143 | 184 |

### Streaming — Triple Ouroboros (64 MiB plaintext, 16 MiB chunk size) — AEAD

| Cipher | AEAD Easy IO Enc | AEAD Easy IO Dec | AEAD LL IO Enc | AEAD LL IO Dec |
|---|---|---|---|---|
| **Areion-SoEM-256** | 123 | 145 | 124 | 145 |
| **Areion-SoEM-512** | 124 | 144 | 124 | 145 |
| **BLAKE2b-256** | 115 | 132 | 115 | 134 |
| **BLAKE2b-512** | 121 | 140 | 120 | 141 |
| **BLAKE2s** | 117 | 134 | 116 | 135 |
| **BLAKE3** | 121 | 141 | 121 | 142 |
| **AES-128-CTR** | 127 | 148 | 127 | 148 |
| **SipHash-2-4** | 126 | 145 | 125 | 147 |
| **ChaCha20** | 125 | 146 | 124 | 147 |

### Streaming — Triple Ouroboros (64 MiB plaintext, 16 MiB chunk size) — Non-AEAD (User-Driven Loop)

| Cipher | Easy Loop Enc | Easy Loop Dec | LL Loop Enc | LL Loop Dec |
|---|---|---|---|---|
| **Areion-SoEM-256** | 178 | 200 | 177 | 197 |
| **Areion-SoEM-512** | 177 | 199 | 176 | 199 |
| **BLAKE2b-256** | 161 | 179 | 159 | 178 |
| **BLAKE2b-512** | 172 | 190 | 170 | 186 |
| **BLAKE2s** | 161 | 179 | 160 | 180 |
| **BLAKE3** | 171 | 194 | 172 | 192 |
| **AES-128-CTR** | 183 | 205 | 181 | 203 |
| **SipHash-2-4** | 181 | 202 | 177 | 197 |
| **ChaCha20** | 179 | 202 | 178 | 200 |

This file is updated by re-running the reproduction command and pasting the bench output into the tables. Numbers above are rounded to MB/s.
