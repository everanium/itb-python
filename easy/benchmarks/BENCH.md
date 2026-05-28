# ITB Python Binding - Easy Mode Benchmark Results

> **Security notice.** ITB is an experimental symmetric cipher construction without prior peer review, independent cryptanalysis, or formal certification. The construction's security properties have **not been verified** by independent cryptographers or mathematicians.
>
> PRF-grade hash functions are **required**. No warranty is provided.

**No bespoke cryptography.** ITB introduces no cryptographic primitive of its own — no custom S-box, permutation, or round function. It is a construction over existing primitives, much as PGP composes standard ciphers rather than defining one. Such constructions are not the object of algorithm-level cryptographic certification: national regimes (NIST CAVP/FIPS in the US, GOST/FSB in Russia, KCMVP in South Korea, OSCCA's SM-series in China, SOG-IS/EUCC and national lists in the EU, ASD's ISM in Australia) certify **primitives** and the **modules** built on them, not compositional schemes. Eligibility for regulated use is therefore inherited from the primitives ITB is configured with, not conferred by ITB itself.

Throughput (MB/s) of `itb.Encryptor.encrypt` / `decrypt` /
`encrypt_auth` / `decrypt_auth` over the libitb c-shared library
through the cffi binding. Single + Triple Ouroboros at 1024-bit
ITB key width on a 16 MiB CSPRNG-filled payload, four ops per
primitive. The MAC slot is bound to **HMAC-BLAKE3** — the lightest
authenticated-mode overhead among the three shipping MACs (the
`encrypt_auth` row sits within a few percent of the matching
`encrypt` row).

The harness lives in this directory — see [README.md](README.md)
for invocation, environment variables, and the per-case output
format. The default measurement window is 5 seconds per case
(`ITB_BENCH_MIN_SEC=5`), wide enough to absorb the cold-cache /
warm-up transient that distorts shorter windows on the 16 MiB
encrypt / decrypt path.

## FFI overhead vs. native Go

The Python path adds buffer-protocol marshalling, a cgo crossing
per call, and a result-copy from the c-shared output buffer back
into a Python `bytes` object. After the binding-side optimisations
landed (`60033eb` — bench infrastructure, `15a08de` — output-buffer
cache + skip the size-probe round-trip + pass-through input
handling) the typical primitive lands in the **84 % – 95 %**
throughput band relative to the matching Go bench in the root
[BENCH.md](../../../../BENCH.md). For applications where every
percent of throughput matters, the native
[github.com/everanium/itb/easy](../../../../easy) Go API
delivers the full asm-accelerated speed of the encrypt /
decrypt path.

The numbers below ride the default build (no opt-out tags). On
hosts without AVX-512+VL the Go side automatically nil-routes
the 4-lane batched chain-absorb arm so the per-pixel hash falls
through to the upstream stdlib asm via the single Func — see the
build-tag table in the [`../../README.md`](../../README.md)
for the `-tags=noitbasm` opt-outs.

## Intel Core i7-11700K (16 HT, native Linux, c-shared mode)

### ITB Single 1024-bit (security: P × 2^1024)

| Hash | Width | Crypto | Encrypt | Decrypt | Encrypt + MAC | Decrypt + MAC |
|---|---|---|---|---|---|---|
| **Areion-SoEM-256** | 256 | PRF | 188 | 284 | 186 | 270 |
| **Areion-SoEM-512** | 512 | PRF | 206 | 302 | 191 | 279 |
| **BLAKE2b-256** | 256 | PRF | 97 | 111 | 92 | 108 |
| **BLAKE2b-512** | 512 | PRF | 138 | 173 | 131 | 165 |
| **BLAKE2s** | 256 | PRF | 102 | 121 | 99 | 117 |
| **BLAKE3** | 256 | PRF | 121 | 150 | 116 | 141 |
| **AES-CMAC** | 128 | PRF | 187 | 261 | 172 | 242 |
| **SipHash-2-4** | 128 | PRF | 152 | 195 | 140 | 185 |
| **ChaCha20** | 256 | PRF | 111 | 130 | 105 | 126 |
| **Mixed** | 256 | PRF | 109 | 133 | 107 | 130 |

### ITB Triple 1024-bit (security: P × 2^(3×1024) = P × 2^3072)

| Hash | Width | Crypto | Encrypt | Decrypt | Encrypt + MAC | Decrypt + MAC |
|---|---|---|---|---|---|---|
| **Areion-SoEM-256** | 256 | PRF | 273 | 327 | 242 | 307 |
| **Areion-SoEM-512** | 512 | PRF | 275 | 338 | 252 | 318 |
| **BLAKE2b-256** | 256 | PRF | 105 | 112 | 101 | 110 |
| **BLAKE2b-512** | 512 | PRF | 163 | 178 | 153 | 174 |
| **BLAKE2s** | 256 | PRF | 116 | 124 | 110 | 120 |
| **BLAKE3** | 256 | PRF | 144 | 156 | 135 | 149 |
| **AES-CMAC** | 128 | PRF | 251 | 295 | 225 | 279 |
| **SipHash-2-4** | 128 | PRF | 188 | 210 | 174 | 203 |
| **ChaCha20** | 256 | PRF | 127 | 136 | 119 | 132 |
| **Mixed** | 256 | PRF | 124 | 134 | 118 | 131 |

## Intel Core i7-11700K (16 HT, native Linux, c-shared mode, Lock Seed + Lock Batch mode)

The Lock Batch performance variant (`ITB_LOCKSEED=1 ITB_LOCKBATCH=1` /
`set_lock_batch(1)`) batches the per-chunk Lock Soup overlay derivation,
reducing per-chunk PRF invocations without affecting security under the
PRF assumption. Numbers below run with `ITB_LOCKSEED=1 ITB_LOCKBATCH=1`,
default nonce, 16 MiB payload, `ITB_BENCH_MIN_SEC=5`.

### ITB Single 1024-bit (security: P × 2^1024)

| Hash | Width | Crypto | Encrypt | Decrypt | Encrypt + MAC | Decrypt + MAC |
|---|---|---|---|---|---|---|
| **Areion-SoEM-256** | 256 | PRF | 95 | 120 | 96 | 123 |
| **Areion-SoEM-512** | 512 | PRF | 116 | 141 | 111 | 133 |
| **BLAKE2b-256** | 256 | PRF | 65 | 71 | 63 | 70 |
| **BLAKE2b-512** | 512 | PRF | 91 | 105 | 88 | 102 |
| **BLAKE2s** | 256 | PRF | 67 | 75 | 66 | 73 |
| **BLAKE3** | 256 | PRF | 74 | 81 | 71 | 80 |
| **AES-CMAC** | 128 | PRF | 94 | 111 | 91 | 107 |
| **SipHash-2-4** | 128 | PRF | 83 | 95 | 80 | 92 |
| **ChaCha20** | 256 | PRF | 68 | 76 | 67 | 75 |
| **Mixed** | 256 | PRF | 52 | 57 | 51 | 56 |

### ITB Triple 1024-bit (security: P × 2^(3×1024) = P × 2^3072)

| Hash | Width | Crypto | Encrypt | Decrypt | Encrypt + MAC | Decrypt + MAC |
|---|---|---|---|---|---|---|
| **Areion-SoEM-256** | 256 | PRF | 155 | 200 | 165 | 193 |
| **Areion-SoEM-512** | 512 | PRF | 198 | 221 | 182 | 196 |
| **BLAKE2b-256** | 256 | PRF | 76 | 86 | 80 | 84 |
| **BLAKE2b-512** | 512 | PRF | 128 | 138 | 122 | 135 |
| **BLAKE2s** | 256 | PRF | 88 | 93 | 85 | 91 |
| **BLAKE3** | 256 | PRF | 99 | 104 | 93 | 101 |
| **AES-CMAC** | 128 | PRF | 151 | 164 | 143 | 159 |
| **SipHash-2-4** | 128 | PRF | 124 | 132 | 117 | 129 |
| **ChaCha20** | 256 | PRF | 89 | 93 | 85 | 92 |
| **Mixed** | 256 | PRF | 52 | 52 | 49 | 51 |

## Intel Core i7-11700K (16 HT, native Linux, c-shared mode, LockSeed mode)

The dedicated lockSeed channel (`set_lock_seed(1)` / `ITB_LOCKSEED=1`)
auto-couples bit-soup + lock-soup on the on-direction. Numbers
below run with all three overlays active. Adding `ITB_LOCKBATCH=1`
(`set_lock_batch(1)`) before `ITB_LOCKSEED=1` selects the Lock Batch
performance variant of Lock Soup.

### ITB Single 1024-bit (security: P × 2^1024)

| Hash | Width | Crypto | Encrypt | Decrypt | Encrypt + MAC | Decrypt + MAC |
|---|---|---|---|---|---|---|
| **Areion-SoEM-256** | 256 | PRF | 60 | 69 | 61 | 70 |
| **Areion-SoEM-512** | 512 | PRF | 51 | 57 | 51 | 56 |
| **BLAKE2b-256** | 256 | PRF | 42 | 46 | 42 | 45 |
| **BLAKE2b-512** | 512 | PRF | 47 | 51 | 47 | 51 |
| **BLAKE2s** | 256 | PRF | 45 | 48 | 44 | 47 |
| **BLAKE3** | 256 | PRF | 45 | 47 | 42 | 45 |
| **AES-CMAC** | 128 | PRF | 76 | 85 | 74 | 83 |
| **SipHash-2-4** | 128 | PRF | 68 | 77 | 66 | 75 |
| **ChaCha20** | 256 | PRF | 46 | 49 | 45 | 49 |
| **Mixed** | 256 | PRF | 50 | 55 | 48 | 54 |

### ITB Triple 1024-bit (security: P × 2^(3×1024) = P × 2^3072)

| Hash | Width | Crypto | Encrypt | Decrypt | Encrypt + MAC | Decrypt + MAC |
|---|---|---|---|---|---|---|
| **Areion-SoEM-256** | 256 | PRF | 62 | 66 | 62 | 65 |
| **Areion-SoEM-512** | 512 | PRF | 54 | 56 | 53 | 55 |
| **BLAKE2b-256** | 256 | PRF | 44 | 45 | 43 | 44 |
| **BLAKE2b-512** | 512 | PRF | 48 | 49 | 47 | 49 |
| **BLAKE2s** | 256 | PRF | 46 | 47 | 45 | 45 |
| **BLAKE3** | 256 | PRF | 44 | 43 | 42 | 43 |
| **AES-CMAC** | 128 | PRF | 78 | 81 | 76 | 78 |
| **SipHash-2-4** | 128 | PRF | 68 | 69 | 65 | 70 |
| **ChaCha20** | 256 | PRF | 48 | 46 | 39 | 42 |
| **Mixed** | 256 | PRF | 47 | 49 | 46 | 49 |
