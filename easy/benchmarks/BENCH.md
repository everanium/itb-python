# ITB Python Binding - Easy Mode Benchmark Results

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
build-tag table in the [Python binding README](../../README.md)
for the `-tags=purego` / `-tags=noitbasm` opt-outs.

## Intel Core i7-11700K (16 HT, native Linux, c-shared mode)

### ITB Single 1024-bit (security: P × 2^1024)

| Hash | Width | Crypto | Encrypt | Decrypt | Encrypt + MAC | Decrypt + MAC |
|---|---|---|---|---|---|---|
| **Areion-SoEM-256** | 256 | PRF | 188 | 284 | 186 | 270 |
| **Areion-SoEM-512** | 512 | PRF | 206 | 302 | 191 | 279 |
| **SipHash-2-4** | 128 | PRF | 152 | 195 | 140 | 185 |
| **AES-CMAC** | 128 | PRF | 187 | 261 | 172 | 242 |
| **BLAKE2b-512** | 512 | PRF | 138 | 173 | 131 | 165 |
| **BLAKE2b-256** | 256 | PRF | 97 | 111 | 92 | 108 |
| **BLAKE2s** | 256 | PRF | 102 | 121 | 99 | 117 |
| **BLAKE3** | 256 | PRF | 121 | 150 | 116 | 141 |
| **ChaCha20** | 256 | PRF | 111 | 130 | 105 | 126 |
| **Mixed** | 256 | PRF | 109 | 133 | 107 | 130 |

### ITB Triple 1024-bit (security: P × 2^(3×1024) = P × 2^3072)

| Hash | Width | Crypto | Encrypt | Decrypt | Encrypt + MAC | Decrypt + MAC |
|---|---|---|---|---|---|---|
| **Areion-SoEM-256** | 256 | PRF | 273 | 327 | 242 | 307 |
| **Areion-SoEM-512** | 512 | PRF | 275 | 338 | 252 | 318 |
| **SipHash-2-4** | 128 | PRF | 188 | 210 | 174 | 203 |
| **AES-CMAC** | 128 | PRF | 251 | 295 | 225 | 279 |
| **BLAKE2b-512** | 512 | PRF | 163 | 178 | 153 | 174 |
| **BLAKE2b-256** | 256 | PRF | 105 | 112 | 101 | 110 |
| **BLAKE2s** | 256 | PRF | 116 | 124 | 110 | 120 |
| **BLAKE3** | 256 | PRF | 144 | 156 | 135 | 149 |
| **ChaCha20** | 256 | PRF | 127 | 136 | 119 | 132 |
| **Mixed** | 256 | PRF | 124 | 134 | 118 | 131 |

## Intel Core i7-11700K (16 HT, native Linux, c-shared mode, LockSeed mode)

The dedicated lockSeed channel (`set_lock_seed(1)` / `ITB_LOCKSEED=1`)
auto-couples bit-soup + lock-soup on the on-direction. Numbers
below run with all three overlays active.

### ITB Single 1024-bit (security: P × 2^1024)

| Hash | Width | Crypto | Encrypt | Decrypt | Encrypt + MAC | Decrypt + MAC |
|---|---|---|---|---|---|---|
| **Areion-SoEM-256** | 256 | PRF | 60 | 69 | 61 | 70 |
| **Areion-SoEM-512** | 512 | PRF | 51 | 57 | 51 | 56 |
| **SipHash-2-4** | 128 | PRF | 68 | 77 | 66 | 75 |
| **AES-CMAC** | 128 | PRF | 76 | 85 | 74 | 83 |
| **BLAKE2b-512** | 512 | PRF | 47 | 51 | 47 | 51 |
| **BLAKE2b-256** | 256 | PRF | 42 | 46 | 42 | 45 |
| **BLAKE2s** | 256 | PRF | 45 | 48 | 44 | 47 |
| **BLAKE3** | 256 | PRF | 45 | 47 | 42 | 45 |
| **ChaCha20** | 256 | PRF | 46 | 49 | 45 | 49 |
| **Mixed** | 256 | PRF | 50 | 55 | 48 | 54 |

### ITB Triple 1024-bit (security: P × 2^(3×1024) = P × 2^3072)

| Hash | Width | Crypto | Encrypt | Decrypt | Encrypt + MAC | Decrypt + MAC |
|---|---|---|---|---|---|---|
| **Areion-SoEM-256** | 256 | PRF | 62 | 66 | 62 | 65 |
| **Areion-SoEM-512** | 512 | PRF | 54 | 56 | 53 | 55 |
| **SipHash-2-4** | 128 | PRF | 68 | 69 | 65 | 70 |
| **AES-CMAC** | 128 | PRF | 78 | 81 | 76 | 78 |
| **BLAKE2b-512** | 512 | PRF | 48 | 49 | 47 | 49 |
| **BLAKE2b-256** | 256 | PRF | 44 | 45 | 43 | 44 |
| **BLAKE2s** | 256 | PRF | 46 | 47 | 45 | 45 |
| **BLAKE3** | 256 | PRF | 44 | 43 | 42 | 43 |
| **ChaCha20** | 256 | PRF | 48 | 46 | 39 | 42 |
| **Mixed** | 256 | PRF | 47 | 49 | 46 | 49 |
