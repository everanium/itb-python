# ITB Python Binding

Cffi-based Python wrapper over the libitb shared library
(`cmd/cshared`). ABI mode — no C compiler at install time, just
``cffi``.

**Path placeholder.** `<itb>` denotes the path to the local ITB
repository checkout (or this binding's mirror clone) — for example,
`/home/you/go/src/itb` or `~/projects/itb-python`. Substitute the
literal token in the recipes below.

## Prerequisites (Arch Linux)

```bash
sudo pacman -S go go-tools python python-cffi
```

## Build the shared library

The convenience driver `bindings/python/build.sh` builds
`libitb.so` in one step. Run it from anywhere:

```bash
./bindings/python/build.sh
```

The driver wraps the libitb build from the repo root; the Python
binding loads `libitb.so` at runtime via cffi with no further
build step on the binding side. Equivalent manual invocation:

```bash
go build -trimpath -buildmode=c-shared \
    -o dist/linux-amd64/libitb.so ./cmd/cshared
```

(macOS produces `libitb.dylib` under `dist/darwin-<arch>/`,
Windows produces `libitb.dll` under `dist/windows-<arch>/`.)

## Library lookup order

1. `ITB_LIBRARY_PATH` environment variable (absolute path).
2. `<repo>/dist/<os>-<arch>/libitb.<ext>` resolved by walking four
   directory levels up from `bindings/python/itb/_ffi.py`.
3. System loader path (`ld.so.cache`, `DYLD_LIBRARY_PATH`, `PATH`).

## Memory

Two process-wide knobs constrain Go runtime arena pacing. Both readable at libitb load time via env vars:

- `ITB_GOMEMLIMIT=512MiB` — soft memory limit in bytes; supports `B` / `KiB` / `MiB` / `GiB` / `TiB` suffixes.
- `ITB_GOGC=20` — GC trigger percentage; default `100`, lower triggers GC more aggressively.

Programmatic setters override env-set values at any time. Pass `-1` to either setter to query the current value without changing it.

```python
itb.set_memory_limit(512 * 1024 * 1024)
itb.set_gc_percent(20)
```

## Tests

```bash
./bindings/python/run_tests.sh
```

The harness verifies `libitb.so` is present, exports
`LD_LIBRARY_PATH`, and invokes
`python -m unittest discover -v tests`. Positional arguments are
forwarded straight to unittest (e.g.
`./run_tests.sh tests/test_blake3.py` to scope the run to one
file). The integration test suite under `bindings/python/tests/`
mirrors the cross-binding coverage: Single + Triple Ouroboros,
mixed primitives, authenticated paths, blob round-trip, streaming
chunked I/O, error paths, lockSeed lifecycle.

## Benchmarks

A custom Go-bench-style harness lives under `easy/benchmarks/`
and covers the four ops (`encrypt`, `decrypt`, `encrypt_auth`,
`decrypt_auth`) across the nine PRF-grade primitives plus one
mixed-primitive variant for both Single and Triple Ouroboros at
1024-bit ITB key width and 16 MiB payload. See
[`easy/benchmarks/README.md`](easy/benchmarks/README.md) for
invocation / environment variables / output format and
[`easy/benchmarks/BENCH.md`](easy/benchmarks/BENCH.md) for
recorded throughput results across the canonical pass matrix.

The four-pass canonical sweep (Single + Triple × ±LockSeed) that
fills `easy/benchmarks/BENCH.md` is driven by the wrapper script
in the binding root:

```bash
./bindings/python/run_bench.sh                  # full 4-pass canonical sweep
./bindings/python/run_bench.sh --lockseed-only  # pass 3 + pass 4 only
```

The harness sets `LD_LIBRARY_PATH` to `dist/linux-amd64/`,
manages `ITB_LOCKSEED` per pass, and forwards `ITB_NONCE_BITS` /
`ITB_BENCH_FILTER` / `ITB_BENCH_MIN_SEC` straight through to the
underlying `python -m easy.benchmarks.bench_single` /
`python -m easy.benchmarks.bench_triple` invocations.

## Streaming AEAD

**Streaming AEAD** authenticates a chunked stream end-to-end while
preserving the deniability of the per-chunk MAC-Inside-Encrypt
container. Each chunk's MAC binds the encrypted payload to a 32-byte
CSPRNG stream anchor (written as a once-per-stream wire prefix), the
cumulative pixel offset of preceding chunks, and a final-flag bit —
defending against chunk reorder, replay within or across streams
sharing the PRF / MAC key, silent mid-stream drop, and truncate-tail.
The wire format adds 32 bytes of stream prefix plus one byte of
encrypted trailing flag per chunk; no externally visible MAC tag.

The two examples below encrypt a 64 MiB random source file in 16 MiB
chunks and verify a sha256 round-trip on the decrypted output.
Production deployments typically encrypt files at 1 GiB+ scale through
the same loop pattern; the chunk size selection (16 MiB here) controls
per-iteration memory residency.

**Easy Mode:**

`Encryptor.encrypt_stream_auth` consumes a
binary file-like input, emits the on-wire transcript (32-byte
`stream_id` prefix + chunked authenticated body) to a binary file-like
output. The matching `decrypt_stream_auth` reverses the flow on the
same encryptor. The MAC key is generated CSPRNG-fresh inside the
encryptor at constructor time and is not exposed to the caller.

```python
import hashlib
import os
import itb
from itb import wrapper

SRC_PATH = "/tmp/64mb.src"
ENC_PATH = "/tmp/64mb.enc"
DST_PATH = "/tmp/64mb.dst"
CHUNK_SIZE = 16 * 1024 * 1024

def sha256_of(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()

# Materialise a 64 MiB random source file once.
if not os.path.exists(SRC_PATH) or os.path.getsize(SRC_PATH) != 64 * 1024 * 1024:
    with open("/dev/urandom", "rb") as r, open(SRC_PATH, "wb") as w:
        w.write(r.read(64 * 1024 * 1024))

# Outer cipher key - preferred surface for HKDF / ML-KEM / key-rotation policy in user-side application. ITB Inner seeds + PRF key keep as CSPRNG derived.
outer_key = wrapper.generate_key(wrapper.CIPHER_AES128_CTR)

enc = itb.Encryptor(primitive="areion512", key_bits=1024,
                    mac="hmac-blake3", mode=1)
try:
    # Sender - encrypt to an intermediate file, then wrap the entire
    # bytestream end-to-end through one keystream session.
    with open(SRC_PATH, "rb") as fin, open(ENC_PATH + ".inner", "wb") as fout:
        enc.encrypt_stream_auth(fin, fout, chunk_size=CHUNK_SIZE)

    # Format-deniability ITB masking via outer-cipher wrapper (AES-128-CTR) ~0% overhead (Recommended in every case).
    with wrapper.WrapStreamWriter(wrapper.CIPHER_AES128_CTR, outer_key) as ww, \
            open(ENC_PATH + ".inner", "rb") as fin, open(ENC_PATH, "wb") as fout:
        fout.write(ww.nonce)
        for chunk in iter(lambda: fin.read(CHUNK_SIZE), b""):
            fout.write(ww.update(chunk))
    os.remove(ENC_PATH + ".inner")

    # Receiver - strip the leading nonce, unwrap the body, decrypt.
    nonce_len = wrapper.nonce_size(wrapper.CIPHER_AES128_CTR)
    with open(ENC_PATH, "rb") as fin:
        nonce_part = fin.read(nonce_len)
        with wrapper.UnwrapStreamReader(wrapper.CIPHER_AES128_CTR, outer_key, nonce_part) as ur, \
                open(ENC_PATH + ".inner", "wb") as fout:
            for chunk in iter(lambda: fin.read(CHUNK_SIZE), b""):
                fout.write(ur.update(chunk))
    with open(ENC_PATH + ".inner", "rb") as fin, open(DST_PATH, "wb") as fout:
        enc.decrypt_stream_auth(fin, fout, read_size=CHUNK_SIZE)
    os.remove(ENC_PATH + ".inner")
finally:
    enc.close()

src_hash = sha256_of(SRC_PATH)
dst_hash = sha256_of(DST_PATH)
print(f"Easy Mode src sha256: {src_hash}")
print(f"Easy Mode dst sha256: {dst_hash}")
assert src_hash == dst_hash
print("[OK] Easy Mode: 64 MiB roundtrip via stream-auth verified")
```

**Build + run:**

```sh
# One-time install of the binding from the repo (editable mode).
pip install -e <itb>/bindings/python

# Place the source above in <itb>/python_example/main.py and run:
cd <itb>/python_example && python3 main.py
```

The binding's library-lookup logic locates
`<itb>/dist/<os>-<arch>/libitb.so` automatically once the editable
install resolves the `itb` package — no `ITB_LIBRARY_PATH` export is
required when the shared library lives under the repository's
canonical `dist/` tree. Override with `ITB_LIBRARY_PATH=/abs/path` to
point at a non-canonical build.

**Output (verified):**

```
Easy Mode src sha256: 7adc82f9bebf205db2a6c8033d7c1fe43d3bf8b3ecb0fbfd6c4c2dff71672425
Easy Mode dst sha256: 7adc82f9bebf205db2a6c8033d7c1fe43d3bf8b3ecb0fbfd6c4c2dff71672425
[OK] Easy Mode: 64 MiB roundtrip via stream-auth verified
```

---

**Low-Level Mode:**

Module-level free functions
`itb.encrypt_stream_auth` / `itb.decrypt_stream_auth` take three
explicit `Seed` handles plus an explicitly constructed `itb.MAC`
(32-byte key drawn from `os.urandom`) and stream through the same
chunked-AEAD construction. The seeds and MAC handle are caller-owned
and must be freed when no longer needed.

```python
import hashlib
import os
import itb
from itb import wrapper

SRC_PATH = "/tmp/64mb.src"
ENC_PATH = "/tmp/64mb.enc"
DST_PATH = "/tmp/64mb.dst"
CHUNK_SIZE = 16 * 1024 * 1024

def sha256_of(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()

# Outer cipher key - preferred surface for HKDF / ML-KEM / key-rotation policy in user-side application. ITB Inner seeds + PRF key keep as CSPRNG derived.
outer_key = wrapper.generate_key(wrapper.CIPHER_AES128_CTR)

noise = itb.Seed("areion512", 1024)
data  = itb.Seed("areion512", 1024)
start = itb.Seed("areion512", 1024)
mac_key = os.urandom(32)
mac = itb.MAC("hmac-blake3", mac_key)
try:
    # Sender - encrypt to an intermediate file, then wrap end-to-end
    # through one keystream session.
    with open(SRC_PATH, "rb") as fin, open(ENC_PATH + ".inner", "wb") as fout:
        itb.encrypt_stream_auth(noise, data, start, mac, fin, fout,
                                chunk_size=CHUNK_SIZE)

    # Format-deniability ITB masking via outer-cipher wrapper (AES-128-CTR) ~0% overhead (Recommended in every case).
    with wrapper.WrapStreamWriter(wrapper.CIPHER_AES128_CTR, outer_key) as ww, \
            open(ENC_PATH + ".inner", "rb") as fin, open(ENC_PATH, "wb") as fout:
        fout.write(ww.nonce)
        for chunk in iter(lambda: fin.read(CHUNK_SIZE), b""):
            fout.write(ww.update(chunk))
    os.remove(ENC_PATH + ".inner")

    # Receiver
    nonce_len = wrapper.nonce_size(wrapper.CIPHER_AES128_CTR)
    with open(ENC_PATH, "rb") as fin:
        nonce_part = fin.read(nonce_len)
        with wrapper.UnwrapStreamReader(wrapper.CIPHER_AES128_CTR, outer_key, nonce_part) as ur, \
                open(ENC_PATH + ".inner", "wb") as fout:
            for chunk in iter(lambda: fin.read(CHUNK_SIZE), b""):
                fout.write(ur.update(chunk))
    with open(ENC_PATH + ".inner", "rb") as fin, open(DST_PATH, "wb") as fout:
        itb.decrypt_stream_auth(noise, data, start, mac, fin, fout,
                                read_size=CHUNK_SIZE)
    os.remove(ENC_PATH + ".inner")
finally:
    mac.free()
    noise.free(); data.free(); start.free()

src_hash = sha256_of(SRC_PATH)
dst_hash = sha256_of(DST_PATH)
print(f"Low-Level src sha256: {src_hash}")
print(f"Low-Level dst sha256: {dst_hash}")
assert src_hash == dst_hash
print("[OK] Low-Level Mode: 64 MiB roundtrip via stream-auth verified")
```

**Build + run:**

```sh
cd <itb>/python_example && python3 main.py
```

**Output (verified):**

```
Low-Level src sha256: 7adc82f9bebf205db2a6c8033d7c1fe43d3bf8b3ecb0fbfd6c4c2dff71672425
Low-Level dst sha256: 7adc82f9bebf205db2a6c8033d7c1fe43d3bf8b3ecb0fbfd6c4c2dff71672425
[OK] Low-Level Mode: 64 MiB roundtrip via stream-auth verified
```

The full-flow examples use `areion512` PRF + 1024-bit ITB key +
`hmac-blake3` authenticator. The Easy Mode `Encryptor` constructor
does not accept a `mac_key` parameter — the MAC key is allocated
CSPRNG-fresh at construction time and lives entirely inside the
encryptor. The 32-byte `mac_key` argument shape applies only to the
low-level `itb.MAC(name, key)` constructor.

## Quick Start — `itb.Encryptor` (No MAC)

The high-level :class:`itb.Encryptor` (mirroring the
``github.com/everanium/itb/easy`` Go sub-package) replaces the
seven-line setup ceremony of the lower-level
``Seed`` / ``encrypt`` / ``decrypt`` path with one constructor call:
the encryptor allocates its own three (Single) or seven (Triple)
seeds + MAC closure, snapshots the global configuration into a
per-instance Config, and exposes setters that mutate only its own
state without touching the process-wide ``itb.set_*`` accessors.
Two encryptors with different settings can run concurrently without
cross-contamination.

```python
# Sender

import itb
from itb import wrapper

# Outer cipher key - preferred surface for HKDF / ML-KEM / key-rotation policy in user-side application. ITB Inner seeds + PRF key keep as CSPRNG derived.
outer_key = wrapper.generate_key(wrapper.CIPHER_AES128_CTR)

# Per-instance configuration — mutates only this encryptor's Config.
# Two encryptors built side-by-side carry independent settings;
# process-wide itb.set_* accessors are NOT consulted after
# construction.
with itb.Encryptor("areion512", 2048, "hmac-blake3") as enc:
    enc.set_nonce_bits(512)   # 512-bit nonce (default: 128-bit)
    enc.set_barrier_fill(4)   # CSPRNG fill margin (default: 1, valid: 1, 2, 4, 8, 16, 32)
    enc.set_bit_soup(1)       # optional bit-level split ("bit-soup"; default: 0 = byte-level)
                              # auto-enabled for Single Ouroboros if set_lock_soup(1) is on
    enc.set_lock_soup(1)      # optional Insane Interlocked Mode: per-chunk PRF-keyed
                              # bit-permutation overlay on top of bit-soup;
                              # auto-enabled for Single Ouroboros if set_bit_soup(1) is on

    #enc.set_lock_seed(1)     # optional dedicated lockSeed for the bit-permutation
                              # derivation channel — separates that PRF's keying material
                              # from the noiseSeed-driven noise-injection channel; auto-
                              # couples set_lock_soup(1) + set_bit_soup(1). Adds one
                              # extra seed slot (3 → 4 for Single, 7 → 8 for Triple).
                              # Must be called BEFORE the first encrypt — switching
                              # mid-session raises ITBError(STATUS_EASY_LOCKSEED_AFTER_ENCRYPT).

    # For cross-process persistence: enc.export() returns a single
    # JSON blob carrying PRF keys, seed components, MAC key, and
    # (when active) the dedicated lockSeed material. Ship it
    # alongside the ciphertext or out-of-band.
    blob = enc.export()
    print(f"state blob: {len(blob)} bytes")
    print(f"primitive: {enc.primitive}, key_bits: {enc.key_bits}, "
          f"mode: {enc.mode}, mac: {enc.mac_name}")

    plaintext = b"any text or binary data - including 0x00 bytes"
    #chunk_size = 4 * 1024 * 1024  # 4 MB - bulk local crypto, not small-frame network streaming
    #read_size  = 64 * 1024        # app-driven feed granularity (independent of chunk_size)

    # One-shot encrypt into RGBWYOPA container.
    encrypted = enc.encrypt(plaintext)
    print(f"encrypted: {len(encrypted)} bytes")

    # Format-deniability ITB masking via outer-cipher wrapper (AES-128-CTR) ~0% overhead (Recommended in every case).
    mutable_blob = bytearray(encrypted)
    nonce = wrapper.wrap_in_place(wrapper.CIPHER_AES128_CTR, outer_key, mutable_blob)
    wire = bytes(nonce) + bytes(mutable_blob)
    print(f"wire: {len(wire)} bytes")

    # Streaming alternative — the application drives chunk boundaries
    # by slicing plaintext into chunk_size pieces and calling
    # enc.encrypt() per chunk. enc.header_size + enc.parse_chunk_len
    # are per-instance accessors (track this encryptor's own
    # nonce_bits, NOT the process-wide itb.header_size).
    #from io import BytesIO
    #cbuf = BytesIO()
    #with wrapper.WrapStreamWriter(wrapper.CIPHER_AES128_CTR, outer_key) as ww:
    #    cbuf.write(ww.nonce)
    #    for i in range(0, len(plaintext), chunk_size):
    #        ct = enc.encrypt(plaintext[i:i+chunk_size])
    #        cbuf.write(ww.update(struct.pack("<I", len(ct))))
    #        cbuf.write(ww.update(ct))
    #wire = cbuf.getvalue()

    # Send wire + state blob


# Receiver

import itb
from itb import wrapper

# Receive wire + state blob
# wire = ...
# blob = ...

# Optional: peek at the blob's metadata before constructing a
# matching encryptor. Useful when the receiver multiplexes blobs
# of different shapes (different primitive / mode / MAC choices).
prim, key_bits, mode, mac = itb.peek_config(blob)
print(f"peek: primitive={prim}, key_bits={key_bits}, mode={mode}, mac={mac}")

with itb.Encryptor(prim, key_bits, mac, mode=mode) as dec:
    # dec.import_state(blob) below automatically restores the full
    # per-instance configuration (nonce_bits, barrier_fill, bit_soup,
    # lock_soup, and the dedicated lockSeed material when sender's
    # set_lock_seed(1) was active). The set_*() lines below are kept
    # for documentation — they show the knobs available for explicit
    # pre-Import override. barrier_fill is asymmetric: a receiver-set
    # value > 1 takes priority over the blob's barrier_fill (the
    # receiver's heavier CSPRNG margin is preserved across Import).
    dec.set_nonce_bits(512)
    dec.set_barrier_fill(4)
    dec.set_bit_soup(1)
    dec.set_lock_soup(1)
    #dec.set_lock_seed(1)     # optional — Import below restores the dedicated
                              # lockSeed slot from the blob's lock_seed:true.

    # Restore PRF keys, seed components, MAC key, and the per-instance
    # configuration overrides (nonce_bits / barrier_fill / bit_soup /
    # lock_soup / lock_seed) from the saved blob.
    dec.import_state(blob)

    #read_size = 64 * 1024  # app-driven feed granularity

    # Strip the leading nonce, unwrap the body, then decrypt.
    wire_buf = bytearray(wire)
    encrypted = bytes(wrapper.unwrap_in_place(wrapper.CIPHER_AES128_CTR, outer_key, wire_buf))

    # One-shot decrypt from RGBWYOPA container.
    decrypted = dec.decrypt(encrypted)
    print(f"decrypted: {decrypted.decode()}")

    # Streaming alternative — strip the leading nonce, unwrap through
    # one keystream session, then walk concatenated chunks by reading
    # dec.header_size bytes, calling dec.parse_chunk_len(buf), reading
    # the remaining body, and feeding the full chunk to dec.decrypt().
    #import struct
    #from io import BytesIO
    #nonce_len = wrapper.nonce_size(wrapper.CIPHER_AES128_CTR)
    #nonce_part = wire[:nonce_len]
    #with wrapper.UnwrapStreamReader(wrapper.CIPHER_AES128_CTR, outer_key, nonce_part) as ur:
    #    decrypted_wire = ur.update(wire[nonce_len:])
    #pbuf = BytesIO()
    #view = memoryview(decrypted_wire)
    #off = 0
    #while off < len(view):
    #    (clen,) = struct.unpack("<I", bytes(view[off:off+4]))
    #    off += 4
    #    pbuf.write(dec.decrypt(bytes(view[off:off+clen])))
    #    off += clen
    #decrypted = pbuf.getvalue()
```

## Quick Start — `itb.Encryptor` + HMAC-BLAKE3 (MAC Authenticated)

The MAC primitive is bound at construction time — the third positional
argument to :class:`itb.Encryptor` selects one of the registry names
(``hmac-blake3`` — recommended default, ``kmac256``, ``hmac-sha256``).
The encryptor
allocates a fresh 32-byte CSPRNG MAC key alongside the per-seed PRF
keys; ``enc.export()`` carries all of them in a single JSON blob. On
the receiver side, ``dec.import_state(blob)`` restores the MAC key
together with the seeds, so the encrypt-today / decrypt-tomorrow flow
is one method call per side.

```python
# Sender

import itb
from itb import wrapper

# Outer cipher key - preferred surface for HKDF / ML-KEM / key-rotation policy in user-side application. ITB Inner seeds + PRF key keep as CSPRNG derived.
outer_key = wrapper.generate_key(wrapper.CIPHER_AES128_CTR)

with itb.Encryptor("areion512", 2048, "hmac-blake3") as enc:
    enc.set_nonce_bits(512)   # per-instance — does NOT touch process-wide state
    enc.set_barrier_fill(4)
    enc.set_bit_soup(1)
    enc.set_lock_soup(1)

    #enc.set_lock_seed(1)     # optional dedicated lockSeed for the bit-permutation
                              # derivation channel — auto-couples set_lock_soup(1) +
                              # set_bit_soup(1). Adds one extra seed slot
                              # (3 → 4 for Single, 7 → 8 for Triple). Must be
                              # called BEFORE the first encrypt_auth — switching
                              # mid-session raises ITBError(STATUS_EASY_LOCKSEED_AFTER_ENCRYPT).

    # Persistence blob — carries seeds + PRF keys + MAC key (and the
    # dedicated lockSeed material when set_lock_seed(1) is active).
    blob = enc.export()
    print(f"state blob: {len(blob)} bytes")

    plaintext = b"any text or binary data - including 0x00 bytes"
    #chunk_size = 4 * 1024 * 1024

    # Authenticated encrypt — 32-byte tag is computed across the
    # entire decrypted capacity and embedded inside the RGBWYOPA
    # container, preserving oracle-free deniability.
    encrypted = enc.encrypt_auth(plaintext)
    print(f"encrypted: {len(encrypted)} bytes")

    # Format-deniability ITB masking via outer-cipher wrapper (AES-128-CTR) ~0% overhead (Recommended in every case).
    mutable_blob = bytearray(encrypted)
    nonce = wrapper.wrap_in_place(wrapper.CIPHER_AES128_CTR, outer_key, mutable_blob)
    wire = bytes(nonce) + bytes(mutable_blob)
    print(f"wire: {len(wire)} bytes")

    # Streaming alternative — slice plaintext into chunk_size pieces
    # and call enc.encrypt_auth() per chunk; each chunk carries its
    # own MAC tag. enc.header_size + enc.parse_chunk_len are
    # per-instance accessors.
    #import struct
    #from io import BytesIO
    #cbuf = BytesIO()
    #with wrapper.WrapStreamWriter(wrapper.CIPHER_AES128_CTR, outer_key) as ww:
    #    cbuf.write(ww.nonce)
    #    for i in range(0, len(plaintext), chunk_size):
    #        ct = enc.encrypt_auth(plaintext[i:i+chunk_size])
    #        cbuf.write(ww.update(struct.pack("<I", len(ct))))
    #        cbuf.write(ww.update(ct))
    #wire = cbuf.getvalue()

    # Send wire + state blob


# Receiver

import itb
from itb import wrapper

# Receive wire + state blob
# wire = ...
# blob = ...

itb.set_max_workers(8)        # limit to 8 CPU cores (default: 0 = all CPUs)

prim, key_bits, mode, mac = itb.peek_config(blob)

with itb.Encryptor(prim, key_bits, mac, mode=mode) as dec:
    # dec.import_state(blob) below automatically restores the full
    # per-instance configuration (nonce_bits, barrier_fill, bit_soup,
    # lock_soup, and the dedicated lockSeed material when sender's
    # set_lock_seed(1) was active). The set_*() lines below are kept
    # for documentation — they show the knobs available for explicit
    # pre-Import override. barrier_fill is asymmetric: a receiver-set
    # value > 1 takes priority over the blob's barrier_fill (the
    # receiver's heavier CSPRNG margin is preserved across Import).
    dec.set_nonce_bits(512)
    dec.set_barrier_fill(4)
    dec.set_bit_soup(1)
    dec.set_lock_soup(1)
    #dec.set_lock_seed(1)     # optional — Import below restores the dedicated
                              # lockSeed slot from the blob's lock_seed:true.

    dec.import_state(blob)

    # Strip the leading nonce, unwrap the body, then decrypt.
    wire_buf = bytearray(wire)
    encrypted = bytes(wrapper.unwrap_in_place(wrapper.CIPHER_AES128_CTR, outer_key, wire_buf))

    # Authenticated decrypt — any single-bit tamper triggers MAC
    # failure (no oracle leak about which byte was tampered).
    # Mismatch surfaces as ITBError(STATUS_MAC_FAILURE), not a
    # corrupted plaintext.
    try:
        decrypted = dec.decrypt_auth(encrypted)
        print(f"decrypted: {decrypted.decode()}")
    except itb.ITBError as e:
        if e.code == itb._ffi.STATUS_MAC_FAILURE:
            print("MAC verification failed — tampered or wrong key")
        else:
            raise

    # Streaming alternative — strip the leading nonce, unwrap through
    # one keystream session, then walk the chunk stream and decrypt_auth
    # each chunk; any tamper inside any chunk surfaces as
    # ITBError(STATUS_MAC_FAILURE) on that chunk.
    #import struct
    #from io import BytesIO
    #nonce_len = wrapper.nonce_size(wrapper.CIPHER_AES128_CTR)
    #nonce_part = wire[:nonce_len]
    #with wrapper.UnwrapStreamReader(wrapper.CIPHER_AES128_CTR, outer_key, nonce_part) as ur:
    #    decrypted_wire = ur.update(wire[nonce_len:])
    #pbuf = BytesIO()
    #view = memoryview(decrypted_wire)
    #off = 0
    #while off < len(view):
    #    (clen,) = struct.unpack("<I", bytes(view[off:off+4]))
    #    off += 4
    #    pbuf.write(dec.decrypt_auth(bytes(view[off:off+clen])))
    #    off += clen
    #decrypted = pbuf.getvalue()
```

## Quick Start — Mixed primitives (Different PRF per seed slot)

`itb.Encryptor.mixed_single` and `itb.Encryptor.mixed_triple`
classmethods accept per-slot primitive names — the noise / data /
start (and optional dedicated lockSeed) seed slots can use
different PRF primitives within the same native hash width. The
mix-and-match-PRF freedom of the lower-level path, surfaced
through the high-level :class:`itb.Encryptor` without forcing
the caller off the Easy Mode constructor. The state blob carries
per-slot primitives + per-slot PRF keys; the receiver constructs
a matching encryptor with the same arguments and calls
``import_state`` to restore.

```python
# Sender

import itb
from itb import wrapper

# Outer cipher key - preferred surface for HKDF / ML-KEM / key-rotation policy in user-side application. ITB Inner seeds + PRF key keep as CSPRNG derived.
outer_key = wrapper.generate_key(wrapper.CIPHER_AES128_CTR)

# Per-slot primitive selection (Single Ouroboros, 3 + 1 slots).
# Every name must share the same native hash width — mixing widths
# raise ITBError at construction time.
# Triple Ouroboros mirror — itb.Encryptor.mixed_triple takes seven
# per-slot names (noise + 3 data + 3 start) plus the optional
# primitive_l lockSeed.
enc = itb.Encryptor.mixed_single(
    primitive_n="blake3",       # noiseSeed:  BLAKE3
    primitive_d="blake2s",      # dataSeed:   BLAKE2s
    primitive_s="areion256",    # startSeed:  Areion-SoEM-256
    primitive_l="blake2b256",   # dedicated lockSeed (optional;
                                #   omit for no lockSeed slot)
    key_bits=1024,
    mac="hmac-blake3",
)
try:
    # Per-instance configuration applies as for itb.Encryptor(...).
    enc.set_nonce_bits(512)
    enc.set_barrier_fill(4)
    # BitSoup + LockSoup are auto-coupled on the on-direction by
    # primitive_l above; explicit calls below are unnecessary but
    # harmless if added.
    #enc.set_bit_soup(1)
    #enc.set_lock_soup(1)

    # Per-slot introspection — primitive returns "mixed" literal,
    # primitive_at(slot) returns each slot's name, is_mixed is the
    # typed predicate. Slot ordering is canonical: 0 = noiseSeed,
    # 1 = dataSeed, 2 = startSeed, 3 = lockSeed (Single); Triple
    # grows the middle range to 7 slots + lockSeed.
    print(f"mixed={enc.is_mixed} primitive={enc.primitive!r}")
    for i in range(4):
        print(f"  slot {i}: {enc.primitive_at(i)}")

    blob = enc.export()
    print(f"state blob: {len(blob)} bytes")

    plaintext = b"mixed-primitive Easy Mode payload"

    # Authenticated encrypt — 32-byte tag is computed across the
    # entire decrypted capacity and embedded inside the RGBWYOPA
    # container, preserving oracle-free deniability.
    encrypted = enc.encrypt_auth(plaintext)
    print(f"encrypted: {len(encrypted)} bytes")

    # Format-deniability ITB masking via outer-cipher wrapper (AES-128-CTR) ~0% overhead (Recommended in every case).
    mutable_blob = bytearray(encrypted)
    nonce = wrapper.wrap_in_place(wrapper.CIPHER_AES128_CTR, outer_key, mutable_blob)
    wire = bytes(nonce) + bytes(mutable_blob)
    print(f"wire: {len(wire)} bytes")

    # Send wire + state blob
finally:
    enc.close()


# Receiver

import itb
from itb import wrapper

# Receive wire + state blob
# wire = ...
# blob = ...

# Receiver constructs a matching mixed encryptor — every per-slot
# primitive name plus key_bits and mac must agree with the sender.
# import_state validates each per-slot primitive against the
# receiver's bound spec; mismatches raise ITBError with the
# "primitive" field tag.
dec = itb.Encryptor.mixed_single(
    primitive_n="blake3",
    primitive_d="blake2s",
    primitive_s="areion256",
    primitive_l="blake2b256",
    key_bits=1024,
    mac="hmac-blake3",
)
try:
    # Restore PRF keys, seed components, MAC key, and the per-
    # instance configuration overrides from the saved blob. Mixed
    # blobs carry mixed:true plus a primitives array; import_state
    # on a single-primitive receiver (or vice versa) is rejected as
    # a primitive mismatch.
    dec.import_state(blob)

    # Strip the leading nonce, unwrap the body, then decrypt.
    wire_buf = bytearray(wire)
    encrypted = bytes(wrapper.unwrap_in_place(wrapper.CIPHER_AES128_CTR, outer_key, wire_buf))

    decrypted = dec.decrypt_auth(encrypted)
    print(f"decrypted: {decrypted.decode()}")
finally:
    dec.close()
```

## Quick Start — Areion-SoEM-512 (Low-level, No MAC)

```python
# Sender

import itb
from itb import wrapper

# Optional: global configuration (all process-wide, atomic)
itb.set_max_workers(8)        # limit to 8 CPU cores (default: 0 = all CPUs)
itb.set_nonce_bits(512)       # 512-bit nonce (default: 128-bit)
itb.set_barrier_fill(4)       # CSPRNG fill margin (default: 1, valid: 1,2,4,8,16,32)

itb.set_bit_soup(1)           # optional bit-level split ("bit-soup"; default: 0 = byte-level)
                              # automatically enabled for Single Ouroboros if
                              # itb.set_lock_soup(1) is enabled or vice versa

itb.set_lock_soup(1)          # optional Insane Interlocked Mode: per-chunk PRF-keyed
                              # bit-permutation overlay on top of bit-soup;
                              # automatically enabled for Single Ouroboros if
                              # itb.set_bit_soup(1) is enabled or vice versa

# Three independent CSPRNG-keyed Areion-SoEM-512 seeds. Each Seed
# pre-keys its primitive once at construction; the C ABI / FFI
# layer auto-wires the AVX-512 + VAES + ILP + ZMM-batched chain-
# absorb dispatch through Seed.BatchHash — no manual batched-arm
# attachment is required on the Python side.
ns = itb.Seed("areion512", 2048)  # random noise CSPRNG seeds + hash key generated
ds = itb.Seed("areion512", 2048)  # random data  CSPRNG seeds + hash key generated
ss = itb.Seed("areion512", 2048)  # random start CSPRNG seeds + hash key generated

# Optional: dedicated lockSeed for the bit-permutation derivation
# channel. Separates that PRF's keying material from the noiseSeed-
# driven noise-injection channel without changing the public encrypt
# / decrypt signatures. The bit-permutation overlay must be engaged
# (itb.set_bit_soup(1) or itb.set_lock_soup(1) — both already on
# above) before the first encrypt; the build-PRF guard panics on
# encrypt-time when an attach is present without either flag.
ls = itb.Seed("areion512", 2048)  # random lock CSPRNG seeds + hash key generated
ns.attach_lock_seed(ls)

# Outer cipher key - preferred surface for HKDF / ML-KEM / key-rotation policy in user-side application. ITB Inner seeds + PRF key keep as CSPRNG derived.
outer_key = wrapper.generate_key(wrapper.CIPHER_AES128_CTR)

plaintext = b"any text or binary data - including 0x00 bytes"
#chunk_size = 4 * 1024 * 1024  # 4 MB - bulk local crypto, not small-frame network streaming
#read_size  = 64 * 1024        # app-driven feed granularity (independent of chunk_size)

try:
    # Encrypt into RGBWYOPA container
    encrypted = itb.encrypt(ns, ds, ss, plaintext)
    print(f"encrypted: {len(encrypted)} bytes")

    # Format-deniability ITB masking via outer-cipher wrapper (AES-128-CTR) ~0% overhead (Recommended in every case).
    mutable_blob = bytearray(encrypted)
    nonce = wrapper.wrap_in_place(wrapper.CIPHER_AES128_CTR, outer_key, mutable_blob)
    wire = bytes(nonce) + bytes(mutable_blob)
    print(f"wire: {len(wire)} bytes")

    # Streaming alternative — the application drives chunk
    # boundaries through StreamEncryptor.write(); the encryptor
    # buffers up to chunk_size bytes before emitting one ITB
    # chunk to fout, with the tail flushed on close().
    #import struct
    #from io import BytesIO
    #fout = BytesIO()
    #inner = BytesIO()
    #with itb.StreamEncryptor(ns, ds, ss, inner, chunk_size=chunk_size) as senc:
    #    for i in range(0, len(plaintext), read_size):
    #        senc.write(plaintext[i:i+read_size])
    #with wrapper.WrapStreamWriter(wrapper.CIPHER_AES128_CTR, outer_key) as ww:
    #    fout.write(ww.nonce)
    #    fout.write(ww.update(inner.getvalue()))
    #wire = fout.getvalue()

    # For cross-process persistence: itb.Blob512 packs every seed's
    # hash key + components and the captured process-wide globals
    # (nonce_bits / barrier_fill / bit_soup / lock_soup) into one
    # JSON blob — the Sender ships blob_bytes alongside the
    # ciphertext (or out-of-band). The receiver round-trips back
    # to working seeds via Blob512.import_blob below.
    with itb.Blob512() as blob:
        blob.set_key("n", ns.hash_key); blob.set_components("n", ns.components)
        blob.set_key("d", ds.hash_key); blob.set_components("d", ds.components)
        blob.set_key("s", ss.hash_key); blob.set_components("s", ss.components)
        blob.set_key("l", ls.hash_key); blob.set_components("l", ls.components)
        blob_bytes = blob.export(lockseed=True)
    print(f"persistence blob: {len(blob_bytes)} bytes")

    # Send wire + blob_bytes
finally:
    ns.free(); ds.free(); ss.free(); ls.free()


# Receiver

import itb
from itb import wrapper

itb.set_max_workers(8)        # deployment knob — not serialised by Blob512

# Receive wire + blob_bytes
# wire = ...; blob_bytes = ...

# Blob512.import_blob applies the captured globals (nonce_bits /
# barrier_fill / bit_soup / lock_soup) via the process-wide setters
# AND populates per-slot hash keys + components. The Receiver does
# NOT need to set these four globals manually — the blob is the
# single source of truth for both the encryptor material and the
# runtime configuration that produced the ciphertext.
restored = itb.Blob512()
restored.import_blob(blob_bytes)

ns = itb.Seed.from_components("areion512", restored.get_components("n"), restored.get_key("n"))
ds = itb.Seed.from_components("areion512", restored.get_components("d"), restored.get_key("d"))
ss = itb.Seed.from_components("areion512", restored.get_components("s"), restored.get_key("s"))
ls = itb.Seed.from_components("areion512", restored.get_components("l"), restored.get_key("l"))
restored.free()
ns.attach_lock_seed(ls)

#read_size = 64 * 1024  # app-driven feed granularity

try:
    # Strip the leading nonce, unwrap the body, then decrypt.
    wire_buf = bytearray(wire)
    encrypted = bytes(wrapper.unwrap_in_place(wrapper.CIPHER_AES128_CTR, outer_key, wire_buf))

    # Decrypt from RGBWYOPA container
    decrypted = itb.decrypt(ns, ds, ss, encrypted)
    print(f"decrypted: {decrypted.decode()}")

    # Streaming alternative — strip the leading nonce, unwrap through
    # one keystream session, then drive StreamDecryptor.feed() with
    # the recovered inner bytestream.
    #from io import BytesIO
    #nonce_len = wrapper.nonce_size(wrapper.CIPHER_AES128_CTR)
    #nonce_part = wire[:nonce_len]
    #with wrapper.UnwrapStreamReader(wrapper.CIPHER_AES128_CTR, outer_key, nonce_part) as ur:
    #    inner_wire = ur.update(wire[nonce_len:])
    #fout = BytesIO()
    #with itb.StreamDecryptor(ns, ds, ss, fout) as sdec:
    #    for i in range(0, len(inner_wire), read_size):
    #        sdec.feed(inner_wire[i:i+read_size])
    #decrypted = fout.getvalue()
finally:
    ns.free(); ds.free(); ss.free(); ls.free()
```

## Quick Start — Areion-SoEM-512 + HMAC-BLAKE3 (Low-Level, MAC Authenticated)

```python
# Sender

import itb
import secrets
from itb import wrapper

# Optional: global configuration (all process-wide, atomic)
itb.set_max_workers(8)        # limit to 8 CPU cores (default: 0 = all CPUs)
itb.set_nonce_bits(512)       # 512-bit nonce (default: 128-bit)
itb.set_barrier_fill(4)       # CSPRNG fill margin (default: 1, valid: 1,2,4,8,16,32)

itb.set_bit_soup(1)           # optional bit-level split ("bit-soup"; default: 0 = byte-level)
                              # automatically enabled for Single Ouroboros if
                              # itb.set_lock_soup(1) is enabled or vice versa

itb.set_lock_soup(1)          # optional Insane Interlocked Mode: per-chunk PRF-keyed
                              # bit-permutation overlay on top of bit-soup;
                              # automatically enabled for Single Ouroboros if
                              # itb.set_bit_soup(1) is enabled or vice versa

ns = itb.Seed("areion512", 2048)
ds = itb.Seed("areion512", 2048)
ss = itb.Seed("areion512", 2048)

# Optional: dedicated lockSeed for the bit-permutation derivation
# channel — same pattern as the no-MAC quick-start above.
ls = itb.Seed("areion512", 2048)
ns.attach_lock_seed(ls)

# HMAC-BLAKE3 — 32-byte CSPRNG key, 32-byte tag.
mac_key = secrets.token_bytes(32)
mac = itb.MAC("hmac-blake3", mac_key)

# Outer cipher key - preferred surface for HKDF / ML-KEM / key-rotation policy in user-side application. ITB Inner seeds + PRF key keep as CSPRNG derived.
outer_key = wrapper.generate_key(wrapper.CIPHER_AES128_CTR)

plaintext = b"any text or binary data - including 0x00 bytes"

try:
    # Authenticated encrypt — 32-byte tag is computed across the
    # entire decrypted capacity and embedded inside the RGBWYOPA
    # container, preserving oracle-free deniability.
    encrypted = itb.encrypt_auth(ns, ds, ss, mac, plaintext)
    print(f"encrypted: {len(encrypted)} bytes")

    # Format-deniability ITB masking via outer-cipher wrapper (AES-128-CTR) ~0% overhead (Recommended in every case).
    mutable_blob = bytearray(encrypted)
    nonce = wrapper.wrap_in_place(wrapper.CIPHER_AES128_CTR, outer_key, mutable_blob)
    wire = bytes(nonce) + bytes(mutable_blob)
    print(f"wire: {len(wire)} bytes")

    # Cross-process persistence: itb.Blob512 packs every seed's
    # hash key + components, the optional dedicated lockSeed, and
    # the MAC key + name into one JSON blob alongside the captured
    # process-wide globals. lockseed=True / mac=True opt the
    # corresponding sections in.
    with itb.Blob512() as blob:
        blob.set_key("n", ns.hash_key); blob.set_components("n", ns.components)
        blob.set_key("d", ds.hash_key); blob.set_components("d", ds.components)
        blob.set_key("s", ss.hash_key); blob.set_components("s", ss.components)
        blob.set_key("l", ls.hash_key); blob.set_components("l", ls.components)
        blob.set_mac_key(mac_key); blob.set_mac_name("hmac-blake3")
        blob_bytes = blob.export(lockseed=True, mac=True)
    print(f"persistence blob: {len(blob_bytes)} bytes")

    # Send wire + blob_bytes
finally:
    mac.free()
    ns.free(); ds.free(); ss.free(); ls.free()


# Receiver

import itb
from itb import wrapper

itb.set_max_workers(8)        # deployment knob — not serialised by Blob512

# Receive wire + blob_bytes
# wire = ...; blob_bytes = ...

# Blob512.import_blob restores per-slot hash keys + components AND
# applies the captured globals (nonce_bits / barrier_fill / bit_soup
# / lock_soup) via the process-wide setters.
restored = itb.Blob512()
restored.import_blob(blob_bytes)

ns = itb.Seed.from_components("areion512", restored.get_components("n"), restored.get_key("n"))
ds = itb.Seed.from_components("areion512", restored.get_components("d"), restored.get_key("d"))
ss = itb.Seed.from_components("areion512", restored.get_components("s"), restored.get_key("s"))
ls = itb.Seed.from_components("areion512", restored.get_components("l"), restored.get_key("l"))
ns.attach_lock_seed(ls)

mac = itb.MAC(restored.get_mac_name(), restored.get_mac_key())
restored.free()

try:
    # Strip the leading nonce, unwrap the body, then decrypt.
    wire_buf = bytearray(wire)
    encrypted = bytes(wrapper.unwrap_in_place(wrapper.CIPHER_AES128_CTR, outer_key, wire_buf))

    # Authenticated decrypt — any single-bit tamper triggers MAC
    # failure (no oracle leak about which byte was tampered).
    decrypted = itb.decrypt_auth(ns, ds, ss, mac, encrypted)
    print(f"decrypted: {decrypted.decode()}")
finally:
    mac.free()
    ns.free(); ds.free(); ss.free(); ls.free()
```

## Hash primitives (Single / Triple)

Names match the canonical `hashes/` registry: `areion256`,
`areion512`, `siphash24`, `aescmac`, `blake2b256`, `blake2b512`,
`blake2s`, `blake3`, `chacha20`. Triple Ouroboros (3× security)
takes seven seeds (one shared `noiseSeed` plus three `dataSeed`
and three `startSeed`) via `itb.encrypt_triple` /
`itb.decrypt_triple` and the authenticated counterparts
`itb.encrypt_auth_triple` / `itb.decrypt_auth_triple`. Streaming
counterparts: `itb.StreamEncryptor3` / `itb.StreamDecryptor3` /
`itb.encrypt_stream_triple` / `itb.decrypt_stream_triple`.

All seeds passed to one `encrypt` / `decrypt` call must share the
same native hash width. Mixing widths raises
`ITBError(STATUS_SEED_WIDTH_MIX)`.

## MAC primitives

Names match the libitb MAC registry; ordering matches that registry's declaration order.

| MAC | Key bytes | Tag bytes | Underlying primitive |
|---|---|---|---|
| `kmac256` | 32 | 32 | KMAC256 (Keccak-derived) |
| `hmac-sha256` | 32 | 32 | HMAC over SHA-256 |
| `hmac-blake3` | 32 | 32 | HMAC over BLAKE3 |

`kmac256` and `hmac-sha256` accept keys 16 bytes and longer; the binding fleet's tests and examples use 32 bytes uniformly across primitives for cross-binding consistency. `hmac-blake3` requires exactly 32 bytes by construction.

## Process-wide configuration

Every setter takes effect for all subsequent encrypt / decrypt
calls in the process. Out-of-range values raise
`ITBError(STATUS_BAD_INPUT)` rather than crashing.

| Function | Accepted values | Default |
|---|---|---|
| `set_max_workers(n)` | non-negative int | 0 (auto) |
| `set_nonce_bits(n)` | 128, 256, 512 | 128 |
| `set_barrier_fill(n)` | 1, 2, 4, 8, 16, 32 | 1 |
| `set_bit_soup(mode)` | 0 (off), non-zero (on) | 0 |
| `set_lock_soup(mode)` | 0 (off), non-zero (on) | 0 |

Read-only constants: `itb.max_key_bits()`, `itb.channels()`,
`itb.header_size()`, `itb.version()`.

For low-level chunk parsing (e.g. when implementing custom file
formats around ITB chunks): `itb.parse_chunk_len(header)` inspects
the fixed-size chunk header and returns the chunk's total
on-the-wire length; `itb.header_size()` returns the active header
byte count (20 / 36 / 68 for nonce sizes 128 / 256 / 512 bits).

## Concurrency

The libitb shared library exposes process-wide configuration through
a small set of atomics (`set_nonce_bits`, `set_barrier_fill`,
`set_bit_soup`, `set_lock_soup`, `set_max_workers`). Multiple threads
calling these setters concurrently without external coordination
will race for the final value visible to subsequent encrypt /
decrypt calls — serialise the mutators behind a `threading.Lock` (or
set them once at startup before spawning workers) when multiple
Python threads need to touch them.

Per-encryptor configuration via `Encryptor.set_nonce_bits` /
`Encryptor.set_barrier_fill` / `Encryptor.set_bit_soup` /
`Encryptor.set_lock_soup` mutates only that handle's Config copy and
is safe to call from the owning thread without affecting other
`Encryptor` instances. The cipher methods (`Encryptor.encrypt` /
`Encryptor.decrypt` / `Encryptor.encrypt_auth` /
`Encryptor.decrypt_auth`) write into the per-instance output-buffer
cache; sharing one `Encryptor` across threads requires external
synchronisation. Distinct `Encryptor` instances, each owned by one
thread, run independently against the libitb worker pool.

By contrast, the low-level cipher free functions (`itb.encrypt` /
`itb.decrypt` / `itb.encrypt_auth` / `itb.decrypt_auth` plus the
Triple counterparts) allocate output per call and are **thread-safe**
under concurrent invocation on the same `Seed` handles — libitb's
worker pool dispatches them independently. Two exceptions:
`Seed.attach_lock_seed` mutates the noise Seed and must not race
against an in-flight cipher call on it, and the process-wide setters
above stay process-global.

The wrapper objects (`Seed`, `MAC`, `Encryptor`, `Blob128` /
`Blob256` / `Blob512`, `StreamEncryptor` / `StreamDecryptor`) are
plain Python classes whose `__del__` finalisers call the matching
libitb release entry points; the FFI-call layer is synchronous and
holds the GIL, so the §11.j keepAlive trap that JIT-compiled GC
runtimes require is N/A here — Python's reference count keeps the
wrapper alive across the FFI call. Use `with Encryptor(...) as enc:`
for deterministic close.

## Error model

Every failure surfaces as `ITBError` (or one of the four typed
subclasses) with a `code` field and a textual message:

```python
try:
    itb.MAC("nonsense", b"\0" * 32)
except itb.ITBError as e:
    print(e.code, e)  # e.code == itb._ffi.STATUS_BAD_MAC
```

The typed-exception hierarchy:

- `ITBError` — base class; carries `code` + the textual message.
- `EasyMismatchError` — Easy Mode `import_state` rejected a field;
  the offending JSON field name is on `.field`.
- `BlobModeMismatchError` — Blob receiver rejected a Single-vs-Triple
  wire mismatch.
- `BlobMalformedError` — Blob payload failed structural checks.
- `BlobVersionTooNewError` — Blob version field higher than this
  libitb build supports.

Status codes are documented in `cmd/cshared/internal/capi/errors.go`
and mirrored as `itb._ffi.STATUS_*` constants. Type / value-input
errors raise `TypeError` / `ValueError` (e.g. `plaintext` not
bytes-like, `chunk_size` ≤ 0); only libitb-side failures route
through `ITBError`.

Note: empty plaintext / ciphertext is rejected by libitb itself
with `ITBError(STATUS_ENCRYPT_FAILED)` ("itb: empty data") on every
cipher entry point. Pass at least one byte.

### Status codes

| Code | Name | Description |
|---|---|---|
| 0 | `STATUS_OK` | Success — the only non-failure return value |
| 1 | `STATUS_BAD_HASH` | Unknown hash primitive name |
| 2 | `STATUS_BAD_KEY_BITS` | ITB key width invalid for the chosen primitive |
| 3 | `STATUS_BAD_HANDLE` | FFI handle invalid or already freed |
| 4 | `STATUS_BAD_INPUT` | Generic shape / range / domain violation on a call argument |
| 5 | `STATUS_BUFFER_TOO_SMALL` | Output buffer cap below required size; probe-then-allocate idiom |
| 6 | `STATUS_ENCRYPT_FAILED` | Encrypt path raised on the Go side (rare; structural / OOM) |
| 7 | `STATUS_DECRYPT_FAILED` | Decrypt path raised on the Go side (corrupt ciphertext shape) |
| 8 | `STATUS_SEED_WIDTH_MIX` | Seeds passed to one call do not share the same native hash width |
| 9 | `STATUS_BAD_MAC` | Unknown MAC name or key-length violates the primitive's `min_key_bytes` |
| 10 | `STATUS_MAC_FAILURE` | MAC verification failed — tampered ciphertext or wrong MAC key |
| 11 | `STATUS_EASY_CLOSED` | Easy Mode encryptor call after `close()` |
| 12 | `STATUS_EASY_MALFORMED` | Easy Mode `import_state` blob fails JSON parse / structural check |
| 13 | `STATUS_EASY_VERSION_TOO_NEW` | Easy Mode blob version field higher than this build supports |
| 14 | `STATUS_EASY_UNKNOWN_PRIMITIVE` | Easy Mode blob references a primitive this build does not know |
| 15 | `STATUS_EASY_UNKNOWN_MAC` | Easy Mode blob references a MAC this build does not know |
| 16 | `STATUS_EASY_BAD_KEY_BITS` | Easy Mode blob's `key_bits` invalid for its primitive |
| 17 | `STATUS_EASY_MISMATCH` | Easy Mode blob disagrees with the receiver on `primitive` / `key_bits` / `mode` / `mac`; field name on `EasyMismatchError.field` |
| 18 | `STATUS_EASY_LOCKSEED_AFTER_ENCRYPT` | `set_lock_seed(1)` called after the first encrypt — must precede the first ciphertext |
| 19 | `STATUS_BLOB_MODE_MISMATCH` | Native Blob importer received a Single blob into a Triple receiver (or vice versa) |
| 20 | `STATUS_BLOB_MALFORMED` | Native Blob payload fails JSON parse / magic / structural check |
| 21 | `STATUS_BLOB_VERSION_TOO_NEW` | Native Blob version field higher than this libitb build supports |
| 22 | `STATUS_BLOB_TOO_MANY_OPTS` | Native Blob export opts mask carries unsupported bits |
| 23 | `STATUS_STREAM_TRUNCATED` | Streaming AEAD transcript truncated before the terminator chunk; raised as `ItbStreamTruncatedError` |
| 24 | `STATUS_STREAM_AFTER_FINAL` | Streaming AEAD transcript carries chunk bytes after the terminator; raised as `ItbStreamAfterFinalError` |
| 99 | `STATUS_INTERNAL` | Generic "internal" sentinel for paths the caller cannot recover from at the binding layer |

## Constraints

- **Python 3.9 minimum.** The package's `pyproject.toml` declares
  `requires-python = ">=3.9"`. Type-hint syntax (`X | None`, builtin
  generics) and modern `dataclasses` features are used throughout the
  wrapper.
- **Single distribution.** All consumer-visible declarations live
  under the `itb` package; the FFI substrate (`itb._sys`) is kept
  separate so audits can read it independently.
- **libitb.so required at runtime.** The package loads
  `dist/<os>-<arch>/libitb.<ext>` via cffi at import time; the shared
  library must be built first and reachable through the loader's
  search path.
- **External runtime deps.** The single non-stdlib runtime dependency
  is `cffi >= 1.15`. The test runner additionally requires `pytest`.
- **Frozen C ABI.** The `ITB_*` exports declared by the cffi-parsed
  header (synced from `dist/<os>-<arch>/libitb.h`) are the contract;
  the binding does not extend or reshape them.
- **No `dlopen` indirection.** cffi resolves symbols at import time
  against the located `libitb.<ext>`. Consumers wanting runtime FFI
  loading against a different `libitb` can override the search via
  the documented environment variables.

## API Overview

Every public symbol is reachable from the top-level `itb` namespace
(via `itb.__all__`). Submodule `itb.wrapper` exposes the
format-deniability outer-cipher surface and is imported on demand
(`from itb import wrapper`).

### Library metadata

| Symbol | Purpose |
|---|---|
| `itb.version() -> str` | Library version `"<major>.<minor>.<patch>"` |
| `itb.max_key_bits() -> int` | Max supported ITB key width in bits |
| `itb.channels() -> int` | Number of native channel slots |
| `itb.header_size() -> int` | Current chunk header size in bytes |
| `itb.parse_chunk_len(header: bytes) -> int` | Parse a chunk header, return total on-wire chunk length |
| `itb.list_hashes() -> list[tuple[str, int]]` | `(name, width_bits)` catalogue |
| `itb.list_macs() -> list[tuple[str, int, int, int]]` | `(name, key_size, tag_size, min_key_bytes)` catalogue |
| `itb.last_error() -> str` | Per-thread last-error message |

### Process-wide configuration

| Symbol | Purpose |
|---|---|
| `itb.set_bit_soup(mode: int)` / `itb.get_bit_soup() -> int` | Bit Soup mode toggle |
| `itb.set_lock_soup(mode: int)` / `itb.get_lock_soup() -> int` | Lock Soup mode toggle |
| `itb.set_max_workers(n: int)` / `itb.get_max_workers() -> int` | Worker pool cap |
| `itb.set_nonce_bits(n: int)` / `itb.get_nonce_bits() -> int` | Nonce width (128 / 256 / 512) |
| `itb.set_barrier_fill(n: int)` / `itb.get_barrier_fill() -> int` | Barrier-fill factor |
| `itb.set_memory_limit(limit: int) -> int` | Go runtime heap soft limit in bytes; pass negative to query only |
| `itb.set_gc_percent(pct: int) -> int` | Go GC trigger percentage; pass negative to query only |

### Seeds and MAC

| Symbol | Purpose |
|---|---|
| `itb.Seed(hash_name: str, key_bits: int)` | CSPRNG-fresh seed |
| `itb.Seed.from_components(hash_name, key_bits, components)` | Reconstruct from explicit components |
| `Seed.width` / `Seed.hash_name` / `Seed.hash_key` / `Seed.components` / `Seed.attach_lock_seed(lock_seed)` | Introspection + lock-seed attachment |
| `itb.MAC(mac_name: str, key: bytes)` | Construct MAC handle (32-byte keys across the shipped catalogue) |

### Low-level cipher (free functions)

| Symbol | Purpose |
|---|---|
| `itb.encrypt(noise, data, start, plaintext) -> bytes` | Single Message encrypt |
| `itb.decrypt(noise, data, start, ciphertext) -> bytes` | Single Message decrypt |
| `itb.encrypt_auth(noise, data, start, mac, plaintext)` / `itb.decrypt_auth(...)` | MAC-authenticated counterparts |
| `itb.encrypt_triple(noise, d1, d2, d3, s1, s2, s3, plaintext)` / `itb.decrypt_triple(...)` | Triple Ouroboros |
| `itb.encrypt_auth_triple(...)` / `itb.decrypt_auth_triple(...)` | Triple Ouroboros MAC-authenticated |

### Easy Mode encryptor

| Symbol | Purpose |
|---|---|
| `itb.Encryptor(primitive, key_bits, mac=None, mode="single")` | Single-primitive constructor |
| `itb.Encryptor.mixed(primitives, key_bits, mac=None)` | Mixed-primitive Single Ouroboros |
| `itb.Encryptor.mixed3(primitives, key_bits, mac=None)` | Mixed-primitive Triple Ouroboros |
| `enc.encrypt(plaintext)` / `enc.decrypt(ciphertext)` | Cipher entry points |
| `enc.encrypt_auth(plaintext)` / `enc.decrypt_auth(ciphertext)` | MAC-authenticated cipher entry points |
| `enc.set_nonce_bits / set_barrier_fill / set_bit_soup / set_lock_soup / set_lock_seed / set_chunk_size` | Per-instance setters |
| `enc.primitive / mac_name / key_bits / mode / nonce_bits / header_size / has_prf_keys / is_mixed / seed_count` | Accessors |
| `enc.prf_key(slot)` / `enc.mac_key()` / `enc.seed_components(slot)` | Key-material accessors |
| `enc.export()` / `enc.import_state(blob)` | State-blob persistence |
| `itb.peek_config(blob) -> dict` / `itb.last_mismatch_field() -> str` | Pre-import discriminator + mismatch-field accessor |
| `enc.close()` | Release encryptor (idempotent) |

### Streaming AEAD

| Symbol | Purpose |
|---|---|
| `itb.encrypt_stream(read_fn, write_fn, noise, data, start, mac=None)` / `itb.decrypt_stream(...)` | Single Low-Level streams |
| `itb.encrypt_stream_triple(read_fn, write_fn, noise, d1, d2, d3, s1, s2, s3, mac=None)` / `itb.decrypt_stream_triple(...)` | Triple Low-Level streams |
| `itb.encrypt_stream_auth(...)` / `itb.decrypt_stream_auth(...)` | Single Low-Level Streaming AEAD |
| `itb.encrypt_stream_auth_triple(...)` / `itb.decrypt_stream_auth_triple(...)` | Triple Low-Level Streaming AEAD |
| `itb.StreamEncryptor / StreamDecryptor / StreamEncryptor3 / StreamDecryptor3` | Push-style Low-Level streamers |
| `itb.StreamEncryptorAuth / StreamDecryptorAuth / StreamEncryptorAuth3 / StreamDecryptorAuth3` | Push-style Streaming AEAD streamers |
| `itb.DEFAULT_CHUNK_SIZE` | Default streaming chunk size in bytes |

### Native Blob

| Symbol | Purpose |
|---|---|
| `itb.Blob128() / Blob256() / Blob512()` | Width-specific Native Blob handles |
| `blob.set_key(slot, key)` / `blob.set_components(slot, components)` / `blob.set_mac_key(key)` / `blob.set_mac_name(name)` | Field setters |
| `blob.get_key(slot)` / `blob.get_components(slot)` / `blob.get_mac_key()` / `blob.get_mac_name()` | Field getters |
| `blob.export(opts=0)` / `blob.export_triple(opts=0)` / `blob.import_blob(payload)` / `blob.import_triple(payload)` | Serialisation |
| `itb.SLOT_N / SLOT_D / SLOT_S / SLOT_L / SLOT_D1 / SLOT_D2 / SLOT_D3 / SLOT_S1 / SLOT_S2 / SLOT_S3` | Slot indices |
| `itb.OPT_LOCKSEED / OPT_MAC` | Export opt-in flag bits |

### Wrapper (`itb.wrapper`)

| Symbol | Purpose |
|---|---|
| `wrapper.key_size(cipher_name: str) -> int` | Wrapper-cipher key size in bytes |
| `wrapper.nonce_size(cipher_name: str) -> int` | Wire nonce size in bytes |
| `wrapper.generate_key(cipher_name: str) -> bytes` | CSPRNG-fresh wrapper key |
| `wrapper.wrap(cipher_name, key, blob) -> bytes` / `wrapper.unwrap(cipher_name, key, wire) -> bytes` | Single Message Wrap / Unwrap |
| `wrapper.wrap_in_place(cipher_name, key, buf) -> bytes` / `wrapper.unwrap_in_place(cipher_name, key, wire) -> memoryview` | In-place Wrap / Unwrap |
| `wrapper.WrapStreamWriter(cipher_name, key)` / `wrapper.UnwrapStreamReader(cipher_name, key, wire_nonce)` | Streaming wrap writer / unwrap reader |

Wrapper cipher names: `aes-128-ctr`, `chacha20`, `siphash24`.

### Error model

| Symbol | Purpose |
|---|---|
| `itb.ITBError` | Base exception class; `.code` carries the numeric status |
| `itb.EasyMismatchError / BlobModeMismatchError / BlobMalformedError / BlobVersionTooNewError` | Typed subclasses for cold-path discriminators |
| `itb.ItbStreamTruncatedError / ItbStreamAfterFinalError` | Streaming AEAD transcript-shape exceptions |
| `itb.STATUS_OK / STATUS_BAD_HASH / ... / STATUS_INTERNAL` | 24 status-code constants plus `STATUS_INTERNAL` |
