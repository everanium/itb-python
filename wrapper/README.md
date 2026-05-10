# ITB Python Binding — Format-Deniability Wrapper

Python-idiomatic surface over the format-deniability wrapper exposed by libitb. Mirrors `github.com/everanium/itb/wrapper` structurally; the wire bytes produced by the Python helpers are byte-identical to the Go-native helpers under the same `(cipher_name, key, nonce)` tuple.

The runtime module lives at `itb.wrapper`; this directory carries the example utility (`bindings/python/eitb/`), the benchmark harness (`bindings/python/wrapper/benchmarks/`), and the BENCH.md result table.

## Threat model

ITB encrypts content into RGBWYOPA pixel containers. The construction provides **content-deniability** unconditionally — no plaintext bit can be extracted from the wire. The wire pattern itself, however, is parseable by an observer who knows the ITB format:

- Non-AEAD path: per-chunk header carries width / height / container layout.
- Streaming AEAD path: a once per-stream 32-byte streamID prefix plus per-chunk `nonce || W || H || container || flag_byte`.

A passive observer who knows ITB ships with an 8-channel pixel container and a 32-byte streamID prefix can pattern-match the bytes. The format-deniability wrap hides that surface under a generic outer cipher: AES-128-CTR, ChaCha20 (RFC8439), or SipHash-2-4 in CTR mode. After wrapping, the wire is `nonce || keystream-XOR(bytestream)` — the same shape used by countless other protocols. An observer sees a small leading nonce followed by pseudorandom-looking bytes; pattern-matching does not distinguish ITB from any other stream cipher payload.

This is **not** a random-oracle indistinguishability claim. It is a "looks like a different well-known cipher" claim. The wrap exists for format-deniability ONLY; ITB already provides confidentiality (content-deniability) and the AEAD path already provides per-stream and per-chunk integrity. The Non-AEAD streaming path has no integrity by design and the wrap does not add any.

## Wrapper API

The Python module exposes Single Message helpers (immutable + in-place mutation) and a streaming class pair:

| Helper | Wire format | Use case |
|---|---|---|
| `wrap` / `unwrap` | `nonce \|\| keystream-XOR(blob)` | Single Message Encrypt / EncryptAuth output, immutable plaintext path. |
| `wrap_in_place` / `unwrap_in_place` | same as `wrap` / `unwrap` | Single Message, zero-allocation steady state. Mutates the caller's `bytearray` / writable `memoryview`. |
| `WrapStreamWriter` / `UnwrapStreamReader` | `nonce` + keystream-XOR(continuous bytestream) | streaming use — Streaming AEAD wraps the entire bytestream end-to-end; User-Driven Loop emits per-chunk caller-side framing (`u32_LE` length prefix) through the wrap-writer so the framing bytes also pass through the keystream XOR. |

The single keystream advances monotonically across all bytes within one wrap session. A fresh CSPRNG nonce is generated per session; emitted once at stream start; never reused across sessions. This is standard CTR mode usage — within one stream, one nonce + counter is correct.

No length-prefix or other framing byte appears in cleartext on the wire in any wrap shape. The User-Driven Loop emits length prefixes through the wrap-writer so they get XORed into the keystream alongside the chunk bodies.

### Binding asymmetry

The Python binding exposes Streaming AEAD as a file-like object surface (`Encryptor.encrypt_stream_auth` / `decrypt_stream_auth`). The Streaming No MAC path has **no** file-like / stream-like wrapper writer or reader pair. This asymmetry is intentional. The Non-AEAD streaming arm in the Python wrapper covers the **User-Driven Loop** variant only — caller produces an ITB ciphertext per chunk via `enc.encrypt(chunk)`, frames `u32_LE_len || ct`, and pushes through the streaming wrapper handle. See CLAUDE.md.

## Outer ciphers

| Cipher | Constant | Key | Nonce | Notes |
|---|---|---|---|---|
| AES-128-CTR | `wrapper.CIPHER_AES128_CTR` (`"aes"`) | 16 B | 16 B | libitb stdlib path with AES-NI. |
| ChaCha20 (RFC 8439) | `wrapper.CIPHER_CHACHA20` (`"chacha"`) | 32 B | 12 B | `golang.org/x/crypto/chacha20`. No AES-NI dependency. |
| SipHash-2-4 in CTR mode | `wrapper.CIPHER_SIPHASH24` (`"siphash"`) | 16 B | 16 B | `github.com/dchest/siphash` PRF. Custom CTR construction; sound under standard PRF assumption. |

The SipHash-CTR construction:
- 16-byte SipHash key = wrapper key.
- 16-byte nonce split into `(nonce_hi, nonce_lo)` 64-bit halves.
- Each keystream block: `siphash.Hash(key, nonce_hi || (nonce_lo XOR counter_LE))` — 8-byte output, XORed with plaintext.
- Counter increments per block; nonce stays fixed for the stream.

## Quick Start

Code paths under `bindings/python/eitb/eitb.py`. Run the matrix:

```sh
PYTHONPATH=bindings/python python3 -m bindings.python.eitb.eitb
PYTHONPATH=bindings/python python3 -m bindings.python.eitb.eitb --help
```

### 1. Streaming AEAD Easy (MAC Authenticated, IO-Driven)

ITB Call: `itb.Encryptor.encrypt_stream_auth` / `decrypt_stream_auth`. Wrap shape: `WrapStreamWriter` / `UnwrapStreamReader` over the continuous bytestream ITB emits.

```python
import io
import itb
from itb import wrapper

enc = itb.Encryptor("areion512", 1024, "hmac-blake3", mode=1)
enc.set_nonce_bits(512); enc.set_barrier_fill(4)
enc.set_bit_soup(1); enc.set_lock_soup(1)

outer_key = wrapper.generate_key(cipher_name)

# Sender
wire_buf = io.BytesIO()
with wrapper.WrapStreamWriter(cipher_name, outer_key) as ww:
    wire_buf.write(ww.nonce)
    inner = io.BytesIO()
    enc.encrypt_stream_auth(plaintext_reader, inner, chunk_size=16 * 1024)
    wire_buf.write(ww.update(inner.getvalue()))

# Receiver
nlen = wrapper.nonce_size(cipher_name)
wire = wire_buf.getvalue()
with wrapper.UnwrapStreamReader(cipher_name, outer_key, wire[:nlen]) as ur:
    inner_wire = ur.update(wire[nlen:])
out_buf = io.BytesIO()
enc.decrypt_stream_auth(io.BytesIO(inner_wire), out_buf)
```

### 2. Streaming AEAD Low-Level (MAC Authenticated, IO-Driven)

ITB Call: `itb.encrypt_stream_auth` / `itb.decrypt_stream_auth` with three explicit `Seed` handles plus an `itb.MAC("hmac-blake3", key)` instance. Wrap shape: `WrapStreamWriter` / `UnwrapStreamReader`.

```python
seeds = [itb.Seed("areion512", 1024) for _ in range(3)]
mac = itb.MAC("hmac-blake3", secrets.token_bytes(32))

outer_key = wrapper.generate_key(cipher_name)
wire_buf = io.BytesIO()
with wrapper.WrapStreamWriter(cipher_name, outer_key) as ww:
    wire_buf.write(ww.nonce)
    inner = io.BytesIO()
    itb.encrypt_stream_auth(*seeds, mac, plaintext_reader, inner, chunk_size=16 * 1024)
    wire_buf.write(ww.update(inner.getvalue()))

# receiver
nlen = wrapper.nonce_size(cipher_name)
wire = wire_buf.getvalue()
with wrapper.UnwrapStreamReader(cipher_name, outer_key, wire[:nlen]) as ur:
    inner_wire = ur.update(wire[nlen:])
out_buf = io.BytesIO()
itb.decrypt_stream_auth(*seeds, mac, io.BytesIO(inner_wire), out_buf)
```

### 3. Streaming Easy (No MAC, User-Driven Loop)

The "Alternative — User-Driven Loop" pattern: each chunk is one independent `enc.encrypt(buf)` call. Wrap shape: `WrapStreamWriter` / `UnwrapStreamReader` driven by a caller loop that emits `u32_LE_len || ct` per chunk through the wrapped writer. Length prefix and chunk body both pass through the keystream XOR — no length appears in cleartext on the wire.

```python
import struct

enc = itb.Encryptor("areion512", 1024, mac=None, mode=1)
enc.set_nonce_bits(512); enc.set_barrier_fill(4)
enc.set_bit_soup(1); enc.set_lock_soup(1)

outer_key = wrapper.generate_key(cipher_name)
wire_buf = io.BytesIO()
with wrapper.WrapStreamWriter(cipher_name, outer_key) as ww:
    wire_buf.write(ww.nonce)
    for off in range(0, len(plaintext), chunk_size):
        chunk = plaintext[off:off + chunk_size]
        ct = enc.encrypt(chunk)
        wire_buf.write(ww.update(struct.pack("<I", len(ct))))
        wire_buf.write(ww.update(ct))

# Receiver — read u32_LE length then body through the unwrap-reader, looping until exhausted.
nlen = wrapper.nonce_size(cipher_name)
wire = wire_buf.getvalue()
with wrapper.UnwrapStreamReader(cipher_name, outer_key, wire[:nlen]) as ur:
    decrypted = ur.update(wire[nlen:])
view = memoryview(decrypted)
off = 0
while off < len(view):
    (clen,) = struct.unpack("<I", bytes(view[off:off + 4]))
    off += 4
    ct = bytes(view[off:off + clen])
    off += clen
    out_buf.write(enc.decrypt(ct))
```

### 4. Streaming Low-Level (No MAC, User-Driven Loop)

Per-chunk `itb.encrypt` / `itb.decrypt` with caller-side framing. Wrap shape: `WrapStreamWriter` / `UnwrapStreamReader`. Each chunk is emitted as `u32_LE_len || ct` through the wrap-writer; the length and the body both pass through the keystream XOR.

```python
seeds = [itb.Seed("areion512", 1024) for _ in range(3)]

outer_key = wrapper.generate_key(cipher_name)
wire_buf = io.BytesIO()
with wrapper.WrapStreamWriter(cipher_name, outer_key) as ww:
    wire_buf.write(ww.nonce)
    for off in range(0, len(plaintext), chunk_size):
        chunk = plaintext[off:off + chunk_size]
        ct = itb.encrypt(*seeds, chunk)
        wire_buf.write(ww.update(struct.pack("<I", len(ct))))
        wire_buf.write(ww.update(ct))

# Receiver
nlen = wrapper.nonce_size(cipher_name)
wire = wire_buf.getvalue()
with wrapper.UnwrapStreamReader(cipher_name, outer_key, wire[:nlen]) as ur:
    decrypted = ur.update(wire[nlen:])
view = memoryview(decrypted)
off = 0
while off < len(view):
    (clen,) = struct.unpack("<I", bytes(view[off:off + 4]))
    off += 4
    ct = bytes(view[off:off + clen])
    off += clen
    out_buf.write(itb.decrypt(*seeds, ct))
```

### 5. Easy: Areion-SoEM-512 (No MAC, Single Message)

ITB Call: `enc.encrypt(plaintext)` returns one ITB blob. Wrap shape: `wrap` — `nonce || ks-XOR(blob)`. The `wrap_in_place` / `unwrap_in_place` variant is shown — mutates the caller's `bytearray` in place to skip the steady-state allocation.

```python
enc = itb.Encryptor("areion512", 2048, mac=None, mode=1)
enc.set_nonce_bits(512); enc.set_barrier_fill(4)
enc.set_bit_soup(1); enc.set_lock_soup(1)

encrypted = enc.encrypt(plaintext)

outer_key = wrapper.generate_key(cipher_name)
# wrap respects immutability of `encrypted` (allocates a fresh wire buffer):
# wire = wrapper.wrap(cipher_name, outer_key, encrypted)
mutable_blob = bytearray(encrypted)
nonce = wrapper.wrap_in_place(cipher_name, outer_key, mutable_blob)
wire = bytes(nonce) + bytes(mutable_blob)

# receiver — unwrap respects immutability of `wire` (allocates a fresh recovered buffer):
# recovered = wrapper.unwrap(cipher_name, outer_key, wire)
wire_buf = bytearray(wire)
recovered_view = wrapper.unwrap_in_place(cipher_name, outer_key, wire_buf)
recovered = bytes(recovered_view)
pt = enc.decrypt(recovered)
```

### 6. Easy: Areion-SoEM-512 + HMAC-BLAKE3 (MAC Authenticated, Single Message)

ITB Call: `enc.encrypt_auth` / `enc.decrypt_auth`. Wrap shape: `wrap` (or `wrap_in_place`). The ITB-internal 32-byte MAC tag remains inside the RGBWYOPA container; outer cipher is format-deniability only.

```python
enc = itb.Encryptor("areion512", 2048, "hmac-blake3", mode=1)
enc.set_nonce_bits(512); enc.set_barrier_fill(4)
enc.set_bit_soup(1); enc.set_lock_soup(1)

encrypted = enc.encrypt_auth(plaintext)

outer_key = wrapper.generate_key(cipher_name)
mutable_blob = bytearray(encrypted)
nonce = wrapper.wrap_in_place(cipher_name, outer_key, mutable_blob)
wire = bytes(nonce) + bytes(mutable_blob)

# receiver
wire_buf = bytearray(wire)
recovered_view = wrapper.unwrap_in_place(cipher_name, outer_key, wire_buf)
pt = enc.decrypt_auth(bytes(recovered_view))
```

### 7. Low-Level: Areion-SoEM-512 (No MAC, Single Message)

ITB Call: `itb.encrypt(*seeds, plaintext)` / `itb.decrypt(...)` with three explicit `Seed` handles. Wrap shape: `wrap` (or `wrap_in_place`). Wire shape matches example 5; the difference is that the seed material is held by caller-side `Seed` handles rather than by an `Encryptor` instance.

```python
seeds = [itb.Seed("areion512", 2048) for _ in range(3)]

encrypted = itb.encrypt(*seeds, plaintext)

outer_key = wrapper.generate_key(cipher_name)
mutable_blob = bytearray(encrypted)
nonce = wrapper.wrap_in_place(cipher_name, outer_key, mutable_blob)
wire = bytes(nonce) + bytes(mutable_blob)

# receiver
wire_buf = bytearray(wire)
recovered_view = wrapper.unwrap_in_place(cipher_name, outer_key, wire_buf)
pt = itb.decrypt(*seeds, bytes(recovered_view))
```

### 8. Low-Level: Areion-SoEM-512 + HMAC-BLAKE3 (MAC Authenticated, Single Message)

ITB Call: `itb.encrypt_auth(*seeds, mac, plaintext)` / `itb.decrypt_auth(...)`.  Wrap shape: `wrap` (or `wrap_in_place`). The ITB-internal 32-byte MAC tag remains inside the RGBWYOPA container; outer cipher is format-deniability only.

```python
seeds = [itb.Seed("areion512", 2048) for _ in range(3)]
mac = itb.MAC("hmac-blake3", secrets.token_bytes(32))

encrypted = itb.encrypt_auth(*seeds, mac, plaintext)

outer_key = wrapper.generate_key(cipher_name)
mutable_blob = bytearray(encrypted)
nonce = wrapper.wrap_in_place(cipher_name, outer_key, mutable_blob)
wire = bytes(nonce) + bytes(mutable_blob)

# receiver
wire_buf = bytearray(wire)
recovered_view = wrapper.unwrap_in_place(cipher_name, outer_key, wire_buf)
pt = itb.decrypt_auth(*seeds, mac, bytes(recovered_view))
```

## Verification matrix

Every example × cipher combination round-trips against random plaintext (1 KiB for Single Message, 64 KiB for streaming) with sha256 byte-equality. Sample run:

```
[PASS] aead-easy-io               + aes        pt=65536 wire=90208
[PASS] aead-easy-io               + chacha     pt=65536 wire=90204
[PASS] aead-easy-io               + siphash    pt=65536 wire=90208
[PASS] aead-lowlevel-io           + aes        pt=65536 wire=90208
[PASS] aead-lowlevel-io           + chacha     pt=65536 wire=90204
[PASS] aead-lowlevel-io           + siphash    pt=65536 wire=90208
[PASS] noaead-easy-userloop       + aes        pt=65536 wire=90192
[PASS] noaead-easy-userloop       + chacha     pt=65536 wire=90188
[PASS] noaead-easy-userloop       + siphash    pt=65536 wire=90192
[PASS] noaead-lowlevel-userloop   + aes        pt=65536 wire=90192
[PASS] noaead-lowlevel-userloop   + chacha     pt=65536 wire=90188
[PASS] noaead-lowlevel-userloop   + siphash    pt=65536 wire=90192
[PASS] message-easy-nomac         + aes        pt=1024 wire=4316
[PASS] message-easy-nomac         + chacha     pt=1024 wire=4312
[PASS] message-easy-nomac         + siphash    pt=1024 wire=4316
[PASS] message-easy-auth          + aes        pt=1024 wire=8276
[PASS] message-easy-auth          + chacha     pt=1024 wire=8272
[PASS] message-easy-auth          + siphash    pt=1024 wire=8276
[PASS] message-lowlevel-nomac     + aes        pt=1024 wire=4316
[PASS] message-lowlevel-nomac     + chacha     pt=1024 wire=4312
[PASS] message-lowlevel-nomac     + siphash    pt=1024 wire=4316
[PASS] message-lowlevel-auth      + aes        pt=1024 wire=8276
[PASS] message-lowlevel-auth      + chacha     pt=1024 wire=8272
[PASS] message-lowlevel-auth      + siphash    pt=1024 wire=8276

=== Summary: 24 PASS, 0 FAIL ===
```

The wire-byte difference between cipher columns is exactly the per-stream nonce-size delta (16 vs 12 vs 16 bytes); the User-Driven Loop variants additionally include 4 bytes of keystream-XORed length prefix per chunk.

## Performance

Bench numbers across Single Ouroboros and Triple Ouroboros, message and streaming, encrypt and decrypt (split sub-benches) are tracked in [BENCH.md](BENCH.md).

## Notes on outer cipher key management

The wrapper itself does not address outer key distribution; the example utility generates a fresh CSPRNG outer key per run for self-test purposes. In a real deployment the outer key is shared out-of-band (or derived via a separate key-exchange step) and is independent of the ITB seed material. The ITB state blob already carries the inner cipher's keying material; the outer key is the additional piece both endpoints need.

The outer key MAY be reused across many streams provided each stream uses a fresh CSPRNG nonce — this is the standard CTR mode safety contract. The wrapper helpers always generate a fresh nonce internally, so caller-side discipline is reduced to "do not reuse the same `(key, nonce)` across distinct streams" — a contract the helper enforces by construction.

## What this is not

- Not an integrity layer. The outer cipher is unauthenticated by design — adding a MAC at this layer would defeat the format-deniability goal (the resulting wire would pattern-match an AEAD construction's tag-bearing format, not a generic stream cipher). Use the ITB AEAD path when integrity is required.
- Not a substitute for ITB's content-deniability. ITB still provides the unconditional content-deniability; the wrap adds format-deniability on top.
