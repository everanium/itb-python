"""Cffi-based binding over libitb's C ABI.

Loads libitb.so / .dll / .dylib via cffi ABI mode (no C compiler at
install time). The shared library is searched in this order:

  1. ``ITB_LIBRARY_PATH`` environment variable (absolute path).
  2. ``<repo>/dist/<os>-<arch>/libitb.<ext>`` resolved from this file
     by walking four directory levels up
     (bindings/python/itb/_ffi.py → repo root → dist/...).
  3. system loader path (``ldconfig`` / ``DYLD_LIBRARY_PATH`` / ``PATH``).

Status codes returned by every entry point are translated to Python
exceptions (``ITBError``) so callers do not have to inspect integers.

Empty plaintext / ciphertext is rejected by libitb itself with
``STATUS_ENCRYPT_FAILED`` (the Go-side ``Encrypt128`` / ``Decrypt128``
family returns ``"itb: empty data"`` before any work). The binding
propagates the rejection verbatim — pass at least one byte.

Threading. The low-level free functions exposed at the module level
(``encrypt`` / ``decrypt`` / ``encrypt_auth`` / ``decrypt_auth`` and
the Triple Ouroboros variants) are thread-safe: each call allocates
its own output buffer and the underlying libitb worker pool dispatches
encrypts independently. Process-wide setters (``set_bit_soup``,
``set_lock_soup``, ``set_max_workers``, ``set_nonce_bits``,
``set_barrier_fill``) are atomic stores — each setter call atomically
updates a single counter and is safe to invoke from any thread in
isolation. The caveat is logical, not atomic: changing a knob WHILE
an encrypt / decrypt call is in flight can corrupt that operation —
the cipher snapshots the configuration at call entry and a mid-flight
change breaks the running invariants. Treat the global knobs as
set-once-at-startup; rare runtime updates need external sequencing
against active cipher calls. ``Seed.attach_lock_seed`` mutates seed
state (not a single atomic counter) — it is NOT thread-safe and must
be called outside any in-flight cipher operation on the same noise
seed.

Threading note. ``ITB_LastError`` and ``ITB_Easy_LastMismatchField``
read process-global atomics that follow the C ``errno`` discipline:
the most recent non-OK Status across the whole process wins, and a
sibling thread that calls into libitb between the failing call and
the diagnostic read overwrites the message. Multi-threaded Python
applications that need reliable diagnostic attribution should
serialise FFI calls under a process-wide lock or accept that the
textual message returned by ``ITBError`` may belong to a different
call. The structural Status code on the failing call's return
value is unaffected — only the textual diagnostic is racy.

Lock-seed lifecycle. ``Seed.attach_lock_seed`` records the lock
seed pointer on the noiseSeed but does not bump a refcount on the
Python object. Releasing the lock seed via ``lockSeed.free()``
before the noiseSeed has finished its useful lifetime invalidates
the bit-permutation overlay derivation; subsequent encrypt calls
panic via ``ErrLockSeedOverlayOff`` or use zeroed components.
Standard pairing: keep the lock seed alive at least as long as the
noiseSeed.
"""

from __future__ import annotations

import os
import platform
import sys
from pathlib import Path
from typing import List, Tuple

import cffi

# Status codes — must mirror cmd/cshared/internal/capi/errors.go
STATUS_OK = 0
STATUS_BAD_HASH = 1
STATUS_BAD_KEY_BITS = 2
STATUS_BAD_HANDLE = 3
STATUS_BAD_INPUT = 4
STATUS_BUFFER_TOO_SMALL = 5
STATUS_ENCRYPT_FAILED = 6
STATUS_DECRYPT_FAILED = 7
STATUS_SEED_WIDTH_MIX = 8
STATUS_BAD_MAC = 9
STATUS_MAC_FAILURE = 10
# Easy encryptor (itb/easy sub-package) sentinel codes — block 11..18
# is dedicated to the Encryptor surface so the lower codes 0..10
# remain reserved for the low-level Encrypt / Decrypt path.
STATUS_EASY_CLOSED = 11
STATUS_EASY_MALFORMED = 12
STATUS_EASY_VERSION_TOO_NEW = 13
STATUS_EASY_UNKNOWN_PRIMITIVE = 14
STATUS_EASY_UNKNOWN_MAC = 15
STATUS_EASY_BAD_KEY_BITS = 16
STATUS_EASY_MISMATCH = 17
STATUS_EASY_LOCKSEED_AFTER_ENCRYPT = 18
# Native Blob (itb.Blob128 / 256 / 512) sentinel codes — block 19..22
# is dedicated to the low-level state-blob surface so the lower codes
# 0..18 remain reserved for the seed-handle / Encrypt / Decrypt /
# Encryptor paths.
STATUS_BLOB_MODE_MISMATCH = 19
STATUS_BLOB_MALFORMED = 20
STATUS_BLOB_VERSION_TOO_NEW = 21
STATUS_BLOB_TOO_MANY_OPTS = 22
# Streaming AEAD sentinel codes — block 23..24 covers the two
# end-of-stream failure modes the binding-side stream-loop helper
# detects after the per-chunk MAC verification path. Numeric values
# are cross-binding canonical (mirrors ITB_STREAM_TRUNCATED /
# ITB_STREAM_AFTER_FINAL in cmd/cshared/internal/capi/errors.go).
STATUS_STREAM_TRUNCATED = 23
STATUS_STREAM_AFTER_FINAL = 24
STATUS_INTERNAL = 99


class ITBError(RuntimeError):
    """Raised on any non-OK status from the libitb C ABI."""

    def __init__(self, code: int, message: str = ""):
        self.code = code
        super().__init__(f"itb: status={code} ({message})" if message else f"itb: status={code}")


class ItbStreamTruncatedError(ITBError):
    """Raised when an authenticated stream input exhausts without
    observing a chunk whose recovered ``final_flag`` is ``1``. Carries
    :data:`STATUS_STREAM_TRUNCATED` (numeric value ``23``)."""

    def __init__(self, message: str = ""):
        super().__init__(STATUS_STREAM_TRUNCATED, message)


class ItbStreamAfterFinalError(ITBError):
    """Raised when extra chunk bytes follow the terminating chunk on an
    authenticated stream's wire transcript. Carries
    :data:`STATUS_STREAM_AFTER_FINAL` (numeric value ``24``)."""

    def __init__(self, message: str = ""):
        super().__init__(STATUS_STREAM_AFTER_FINAL, message)


# C ABI integer-typedef widths track the host word size — uintptr_t
# and size_t are 8 bytes on 64-bit systems and 4 bytes on 32-bit
# systems. cffi ABI mode resolves typedefs literally, so the CDEF
# string must declare the right width for the target Python build.
# sys.maxsize crosses 2**31 on 64-bit Pythons (typically ~2**63 - 1)
# and stays below it on 32-bit Pythons (~2**31 - 1), giving a
# reliable proxy for the host's C-side word size.
if sys.maxsize > 2**31:
    _PTR_TYPE = "unsigned long long"
    _SIZE_TYPE = "unsigned long long"
else:
    _PTR_TYPE = "unsigned int"
    _SIZE_TYPE = "unsigned int"

_CDEF = f"""
typedef {_PTR_TYPE} uintptr_t;
typedef {_SIZE_TYPE} size_t;
typedef long long int64_t;

extern int ITB_Version(char* out, size_t capBytes, size_t* outLen);
extern int ITB_HashCount(void);
extern int ITB_HashName(int i, char* out, size_t capBytes, size_t* outLen);
extern int ITB_HashWidth(int i);
extern int ITB_LastError(char* out, size_t capBytes, size_t* outLen);

extern int ITB_NewSeed(char* hashName, int keyBits, uintptr_t* outHandle);
extern int ITB_FreeSeed(uintptr_t handle);
extern int ITB_SeedWidth(uintptr_t handle, int* outStatus);
extern int ITB_SeedHashName(uintptr_t handle, char* out, size_t capBytes, size_t* outLen);

extern int ITB_AttachLockSeed(uintptr_t noiseHandle, uintptr_t lockHandle);

extern int ITB_NewSeedFromComponents(
    char* hashName,
    unsigned long long* components, int componentsLen,
    unsigned char* hashKey, int hashKeyLen,
    uintptr_t* outHandle);
extern int ITB_GetSeedHashKey(
    uintptr_t handle,
    unsigned char* out, size_t capBytes, size_t* outLen);
extern int ITB_GetSeedComponents(
    uintptr_t handle,
    unsigned long long* out, int capCount, int* outLen);

extern int ITB_Encrypt(
    uintptr_t noiseHandle, uintptr_t dataHandle, uintptr_t startHandle,
    void* plaintext, size_t ptlen,
    void* out, size_t outCap, size_t* outLen);
extern int ITB_Decrypt(
    uintptr_t noiseHandle, uintptr_t dataHandle, uintptr_t startHandle,
    void* ciphertext, size_t ctlen,
    void* out, size_t outCap, size_t* outLen);

extern int ITB_Encrypt3(
    uintptr_t noiseHandle,
    uintptr_t dataHandle1, uintptr_t dataHandle2, uintptr_t dataHandle3,
    uintptr_t startHandle1, uintptr_t startHandle2, uintptr_t startHandle3,
    void* plaintext, size_t ptlen,
    void* out, size_t outCap, size_t* outLen);
extern int ITB_Decrypt3(
    uintptr_t noiseHandle,
    uintptr_t dataHandle1, uintptr_t dataHandle2, uintptr_t dataHandle3,
    uintptr_t startHandle1, uintptr_t startHandle2, uintptr_t startHandle3,
    void* ciphertext, size_t ctlen,
    void* out, size_t outCap, size_t* outLen);

extern int ITB_MACCount(void);
extern int ITB_MACName(int i, char* out, size_t capBytes, size_t* outLen);
extern int ITB_MACKeySize(int i);
extern int ITB_MACTagSize(int i);
extern int ITB_MACMinKeyBytes(int i);
extern int ITB_NewMAC(char* macName, void* key, size_t keyLen, uintptr_t* outHandle);
extern int ITB_FreeMAC(uintptr_t handle);

extern int ITB_EncryptAuth(
    uintptr_t noiseHandle, uintptr_t dataHandle, uintptr_t startHandle,
    uintptr_t macHandle,
    void* plaintext, size_t ptlen,
    void* out, size_t outCap, size_t* outLen);
extern int ITB_DecryptAuth(
    uintptr_t noiseHandle, uintptr_t dataHandle, uintptr_t startHandle,
    uintptr_t macHandle,
    void* ciphertext, size_t ctlen,
    void* out, size_t outCap, size_t* outLen);

extern int ITB_EncryptAuth3(
    uintptr_t noiseHandle,
    uintptr_t dataHandle1, uintptr_t dataHandle2, uintptr_t dataHandle3,
    uintptr_t startHandle1, uintptr_t startHandle2, uintptr_t startHandle3,
    uintptr_t macHandle,
    void* plaintext, size_t ptlen,
    void* out, size_t outCap, size_t* outLen);
extern int ITB_DecryptAuth3(
    uintptr_t noiseHandle,
    uintptr_t dataHandle1, uintptr_t dataHandle2, uintptr_t dataHandle3,
    uintptr_t startHandle1, uintptr_t startHandle2, uintptr_t startHandle3,
    uintptr_t macHandle,
    void* ciphertext, size_t ctlen,
    void* out, size_t outCap, size_t* outLen);

extern int ITB_SetBitSoup(int mode);
extern int ITB_GetBitSoup(void);
extern int ITB_SetLockSoup(int mode);
extern int ITB_GetLockSoup(void);
extern int ITB_SetMaxWorkers(int n);
extern int ITB_GetMaxWorkers(void);
extern int ITB_SetNonceBits(int n);
extern int ITB_GetNonceBits(void);
extern int ITB_SetBarrierFill(int n);
extern int ITB_GetBarrierFill(void);
extern int64_t ITB_SetMemoryLimit(int64_t limit);
extern int ITB_SetGCPercent(int pct);

extern int ITB_MaxKeyBits(void);
extern int ITB_Channels(void);
extern int ITB_HeaderSize(void);

extern int ITB_ParseChunkLen(void* header, size_t headerLen, size_t* outChunkLen);

/* Easy encryptor surface — wraps github.com/everanium/itb/easy. */

extern int ITB_Easy_New(
    char* primitive, int keyBits, char* macName, int mode,
    uintptr_t* outHandle);
extern int ITB_Easy_NewMixed(
    char* primN, char* primD, char* primS, char* primL,
    int keyBits, char* macName,
    uintptr_t* outHandle);
extern int ITB_Easy_NewMixed3(
    char* primN,
    char* primD1, char* primD2, char* primD3,
    char* primS1, char* primS2, char* primS3,
    char* primL,
    int keyBits, char* macName,
    uintptr_t* outHandle);
extern int ITB_Easy_Free(uintptr_t handle);
extern int ITB_Easy_PrimitiveAt(
    uintptr_t handle, int slot,
    char* out, size_t capBytes, size_t* outLen);
extern int ITB_Easy_IsMixed(uintptr_t handle, int* outStatus);

extern int ITB_Easy_Encrypt(
    uintptr_t handle,
    void* plaintext, size_t ptlen,
    void* out, size_t outCap, size_t* outLen);
extern int ITB_Easy_Decrypt(
    uintptr_t handle,
    void* ciphertext, size_t ctlen,
    void* out, size_t outCap, size_t* outLen);
extern int ITB_Easy_EncryptAuth(
    uintptr_t handle,
    void* plaintext, size_t ptlen,
    void* out, size_t outCap, size_t* outLen);
extern int ITB_Easy_DecryptAuth(
    uintptr_t handle,
    void* ciphertext, size_t ctlen,
    void* out, size_t outCap, size_t* outLen);

extern int ITB_Easy_SetNonceBits(uintptr_t handle, int n);
extern int ITB_Easy_SetBarrierFill(uintptr_t handle, int n);
extern int ITB_Easy_SetBitSoup(uintptr_t handle, int mode);
extern int ITB_Easy_SetLockSoup(uintptr_t handle, int mode);
extern int ITB_Easy_SetLockSeed(uintptr_t handle, int mode);
extern int ITB_Easy_SetChunkSize(uintptr_t handle, int n);

extern int ITB_Easy_Primitive(uintptr_t handle, char* out, size_t capBytes, size_t* outLen);
extern int ITB_Easy_KeyBits(uintptr_t handle, int* outStatus);
extern int ITB_Easy_Mode(uintptr_t handle, int* outStatus);
extern int ITB_Easy_MACName(uintptr_t handle, char* out, size_t capBytes, size_t* outLen);

extern int ITB_Easy_SeedCount(uintptr_t handle, int* outStatus);
extern int ITB_Easy_SeedComponents(
    uintptr_t handle, int slot,
    unsigned long long* out, int capCount, int* outLen);
extern int ITB_Easy_HasPRFKeys(uintptr_t handle, int* outStatus);
extern int ITB_Easy_PRFKey(
    uintptr_t handle, int slot,
    unsigned char* out, size_t capBytes, size_t* outLen);
extern int ITB_Easy_MACKey(
    uintptr_t handle,
    unsigned char* out, size_t capBytes, size_t* outLen);

extern int ITB_Easy_Close(uintptr_t handle);

extern int ITB_Easy_Export(
    uintptr_t handle,
    void* out, size_t outCap, size_t* outLen);
extern int ITB_Easy_Import(
    uintptr_t handle,
    void* blob, size_t blobLen);
extern int ITB_Easy_PeekConfig(
    void* blob, size_t blobLen,
    char* primOut, size_t primCap, size_t* primLen,
    int* keyBitsOut, int* modeOut,
    char* macOut, size_t macCap, size_t* macLen);
extern int ITB_Easy_LastMismatchField(char* out, size_t capBytes, size_t* outLen);

extern int ITB_Easy_NonceBits(uintptr_t handle, int* outStatus);
extern int ITB_Easy_HeaderSize(uintptr_t handle, int* outStatus);
extern int ITB_Easy_ParseChunkLen(
    uintptr_t handle,
    void* header, size_t headerLen,
    size_t* outChunkLen);

/* Native Blob — low-level state persistence (itb.Blob128/256/512). */

extern int ITB_Blob128_New(uintptr_t* outHandle);
extern int ITB_Blob256_New(uintptr_t* outHandle);
extern int ITB_Blob512_New(uintptr_t* outHandle);
extern int ITB_Blob_Free(uintptr_t handle);

extern int ITB_Blob_Width(uintptr_t handle, int* outStatus);
extern int ITB_Blob_Mode(uintptr_t handle, int* outStatus);

extern int ITB_Blob_SetKey(
    uintptr_t handle, int slot,
    void* key, size_t keyLen);
extern int ITB_Blob_GetKey(
    uintptr_t handle, int slot,
    void* out, size_t outCap, size_t* outLen);

extern int ITB_Blob_SetComponents(
    uintptr_t handle, int slot,
    unsigned long long* comps, size_t count);
extern int ITB_Blob_GetComponents(
    uintptr_t handle, int slot,
    unsigned long long* out, size_t outCap, size_t* outCount);

extern int ITB_Blob_SetMACKey(
    uintptr_t handle,
    void* key, size_t keyLen);
extern int ITB_Blob_GetMACKey(
    uintptr_t handle,
    void* out, size_t outCap, size_t* outLen);

extern int ITB_Blob_SetMACName(
    uintptr_t handle,
    char* name, size_t nameLen);
extern int ITB_Blob_GetMACName(
    uintptr_t handle,
    char* out, size_t outCap, size_t* outLen);

extern int ITB_Blob_Export(
    uintptr_t handle, int optsBitmask,
    void* out, size_t outCap, size_t* outLen);
extern int ITB_Blob_Export3(
    uintptr_t handle, int optsBitmask,
    void* out, size_t outCap, size_t* outLen);
extern int ITB_Blob_Import(
    uintptr_t handle,
    void* blob, size_t blobLen);
extern int ITB_Blob_Import3(
    uintptr_t handle,
    void* blob, size_t blobLen);

/* Streaming AEAD per-chunk dispatch — Single Ouroboros (3 seeds + MAC).
 * Mirrors the parameter order in libitb.h. The streamID buffer is a
 * 32-byte array (length fixed by the Streaming AEAD construction). The
 * cumulativePixelOffset is the running sum of W*H over preceding
 * chunks; finalFlag is non-zero for the terminating chunk. */
extern int ITB_EncryptStreamAuthenticated128(
    uintptr_t noiseHandle, uintptr_t dataHandle, uintptr_t startHandle,
    uintptr_t macHandle,
    void* plaintext, size_t ptlen,
    unsigned char* streamID,
    unsigned long long cumulativePixelOffset,
    int finalFlag,
    void* out, size_t outCap, size_t* outLen);
extern int ITB_EncryptStreamAuthenticated256(
    uintptr_t noiseHandle, uintptr_t dataHandle, uintptr_t startHandle,
    uintptr_t macHandle,
    void* plaintext, size_t ptlen,
    unsigned char* streamID,
    unsigned long long cumulativePixelOffset,
    int finalFlag,
    void* out, size_t outCap, size_t* outLen);
extern int ITB_EncryptStreamAuthenticated512(
    uintptr_t noiseHandle, uintptr_t dataHandle, uintptr_t startHandle,
    uintptr_t macHandle,
    void* plaintext, size_t ptlen,
    unsigned char* streamID,
    unsigned long long cumulativePixelOffset,
    int finalFlag,
    void* out, size_t outCap, size_t* outLen);

extern int ITB_DecryptStreamAuthenticated128(
    uintptr_t noiseHandle, uintptr_t dataHandle, uintptr_t startHandle,
    uintptr_t macHandle,
    void* ciphertext, size_t ctlen,
    unsigned char* streamID,
    unsigned long long cumulativePixelOffset,
    void* out, size_t outCap, size_t* outLen,
    int* finalFlagOut);
extern int ITB_DecryptStreamAuthenticated256(
    uintptr_t noiseHandle, uintptr_t dataHandle, uintptr_t startHandle,
    uintptr_t macHandle,
    void* ciphertext, size_t ctlen,
    unsigned char* streamID,
    unsigned long long cumulativePixelOffset,
    void* out, size_t outCap, size_t* outLen,
    int* finalFlagOut);
extern int ITB_DecryptStreamAuthenticated512(
    uintptr_t noiseHandle, uintptr_t dataHandle, uintptr_t startHandle,
    uintptr_t macHandle,
    void* ciphertext, size_t ctlen,
    unsigned char* streamID,
    unsigned long long cumulativePixelOffset,
    void* out, size_t outCap, size_t* outLen,
    int* finalFlagOut);

/* Streaming AEAD per-chunk dispatch — Triple Ouroboros (7 seeds + MAC). */
extern int ITB_EncryptStreamAuthenticated3x128(
    uintptr_t noiseHandle,
    uintptr_t dataHandle1, uintptr_t dataHandle2, uintptr_t dataHandle3,
    uintptr_t startHandle1, uintptr_t startHandle2, uintptr_t startHandle3,
    uintptr_t macHandle,
    void* plaintext, size_t ptlen,
    unsigned char* streamID,
    unsigned long long cumulativePixelOffset,
    int finalFlag,
    void* out, size_t outCap, size_t* outLen);
extern int ITB_EncryptStreamAuthenticated3x256(
    uintptr_t noiseHandle,
    uintptr_t dataHandle1, uintptr_t dataHandle2, uintptr_t dataHandle3,
    uintptr_t startHandle1, uintptr_t startHandle2, uintptr_t startHandle3,
    uintptr_t macHandle,
    void* plaintext, size_t ptlen,
    unsigned char* streamID,
    unsigned long long cumulativePixelOffset,
    int finalFlag,
    void* out, size_t outCap, size_t* outLen);
extern int ITB_EncryptStreamAuthenticated3x512(
    uintptr_t noiseHandle,
    uintptr_t dataHandle1, uintptr_t dataHandle2, uintptr_t dataHandle3,
    uintptr_t startHandle1, uintptr_t startHandle2, uintptr_t startHandle3,
    uintptr_t macHandle,
    void* plaintext, size_t ptlen,
    unsigned char* streamID,
    unsigned long long cumulativePixelOffset,
    int finalFlag,
    void* out, size_t outCap, size_t* outLen);

extern int ITB_DecryptStreamAuthenticated3x128(
    uintptr_t noiseHandle,
    uintptr_t dataHandle1, uintptr_t dataHandle2, uintptr_t dataHandle3,
    uintptr_t startHandle1, uintptr_t startHandle2, uintptr_t startHandle3,
    uintptr_t macHandle,
    void* ciphertext, size_t ctlen,
    unsigned char* streamID,
    unsigned long long cumulativePixelOffset,
    void* out, size_t outCap, size_t* outLen,
    int* finalFlagOut);
extern int ITB_DecryptStreamAuthenticated3x256(
    uintptr_t noiseHandle,
    uintptr_t dataHandle1, uintptr_t dataHandle2, uintptr_t dataHandle3,
    uintptr_t startHandle1, uintptr_t startHandle2, uintptr_t startHandle3,
    uintptr_t macHandle,
    void* ciphertext, size_t ctlen,
    unsigned char* streamID,
    unsigned long long cumulativePixelOffset,
    void* out, size_t outCap, size_t* outLen,
    int* finalFlagOut);
extern int ITB_DecryptStreamAuthenticated3x512(
    uintptr_t noiseHandle,
    uintptr_t dataHandle1, uintptr_t dataHandle2, uintptr_t dataHandle3,
    uintptr_t startHandle1, uintptr_t startHandle2, uintptr_t startHandle3,
    uintptr_t macHandle,
    void* ciphertext, size_t ctlen,
    unsigned char* streamID,
    unsigned long long cumulativePixelOffset,
    void* out, size_t outCap, size_t* outLen,
    int* finalFlagOut);

/* Easy Mode Streaming AEAD per-chunk dispatch (driven by the
 * encryptor handle rather than seed handles + MAC handle). */
extern int ITB_Easy_EncryptStreamAuth(
    uintptr_t handle,
    void* plaintext, size_t ptlen,
    unsigned char* streamID,
    unsigned long long cumulativePixelOffset,
    int finalFlag,
    void* out, size_t outCap, size_t* outLen);
extern int ITB_Easy_DecryptStreamAuth(
    uintptr_t handle,
    void* ciphertext, size_t ctlen,
    unsigned char* streamID,
    unsigned long long cumulativePixelOffset,
    void* out, size_t outCap, size_t* outLen,
    int* finalFlagOut);

/* Format-deniability wrapper (outer CTR cipher). Mirrors the
 * 12 entry points exported by cmd/cshared/main.go for the
 * github.com/everanium/itb/wrapper Go package. The cipher_name
 * argument selects one of three outer keystream ciphers
 * ("aes" / "chacha" / "siphash"). */

extern int ITB_WrapperKeySize(char* cipherName, size_t* outSize);
extern int ITB_WrapperNonceSize(char* cipherName, size_t* outSize);

extern int ITB_Wrap(
    char* cipherName,
    void* key, size_t keyLen,
    void* blob, size_t blobLen,
    void* out, size_t outCap, size_t* outLen);
extern int ITB_Unwrap(
    char* cipherName,
    void* key, size_t keyLen,
    void* wire, size_t wireLen,
    void* out, size_t outCap, size_t* outLen);

extern int ITB_WrapInPlace(
    char* cipherName,
    void* key, size_t keyLen,
    void* blob, size_t blobLen,
    void* outNonce, size_t nonceCap);
extern int ITB_UnwrapInPlace(
    char* cipherName,
    void* key, size_t keyLen,
    void* wire, size_t wireLen);

extern int ITB_WrapStreamWriter_Init(
    char* cipherName,
    void* key, size_t keyLen,
    void* outNonce, size_t nonceCap,
    uintptr_t* outHandle);
extern int ITB_WrapStreamWriter_Update(
    uintptr_t handle,
    void* src, size_t srcLen,
    void* dst, size_t dstCap);
extern int ITB_WrapStreamWriter_Free(uintptr_t handle);

extern int ITB_UnwrapStreamReader_Init(
    char* cipherName,
    void* key, size_t keyLen,
    void* wireNonce, size_t nonceLen,
    uintptr_t* outHandle);
extern int ITB_UnwrapStreamReader_Update(
    uintptr_t handle,
    void* src, size_t srcLen,
    void* dst, size_t dstCap);
extern int ITB_UnwrapStreamReader_Free(uintptr_t handle);
"""


def _platform_lib_dir() -> str:
    """Maps Python platform.system() / machine() to the dist/ subfolder
    naming convention used by cmd/cshared builds."""
    sysname = {
        "Linux": "linux",
        "Darwin": "darwin",
        "Windows": "windows",
        "FreeBSD": "freebsd",
    }.get(platform.system(), platform.system().lower())
    arch = {
        "x86_64": "amd64",
        "AMD64": "amd64",
        "aarch64": "arm64",
        "arm64": "arm64",
    }.get(platform.machine(), platform.machine().lower())
    return f"{sysname}-{arch}"


def _lib_filename() -> str:
    return {
        "Linux": "libitb.so",
        "Darwin": "libitb.dylib",
        "Windows": "libitb.dll",
        "FreeBSD": "libitb.so",
    }.get(platform.system(), "libitb.so")


def _resolve_library_path() -> str:
    env = os.environ.get("ITB_LIBRARY_PATH")
    if env:
        return env

    here = Path(__file__).resolve()
    repo_root = here.parents[3]
    candidate = repo_root / "dist" / _platform_lib_dir() / _lib_filename()
    if candidate.exists():
        return str(candidate)

    return _lib_filename()


_ffi = cffi.FFI()
_ffi.cdef(_CDEF)
_lib = _ffi.dlopen(_resolve_library_path())


def _read_str(call) -> str:
    """Common idiom for size-out-param string accessors:
    first call reports required size, second call writes."""
    out_len = _ffi.new("size_t*")
    rc = call(_ffi.NULL, 0, out_len)
    if rc not in (STATUS_OK, STATUS_BUFFER_TOO_SMALL):
        _raise(rc)
    cap = int(out_len[0])
    buf = _ffi.new("char[]", cap)
    rc = call(buf, cap, out_len)
    if rc != STATUS_OK:
        _raise(rc)
    return _ffi.string(buf, int(out_len[0]) - 1).decode("utf-8")


def _last_error() -> str:
    out_len = _ffi.new("size_t*")
    rc = _lib.ITB_LastError(_ffi.NULL, 0, out_len)
    if rc not in (STATUS_OK, STATUS_BUFFER_TOO_SMALL):
        return ""
    cap = int(out_len[0])
    if cap <= 1:
        return ""
    buf = _ffi.new("char[]", cap)
    rc = _lib.ITB_LastError(buf, cap, out_len)
    if rc != STATUS_OK:
        return ""
    return _ffi.string(buf, int(out_len[0]) - 1).decode("utf-8")


def _raise(code: int):
    raise ITBError(code, _last_error())


def version() -> str:
    """Returns the libitb library version string."""
    return _read_str(_lib.ITB_Version)


def list_hashes() -> List[Tuple[str, int]]:
    """Returns ``[(name, native_width_bits), ...]`` in canonical order."""
    n = _lib.ITB_HashCount()
    out: List[Tuple[str, int]] = []
    out_len = _ffi.new("size_t*")
    for i in range(n):
        # First call to discover required size.
        rc = _lib.ITB_HashName(i, _ffi.NULL, 0, out_len)
        if rc not in (STATUS_OK, STATUS_BUFFER_TOO_SMALL):
            _raise(rc)
        cap = int(out_len[0])
        buf = _ffi.new("char[]", cap)
        rc = _lib.ITB_HashName(i, buf, cap, out_len)
        if rc != STATUS_OK:
            _raise(rc)
        name = _ffi.string(buf, int(out_len[0]) - 1).decode("utf-8")
        width = int(_lib.ITB_HashWidth(i))
        out.append((name, width))
    return out


def max_key_bits() -> int:
    return int(_lib.ITB_MaxKeyBits())


def channels() -> int:
    return int(_lib.ITB_Channels())


def header_size() -> int:
    """Returns the current ciphertext-chunk header size in bytes
    (nonce + width(2) + height(2)). Tracks the active SetNonceBits
    configuration: 20 by default, 36 under set_nonce_bits(256), 68
    under set_nonce_bits(512). Used by streaming consumers to know
    how many bytes to read from disk / wire before calling
    parse_chunk_len on each chunk."""
    return int(_lib.ITB_HeaderSize())


def parse_chunk_len(header: bytes) -> int:
    """Inspects a chunk header (the fixed-size [nonce || width(2) ||
    height(2)] prefix at the start of a ciphertext chunk) and
    returns the total chunk length on the wire.

    The buffer must contain at least header_size() bytes; only the
    header is consulted, the body bytes do not need to be present.
    Raises ITBError on too-short buffer, zero dimensions, or
    overflow.
    """
    if not isinstance(header, (bytes, bytearray, memoryview)):
        raise TypeError("header must be bytes-like")
    hdr = bytes(header)
    out = _ffi.new("size_t*")
    rc = _lib.ITB_ParseChunkLen(hdr, len(hdr), out)
    if rc != STATUS_OK:
        _raise(rc)
    return int(out[0])


# The set_* / get_* knobs below are process-global libitb state.
# Setter calls are atomic — each one atomically updates a single
# counter and is safe to invoke from any thread in isolation. The
# caveat is logical rather than atomic: changing a knob WHILE a
# cipher call is in flight can corrupt that operation (the cipher
# snapshots the configuration at call entry and a mid-flight change
# breaks the running invariants). Treat the knobs as set-once-at-
# startup, or sequence rare runtime updates externally against
# active cipher calls.


def set_bit_soup(mode: int) -> None:
    """0 = byte-level split (default); non-zero = bit-level Bit Soup
    split. Process-global. Independent of :func:`set_lock_soup` at
    the setter level — there is no ``BitSoup → LockSoup`` cascade. In
    Single Ouroboros, either flag alone activates the dispatcher's
    keyed bit-permutation overlay (Single OR-gates the two flags)."""
    rc = _lib.ITB_SetBitSoup(int(mode))
    if rc != STATUS_OK:
        _raise(rc)


def get_bit_soup() -> int:
    """Returns the current process-global Bit Soup mode (0 / non-zero)."""
    return int(_lib.ITB_GetBitSoup())


def set_lock_soup(mode: int) -> None:
    """0 = off (default); non-zero = enable Insane Interlocked Mode
    (per-chunk PRF-keyed bit-permutation overlay). Process-global. A
    non-zero value auto-couples :func:`set_bit_soup` ``(1)`` (Lock
    Soup overlay layers on top of bit soup; one-direction cascade).
    The off-direction does not auto-disable bit soup."""
    rc = _lib.ITB_SetLockSoup(int(mode))
    if rc != STATUS_OK:
        _raise(rc)


def get_lock_soup() -> int:
    """Returns the current process-global Lock Soup mode (0 / non-zero)."""
    return int(_lib.ITB_GetLockSoup())


def set_max_workers(n: int) -> None:
    """Cap the libitb worker pool to ``n`` CPUs (0 = all CPUs, the default). Process-global."""
    rc = _lib.ITB_SetMaxWorkers(int(n))
    if rc != STATUS_OK:
        _raise(rc)


def get_max_workers() -> int:
    """Returns the current process-global worker-pool cap (0 = all CPUs)."""
    return int(_lib.ITB_GetMaxWorkers())


def set_nonce_bits(n: int) -> None:
    """Accepts 128, 256, or 512. Other values raise ITBError(STATUS_BAD_INPUT)."""
    rc = _lib.ITB_SetNonceBits(int(n))
    if rc != STATUS_OK:
        _raise(rc)


def get_nonce_bits() -> int:
    """Returns the current process-global nonce-size override (128 / 256 / 512)."""
    return int(_lib.ITB_GetNonceBits())


def set_barrier_fill(n: int) -> None:
    """Accepts 1, 2, 4, 8, 16, 32. Other values raise ITBError(STATUS_BAD_INPUT)."""
    rc = _lib.ITB_SetBarrierFill(int(n))
    if rc != STATUS_OK:
        _raise(rc)


def get_barrier_fill() -> int:
    """Returns the current process-global barrier-fill margin (1 / 2 / 4 / 8 / 16 / 32)."""
    return int(_lib.ITB_GetBarrierFill())


def set_memory_limit(limit: int) -> int:
    """Configures the Go runtime's heap-size soft limit (bytes). Pass -1
    (or any negative value) to query the current limit without changing
    it; the previous limit is returned. Setter calls override any
    ITB_GOMEMLIMIT env var set at libitb load time.
    """
    return int(_lib.ITB_SetMemoryLimit(int(limit)))


def set_gc_percent(pct: int) -> int:
    """Configures the Go runtime's GC trigger percentage. The default is
    100 (GC fires at +100% heap growth); lower values trigger GC more
    aggressively. Pass -1 (or any negative value) to query the current
    value without changing it; the previous value is returned. Setter
    calls override any ITB_GOGC env var set at libitb load time.
    """
    return int(_lib.ITB_SetGCPercent(int(pct)))


class Seed:
    """A handle to one ITB seed.

    Parameters
    ----------
    hash_name:
        Canonical hash name from list_hashes(), e.g. "blake3", "areion256".
    key_bits:
        ITB key width in bits — 512, 1024, or 2048 (multiple of 64).

    The native hash width (128 / 256 / 512) is determined by hash_name.
    All three seeds passed to encrypt() / decrypt() must share the same
    hash_name (or at least the same native width); mixing widths raises
    ITBError(STATUS_SEED_WIDTH_MIX).
    """

    __slots__ = ("_handle", "_hash_name")

    def __init__(self, hash_name: str, key_bits: int):
        h = _ffi.new("uintptr_t*")
        rc = _lib.ITB_NewSeed(hash_name.encode("utf-8"), int(key_bits), h)
        if rc != STATUS_OK:
            _raise(rc)
        self._handle = int(h[0])
        self._hash_name = hash_name

    @property
    def handle(self) -> int:
        """Returns the raw libitb handle (an opaque uintptr_t token).

        Used by the low-level encrypt / decrypt free functions and by
        :meth:`attach_lock_seed`."""
        return self._handle

    @property
    def hash_name(self) -> str:
        """Returns the canonical hash name this seed was constructed with."""
        return self._hash_name

    @property
    def width(self) -> int:
        """Returns the seed's native hash width in bits (128 / 256 / 512)."""
        st = _ffi.new("int*")
        w = int(_lib.ITB_SeedWidth(self._handle, st))
        if int(st[0]) != STATUS_OK:
            _raise(int(st[0]))
        return w

    @property
    def hash_key(self) -> bytes:
        """Returns the fixed key the underlying hash closure is bound
        to (16 / 32 / 64 bytes depending on the primitive). Save these
        bytes alongside ``components`` for cross-process persistence —
        the pair fully reconstructs the seed via ``Seed.from_components``.

        ``siphash24`` returns an empty ``bytes`` since SipHash-2-4 has
        no internal fixed key (its keying material is the seed
        components themselves)."""
        # Two-call pattern: first probe length (cap=0), then allocate.
        out_len = _ffi.new("size_t*")
        rc = _lib.ITB_GetSeedHashKey(self._handle, _ffi.NULL, 0, out_len)
        # Probing returns BUFFER_TOO_SMALL when the key is non-empty
        # (no buffer to write into); empty key is OK.
        if rc == STATUS_OK and int(out_len[0]) == 0:
            return b""
        if rc != STATUS_BUFFER_TOO_SMALL:
            _raise(rc)
        n = int(out_len[0])
        buf = _ffi.new(f"unsigned char[{n}]")
        rc = _lib.ITB_GetSeedHashKey(self._handle, buf, n, out_len)
        if rc != STATUS_OK:
            _raise(rc)
        return bytes(_ffi.buffer(buf, int(out_len[0])))

    @property
    def components(self) -> List[int]:
        """Returns the seed's underlying uint64 components (8..32
        elements). Save these alongside ``hash_key`` for cross-process
        persistence — the pair fully reconstructs the seed via
        ``Seed.from_components``."""
        out_len = _ffi.new("int*")
        rc = _lib.ITB_GetSeedComponents(self._handle, _ffi.NULL, 0, out_len)
        if rc != STATUS_BUFFER_TOO_SMALL:
            _raise(rc)
        n = int(out_len[0])
        buf = _ffi.new(f"unsigned long long[{n}]")
        rc = _lib.ITB_GetSeedComponents(self._handle, buf, n, out_len)
        if rc != STATUS_OK:
            _raise(rc)
        return [int(buf[i]) for i in range(int(out_len[0]))]

    @classmethod
    def from_components(
        cls,
        hash_name: str,
        components,
        hash_key: bytes = b"",
    ) -> "Seed":
        """Builds a seed deterministically from caller-supplied uint64
        components and an optional fixed hash key. Use this on the
        persistence-restore path (encrypt today, decrypt tomorrow);
        leave ``hash_key=b""`` for a CSPRNG-generated key (still
        useful when only the components need to be deterministic).

        ``components`` accepts any iterable of int (length 8..32,
        multiple of 8). ``hash_key`` length, when non-empty, must
        match the primitive's native fixed-key size: 16 (aescmac),
        32 (areion256 / blake2{s,b256} / blake3 / chacha20),
        64 (areion512 / blake2b512). Pass ``b""`` for ``siphash24``
        (no internal fixed key)."""
        comps = list(components)
        comps_arr = _ffi.new("unsigned long long[]", comps)
        if len(hash_key) > 0:
            key_arr = _ffi.new("unsigned char[]", bytes(hash_key))
            key_len = len(hash_key)
        else:
            key_arr = _ffi.NULL
            key_len = 0
        h = _ffi.new("uintptr_t*")
        rc = _lib.ITB_NewSeedFromComponents(
            hash_name.encode("utf-8"),
            comps_arr, len(comps),
            key_arr, key_len,
            h,
        )
        if rc != STATUS_OK:
            _raise(rc)
        # Allocate Seed without going through __init__ (which would
        # call ITB_NewSeed). Bypass __slots__ assignment via direct
        # attribute setting, which __slots__ permits for declared
        # slot names.
        inst = object.__new__(cls)
        inst._handle = int(h[0])
        inst._hash_name = hash_name
        return inst

    def free(self) -> None:
        """Releases the underlying libitb handle.

        Idempotent — the handle attribute is zeroed after the first
        call so a second :meth:`free` is a no-op. Called automatically
        by :meth:`__exit__` and :meth:`__del__`; an explicit call is
        only needed when the caller wants release-time errors to
        surface (rare)."""
        if self._handle:
            rc = _lib.ITB_FreeSeed(self._handle)
            self._handle = 0
            if rc != STATUS_OK:
                _raise(rc)

    def attach_lock_seed(self, lock_seed: "Seed") -> None:
        """Wires a dedicated lockSeed onto this noise seed. The
        per-chunk PRF closure for the bit-permutation overlay
        captures BOTH the lockSeed's components AND its hash
        function — keying-material isolation plus algorithm
        diversity (the lockSeed primitive may legitimately differ
        from the noise-seed primitive within the same native hash
        width) for defence-in-depth on the overlay channel. Both
        seeds must share the same native hash width.

        The dedicated lockSeed has no observable effect on the wire
        output unless the bit-permutation overlay is engaged via
        :func:`itb.set_bit_soup` ``(1)`` or :func:`itb.set_lock_soup`
        ``(1)`` before the first ``encrypt`` / ``decrypt`` call. The
        Go-side build-PRF guard panics on encrypt-time when an
        attach is present without either flag, surfacing as
        :class:`ITBError`.

        Misuse paths surface as ``ITBError(STATUS_BAD_INPUT)``:
        self-attach (passing the same seed twice), component-array
        aliasing (two distinct Seed handles whose components share
        the same backing array — only reachable via raw FFI), and
        post-encrypt switching (calling ``attach_lock_seed`` on a
        noise seed that has already produced ciphertext). Width
        mismatch surfaces as ``ITBError(STATUS_SEED_WIDTH_MIX)``.

        The dedicated lockSeed remains owned by the caller —
        attach only records the pointer on the noise seed, so
        keep the lockSeed alive for the lifetime of the noise seed
        (do not call ``lock_seed.free()`` before encrypt finishes).
        """
        if not isinstance(lock_seed, Seed):
            raise TypeError("lock_seed must be an itb.Seed instance")
        rc = _lib.ITB_AttachLockSeed(self._handle, lock_seed.handle)
        if rc != STATUS_OK:
            _raise(rc)

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        self.free()

    def __del__(self):
        # Best-effort GC release; ignore any error since interpreter
        # shutdown ordering is unpredictable.
        try:
            if self._handle:
                _lib.ITB_FreeSeed(self._handle)
                self._handle = 0
        except Exception:
            pass


def list_macs() -> List[Tuple[str, int, int, int]]:
    """Returns ``[(name, key_size, tag_size, min_key_bytes), ...]`` in
    canonical FFI order (kmac256, hmac-sha256, hmac-blake3)."""
    n = _lib.ITB_MACCount()
    out: List[Tuple[str, int, int, int]] = []
    out_len = _ffi.new("size_t*")
    for i in range(n):
        rc = _lib.ITB_MACName(i, _ffi.NULL, 0, out_len)
        if rc not in (STATUS_OK, STATUS_BUFFER_TOO_SMALL):
            _raise(rc)
        cap = int(out_len[0])
        buf = _ffi.new("char[]", cap)
        rc = _lib.ITB_MACName(i, buf, cap, out_len)
        if rc != STATUS_OK:
            _raise(rc)
        name = _ffi.string(buf, int(out_len[0]) - 1).decode("utf-8")
        out.append((
            name,
            int(_lib.ITB_MACKeySize(i)),
            int(_lib.ITB_MACTagSize(i)),
            int(_lib.ITB_MACMinKeyBytes(i)),
        ))
    return out


class MAC:
    """A handle to one keyed MAC.

    Parameters
    ----------
    mac_name:
        Canonical MAC name from list_macs(): "kmac256", "hmac-sha256",
        or "hmac-blake3".
    key:
        Bytes-like key. Length must be at least the primitive's
        min_key_bytes (16 for kmac256/hmac-sha256, 32 for hmac-blake3).
    """

    __slots__ = ("_handle", "_name")

    def __init__(self, mac_name: str, key: bytes):
        if not isinstance(key, (bytes, bytearray, memoryview)):
            raise TypeError("key must be bytes-like")
        kb = bytes(key)
        h = _ffi.new("uintptr_t*")
        rc = _lib.ITB_NewMAC(mac_name.encode("utf-8"), kb, len(kb), h)
        if rc != STATUS_OK:
            _raise(rc)
        self._handle = int(h[0])
        self._name = mac_name

    @property
    def handle(self) -> int:
        return self._handle

    @property
    def name(self) -> str:
        return self._name

    def free(self) -> None:
        """Releases the underlying libitb MAC handle.

        Idempotent — the handle attribute is zeroed after the first
        call so a second :meth:`free` is a no-op. Called automatically
        by :meth:`__exit__` and :meth:`__del__`; an explicit call is
        only needed when the caller wants release-time errors to
        surface (rare)."""
        if self._handle:
            rc = _lib.ITB_FreeMAC(self._handle)
            self._handle = 0
            if rc != STATUS_OK:
                _raise(rc)

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        self.free()

    def __del__(self):
        try:
            if self._handle:
                _lib.ITB_FreeMAC(self._handle)
                self._handle = 0
        except Exception:
            pass


def encrypt_auth(
    noise: Seed, data: Seed, start: Seed, mac: MAC, plaintext: bytes,
) -> bytes:
    """Authenticated single-Ouroboros encrypt with MAC-Inside-Encrypt."""
    if not isinstance(plaintext, (bytes, bytearray, memoryview)):
        raise TypeError("plaintext must be bytes-like")
    return _enc_dec_auth(_lib.ITB_EncryptAuth, noise, data, start, mac, bytes(plaintext))


def decrypt_auth(
    noise: Seed, data: Seed, start: Seed, mac: MAC, ciphertext: bytes,
) -> bytes:
    """Authenticated single-Ouroboros decrypt. Raises ITBError with
    code STATUS_MAC_FAILURE on tampered ciphertext / wrong MAC key."""
    if not isinstance(ciphertext, (bytes, bytearray, memoryview)):
        raise TypeError("ciphertext must be bytes-like")
    return _enc_dec_auth(_lib.ITB_DecryptAuth, noise, data, start, mac, bytes(ciphertext))


def encrypt_auth_triple(
    noise: Seed,
    data1: Seed, data2: Seed, data3: Seed,
    start1: Seed, start2: Seed, start3: Seed,
    mac: MAC, plaintext: bytes,
) -> bytes:
    """Authenticated Triple Ouroboros encrypt (7 seeds + MAC)."""
    if not isinstance(plaintext, (bytes, bytearray, memoryview)):
        raise TypeError("plaintext must be bytes-like")
    return _enc_dec_auth_triple(
        _lib.ITB_EncryptAuth3,
        noise, data1, data2, data3, start1, start2, start3, mac,
        bytes(plaintext),
    )


def decrypt_auth_triple(
    noise: Seed,
    data1: Seed, data2: Seed, data3: Seed,
    start1: Seed, start2: Seed, start3: Seed,
    mac: MAC, ciphertext: bytes,
) -> bytes:
    """Authenticated Triple Ouroboros decrypt."""
    if not isinstance(ciphertext, (bytes, bytearray, memoryview)):
        raise TypeError("ciphertext must be bytes-like")
    return _enc_dec_auth_triple(
        _lib.ITB_DecryptAuth3,
        noise, data1, data2, data3, start1, start2, start3, mac,
        bytes(ciphertext),
    )


def _enc_dec_auth(fn, noise: Seed, data: Seed, start: Seed, mac: MAC, payload: bytes) -> bytes:
    # Pre-allocate from the 1.25× + 128 KiB envelope (mirror of
    # easy.Encryptor._cipher_call). The C ABI runs the full crypto on
    # every call regardless of out-buffer capacity, so a NULL/0 probe
    # would double the work; the formula sizes the buffer correctly
    # in one call across the full primitive / mode / nonce-bits /
    # barrier-fill matrix. STATUS_BUFFER_TOO_SMALL retry stays as the
    # safety net.
    payload_len = len(payload)
    cap = max(131072, (payload_len * 5) // 4 + 131072)
    out_buf = _ffi.new("unsigned char[]", cap)
    out_len = _ffi.new("size_t*")
    rc = fn(noise.handle, data.handle, start.handle, mac.handle,
            payload, payload_len, out_buf, cap, out_len)
    if rc == STATUS_BUFFER_TOO_SMALL:
        need = int(out_len[0])
        out_buf = _ffi.new("unsigned char[]", need)
        rc = fn(noise.handle, data.handle, start.handle, mac.handle,
                payload, payload_len, out_buf, need, out_len)
    if rc != STATUS_OK:
        _raise(rc)
    return bytes(_ffi.buffer(out_buf, int(out_len[0])))


def _enc_dec_auth_triple(
    fn, noise: Seed,
    data1: Seed, data2: Seed, data3: Seed,
    start1: Seed, start2: Seed, start3: Seed,
    mac: MAC, payload: bytes,
) -> bytes:
    # Pre-allocate from the 1.25× + 128 KiB envelope (mirror of
    # easy.Encryptor._cipher_call); see _enc_dec_auth above for the
    # rationale. STATUS_BUFFER_TOO_SMALL retry stays as the safety net.
    payload_len = len(payload)
    cap = max(131072, (payload_len * 5) // 4 + 131072)
    out_buf = _ffi.new("unsigned char[]", cap)
    out_len = _ffi.new("size_t*")
    rc = fn(noise.handle,
            data1.handle, data2.handle, data3.handle,
            start1.handle, start2.handle, start3.handle,
            mac.handle, payload, payload_len,
            out_buf, cap, out_len)
    if rc == STATUS_BUFFER_TOO_SMALL:
        need = int(out_len[0])
        out_buf = _ffi.new("unsigned char[]", need)
        rc = fn(noise.handle,
                data1.handle, data2.handle, data3.handle,
                start1.handle, start2.handle, start3.handle,
                mac.handle, payload, payload_len,
                out_buf, need, out_len)
    if rc != STATUS_OK:
        _raise(rc)
    return bytes(_ffi.buffer(out_buf, int(out_len[0])))


def encrypt(noise: Seed, data: Seed, start: Seed, plaintext: bytes) -> bytes:
    """Encrypts plaintext under the (noise, data, start) seed trio.

    All three seeds must share the same native hash width.
    """
    if not isinstance(plaintext, (bytes, bytearray, memoryview)):
        raise TypeError("plaintext must be bytes-like")
    pt = bytes(plaintext)
    return _encrypt_or_decrypt(_lib.ITB_Encrypt, noise, data, start, pt)


def decrypt(noise: Seed, data: Seed, start: Seed, ciphertext: bytes) -> bytes:
    """Decrypts ciphertext produced by encrypt() under the same seed trio."""
    if not isinstance(ciphertext, (bytes, bytearray, memoryview)):
        raise TypeError("ciphertext must be bytes-like")
    ct = bytes(ciphertext)
    return _encrypt_or_decrypt(_lib.ITB_Decrypt, noise, data, start, ct)


def encrypt_triple(
    noise: Seed,
    data1: Seed, data2: Seed, data3: Seed,
    start1: Seed, start2: Seed, start3: Seed,
    plaintext: bytes,
) -> bytes:
    """Triple Ouroboros encrypt over seven seeds.

    Splits plaintext across three interleaved snake payloads. The
    on-wire ciphertext format is the same shape as encrypt() — only
    the internal split / interleave differs. All seven seeds must
    share the same native hash width and be pairwise distinct
    handles (the underlying ITB API enforces seven-seed isolation).
    """
    if not isinstance(plaintext, (bytes, bytearray, memoryview)):
        raise TypeError("plaintext must be bytes-like")
    return _encrypt_or_decrypt_triple(
        _lib.ITB_Encrypt3,
        noise, data1, data2, data3, start1, start2, start3,
        bytes(plaintext),
    )


def decrypt_triple(
    noise: Seed,
    data1: Seed, data2: Seed, data3: Seed,
    start1: Seed, start2: Seed, start3: Seed,
    ciphertext: bytes,
) -> bytes:
    """Inverse of encrypt_triple()."""
    if not isinstance(ciphertext, (bytes, bytearray, memoryview)):
        raise TypeError("ciphertext must be bytes-like")
    return _encrypt_or_decrypt_triple(
        _lib.ITB_Decrypt3,
        noise, data1, data2, data3, start1, start2, start3,
        bytes(ciphertext),
    )


def _encrypt_or_decrypt(fn, noise: Seed, data: Seed, start: Seed, payload: bytes) -> bytes:
    # Pre-allocate from the 1.25× + 128 KiB envelope (mirror of
    # easy.Encryptor._cipher_call). The C ABI runs the full crypto on
    # every call regardless of out-buffer capacity, so a NULL/0 probe
    # would double the work; the formula sizes the buffer correctly
    # in one call across the full primitive / mode / nonce-bits /
    # barrier-fill matrix. STATUS_BUFFER_TOO_SMALL retry stays as the
    # safety net.
    payload_len = len(payload)
    cap = max(131072, (payload_len * 5) // 4 + 131072)
    out_buf = _ffi.new("unsigned char[]", cap)
    out_len = _ffi.new("size_t*")
    rc = fn(noise.handle, data.handle, start.handle,
            payload, payload_len,
            out_buf, cap, out_len)
    if rc == STATUS_BUFFER_TOO_SMALL:
        need = int(out_len[0])
        out_buf = _ffi.new("unsigned char[]", need)
        rc = fn(noise.handle, data.handle, start.handle,
                payload, payload_len,
                out_buf, need, out_len)
    if rc != STATUS_OK:
        _raise(rc)
    return bytes(_ffi.buffer(out_buf, int(out_len[0])))


def _encrypt_or_decrypt_triple(
    fn,
    noise: Seed,
    data1: Seed, data2: Seed, data3: Seed,
    start1: Seed, start2: Seed, start3: Seed,
    payload: bytes,
) -> bytes:
    # Pre-allocate from the 1.25× + 128 KiB envelope (mirror of
    # easy.Encryptor._cipher_call); see _encrypt_or_decrypt above for
    # the rationale. STATUS_BUFFER_TOO_SMALL retry stays as the safety
    # net.
    payload_len = len(payload)
    cap = max(131072, (payload_len * 5) // 4 + 131072)
    out_buf = _ffi.new("unsigned char[]", cap)
    out_len = _ffi.new("size_t*")
    rc = fn(noise.handle,
            data1.handle, data2.handle, data3.handle,
            start1.handle, start2.handle, start3.handle,
            payload, payload_len,
            out_buf, cap, out_len)
    if rc == STATUS_BUFFER_TOO_SMALL:
        need = int(out_len[0])
        out_buf = _ffi.new("unsigned char[]", need)
        rc = fn(noise.handle,
                data1.handle, data2.handle, data3.handle,
                start1.handle, start2.handle, start3.handle,
                payload, payload_len,
                out_buf, need, out_len)
    if rc != STATUS_OK:
        _raise(rc)
    return bytes(_ffi.buffer(out_buf, int(out_len[0])))


# ─── Streaming AEAD per-chunk helpers ──────────────────────────────────
#
# The 32-byte stream_id anchor and the per-chunk dispatch helpers below
# are the binding-side primitives the StreamEncryptorAuth /
# StreamDecryptorAuth classes (and the Encryptor.encrypt_stream_auth /
# Encryptor.decrypt_stream_auth methods) compose into the Streaming AEAD
# loop. Logic mirrors the C reference helpers in
# bindings/c/src/streams.c — the binding-level helper handles
# CSPRNG anchor generation, width dispatch, BUFFER_TOO_SMALL probe-and-
# allocate retry, and the (cumulative_pixel_offset, final_flag) MAC
# binding. Failure surfaces include the new STATUS_STREAM_TRUNCATED /
# STATUS_STREAM_AFTER_FINAL codes typed via ItbStreamTruncatedError /
# ItbStreamAfterFinalError.

STREAM_ID_LEN = 32


def _generate_stream_id() -> bytes:
    """Returns a CSPRNG-fresh 32-byte Streaming AEAD anchor by
    piggybacking on libitb's own CSPRNG: ITB_NewSeedFromComponents
    with hash_key=NULL triggers a CSPRNG draw on the Go side, and
    ITB_GetSeedHashKey reads back the 32-byte fixed key under the
    blake3 primitive. The seed handle is freed before returning;
    only the 32 random bytes survive. Mirrors the C reference helper
    generate_stream_id in bindings/c/src/streams.c."""
    comps = _ffi.new("unsigned long long[]", [1, 2, 3, 4, 5, 6, 7, 8])
    h = _ffi.new("uintptr_t*")
    rc = _lib.ITB_NewSeedFromComponents(
        b"blake3", comps, 8, _ffi.NULL, 0, h,
    )
    if rc != STATUS_OK:
        _raise(rc)
    handle = int(h[0])
    out_buf = _ffi.new(f"unsigned char[{STREAM_ID_LEN}]")
    out_len = _ffi.new("size_t*")
    rc = _lib.ITB_GetSeedHashKey(handle, out_buf, STREAM_ID_LEN, out_len)
    free_rc = _lib.ITB_FreeSeed(handle)
    if rc != STATUS_OK:
        _raise(rc)
    if free_rc != STATUS_OK:
        _raise(free_rc)
    if int(out_len[0]) != STREAM_ID_LEN:
        raise ITBError(STATUS_INTERNAL, "stream_id CSPRNG draw returned wrong byte count")
    return bytes(_ffi.buffer(out_buf, STREAM_ID_LEN))


def _enc_auth_single_for_width(width: int):
    return {
        128: _lib.ITB_EncryptStreamAuthenticated128,
        256: _lib.ITB_EncryptStreamAuthenticated256,
        512: _lib.ITB_EncryptStreamAuthenticated512,
    }[width]


def _dec_auth_single_for_width(width: int):
    return {
        128: _lib.ITB_DecryptStreamAuthenticated128,
        256: _lib.ITB_DecryptStreamAuthenticated256,
        512: _lib.ITB_DecryptStreamAuthenticated512,
    }[width]


def _enc_auth_triple_for_width(width: int):
    return {
        128: _lib.ITB_EncryptStreamAuthenticated3x128,
        256: _lib.ITB_EncryptStreamAuthenticated3x256,
        512: _lib.ITB_EncryptStreamAuthenticated3x512,
    }[width]


def _dec_auth_triple_for_width(width: int):
    return {
        128: _lib.ITB_DecryptStreamAuthenticated3x128,
        256: _lib.ITB_DecryptStreamAuthenticated3x256,
        512: _lib.ITB_DecryptStreamAuthenticated3x512,
    }[width]


class _StreamAuthCache:
    """Per-stream output buffer cache for Streaming AEAD per-chunk
    dispatchers. Mirrors the per-encryptor ``_out_buf`` / ``_out_cap``
    pair on :class:`itb.easy.Encryptor` but lives on the streaming
    class instance. The cache grows  on demand with the same wipe-on-grow + 1.25× 
    + 128 KiB envelope shape as :meth:`itb.easy.Encryptor._cipher_call`.

    The class is not thread-safe; each :class:`StreamEncryptorAuth` /
    :class:`StreamDecryptorAuth` instance owns one cache, and a
    streaming class instance is single-writer / single-feeder by
    construction (no caller would interleave ``write`` calls from two
    threads on the same writer)."""

    __slots__ = ("buf", "cap")

    def __init__(self) -> None:
        self.buf = _ffi.NULL
        self.cap = 0

    def ensure(self, need: int) -> None:
        """Grows the cache to at least ``need`` bytes, wiping the
        previous slab before reassignment. Idempotent when the cache
        already meets the requested capacity."""
        if self.cap >= need:
            return
        if self.cap > 0 and self.buf != _ffi.NULL:
            _ffi.memmove(self.buf, b"\x00" * self.cap, self.cap)
        self.buf = _ffi.new("unsigned char[]", need)
        self.cap = need

    def wipe(self) -> None:
        """Zeroes and drops the cache. Called from the streaming
        class's ``close`` / ``__exit__`` / ``__del__`` paths."""
        if self.cap > 0 and self.buf != _ffi.NULL:
            _ffi.memmove(self.buf, b"\x00" * self.cap, self.cap)
        self.buf = _ffi.NULL
        self.cap = 0


def _emit_chunk_auth_single(
    width: int,
    noise: "Seed", data: "Seed", start: "Seed",
    mac: "MAC",
    plaintext: bytes,
    stream_id: bytes,
    cum_pixels: int,
    final_flag: bool,
    cache: "_StreamAuthCache | None" = None,
) -> bytes:
    """Per-chunk encrypt dispatch (Single Ouroboros + MAC). Pre-
    allocates output capacity from the 1.25× + 128 KiB envelope
    (mirror of easy.Encryptor._cipher_call); the C ABI runs the full
    crypto on every call regardless of out-buffer capacity, so a
    NULL/0 probe would double the work. The +32-byte tag and +1-byte
    flag inherent to the Streaming AEAD per-chunk wire layout are
    inside the 128 KiB pad's headroom even at chunk_size = 1.
    STATUS_BUFFER_TOO_SMALL retry stays as the safety net.

    When ``cache`` is provided, the per-stream buffer is reused
    instead of allocating a fresh cffi slab per chunk. When ``None``,
    falls back to the per-call allocation."""
    fn = _enc_auth_single_for_width(width)
    sid_buf = _ffi.new(f"unsigned char[{STREAM_ID_LEN}]", stream_id)
    in_arg = plaintext if plaintext else _ffi.NULL
    payload_len = len(plaintext)
    cap = max(131072, (payload_len * 5) // 4 + 131072)
    if cache is not None:
        cache.ensure(cap)
        out_buf = cache.buf
        out_cap = cache.cap
    else:
        out_buf = _ffi.new(f"unsigned char[{cap}]")
        out_cap = cap
    out_len = _ffi.new("size_t*")
    rc = fn(noise.handle, data.handle, start.handle, mac.handle,
            in_arg, payload_len,
            sid_buf, int(cum_pixels), 1 if final_flag else 0,
            out_buf, out_cap, out_len)
    if rc == STATUS_BUFFER_TOO_SMALL:
        need = int(out_len[0])
        if need == 0:
            return b""
        if cache is not None:
            cache.ensure(need)
            out_buf = cache.buf
            out_cap = cache.cap
        else:
            out_buf = _ffi.new(f"unsigned char[{need}]")
            out_cap = need
        rc = fn(noise.handle, data.handle, start.handle, mac.handle,
                in_arg, payload_len,
                sid_buf, int(cum_pixels), 1 if final_flag else 0,
                out_buf, out_cap, out_len)
    if rc != STATUS_OK:
        _raise(rc)
    return bytes(_ffi.buffer(out_buf, int(out_len[0])))


def _emit_chunk_auth_triple(
    width: int,
    noise: "Seed",
    data1: "Seed", data2: "Seed", data3: "Seed",
    start1: "Seed", start2: "Seed", start3: "Seed",
    mac: "MAC",
    plaintext: bytes,
    stream_id: bytes,
    cum_pixels: int,
    final_flag: bool,
    cache: "_StreamAuthCache | None" = None,
) -> bytes:
    """Per-chunk encrypt dispatch (Triple Ouroboros + MAC). Pre-
    allocates from the 1.25× + 128 KiB envelope; see
    _emit_chunk_auth_single above for the rationale.
    STATUS_BUFFER_TOO_SMALL retry stays as the safety net.

    When ``cache`` is provided, the per-stream buffer is reused
    instead of allocating a fresh cffi slab per chunk. When ``None``,
    falls back to the per-call allocation."""
    fn = _enc_auth_triple_for_width(width)
    sid_buf = _ffi.new(f"unsigned char[{STREAM_ID_LEN}]", stream_id)
    in_arg = plaintext if plaintext else _ffi.NULL
    payload_len = len(plaintext)
    cap = max(131072, (payload_len * 5) // 4 + 131072)
    if cache is not None:
        cache.ensure(cap)
        out_buf = cache.buf
        out_cap = cache.cap
    else:
        out_buf = _ffi.new(f"unsigned char[{cap}]")
        out_cap = cap
    out_len = _ffi.new("size_t*")
    rc = fn(noise.handle,
            data1.handle, data2.handle, data3.handle,
            start1.handle, start2.handle, start3.handle,
            mac.handle, in_arg, payload_len,
            sid_buf, int(cum_pixels), 1 if final_flag else 0,
            out_buf, out_cap, out_len)
    if rc == STATUS_BUFFER_TOO_SMALL:
        need = int(out_len[0])
        if need == 0:
            return b""
        if cache is not None:
            cache.ensure(need)
            out_buf = cache.buf
            out_cap = cache.cap
        else:
            out_buf = _ffi.new(f"unsigned char[{need}]")
            out_cap = need
        rc = fn(noise.handle,
                data1.handle, data2.handle, data3.handle,
                start1.handle, start2.handle, start3.handle,
                mac.handle, in_arg, payload_len,
                sid_buf, int(cum_pixels), 1 if final_flag else 0,
                out_buf, out_cap, out_len)
    if rc != STATUS_OK:
        _raise(rc)
    return bytes(_ffi.buffer(out_buf, int(out_len[0])))


def _consume_chunk_auth_single(
    width: int,
    noise: "Seed", data: "Seed", start: "Seed",
    mac: "MAC",
    ciphertext: bytes,
    stream_id: bytes,
    cum_pixels: int,
    cache: "_StreamAuthCache | None" = None,
):
    """Per-chunk decrypt dispatch (Single Ouroboros + MAC). Pre-
    allocates from the 1.25× + 128 KiB envelope (mirror of
    easy.Encryptor._cipher_call); the C ABI runs the full crypto on
    every call regardless of out-buffer capacity, so a NULL/0 probe
    would double the work. Returns ``(plaintext, final_flag)``.
    Surfaces ITBError on any non-OK status — STATUS_MAC_FAILURE on
    tampered transcript, etc. STATUS_BUFFER_TOO_SMALL retry stays as
    the safety net.

    When ``cache`` is provided, the per-stream buffer is reused
    instead of allocating a fresh cffi slab per chunk. When ``None``,
    falls back to the per-call allocation."""
    fn = _dec_auth_single_for_width(width)
    sid_buf = _ffi.new(f"unsigned char[{STREAM_ID_LEN}]", stream_id)
    in_arg = ciphertext if ciphertext else _ffi.NULL
    payload_len = len(ciphertext)
    cap = max(131072, (payload_len * 5) // 4 + 131072)
    if cache is not None:
        cache.ensure(cap)
        out_buf = cache.buf
        out_cap = cache.cap
    else:
        out_buf = _ffi.new(f"unsigned char[{cap}]")
        out_cap = cap
    out_len = _ffi.new("size_t*")
    ff = _ffi.new("int*")
    rc = fn(noise.handle, data.handle, start.handle, mac.handle,
            in_arg, payload_len,
            sid_buf, int(cum_pixels),
            out_buf, out_cap, out_len, ff)
    if rc == STATUS_BUFFER_TOO_SMALL:
        need = int(out_len[0])
        if need == 0:
            return b"", bool(int(ff[0]))
        if cache is not None:
            cache.ensure(need)
            out_buf = cache.buf
            out_cap = cache.cap
        else:
            out_buf = _ffi.new(f"unsigned char[{need}]")
            out_cap = need
        rc = fn(noise.handle, data.handle, start.handle, mac.handle,
                in_arg, payload_len,
                sid_buf, int(cum_pixels),
                out_buf, out_cap, out_len, ff)
    if rc != STATUS_OK:
        _raise(rc)
    return bytes(_ffi.buffer(out_buf, int(out_len[0]))), bool(int(ff[0]))


def _consume_chunk_auth_triple(
    width: int,
    noise: "Seed",
    data1: "Seed", data2: "Seed", data3: "Seed",
    start1: "Seed", start2: "Seed", start3: "Seed",
    mac: "MAC",
    ciphertext: bytes,
    stream_id: bytes,
    cum_pixels: int,
    cache: "_StreamAuthCache | None" = None,
):
    """Per-chunk decrypt dispatch (Triple Ouroboros + MAC). Pre-
    allocates from the 1.25× + 128 KiB envelope; see
    _consume_chunk_auth_single above for the rationale.
    STATUS_BUFFER_TOO_SMALL retry stays as the safety net.

    When ``cache`` is provided, the per-stream buffer is reused
    instead of allocating a fresh cffi slab per chunk. When ``None``,
    falls back to the per-call allocation."""
    fn = _dec_auth_triple_for_width(width)
    sid_buf = _ffi.new(f"unsigned char[{STREAM_ID_LEN}]", stream_id)
    in_arg = ciphertext if ciphertext else _ffi.NULL
    payload_len = len(ciphertext)
    cap = max(131072, (payload_len * 5) // 4 + 131072)
    if cache is not None:
        cache.ensure(cap)
        out_buf = cache.buf
        out_cap = cache.cap
    else:
        out_buf = _ffi.new(f"unsigned char[{cap}]")
        out_cap = cap
    out_len = _ffi.new("size_t*")
    ff = _ffi.new("int*")
    rc = fn(noise.handle,
            data1.handle, data2.handle, data3.handle,
            start1.handle, start2.handle, start3.handle,
            mac.handle, in_arg, payload_len,
            sid_buf, int(cum_pixels),
            out_buf, out_cap, out_len, ff)
    if rc == STATUS_BUFFER_TOO_SMALL:
        need = int(out_len[0])
        if need == 0:
            return b"", bool(int(ff[0]))
        if cache is not None:
            cache.ensure(need)
            out_buf = cache.buf
            out_cap = cache.cap
        else:
            out_buf = _ffi.new(f"unsigned char[{need}]")
            out_cap = need
        rc = fn(noise.handle,
                data1.handle, data2.handle, data3.handle,
                start1.handle, start2.handle, start3.handle,
                mac.handle, in_arg, payload_len,
                sid_buf, int(cum_pixels),
                out_buf, out_cap, out_len, ff)
    if rc != STATUS_OK:
        _raise(rc)
    return bytes(_ffi.buffer(out_buf, int(out_len[0]))), bool(int(ff[0]))


def last_error() -> str:
    """Reads ITB_LastError diagnostic for the most recent non-OK
    status returned on this thread. Empty string when no error has
    been recorded.

    The textual message follows C errno discipline: it is published
    through a process-wide atomic, so a sibling thread that calls
    into libitb between the failing call and this read can overwrite
    the message. The structural status code on the failing call is
    unaffected — only the textual message is racy. The
    ITBError exception class already attaches this string to its
    .args[1] / Exception message at raise time; this free function is
    exposed for callers that want to read the diagnostic independently
    of the exception path."""
    return _last_error()
