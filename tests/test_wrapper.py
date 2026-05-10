"""Tests for the Python format-deniability wrapper module
(:mod:`itb.wrapper`).

Coverage mirrors the cross-binding contract for the wrapper surface:

- 3 outer ciphers × 4 Single Message variants (wrap / unwrap /
  wrap_in_place / unwrap_in_place) — round-trip + nonce hygiene.
- 3 outer ciphers × streaming WrapStreamWriter / UnwrapStreamReader
  multi-chunk round-trip.
- 3 outer ciphers × cross-FFI parity: Python ``wrapper.wrap`` output
  is byte-recovered by the Go-native ``wrapper.Unwrap`` via a
  helper binary (``$ITB_WRAPPER_PARITY_BIN`` — optional; tests skip
  cleanly when the helper is not available).
- Error paths: unknown cipher name, key length mismatch, nonce
  length mismatch, immutable-input rejection on the in-place
  variants, closed-handle rejection on the streaming surface.

The wrap layer never touches the libitb encrypt / decrypt path, so
the tests never construct an Encryptor — the assertions are about
the keystream-XOR envelope round-trip alone.
"""

import os
import secrets
import shutil
import subprocess
import sys
import unittest
from pathlib import Path

HERE = Path(__file__).resolve()
sys.path.insert(0, str(HERE.parents[1]))

from itb import wrapper  # noqa: E402
from itb._ffi import STATUS_BAD_INPUT, STATUS_BAD_HANDLE  # noqa: E402


CIPHERS = (
    wrapper.CIPHER_AES128_CTR,
    wrapper.CIPHER_CHACHA20,
    wrapper.CIPHER_SIPHASH24,
)

# Expected shapes per cipher: (key_size, nonce_size).
EXPECTED_SHAPE = {
    wrapper.CIPHER_AES128_CTR: (16, 16),
    wrapper.CIPHER_CHACHA20: (32, 12),
    wrapper.CIPHER_SIPHASH24: (16, 16),
}


class TestWrapperConstants(unittest.TestCase):
    def test_cipher_names(self):
        self.assertEqual(
            wrapper.CIPHER_NAMES,
            (wrapper.CIPHER_AES128_CTR, wrapper.CIPHER_CHACHA20, wrapper.CIPHER_SIPHASH24),
        )

    def test_key_size_per_cipher(self):
        for cipher, (ks, _) in EXPECTED_SHAPE.items():
            with self.subTest(cipher=cipher):
                self.assertEqual(wrapper.key_size(cipher), ks)

    def test_nonce_size_per_cipher(self):
        for cipher, (_, ns) in EXPECTED_SHAPE.items():
            with self.subTest(cipher=cipher):
                self.assertEqual(wrapper.nonce_size(cipher), ns)

    def test_unknown_cipher_raises(self):
        with self.assertRaises(wrapper.InvalidCipherError):
            wrapper.key_size("xchacha")
        with self.assertRaises(wrapper.InvalidCipherError):
            wrapper.nonce_size("rc4")
        with self.assertRaises(wrapper.InvalidCipherError):
            wrapper.generate_key("AES")  # case-sensitive

    def test_generate_key_length(self):
        for cipher in CIPHERS:
            with self.subTest(cipher=cipher):
                k1 = wrapper.generate_key(cipher)
                k2 = wrapper.generate_key(cipher)
                self.assertEqual(len(k1), wrapper.key_size(cipher))
                self.assertEqual(len(k2), wrapper.key_size(cipher))
                # CSPRNG: two draws should differ with overwhelming probability.
                self.assertNotEqual(k1, k2)


class TestWrapUnwrap(unittest.TestCase):
    def test_roundtrip_per_cipher(self):
        for cipher in CIPHERS:
            with self.subTest(cipher=cipher):
                key = wrapper.generate_key(cipher)
                blob = secrets.token_bytes(2048)
                wire = wrapper.wrap(cipher, key, blob)
                # Wire = nonce || ks-XOR(blob); length matches.
                self.assertEqual(len(wire), wrapper.nonce_size(cipher) + len(blob))
                recovered = wrapper.unwrap(cipher, key, wire)
                self.assertEqual(recovered, blob)

    def test_roundtrip_empty_blob(self):
        for cipher in CIPHERS:
            with self.subTest(cipher=cipher):
                key = wrapper.generate_key(cipher)
                wire = wrapper.wrap(cipher, key, b"")
                self.assertEqual(len(wire), wrapper.nonce_size(cipher))
                self.assertEqual(wrapper.unwrap(cipher, key, wire), b"")

    def test_two_wraps_differ_via_fresh_nonce(self):
        """The wrapper draws a fresh CSPRNG nonce per Wrap call. Two
        Wrap invocations on identical (key, blob) inputs produce
        distinct wires because the nonces — and therefore the
        keystream — differ."""
        for cipher in CIPHERS:
            with self.subTest(cipher=cipher):
                key = wrapper.generate_key(cipher)
                blob = b"deterministic input bytes" * 4
                w1 = wrapper.wrap(cipher, key, blob)
                w2 = wrapper.wrap(cipher, key, blob)
                self.assertNotEqual(w1, w2)
                self.assertEqual(wrapper.unwrap(cipher, key, w1), blob)
                self.assertEqual(wrapper.unwrap(cipher, key, w2), blob)

    def test_wrong_key_length_rejected(self):
        for cipher in CIPHERS:
            with self.subTest(cipher=cipher):
                short = b"\x00" * (wrapper.key_size(cipher) - 1)
                with self.assertRaises(wrapper.InvalidKeyError):
                    wrapper.wrap(cipher, short, b"hello")
                with self.assertRaises(wrapper.InvalidKeyError):
                    wrapper.unwrap(cipher, short, b"\x00" * 32)

    def test_short_wire_rejected(self):
        for cipher in CIPHERS:
            with self.subTest(cipher=cipher):
                key = wrapper.generate_key(cipher)
                # wire shorter than nonce — InvalidNonceError.
                tiny = b"\x00" * (wrapper.nonce_size(cipher) - 1)
                with self.assertRaises(wrapper.InvalidNonceError):
                    wrapper.unwrap(cipher, key, tiny)


class TestWrapInPlace(unittest.TestCase):
    def test_roundtrip_per_cipher(self):
        for cipher in CIPHERS:
            with self.subTest(cipher=cipher):
                key = wrapper.generate_key(cipher)
                blob = secrets.token_bytes(1024)
                # Use bytearray to allow in-place mutation.
                mutable = bytearray(blob)
                nonce = wrapper.wrap_in_place(cipher, key, mutable)
                self.assertEqual(len(nonce), wrapper.nonce_size(cipher))
                # Mutated buffer no longer equals original plaintext.
                self.assertNotEqual(bytes(mutable), blob)
                # Recover via unwrap_in_place.
                wire = bytearray(nonce + bytes(mutable))
                recovered_view = wrapper.unwrap_in_place(cipher, key, wire)
                self.assertEqual(bytes(recovered_view), blob)

    def test_immutable_input_rejected(self):
        for cipher in CIPHERS:
            with self.subTest(cipher=cipher):
                key = wrapper.generate_key(cipher)
                blob = b"immutable bytes can not be mutated"
                with self.assertRaises(TypeError):
                    wrapper.wrap_in_place(cipher, key, blob)
                with self.assertRaises(TypeError):
                    wrapper.unwrap_in_place(cipher, key, blob)

    def test_memoryview_writable_supported(self):
        for cipher in CIPHERS:
            with self.subTest(cipher=cipher):
                key = wrapper.generate_key(cipher)
                buf = bytearray(b"memview path: " + secrets.token_bytes(64))
                snapshot = bytes(buf)
                view = memoryview(buf)
                nonce = wrapper.wrap_in_place(cipher, key, view)
                self.assertNotEqual(bytes(buf), snapshot)
                # Recover. Compose wire as nonce || mutated buf.
                wire = bytearray(nonce + bytes(buf))
                recovered = wrapper.unwrap_in_place(cipher, key, wire)
                self.assertEqual(bytes(recovered), snapshot)

    def test_readonly_memoryview_rejected(self):
        for cipher in CIPHERS:
            with self.subTest(cipher=cipher):
                key = wrapper.generate_key(cipher)
                ro = memoryview(b"readonly memview")
                with self.assertRaises(TypeError):
                    wrapper.wrap_in_place(cipher, key, ro)


class TestStreamingHandle(unittest.TestCase):
    def test_streaming_roundtrip_per_cipher(self):
        for cipher in CIPHERS:
            with self.subTest(cipher=cipher):
                key = wrapper.generate_key(cipher)
                chunks_pt = [secrets.token_bytes(256), secrets.token_bytes(512), secrets.token_bytes(128)]

                # Encrypt via WrapStreamWriter handle.
                with wrapper.WrapStreamWriter(cipher, key) as ww:
                    self.assertEqual(len(ww.nonce), wrapper.nonce_size(cipher))
                    self.assertEqual(ww.cipher_name, cipher)
                    encrypted = b"".join(ww.update(c) for c in chunks_pt)
                    sender_nonce = ww.nonce
                # Confirm closed.
                self.assertTrue(ww._closed)

                # Decrypt via UnwrapStreamReader handle.
                with wrapper.UnwrapStreamReader(cipher, key, sender_nonce) as ur:
                    recovered = ur.update(encrypted)
                self.assertEqual(recovered, b"".join(chunks_pt))

    def test_streaming_one_byte_at_a_time(self):
        cipher = wrapper.CIPHER_CHACHA20
        key = wrapper.generate_key(cipher)
        plaintext = b"streaming byte by byte"
        with wrapper.WrapStreamWriter(cipher, key) as ww:
            encrypted = b"".join(ww.update(bytes([b])) for b in plaintext)
            nonce = ww.nonce
        with wrapper.UnwrapStreamReader(cipher, key, nonce) as ur:
            recovered = b"".join(ur.update(bytes([b])) for b in encrypted)
        self.assertEqual(recovered, plaintext)

    def test_streaming_empty_update(self):
        cipher = wrapper.CIPHER_AES128_CTR
        key = wrapper.generate_key(cipher)
        with wrapper.WrapStreamWriter(cipher, key) as ww:
            self.assertEqual(ww.update(b""), b"")

    def test_use_after_close_raises(self):
        cipher = wrapper.CIPHER_SIPHASH24
        key = wrapper.generate_key(cipher)
        ww = wrapper.WrapStreamWriter(cipher, key)
        ww.update(b"hello")
        ww.close()
        with self.assertRaises(wrapper.WrapperHandleClosedError):
            ww.update(b"after close")
        # Idempotent close.
        ww.close()

    def test_unwrap_reader_use_after_close_raises(self):
        cipher = wrapper.CIPHER_AES128_CTR
        key = wrapper.generate_key(cipher)
        # Build a sample wire.
        with wrapper.WrapStreamWriter(cipher, key) as ww:
            ct = ww.update(b"sample")
            nonce = ww.nonce

        ur = wrapper.UnwrapStreamReader(cipher, key, nonce)
        ur.update(ct)
        ur.close()
        with self.assertRaises(wrapper.WrapperHandleClosedError):
            ur.update(b"after close")

    def test_streaming_wrong_nonce_length(self):
        cipher = wrapper.CIPHER_AES128_CTR
        key = wrapper.generate_key(cipher)
        bad_nonce = b"\x00" * (wrapper.nonce_size(cipher) - 1)
        with self.assertRaises(wrapper.InvalidNonceError):
            wrapper.UnwrapStreamReader(cipher, key, bad_nonce)


class TestCrossFFIParity(unittest.TestCase):
    """Cross-FFI parity: Python ``wrapper.wrap`` output is recovered
    byte-equal by the Go-native ``wrapper.Unwrap`` via a helper
    binary. Skips cleanly when the helper is not available — the
    parity check is opportunistic and runs only when the developer
    has built the scratch helper.

    Build the helper with::

        cd ~/scratch/wrapper_parity && go build -o parity_helper .

    or set ``ITB_WRAPPER_PARITY_BIN`` to the absolute path of any
    other helper binary that follows the same protocol (one-line
    stdin: ``cipher_name key_hex payload_hex mode``; one-line
    stdout: ``result_hex``).
    """

    @classmethod
    def setUpClass(cls):
        path = os.environ.get(
            "ITB_WRAPPER_PARITY_BIN",
            "/home/andrew/scratch/wrapper_parity/parity_helper",
        )
        cls.parity_bin = path if shutil.which(path) or Path(path).is_file() else None

    def test_python_wrap_unwraps_in_go(self):
        if not self.parity_bin:
            self.skipTest("parity helper not available")
        for cipher in CIPHERS:
            with self.subTest(cipher=cipher):
                key = wrapper.generate_key(cipher)
                blob = secrets.token_bytes(512)
                py_wire = wrapper.wrap(cipher, key, blob)
                payload = f"{cipher} {key.hex()} {py_wire.hex()} unwrap\n".encode()
                res = subprocess.run(
                    [self.parity_bin],
                    input=payload,
                    capture_output=True,
                    check=True,
                    timeout=30,
                )
                go_recovered = bytes.fromhex(res.stdout.decode().strip())
                self.assertEqual(go_recovered, blob)

    def test_go_wrap_unwraps_in_python(self):
        if not self.parity_bin:
            self.skipTest("parity helper not available")
        for cipher in CIPHERS:
            with self.subTest(cipher=cipher):
                key = wrapper.generate_key(cipher)
                blob = secrets.token_bytes(512)
                payload = f"{cipher} {key.hex()} {blob.hex()} wrap\n".encode()
                res = subprocess.run(
                    [self.parity_bin],
                    input=payload,
                    capture_output=True,
                    check=True,
                    timeout=30,
                )
                go_wire = bytes.fromhex(res.stdout.decode().strip())
                py_recovered = wrapper.unwrap(cipher, key, go_wire)
                self.assertEqual(py_recovered, blob)


if __name__ == "__main__":
    unittest.main()
