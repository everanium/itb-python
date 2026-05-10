"""Python eitb runner — companion to ``cmd/eitb`` in the root repo.

Runs the format-deniability wrapper × ITB Python binding example
matrix end-to-end. Matrix: 8 examples × 3 outer ciphers = 24 cells.

Binding asymmetry note. The Python binding does not expose a
file-like / stream-like Streaming No MAC writer or reader pair
(``noaead-easy-io`` / ``noaead-lowlevel-io`` from the Go-side
``cmd/eitb`` matrix). The Streaming No MAC arm in Python is the
User-Driven Loop variant only — caller produces ITB ciphertext per
chunk via :meth:`itb.Encryptor.encrypt` (or :func:`itb.encrypt`),
frames ``u32_LE_len || ct`` per chunk, and pushes through the
wrapper streaming handle. This is intentional — see CLAUDE.md.
"""

__all__ = []
