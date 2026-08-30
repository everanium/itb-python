"""eitb — command-line demonstrator for the ITB Python binding.

Subcommands::

    eitb.py version                                   library + binding versions
    eitb.py hashes                                    shipped hash primitive roster
    eitb.py encrypt <profile> <in-file> <out-file>    Single Message encrypt
    eitb.py decrypt <profile> <blob-hex> <in-file> <out-file>

``encrypt`` prints the session blob to stderr as hex; feed that hex
back to ``decrypt`` on the receiving side.
"""

from __future__ import annotations

import ctypes
import os
import sys
from pathlib import Path

# Make the itb package importable when the CLI is run by path
# (python3 eitb/eitb.py ...).
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import itb  # noqa: E402
from itb import _ffi  # noqa: E402

USAGE = """\
usage: eitb.py version
       eitb.py hashes
       eitb.py encrypt <profile> <in-file> <out-file>
       eitb.py decrypt <profile> <blob-hex> <in-file> <out-file>"""


def cmd_version() -> None:
    print(f"libitb {itb.version()}")
    print(f"itb-python {itb.__version__}")


def cmd_hashes() -> None:
    # The binding package deliberately exposes no primitive
    # enumeration; this CLI diagnostic prototypes the three iteration
    # symbols itself so the shipped roster can be inspected from the
    # shell.
    lib = _ffi.syms().lib
    lib.ITB_HashCount.argtypes = []
    lib.ITB_HashCount.restype = ctypes.c_int
    lib.ITB_HashName.argtypes = [
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_size_t,
        ctypes.POINTER(ctypes.c_size_t),
    ]
    lib.ITB_HashName.restype = ctypes.c_int
    lib.ITB_HashWidth.argtypes = [ctypes.c_int]
    lib.ITB_HashWidth.restype = ctypes.c_int

    for i in range(int(lib.ITB_HashCount())):
        buf = ctypes.create_string_buffer(128)
        n = ctypes.c_size_t(0)
        rc = int(lib.ITB_HashName(i, buf, len(buf), ctypes.byref(n)))
        if rc != 0:
            raise itb.ItbError(f"ITB_HashName({i}) failed with status {rc}")
        name = buf.raw[: max(n.value - 1, 0)].decode("utf-8", "replace")
        width = int(lib.ITB_HashWidth(i))
        print(f"{i:2}  {name:<12} {width} bits")


def _ensure_parent_dir(out: str) -> None:
    """Create the parent directory of out recursively (mkdir -p)."""
    parent = os.path.dirname(out)
    if parent:
        os.makedirs(parent, exist_ok=True)


def _is_streaming_profile(profile: str) -> bool:
    """Profiles whose canonical name begins with ``streaming-`` route
    through the one-shot streaming buffered pair instead of the
    Single Message pair."""
    return profile.startswith("streaming-")


def cmd_encrypt(profile: str, infile: str, outfile: str) -> None:
    plain = Path(infile).read_bytes()
    with itb.Pipeline.init(profile) as pipe:
        if _is_streaming_profile(profile):
            wire = pipe.encrypt_stream_one_shot(plain)
        else:
            wire = pipe.encrypt_message(plain)
        _ensure_parent_dir(outfile)
        Path(outfile).write_bytes(wire)
        print(pipe.blob.hex(), file=sys.stderr)
    print(f"encrypted {infile} -> {outfile} ({len(plain)} -> {len(wire)} bytes)")


def cmd_decrypt(profile: str, blob_hex: str, infile: str, outfile: str) -> None:
    try:
        blob = bytes.fromhex(blob_hex)
    except ValueError as exc:
        raise itb.ItbError(f"blob hex: {exc}") from exc
    wire = Path(infile).read_bytes()
    with itb.Pipeline.open(profile, blob) as pipe:
        if _is_streaming_profile(profile):
            plain = pipe.decrypt_stream_one_shot(wire)
        else:
            plain = pipe.decrypt_message(wire)
    _ensure_parent_dir(outfile)
    Path(outfile).write_bytes(plain)
    print(f"decrypted {infile} -> {outfile} ({len(wire)} -> {len(plain)} bytes)")


def main(argv: list[str]) -> int:
    known_shape = (
        (len(argv) == 1 and argv[0] in ("version", "hashes"))
        or (len(argv) == 4 and argv[0] == "encrypt")
        or (len(argv) == 5 and argv[0] == "decrypt")
    )
    if not known_shape:
        print(USAGE, file=sys.stderr)
        return 2
    try:
        # Go-runtime pacing caps applied before any cipher work.
        itb.set_memory_limit(512 << 20)
        itb.set_gc_percent(20)
        if argv[0] == "version":
            cmd_version()
        elif argv[0] == "hashes":
            cmd_hashes()
        elif argv[0] == "encrypt":
            cmd_encrypt(argv[1], argv[2], argv[3])
        else:
            cmd_decrypt(argv[1], argv[2], argv[3], argv[4])
    except (itb.ItbError, OSError) as exc:
        print(f"eitb: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
