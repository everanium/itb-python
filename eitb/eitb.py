"""eitb — command-line demonstrator for the ITB Python binding.

Subcommands::

    eitb.py version                                   library + binding versions
    eitb.py profiles                                  registered profile catalogue
    eitb.py inspect <blob-hex>                        profile record of a blob
    eitb.py encrypt <profile> <in-file> <out-file>    Single Message encrypt
    eitb.py decrypt <profile> <blob-hex> <in-file> <out-file>

``encrypt`` prints the session blob (``Pipeline.save``) to stderr as
hex; feed that hex back to ``decrypt`` on the receiving side, which
reopens the session with ``Pipeline.load`` (the profile argument only
routes Single Message versus streaming). ``profiles`` lists the
registered profile catalogue one name per line; the profiles that
carry a cipher surface are the ones ``encrypt`` / ``decrypt`` accept.
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

# Make the itb package importable when the CLI is run by path
# (python3 eitb/eitb.py ...).
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import itb  # noqa: E402

USAGE = """\
usage: eitb.py version
       eitb.py profiles
       eitb.py inspect <blob-hex>
       eitb.py encrypt <profile> <in-file> <out-file>
       eitb.py decrypt <profile> <blob-hex> <in-file> <out-file>"""


def cmd_version() -> None:
    print(f"libitb {itb.version()}")
    print(f"itb-python {itb.__version__}")


def cmd_profiles() -> None:
    for name in itb.profiles():
        print(name)


def _blob_from_hex(blob_hex: str) -> bytes:
    try:
        return bytes.fromhex(blob_hex)
    except ValueError as exc:
        raise itb.ItbError(f"blob hex: {exc}") from exc


def cmd_inspect(blob_hex: str) -> None:
    print(json.dumps(itb.inspect(_blob_from_hex(blob_hex)), indent=2))


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
        print(pipe.save().hex(), file=sys.stderr)
    print(f"encrypted {infile} -> {outfile} ({len(plain)} -> {len(wire)} bytes)")


def cmd_decrypt(profile: str, blob_hex: str, infile: str, outfile: str) -> None:
    blob = _blob_from_hex(blob_hex)
    wire = Path(infile).read_bytes()
    with itb.Pipeline.load(blob) as pipe:
        if _is_streaming_profile(profile):
            plain = pipe.decrypt_stream_one_shot(wire)
        else:
            plain = pipe.decrypt_message(wire)
    _ensure_parent_dir(outfile)
    Path(outfile).write_bytes(plain)
    print(f"decrypted {infile} -> {outfile} ({len(wire)} -> {len(plain)} bytes)")


def main(argv: list[str]) -> int:
    known_shape = (
        (len(argv) == 1 and argv[0] in ("version", "profiles"))
        or (len(argv) == 2 and argv[0] == "inspect")
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
        elif argv[0] == "profiles":
            cmd_profiles()
        elif argv[0] == "inspect":
            cmd_inspect(argv[1])
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
