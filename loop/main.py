"""Long-run stress harness. The loop utility holds one Pipeline handle
per exercised cipher surface for minutes, hammers it with concurrent
encrypt -> decrypt -> compare round-trips from N worker threads, rotates
the outer masters and reopens the handle from its session blob on a
schedule, and reports whether the process survived with every byte
intact. It is the Python binding's counterpart of the Go harness under
tools/loop: the same flags, the same round structure, the same summary
in both renderings.

The default shape is full production: the Streaming AEAD profile with
parallax on, wrapper on, hmac-blake3 MAC, Areion-SoEM-512 inner hash,
1024-bit keys, and the compile-in 512-bit nonce width, driven through a
stream session by three workers for five minutes on 16 MiB plaintexts.
Every worker owns a distinct CSPRNG-generated plaintext held for the
whole run, so any cross-call state leakage inside the Pipeline surfaces
as a data mismatch between workers rather than cancelling out.

A failure is one of two things. A cipher, rekey or load call that
returns a non-OK status is a worker error: the run stops, the summary
lists it, the verdict is FAIL and the exit code 1. A round-trip that
returns without error but with different bytes is a data mismatch: the
process terminates on the spot with exit code 3, printing the worker,
the iteration and the first differing offset, and no summary — the
state that produced the wrong bytes is the evidence. A crash inside the
shared library or the host runtime has no exit code of its own here;
surfacing it is what the utility is for.

Usage:

  python3 loop/main.py --duration 5m --goroutines 3 --shape stream \
      --hash areion512 --mac hmac-blake3 --payload-size 16MB \
      --memlimit auto --parallax on --wrapper on

Ctrl-C triggers a graceful shutdown: in-flight iterations complete,
then the partial summary prints.
"""

from __future__ import annotations

import json
import os
import signal
import sys
import threading
from pathlib import Path

# Python-specific. Running a script puts its own directory on the
# import path, not the binding's, so the package this utility consumes
# is placed there explicitly rather than through an environment
# variable the launcher would have to set — everything the launcher
# contributes has to be part of what a reader runs by hand.
sys.path.insert(1, str(Path(__file__).resolve().parents[1]))

import itb3 as itb  # noqa: E402

from ops import worker_maintenance  # noqa: E402,F401  (unit wiring)
from payload import (  # noqa: E402
    PAYLOAD_NAMES,
    fill_payload,
    parse_payload_mode,
    payload_mode_name,
    seed_worker,
)
from size import (  # noqa: E402
    human_bytes,
    human_duration,
    now_ns,
    parse_duration,
    parse_size,
)
from state import (  # noqa: E402
    CONCURRENCY,
    MAX_WORKERS,
    SHAPE_BOTH,
    SHAPE_MESSAGE,
    SHAPE_STREAM,
    SHAPE_STREAM_ONE_SHOT,
    Config,
    RunState,
    Worker,
    log_line,
    on_off,
    policy_label,
    status_detail,
)
from summary import final_summary, pool_snapshot, read_rss  # noqa: E402
from worker import parse_shape, shape_name, worker_main  # noqa: E402

# Profiles the shape-based pair is built against when --profile is
# empty.
DEFAULT_STREAM_PROFILE = "streaming-aead-triple-mac-v1"
DEFAULT_MESSAGE_PROFILE = "singlemsg-triple-mac-v1"

# The primitive supplied for the parallax palette and the outer cipher
# when a profile leaves them unnamed. AES-CMAC is PRF-grade, so it is
# sound outside the Interlocked Barrier, and it is the closest relative
# of the AES-based inner primitive whose profiles need this fill.
KEYSTREAM_FILL_CIPHER = "aescmac"

# ------------------------------------------------------------------ #
# Flags                                                               #
# ------------------------------------------------------------------ #

INT, INT64, UINT64, STRING, BOOL = range(5)

# One command-line flag: its name, the type label the usage prints, its
# kind, its default, and its help text. Values are validated after the
# whole line is parsed. The table is in alphabetical order, which is
# the order the usage prints.
FLAGS: tuple[tuple[str, str, int, object, str], ...] = (
    ("barrier-fill", "int", INT, 0,
     "DRBG barrier fill margin: 1 | 2 | 4 | 8 | 16 | 32; 0 = profile default (1)"),
    ("blob-cycle-every", "int", INT64, 0,
     "reopen each pipeline from its session blob every N iterations per worker; 0 = never"),
    ("blob-mode", "int", INT, 1,
     "container floor sizing mode: 1 (per-region, default) | 2 (per-container)"),
    ("chunk-size", "string", STRING, "0",
     "streaming chunk-size budget (e.g. 4MB); 0 = profile default; inert for pure message shape"),
    ("drbg", "string", STRING, "",
     "DRBG fill primitive name (see itb3 drbgs); empty = profile default (auto tier)"),
    ("duration", "duration", STRING, "5m",
     "run duration (Go format: 30s / 5m / 1h); ignored when --iterations > 0"),
    ("gogc", "int", INT, 0,
     "GC trigger percentage; 0 = leave the runtime default"),
    ("gomaxprocs", "int", INT, 0,
     "Go runtime GOMAXPROCS override; 0 = inherit from the environment"),
    ("goroutines", "int", INT, 3,
     "concurrent workers (1..10); on runtimes without parallelism values above 1 are clamped to 1"),
    ("hash", "string", STRING, "areion512",
     "inner ITB hash primitive name"),
    ("iterations", "int", INT64, 0,
     "fixed per-worker iteration count; 0 = duration-based"),
    ("json-output", "", BOOL, False,
     "print the final summary as one compact JSON object instead of log lines"),
    ("key-bits", "int", INT, 0,
     "per-seed key width in bits: 512 | 1024 | 2048; 0 = profile default (1024)"),
    ("mac", "string", STRING, "hmac-blake3",
     "MAC primitive name"),
    ("memlimit", "string", STRING, "auto",
     "Go heap soft limit: auto (1GiB when goroutines <= 3, else 256MiB, applied only when the "
     "runtime has no limit) or a size (e.g. 512MB)"),
    ("memprofile", "string", STRING, "",
     "write a Go runtime heap profile (pprof) to this path at the end of the run; empty = none"),
    ("nonce-bits", "int", INT, 0,
     "on-wire nonce width in bits: 128 | 256 | 512; 0 = profile default (512)"),
    ("parallax", "string", STRING, "on",
     "parallax layer: on | off"),
    ("payload-mode", "string", STRING, "fixed",
     "plaintext content: fixed | rotating | pattern-zero | pattern-ff | pattern-ascii"),
    ("payload-size", "string", STRING, "16MB",
     "per-iteration plaintext size (e.g. 1MB / 16MB / 64MB)"),
    ("profile", "string", STRING, "",
     "exercise this single registered triple profile (overrides --shape with the profile's "
     "surface); empty = shape-based profile pair"),
    ("rekey-every", "int", INT64, 0,
     "rotate the parallax + wrapper masters via Rekey every N iterations per worker; 0 = never"),
    ("seed", "uint", UINT64, 0,
     "deterministic plaintext RNG seed for bug reproduction, NOT for security testing (pipeline "
     "keys stay CSPRNG-drawn); 0 = crypto/rand plaintexts"),
    ("shape", "string", STRING, "stream",
     "cipher surface to exercise: stream | message | stream_one_shot | both"),
    ("wrapper", "string", STRING, "on",
     "wrapper layer: on | off"),
)

_INT32_MAX = 2147483647
_UINT64_MAX = (1 << 64) - 1


def _err(text: str) -> None:
    sys.stderr.write(f"loop: {text}\n")
    sys.stderr.flush()


def _usage() -> None:
    out = ["Usage of loop:\n"]
    for name, label, kind, default, help_text in FLAGS:
        out.append(f"  -{name}{' ' if label else ''}{label}\n")
        line = f"    \t{help_text}"
        # The default-value suffix follows the shape a Go flag set
        # prints: an integer default only when it is non-zero, a string
        # default only when it is non-empty.
        if kind == INT and default != 0:
            line += f" (default {default})"
        elif kind == STRING and default != "":
            line += f' (default "{default}")'
        out.append(line + "\n")
    sys.stderr.write("".join(out))
    sys.stderr.flush()


def _assign(kind: int, value: str) -> object | None:
    """Parses one value into its flag slot; None on a malformed value."""
    if kind in (INT, INT64):
        body = value[1:] if value[:1] in "+-" else value
        if not body.isdigit() or not body.isascii():
            return None
        n = int(value)
        if kind == INT and (n > _INT32_MAX or n < -_INT32_MAX):
            return None
        return n
    if kind == UINT64:
        body = value[1:] if value[:1] == "+" else value
        if not body.isdigit() or not body.isascii():
            return None
        n = int(body)
        return n if n <= _UINT64_MAX else None
    if kind == STRING:
        return value
    if value == "true":
        return True
    if value == "false":
        return False
    return None


def _parse_argv(argv: list[str]) -> tuple[int, dict[str, object]]:
    """Parses argv into the raw flag values. Accepts -name value,
    --name value, -name=value and --name=value; a boolean flag takes no
    value unless given as -name=true / -name=false. Returns (0, values),
    (1, {}) for -h / --help (usage printed), or (-1, {}) after printing
    the error."""
    raw: dict[str, object] = {name: default for name, _, _, default, _ in FLAGS}
    by_name = {name: (kind, label) for name, label, kind, _, _ in FLAGS}
    i = 0
    while i < len(argv):
        arg = argv[i]
        if not arg.startswith("-") or arg == "-":
            _err(f"unexpected positional arguments: [{arg}]")
            return -1, {}
        name = arg[2:] if arg.startswith("--") else arg[1:]
        if name in ("h", "help"):
            _usage()
            return 1, {}
        eq = name.find("=")
        value: str | None = None
        if eq >= 0:
            name, value = name[:eq], name[eq + 1 :]
        if name not in by_name:
            _err(f"flag provided but not defined: -{name}")
            _usage()
            return -1, {}
        kind, _label = by_name[name]
        if value is None:
            if kind == BOOL:
                value = "true"
            elif i + 1 < len(argv):
                i += 1
                value = argv[i]
            else:
                _err(f"flag needs an argument: -{name}")
                return -1, {}
        parsed = _assign(kind, value)
        if parsed is None:
            _err(f'invalid value "{value}" for flag -{name}')
            return -1, {}
        raw[name] = parsed
        i += 1
    return 0, raw


def _parse_on_off(v: str) -> bool | None:
    if v == "on":
        return True
    if v == "off":
        return False
    return None


def _hash_registered(name: str) -> bool:
    """Whether name is in the shipped hash registry the binding
    enumerates."""
    try:
        return name in itb.hash_names()
    except itb.ItbError:
        return False


def _profile_surface(name: str) -> int | None:
    """Resolves a registered profile to the shape family its record's
    mode exposes by reading the record through the binding's lookup: a
    mode beginning with "streaming" exposes the stream surfaces, one
    beginning with "singlemsg" the message surface, "blob-only" none.
    Prints the validation message and returns None on rejection."""
    try:
        record = itb.lookup(name)
    except itb.ItbError:
        _err(f'--profile "{name}" is not a registered triple profile')
        return None
    mode = str(record.get("mode", ""))
    if mode.startswith("streaming"):
        return SHAPE_STREAM
    if mode.startswith("singlemsg"):
        return SHAPE_MESSAGE
    _err(f'--profile "{name}" carries no cipher surface (blob-only mode)')
    return None


def _narrow_shape(requested: int, surface: int) -> int:
    """Applies a --profile's surface to the requested shape: a
    message-surface profile forces message; a stream-surface profile
    keeps stream or stream_one_shot as requested and turns message or
    both into stream."""
    if surface == SHAPE_MESSAGE:
        return SHAPE_MESSAGE
    return SHAPE_STREAM_ONE_SHOT if requested == SHAPE_STREAM_ONE_SHOT else SHAPE_STREAM


def parse_flags(argv: list[str]) -> tuple[int, Config]:
    """Builds the resolved config from argv. Returns (0, cfg), (1, cfg)
    for help, or (-1, cfg) after printing "loop: <message>" for the
    first failing rule."""
    cfg = Config()
    rc, raw = _parse_argv(argv)
    if rc != 0:
        return rc, cfg

    duration_ns = parse_duration(str(raw["duration"]))
    if duration_ns is None or duration_ns <= 0:
        _err(f"--duration must be positive, got {raw['duration']}")
        return -1, cfg
    cfg.duration_ns = duration_ns
    cfg.iterations = int(raw["iterations"])
    if cfg.iterations < 0:
        _err(f"--iterations must be >= 0, got {cfg.iterations}")
        return -1, cfg
    goroutines = int(raw["goroutines"])
    if goroutines < 1 or goroutines > MAX_WORKERS:
        _err(f"--goroutines must be in 1..{MAX_WORKERS}, got {goroutines}")
        return -1, cfg
    # Concurrency mode. This binding runs shared-handle: ctypes releases
    # the interpreter lock for the duration of every foreign call, so
    # OS threads call into one Pipeline handle concurrently, which the
    # shared library permits after construction. --goroutines is the
    # thread count verbatim, never clamped.
    cfg.workers_requested = goroutines
    cfg.workers = goroutines
    shape = parse_shape(str(raw["shape"]))
    if shape is None:
        _err(f'--shape must be stream | message | stream_one_shot | both, got "{raw["shape"]}"')
        return -1, cfg
    cfg.shape = shape
    if not _hash_registered(str(raw["hash"])):
        _err(f'--hash "{raw["hash"]}" is not a registered hash primitive')
        return -1, cfg
    cfg.hash = str(raw["hash"])
    # Validated by Init: the C ABI enumerates no MAC names.
    cfg.mac = str(raw["mac"])
    payload = parse_size(str(raw["payload-size"]))
    if payload is None:
        _err(f'--payload-size: invalid size "{raw["payload-size"]}"')
        return -1, cfg
    cfg.payload = payload
    if cfg.payload < 1:
        _err("--payload-size must be at least 1 byte")
        return -1, cfg
    if str(raw["memlimit"]) == "auto":
        cfg.memlimit_auto = True
        cfg.memlimit = (1 << 30) if cfg.workers <= 3 else (256 << 20)
    else:
        memlimit = parse_size(str(raw["memlimit"]))
        if memlimit is None:
            _err(f'--memlimit: invalid size "{raw["memlimit"]}"')
            return -1, cfg
        cfg.memlimit = memlimit
    cfg.gogc = int(raw["gogc"])
    if cfg.gogc < 0:
        _err(f"--gogc must be >= 0, got {cfg.gogc}")
        return -1, cfg
    parallax = _parse_on_off(str(raw["parallax"]))
    if parallax is None:
        _err(f'--parallax must be on | off, got "{raw["parallax"]}"')
        return -1, cfg
    cfg.parallax = parallax
    wrapper = _parse_on_off(str(raw["wrapper"]))
    if wrapper is None:
        _err(f'--wrapper must be on | off, got "{raw["wrapper"]}"')
        return -1, cfg
    cfg.wrapper = wrapper
    cfg.profile = str(raw["profile"])
    if cfg.profile:
        surface = _profile_surface(cfg.profile)
        if surface is None:
            return -1, cfg
        cfg.shape = _narrow_shape(cfg.shape, surface)
    cfg.key_bits = int(raw["key-bits"])
    if cfg.key_bits not in (0, 512, 1024, 2048):
        _err(f"--key-bits must be 512 | 1024 | 2048 (or 0 = profile default), got {cfg.key_bits}")
        return -1, cfg
    cfg.nonce_bits = int(raw["nonce-bits"])
    if cfg.nonce_bits not in (0, 128, 256, 512):
        _err(f"--nonce-bits must be 128 | 256 | 512 (or 0 = profile default), got {cfg.nonce_bits}")
        return -1, cfg
    cfg.blob_mode = int(raw["blob-mode"])
    if cfg.blob_mode not in (1, 2):
        _err(f"--blob-mode must be 1 (per-region) | 2 (per-container), got {cfg.blob_mode}")
        return -1, cfg
    cfg.barrier_fill = int(raw["barrier-fill"])
    if cfg.barrier_fill not in (0, 1, 2, 4, 8, 16, 32):
        _err(
            "--barrier-fill must be 1 | 2 | 4 | 8 | 16 | 32 (or 0 = profile default), "
            f"got {cfg.barrier_fill}"
        )
        return -1, cfg
    # Validated by Init: the C ABI enumerates no DRBG names.
    cfg.drbg = str(raw["drbg"])
    chunk_size = parse_size(str(raw["chunk-size"]))
    if chunk_size is None:
        _err(f'--chunk-size: invalid size "{raw["chunk-size"]}"')
        return -1, cfg
    cfg.chunk_size = chunk_size
    cfg.gomaxprocs = int(raw["gomaxprocs"])
    if cfg.gomaxprocs < 0:
        _err(f"--gomaxprocs must be > 0 when specified, got {cfg.gomaxprocs}")
        return -1, cfg
    cfg.rekey_every = int(raw["rekey-every"])
    if cfg.rekey_every < 0:
        _err(f"--rekey-every must be >= 0, got {cfg.rekey_every}")
        return -1, cfg
    cfg.blob_cycle_every = int(raw["blob-cycle-every"])
    if cfg.blob_cycle_every < 0:
        _err(f"--blob-cycle-every must be >= 0, got {cfg.blob_cycle_every}")
        return -1, cfg
    payload_mode = parse_payload_mode(str(raw["payload-mode"]))
    if payload_mode is None:
        _err(
            "--payload-mode must be " + " | ".join(PAYLOAD_NAMES)
            + f', got "{raw["payload-mode"]}"'
        )
        return -1, cfg
    cfg.payload_mode = payload_mode
    cfg.seed = int(raw["seed"])
    cfg.json_output = bool(raw["json-output"])
    cfg.memprofile = str(raw["memprofile"])
    return 0, cfg


# ------------------------------------------------------------------ #
# Signals                                                             #
# ------------------------------------------------------------------ #

_signal_seen = False


def _on_signal(signum: int, frame: object) -> None:
    global _signal_seen
    _signal_seen = True


def _restore_sigpipe() -> None:
    """A consumer that stops reading ends the run. The default
    disposition for SIGPIPE is restored so the process dies from the
    signal with status 141 and prints nothing — the reference behaviour,
    and what anyone piping into head or less expects. Python installs a
    handler of its own at interpreter startup that turns the failed
    write into a BrokenPipeError and a traceback, so restoring the
    default is an explicit step here rather than something inherited.

    It runs before the first line is printed, because the first line is
    already a write that can fail."""
    signal.signal(signal.SIGPIPE, signal.SIG_DFL)


def _install_signals() -> None:
    """Graceful stop. SIGINT / SIGTERM set a flag the main thread polls
    while it waits for the workers; it turns the flag into the stop
    request every worker checks before starting an iteration, so a
    signal interrupts nothing mid-call — the in-flight encrypt /
    decrypt / compare completes, the worker returns, and the partial
    summary prints with the verdict the completed iterations earned."""
    signal.signal(signal.SIGINT, _on_signal)
    signal.signal(signal.SIGTERM, _on_signal)


# ------------------------------------------------------------------ #
# Pipelines                                                           #
# ------------------------------------------------------------------ #


def _record_str(record: dict, key: str) -> str:
    """String value of key in a profile record, or "-" when absent or
    empty."""
    value = record.get(key)
    return str(value) if isinstance(value, str) and value else "-"


def _log_pipeline_initialised(profile: str, blob: bytes) -> None:
    """Prints the construction line with the recipe read back from the
    blob the Pipeline handed out, not echoed from the flags: every
    construction override is proven to have reached the library by the
    value the receiver would see. Record values that are empty (a No MAC
    profile's MAC, a mixed profile's single hash) print as "-"."""
    try:
        record = itb.inspect(blob)
    except itb.ItbError as exc:
        log_line(
            f"pipeline initialised: profile={profile} blob={len(blob)} bytes "
            f"(inspect: {getattr(exc, 'message', str(exc))})"
        )
        return
    log_line(
        f"pipeline initialised: profile={profile} blob={len(blob)} bytes "
        f"hash={_record_str(record, 'hash')} "
        f"key-bits={int(record.get('keybits', 0))} "
        f"nonce-bits={int(record.get('nonce_bits', 0))} "
        f"barrier-fill={int(record.get('barrier_fill', 0))} "
        f"chunk-size={int(record.get('chunk', 0))} "
        f"mac={_record_str(record, 'mac')} "
        f"parallax={on_off(bool(record.get('parallax', False)))} "
        f"wrapper={on_off(bool(record.get('wrapper', False)))}"
        + (" container-mode=2" if record.get("container_mode") == 2 else "")
        + (f" drbg={record['drbg']}" if _record_str(record, "drbg") != "-" else "")
    )


def _edit_inner_blob_mode(blob: bytes, target_mode: int) -> bytes:
    """Returns a copy of a wrap-layer session blob whose inner blob's
    "mode" field is set to target_mode (1 = per-region, 2 =
    per-container). The wrap layer's profile record carries its own
    "mode" (a string); the target is the inner blob's ("ib") integer
    field. Raises ValueError when the blob is not the expected JSON
    object or carries no inner blob mode field."""
    doc = json.loads(blob)
    inner = doc.get("ib") if isinstance(doc, dict) else None
    if not isinstance(inner, dict) or "mode" not in inner:
        raise ValueError("inner blob mode field not found")
    inner["mode"] = target_mode
    return json.dumps(doc, separators=(",", ":")).encode("utf-8")


def _fill_keystream_layers(name: str, opts: itb.Opts, want_parallax: bool,
                           want_wrapper: bool) -> int:
    """Folds a keystream primitive into opts for any layer the named
    profile leaves unfilled but the operator asked for.

    A profile built around a primitive that is safe only inside the
    Interlocked Barrier ships with no parallax palette and no outer
    cipher: both layers run outside the barrier, where that primitive
    would stand bare, so the recipe leaves them unnamed rather than
    naming a primitive that must not key them. Engaging either layer
    therefore needs a keystream-capable primitive supplied from outside
    the recipe; without it construction fails on a palette below its
    minimum or an unnamed outer cipher, and the primitive that most
    deserves stressing becomes the one that cannot be stressed with
    those layers engaged.

    Overrides fold into the resolved record the blob carries, so the
    receiver rebuilds the same shape from the blob alone.

    Returns 1 when a layer was filled, 0 when none needed it, -1 on a
    lookup failure (message already printed)."""
    try:
        record = itb.lookup(name)
    except itb.ItbError:
        _err(f'--profile "{name}" is not a registered triple profile')
        return -1
    filled = 0
    if want_parallax and "palette" not in record:
        opts.with_parallax_palette([KEYSTREAM_FILL_CIPHER] * 3)
        if "segment" not in record:
            # A recipe that never carried a palette never carried a
            # segment size either, and the schedule rejects zero.
            opts.with_parallax_segment_size(4093)
        filled = 1
    if want_wrapper and "outer" not in record:
        opts.with_outer_cipher(KEYSTREAM_FILL_CIPHER)
        filled = 1
    return filled


def _build_pipeline(cfg: Config, profile: str) -> tuple[itb.Pipeline, bytes] | None:
    """Constructs one Pipeline against profile with every flag-carried
    override in the opts string (zero values included — the shared
    library treats zero as "profile default"), then obtains the Init
    blob once through save: the binding's init entry does not hand the
    blob back, and the bytes are the ones Init produced. Later blob
    reopens use the retained blob; save is never called again."""
    opts = (
        itb.Opts()
        .with_inner_hash(cfg.hash)
        .with_mac_name(cfg.mac)
        .with_parallax(cfg.parallax)
        .with_wrapper(cfg.wrapper)
        .with_key_bits(cfg.key_bits)
        .with_nonce_bits(cfg.nonce_bits)
        .with_barrier_fill(cfg.barrier_fill)
        .with_drbg(cfg.drbg)
        .with_chunk_size(cfg.chunk_size)
    )
    if cfg.profile:
        filled = _fill_keystream_layers(cfg.profile, opts, cfg.parallax, cfg.wrapper)
        if filled < 0:
            return None
        if filled > 0:
            _err(
                f"{cfg.profile} leaves the requested keystream layers unnamed; "
                f"{KEYSTREAM_FILL_CIPHER} supplied for them"
            )
    try:
        pipe = itb.Pipeline.init(profile, opts)
    except itb.ItbError as exc:
        _err(f"Init({profile}): {status_detail(exc)}")
        return None
    try:
        blob = pipe.save()
    except itb.ItbError as exc:
        _err(f"Save({profile}): {status_detail(exc)}")
        pipe.free()
        return None
    if cfg.blob_mode == 2:
        # The sizing mode is not an Opts knob: the Init blob is edited
        # and the pipeline reopened from it, so the retained blob (the
        # one blob-cycle reopens from) carries the edited mode.
        try:
            edited = _edit_inner_blob_mode(blob, 2)
        except ValueError as exc:
            _err(f"rewrite blob mode: {exc}")
            pipe.free()
            return None
        pipe.free()
        try:
            pipe = itb.Pipeline.load(edited)
        except itb.ItbError as exc:
            _err(f"reload Mode 2 blob: {status_detail(exc)}")
            return None
        blob = edited
    _log_pipeline_initialised(profile, blob)
    return pipe, blob


# ------------------------------------------------------------------ #
# Run                                                                 #
# ------------------------------------------------------------------ #


def run(argv: list[str]) -> int:
    rc, cfg = parse_flags(argv)
    if rc == 1:
        return 0
    if rc != 0:
        return 2

    r = RunState(cfg=cfg)

    # Runtime shaping. A long run under allocation churn grows the Go
    # heap inside the shared library without bound unless a soft limit
    # paces the collector, so a limit is always in force: an explicit
    # --memlimit is set as given, and auto caps the heap only when the
    # runtime reports no limit at all (a limit already installed from
    # the environment is left standing). The GC percentage and
    # GOMAXPROCS are set only when their flag is non-zero — a zero flag
    # skips the setter rather than calling it with zero, because zero is
    # a real value to the GC-percent setter, and a call would clobber
    # whatever the environment installed. All of it lands before any
    # Pipeline exists so the baselines are taken under the shaped
    # runtime.
    if cfg.memlimit_auto:
        if itb.set_memory_limit(-1) == (1 << 63) - 1:
            itb.set_memory_limit(cfg.memlimit)
    else:
        itb.set_memory_limit(cfg.memlimit)
    cfg.memlimit = itb.set_memory_limit(-1)
    if cfg.gogc > 0:
        itb.set_gc_percent(cfg.gogc)
    if cfg.gomaxprocs > 0:
        itb.set_gomaxprocs(cfg.gomaxprocs)

    log_line(
        f"start: duration={human_duration(cfg.duration_ns)} iterations={cfg.iterations} "
        f"goroutines={cfg.workers_requested} workers={cfg.workers} "
        f"concurrency={CONCURRENCY} shape={shape_name(cfg.shape)} hash={cfg.hash} "
        f"mac={cfg.mac} payload={human_bytes(cfg.payload)} "
        f"memlimit={human_bytes(cfg.memlimit)} parallax={on_off(cfg.parallax)} "
        f"wrapper={on_off(cfg.wrapper)}"
    )
    log_line(
        f'overrides: profile="{cfg.profile}" key-bits={cfg.key_bits} '
        f"nonce-bits={cfg.nonce_bits} chunk-size={human_bytes(cfg.chunk_size)} "
        f"barrier-fill={cfg.barrier_fill} gomaxprocs={cfg.gomaxprocs} "
        f"rekey-every={cfg.rekey_every} blob-cycle-every={cfg.blob_cycle_every} "
        f"payload-mode={payload_mode_name(cfg.payload_mode)} seed={cfg.seed} "
        f"json-output={'true' if cfg.json_output else 'false'}"
        + (f" blob-mode={cfg.blob_mode}" if cfg.blob_mode != 1 else "")
        + (f" drbg={cfg.drbg}" if cfg.drbg else "")
    )
    log_line(
        "policy: microbatch-tiers="
        f"{policy_label(os.environ.get('ITB_MICROBATCH_TIERS'))} "
        f"hashpool-starters={policy_label(os.environ.get('ITB_HASHPOOL_STARTERS'))}"
    )

    # Pipeline construction — one shared handle per exercised shape.
    # stream and stream_one_shot share the streaming handle.
    r.stream_profile = cfg.profile if cfg.profile else DEFAULT_STREAM_PROFILE
    r.msg_profile = cfg.profile if cfg.profile else DEFAULT_MESSAGE_PROFILE
    if cfg.shape in (SHAPE_STREAM, SHAPE_STREAM_ONE_SHOT, SHAPE_BOTH):
        built = _build_pipeline(cfg, r.stream_profile)
        if built is None:
            return 1
        r.stream_pipe, r.stream_blob = built
    if cfg.shape in (SHAPE_MESSAGE, SHAPE_BOTH):
        built = _build_pipeline(cfg, r.msg_profile)
        if built is None:
            return 1
        r.msg_pipe, r.msg_blob = built

    # Allocation posture. Per-worker plaintexts are built once and held
    # for the whole run (rotating mode replaces them per iteration); the
    # wire and round-trip buffers are the values the binding returns per
    # call and the interpreter reclaims them when the iteration drops
    # them, and the pump loop accumulates its slices into one joined
    # buffer per direction. Under the default fixed CSPRNG mode every
    # worker's buffer is distinct, so cross-worker data crossover is
    # detectable; pattern modes trade that property for content
    # edge-case coverage.
    for i in range(cfg.workers):
        w = Worker(id=i, run=r)
        w.payload_mode = cfg.payload_mode
        w.seeded = cfg.seed != 0
        w.rng = seed_worker(cfg.seed, i)
        try:
            w.plaintext, w.rng = fill_payload(cfg.payload_mode, w.seeded, w.rng, cfg.payload)
        except (MemoryError, OSError):
            _err("payload alloc: out of memory")
            return 1
        r.workers.append(w)

    r.pool_warmup = pool_snapshot()
    r.pool_steady = list(r.pool_warmup)
    if not r.pool_warmup:
        _err("pool snapshot alloc failed")
        return 1

    _install_signals()
    r.done_cond = threading.Condition(threading.Lock())
    r.warmup_done = threading.Barrier(cfg.workers + 1)
    r.release = threading.Barrier(cfg.workers + 1)
    r.stop = False
    r.active = cfg.workers

    # Warmup barrier. Every worker runs one iteration and waits; the
    # clock starts only once all of them have paid their first-call
    # costs (pool warm-up, lazy kernel dispatch, page faults on the
    # payload buffers), and the RSS and pool baselines taken here
    # describe a process that has already run the whole cipher path once
    # per worker.
    warmup_start = now_ns()
    for w in r.workers:
        w.thread = threading.Thread(target=worker_main, args=(w,), daemon=True)
        w.thread.start()
    r.warmup_done.wait()
    r.rss_warmup, r.rss_peak = read_rss()
    r.pool_warmup = pool_snapshot()
    warmup_ns = now_ns() - warmup_start
    log_line(
        f"warmup: {cfg.workers} workers x 1 iter completed in "
        f"{human_duration((warmup_ns + 50_000_000) // 100_000_000 * 100_000_000)} "
        f"(baseline rss={human_bytes(r.rss_warmup)})"
    )

    # Open the gate; the duration deadline is enforced by the waiter
    # below in duration mode.
    r.start_ns = now_ns()
    r.finish_ns = r.start_ns
    r.release.wait()

    # Wait for every worker, polling every 100 ms so the deadline and a
    # signal are both noticed promptly.
    with r.done_cond:
        while r.active > 0:
            if _signal_seen:
                r.stop = True
            if cfg.iterations == 0 and now_ns() - r.start_ns >= cfg.duration_ns:
                r.stop = True
            r.done_cond.wait(0.1)
    for w in r.workers:
        w.thread.join()
    elapsed_ns = r.finish_ns - r.start_ns
    r.rss_final, peak = read_rss()
    r.rss_peak = max(r.rss_peak, peak)
    r.pool_steady = pool_snapshot()

    if cfg.memprofile:
        try:
            itb.write_heap_profile(cfg.memprofile)
        except itb.ItbError as exc:
            _err(f"memprofile: {getattr(exc, 'message', str(exc))}")
        else:
            log_line(f"memprofile: heap profile written to {cfg.memprofile}")

    rc = final_summary(r, elapsed_ns)

    if r.stream_pipe is not None:
        r.stream_pipe.free()
    if r.msg_pipe is not None:
        r.msg_pipe.free()
    return rc


def main() -> int:
    _restore_sigpipe()
    return run(sys.argv[1:])


if __name__ == "__main__":
    sys.exit(main())
