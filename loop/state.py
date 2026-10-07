"""Shared declarations of the loop stress harness: the resolved
configuration, the per-worker state, the run state every worker shares,
the read-write lock that keeps iterations clear of handle mutation, and
the shared output helpers every unit logs through.

Python-specific. Python resolves an import at module execution time, so
two units that name each other's types cannot both import at the top
level; the worker unit drives maintenance and the ops unit reads the run
state, which is exactly that shape. A declarations unit holding what
both sides need is the same answer the C reference reaches with its
header.
"""

from __future__ import annotations

import sys
import threading
from dataclasses import dataclass, field
from typing import Any

# Cipher surfaces the --shape flag selects.
SHAPE_STREAM = 0  # session pump: begin / write / read / end
SHAPE_MESSAGE = 1  # Single Message: one whole-buffer call
SHAPE_STREAM_ONE_SHOT = 2  # stream surface, one whole-buffer call
SHAPE_BOTH = 3  # all three, rotating by iteration number

SHAPE_NAMES: tuple[str, ...] = ("stream", "message", "stream_one_shot", "both")

# --goroutines ceiling; the harness targets modest hosts and each
# worker pins payload-sized buffers for the whole run.
MAX_WORKERS = 10

# The concurrency mode this binding implements, as the summary reports
# it (shared-handle / independent-handles / single).
CONCURRENCY = "shared-handle"

# Largest slice fed to a stream session per write; the drain after
# every write uses the same bound.
PUMP_SLICE = 1 << 20


@dataclass
class Config:
    """The resolved command line."""

    duration_ns: int = 0  # run duration; ignored when iterations > 0
    iterations: int = 0  # per-worker count incl. warmup; 0 = duration-based
    workers_requested: int = 0  # the --goroutines value as given
    workers: int = 0  # the effective worker count
    shape: int = SHAPE_STREAM
    hash: str = ""
    mac: str = ""
    payload: int = 0  # bytes per iteration
    memlimit: int = 0  # resolved bytes; the effective limit once shaped
    memlimit_auto: bool = False  # --memlimit auto: cap only when the runtime has none
    gogc: int = 0  # 0 = leave the runtime default
    parallax: bool = True
    wrapper: bool = True

    profile: str = ""  # empty = shape-based profile pair
    key_bits: int = 0  # 0 = profile default
    nonce_bits: int = 0  # 0 = profile default
    blob_mode: int = 1  # container floor sizing mode: 1 (per-region, default) | 2 (per-container)
    chunk_size: int = 0  # 0 = profile default
    barrier_fill: int = 0  # 0 = profile default
    drbg: str = ""  # DRBG fill primitive; "" = profile default (auto tier)
    gomaxprocs: int = 0  # 0 = inherit from the environment
    rekey_every: int = 0  # per-worker iterations between rotations; 0 = never
    blob_cycle_every: int = 0  # per-worker iterations between reopens; 0 = never
    payload_mode: int = 0
    seed: int = 0  # 0 = OS CSPRNG plaintexts
    json_output: bool = False
    memprofile: str = ""  # empty = none


class RWLock:
    """A reader-preferring read-write lock.

    Python-specific. The standard library ships a mutex and a condition
    variable but no read-write lock, so the one the contract calls for
    is built from them: readers admit each other while no writer holds
    the lock, a writer waits for every reader to leave, and the whole
    waiting set is woken on release."""

    def __init__(self) -> None:
        self._cond = threading.Condition(threading.Lock())
        self._readers = 0
        self._writer = False

    def acquire_read(self) -> None:
        with self._cond:
            while self._writer:
                self._cond.wait()
            self._readers += 1

    def release_read(self) -> None:
        with self._cond:
            self._readers -= 1
            if self._readers == 0:
                self._cond.notify_all()

    def acquire_write(self) -> None:
        with self._cond:
            while self._writer or self._readers > 0:
                self._cond.wait()
            self._writer = True

    def release_write(self) -> None:
        with self._cond:
            self._writer = False
            self._cond.notify_all()


@dataclass
class Worker:
    """One worker's private state: its plaintext, its generator, its
    counters, and the error it stopped on."""

    id: int = 0
    run: Any = None
    thread: Any = None

    plaintext: bytes = b""
    payload_mode: int = 0
    seeded: bool = False
    rng: int = 0  # splitmix64 state when seeded

    # Counters read by the summary after every worker has returned.
    # Each is written by its own worker only, so the summary's read
    # after the join needs no further synchronisation.
    iters: int = 0
    bytes_enc: int = 0
    bytes_dec: int = 0
    nanos_enc: int = 0
    nanos_dec: int = 0

    failed: bool = False
    error: str = ""


@dataclass
class RunState:
    """The state every worker shares: the Pipeline handles, the
    retained blobs, the lock that keeps iterations clear of handle
    mutation, the stop request, the barriers, and the baselines the
    summary reads."""

    cfg: Config = field(default_factory=Config)

    stream_pipe: Any = None  # None unless the shape uses it
    msg_pipe: Any = None  # None unless the shape uses it
    stream_profile: str = ""
    msg_profile: str = ""

    # Handle mutation. Iterations hold the read side for their whole
    # encrypt -> decrypt -> compare; rekey and blob reopen take the
    # write side, so no cipher call is in flight while a handle's
    # keying changes or the handle itself is swapped, and no encrypt is
    # separated from its decrypt by either.
    pipe_lock: RWLock = field(default_factory=RWLock)

    # The blob Init handed out, replaced by every rekey; the input of
    # the next blob reopen. Guarded by pipe_lock.
    stream_blob: bytes = b""
    msg_blob: bytes = b""

    rekeys: int = 0
    blob_cycles: int = 0

    workers: list[Worker] = field(default_factory=list)

    # Warmup barrier: workers arrive at warmup_done after iteration 0
    # and at release once main has taken the baselines.
    warmup_done: Any = None
    release: Any = None

    # Set by the duration deadline, by a signal, or by a failing
    # worker; checked by every worker before it starts an iteration.
    stop: bool = False

    # Main waits for active to reach zero; the last returning worker
    # stamps finish_ns so elapsed excludes the waiter's wake-up
    # latency.
    done_cond: Any = None
    active: int = 0
    start_ns: int = 0
    finish_ns: int = 0

    # Baselines taken after the warmup barrier and at shutdown.
    rss_warmup: int = 0
    rss_peak: int = 0
    rss_final: int = 0
    pool_warmup: list[int] = field(default_factory=list)
    pool_steady: list[int] = field(default_factory=list)


# Serialises the line emitter below. Workers log concurrently during
# maintenance, so the text and its newline have to reach the stream as
# one write and the flush has to stay attached to it.
_LOG_LOCK = threading.Lock()


def log_line(text: str) -> None:
    """Prints one prefixed status line to stdout.

    The line is assembled with its newline and handed over in a single
    write, so a worker logging a maintenance line from another thread
    cannot land between a text and the newline that terminates it."""
    with _LOG_LOCK:
        sys.stdout.write("[loop] " + text + "\n")
        sys.stdout.flush()


def on_off(b: bool) -> str:
    return "on" if b else "off"


def policy_label(env: str | None) -> str:
    """Renders an encoder policy env value for the summary: the raw
    string when set, "default" when the shipped ladder applies."""
    if env is None:
        return "default"
    env = env.lstrip(" \t")
    return env if env else "default"


def status_detail(exc: Exception) -> str:
    """The failure detail a log line carries: the numeric status the
    binding's own surface exposes and the finished sentence the library
    left behind. Nothing is composed here — the wording arrives whole
    from the failing call."""
    status = getattr(exc, "status", None)
    message = getattr(exc, "message", None)
    if status is None or message is None:
        return str(exc)
    return f"status {int(status)}: {message}"


def worker_fail(w: Worker, text: str) -> None:
    """Records the worker's error text (first error wins) and requests a
    stop of the whole run."""
    if not w.failed:
        w.error = text
        w.failed = True
    w.run.stop = True
