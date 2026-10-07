"""The worker: its thread body (one warmup iteration, the warmup
barrier, the main loop), one iteration, the session pump loop the
stream shape drives, and the round-trip comparison that decides between
a worker error and a data mismatch.
"""

from __future__ import annotations

import os
import sys

import itb3 as itb

from ops import worker_maintenance
from payload import ROTATING, fill_payload
from size import now_ns
from state import (
    PUMP_SLICE,
    SHAPE_BOTH,
    SHAPE_MESSAGE,
    SHAPE_NAMES,
    SHAPE_STREAM,
    SHAPE_STREAM_ONE_SHOT,
    RunState,
    Worker,
    status_detail,
    worker_fail,
)


def shape_name(shape: int) -> str:
    return SHAPE_NAMES[shape]


def parse_shape(s: str) -> int | None:
    try:
        return SHAPE_NAMES.index(s)
    except ValueError:
        return None


def _pump(pipe: itb.Pipeline, encrypt: bool, src: bytes) -> bytes:
    """Pump loop. The Go harness hands ITB an io.Reader / io.Writer pair
    and ITB drives the chunk loop internally; the C ABI has no reader /
    writer entry, so the caller drives it: open a session, feed slices
    of at most 1 MiB, drain whatever the session has produced after
    every write (a read before end never blocks), end, then drain until
    the session reports finished (after end, a read on an empty spool
    blocks until the terminal bytes arrive). The loop is written here
    rather than delegated to the binding's pump convenience so it stands
    in the utility, at the same place, in every language."""
    session = pipe.encrypt_stream() if encrypt else pipe.decrypt_stream()
    try:
        parts: list[bytes] = []
        off = 0
        total = len(src)
        while off < total:
            end = min(off + PUMP_SLICE, total)
            session.write(src[off:end])
            off = end
            while True:
                chunk, _ = session.read(PUMP_SLICE)
                if not chunk:
                    break
                parts.append(chunk)
        session.end()
        while True:
            chunk, finished = session.read(PUMP_SLICE)
            if chunk:
                parts.append(chunk)
            if finished:
                break
        return b"".join(parts)
    finally:
        session.free()


def _first_difference(a: bytes, b: bytes) -> int:
    """First offset at which a and b differ; the shorter length when one
    is a prefix of the other."""
    n = min(len(a), len(b))
    for i in range(n):
        if a[i] != b[i]:
            return i
    return n


def _hex_window(buf: bytes, off: int) -> str:
    """Up to 16 bytes of buf from off as lowercase hex, or "-" when buf
    has no bytes there."""
    if off >= len(buf):
        return "-"
    return buf[off : off + 16].hex()


def _cipher_fail(w: Worker, it: int, shape: int, direction: str, exc: Exception) -> None:
    """Records a worker error for a failed cipher call."""
    worker_fail(
        w,
        f"g{w.id} iter {it} shape={shape_name(shape)}: {direction}: {status_detail(exc)}",
    )


def iterate(w: Worker, it: int) -> bool:
    """One iteration. In order: refill the plaintext under rotating
    mode; take the read lock; pick the surface; encrypt (timed); decrypt
    (timed); compare the round-trip with the plaintext; bump the
    counters; release the lock. The whole round-trip runs under the read
    lock so handle-mutating maintenance (rekey, blob reopen) never lands
    between an encrypt and its matching decrypt — maintenance runs after
    this returns, from the worker loop. Returns False after recording
    the worker error."""
    r = w.run

    if w.payload_mode == ROTATING:
        w.plaintext, w.rng = fill_payload(ROTATING, w.seeded, w.rng, len(w.plaintext))

    r.pipe_lock.acquire_read()
    try:
        # Shape dispatch. message is one whole-buffer call on the Single
        # Message Pipeline; stream_one_shot is one whole-buffer call on
        # the streaming Pipeline (the C ABI's ITB_Triple_EncryptStream,
        # which routes to the same one-shot stream entry the Go
        # harness calls by name); stream opens a session on the same
        # streaming Pipeline and drives the chunk loop from here. Under
        # both the three rotate by iteration number so the session path
        # and the whole-buffer path alternate on one handle inside every
        # worker — the cross-path state-reuse hazard this harness exists
        # to catch.
        shape = r.cfg.shape
        if shape == SHAPE_BOTH:
            shape = (SHAPE_STREAM, SHAPE_MESSAGE, SHAPE_STREAM_ONE_SHOT)[it % 3]

        want = w.plaintext
        if shape == SHAPE_STREAM:
            t0 = now_ns()
            try:
                wire = _pump(r.stream_pipe, True, want)
            except itb.ItbError as exc:
                _cipher_fail(w, it, shape, "encrypt", exc)
                return False
            w.nanos_enc += now_ns() - t0
            t0 = now_ns()
            try:
                got = _pump(r.stream_pipe, False, wire)
            except itb.ItbError as exc:
                _cipher_fail(w, it, shape, "decrypt", exc)
                return False
            w.nanos_dec += now_ns() - t0
        else:
            if shape == SHAPE_MESSAGE:
                pipe = r.msg_pipe
                enc, dec = pipe.encrypt_message, pipe.decrypt_message
            else:
                pipe = r.stream_pipe
                enc, dec = pipe.encrypt_stream_one_shot, pipe.decrypt_stream_one_shot
            t0 = now_ns()
            try:
                wire = enc(want)
            except itb.ItbError as exc:
                _cipher_fail(w, it, shape, "encrypt", exc)
                return False
            w.nanos_enc += now_ns() - t0
            t0 = now_ns()
            try:
                got = dec(wire)
            except itb.ItbError as exc:
                _cipher_fail(w, it, shape, "decrypt", exc)
                return False
            w.nanos_dec += now_ns() - t0

        # Failure model. A cipher call that returns a non-OK status is a
        # worker error: it is recorded, the run is asked to stop, the
        # other workers finish their in-flight iteration, and the error
        # is listed in the summary with the FAIL verdict. A round-trip
        # that returns OK with different bytes is a data mismatch: the
        # process terminates here, without summary or cleanup, because
        # the Pipeline state that produced the wrong bytes is the
        # evidence and nothing that runs afterwards may touch it.
        if got != want:
            off = _first_difference(want, got)
            sys.stderr.write(
                f"loop: DATA MISMATCH g{w.id} iter {it} shape={shape_name(shape)}: "
                f"want {len(want)} bytes, got {len(got)} bytes, "
                f"first difference at offset {off}: "
                f"want {_hex_window(want, off)} got {_hex_window(got, off)}\n"
            )
            sys.stderr.flush()
            # Python-specific. os._exit leaves the process on the spot
            # without unwinding, running an atexit hook or flushing
            # another thread's buffered output, which is what "no
            # summary, no cleanup" asks for; sys.exit only raises in
            # this thread and the run would carry on around it.
            os._exit(3)

        w.iters += 1
        w.bytes_enc += len(want)
        w.bytes_dec += len(got)
        return True
    finally:
        r.pipe_lock.release_read()


def worker_main(w: Worker) -> None:
    """The worker thread body: one warmup iteration, the warmup barrier,
    then the main loop until a stop is requested or the fixed per-worker
    iteration budget (warmup included) is spent. A failing warmup still
    passes both barriers so the launcher never waits on a worker that
    has already given up."""
    r = w.run
    try:
        # Warmup iteration — counted in the totals; its completion feeds
        # the post-warmup baselines. Anything that escapes an iteration
        # other than a library status becomes a worker error rather than
        # a lost thread: the barriers below have a fixed party count, so
        # a worker that unwound past them would leave the launcher
        # waiting for a rendezvous that can no longer happen.
        try:
            ok = iterate(w, 0)
        except BaseException as exc:  # noqa: BLE001 — a lost worker hangs the run
            worker_fail(w, f"g{w.id} iter 0: {type(exc).__name__}: {exc}")
            ok = False
        r.warmup_done.wait()
        r.release.wait()
        if not ok:
            return

        it = 1
        while True:
            if r.cfg.iterations > 0 and it >= r.cfg.iterations:
                break
            if r.stop:
                break
            try:
                if not iterate(w, it):
                    break
                if not worker_maintenance(w, it):
                    break
            except BaseException as exc:  # noqa: BLE001 — see above
                worker_fail(w, f"g{w.id} iter {it}: {type(exc).__name__}: {exc}")
                break
            it += 1
    finally:
        _worker_done(r)


def _worker_done(r: RunState) -> None:
    """Marks this worker returned; the last one to return stamps the
    finish instant and wakes main."""
    with r.done_cond:
        r.active -= 1
        if r.active == 0:
            r.finish_ns = now_ns()
            r.done_cond.notify_all()
