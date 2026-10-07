"""The maintenance operations that mutate a live Pipeline handle
between iterations: master rotation (--rekey-every) and blob reopen
(--blob-cycle-every).
"""

from __future__ import annotations

import os

import itb3 as itb

from state import Worker, log_line, status_detail, worker_fail

# Byte length of each fresh master drawn for a rotation. Matches the
# size Init auto-generates for both the parallax and the wrapper
# master.
REKEY_MASTER_SIZE = 32


def _rekey_pipes(w: Worker, it: int) -> bool:
    """Master rotation. Rotates the parallax + wrapper masters on every
    active Pipeline under the write lock and retains the refreshed blob
    for subsequent blob reopens. Masters are drawn fresh from the OS
    CSPRNG on every rotation regardless of --seed (master rotation is
    pipeline keying, not plaintext content); a disabled layer passes no
    bytes, which Rekey ignores. The eight inner seeds and the MAC key
    are untouched by design — Rekey targets only the two outer-layer
    master secrets."""
    r = w.run
    perm = os.urandom(REKEY_MASTER_SIZE) if r.cfg.parallax else b""
    wrap = os.urandom(REKEY_MASTER_SIZE) if r.cfg.wrapper else b""

    r.pipe_lock.acquire_write()
    try:
        if r.stream_pipe is not None:
            try:
                r.stream_blob = r.stream_pipe.rekey(perm, wrap)
            except itb.ItbError as exc:
                worker_fail(
                    w,
                    f"g{w.id} iter {it}: Rekey({r.stream_profile}): {status_detail(exc)}",
                )
                return False
        if r.msg_pipe is not None:
            try:
                r.msg_blob = r.msg_pipe.rekey(perm, wrap)
            except itb.ItbError as exc:
                worker_fail(
                    w,
                    f"g{w.id} iter {it}: Rekey({r.msg_profile}): {status_detail(exc)}",
                )
                return False
        r.rekeys += 1
        n = r.rekeys
    finally:
        r.pipe_lock.release_write()
    log_line(
        f"rekey: g{w.id} iter {it} rotated parallax + wrapper masters (rekey #{n})"
    )
    return True


def _blob_cycle_pipes(w: Worker, it: int) -> bool:
    """Blob reopen. Reopens every active Pipeline from its retained blob
    under the write lock: a fresh handle is loaded from the blob, the
    running handle is freed, and the fresh one is swapped in, so every
    later iteration round-trips through seeds and masters that survived
    a blob crossing. The input is the blob Init or the latest Rekey
    handed out, not a fresh Save: that is what a receiver holds, and
    reopening from it proves the handed-out bytes rather than the live
    state. The blob carries the Pipeline's full shape, so no override
    reaches the reopen. On a Load failure the running handle stays and
    the failure aborts the run."""
    r = w.run
    r.pipe_lock.acquire_write()
    try:
        if r.stream_pipe is not None:
            try:
                fresh = itb.Pipeline.load(r.stream_blob)
            except itb.ItbError as exc:
                worker_fail(
                    w,
                    f"g{w.id} iter {it}: Load({r.stream_profile}): {status_detail(exc)}",
                )
                return False
            r.stream_pipe.free()
            r.stream_pipe = fresh
        if r.msg_pipe is not None:
            try:
                fresh = itb.Pipeline.load(r.msg_blob)
            except itb.ItbError as exc:
                worker_fail(
                    w,
                    f"g{w.id} iter {it}: Load({r.msg_profile}): {status_detail(exc)}",
                )
                return False
            r.msg_pipe.free()
            r.msg_pipe = fresh
        r.blob_cycles += 1
        n = r.blob_cycles
    finally:
        r.pipe_lock.release_write()
    log_line(f"blob-cycle: g{w.id} iter {it} reopened from session blob (cycle #{n})")
    return True


def worker_maintenance(w: Worker, it: int) -> bool:
    """Handle mutation. Runs the periodic Pipeline-mutating operations
    after a completed iteration: master rotation (--rekey-every) and
    blob reopen (--blob-cycle-every). Both intervals count per-worker
    iterations; the warmup iteration (iter 0) never triggers because the
    worker loop calls this for iter >= 1 only. Rekey rewrites the
    outer-layer keying of a live handle and a blob reopen replaces the
    handle outright; each takes the write lock, so in-flight cipher
    calls on other workers drain before anything changes and no encrypt
    is separated from its decrypt by either. Returns False after
    recording a worker error."""
    cfg = w.run.cfg
    if cfg.rekey_every > 0 and it % cfg.rekey_every == 0:
        if not _rekey_pipes(w, it):
            return False
    if cfg.blob_cycle_every > 0 and it % cfg.blob_cycle_every == 0:
        if not _blob_cycle_pipes(w, it):
            return False
    return True
