"""The final summary in both renderings, and the two measurements it
folds in that are not per-worker counters: the process resident set and
the shared library's pool counters.
"""

from __future__ import annotations

import json
import os
import sys

import itb3 as itb

from payload import payload_mode_name
from size import human_bytes, human_bytes_signed, human_duration, human_rate, mb_per_sec
from state import CONCURRENCY, SHAPE_NAMES, RunState, log_line, on_off, policy_label

# ------------------------------------------------------------------ #
# Resident set                                                        #
# ------------------------------------------------------------------ #


def read_rss() -> tuple[int, int]:
    """The process's current resident set and its high-water mark in
    bytes, from /proc/self/status (VmRSS and VmHWM, reported in kB).
    Both are zero on a platform without that file; the figures are
    informational and never enter the verdict."""
    current = 0
    peak = 0
    try:
        with open("/proc/self/status", encoding="utf-8", errors="replace") as f:
            for line in f:
                if line.startswith("VmRSS:"):
                    current = _status_kb(line)
                elif line.startswith("VmHWM:"):
                    peak = _status_kb(line)
    except OSError:
        return 0, 0
    return current, peak


def _status_kb(line: str) -> int:
    """Parses one "Vm...:   1234 kB" line of /proc/self/status into
    bytes; zero on any parse failure."""
    fields = line.split()
    if len(fields) < 2 or not fields[1].isdigit():
        return 0
    return int(fields[1]) * 1024


# ------------------------------------------------------------------ #
# Pool counters                                                       #
# ------------------------------------------------------------------ #


def pool_snapshot() -> list[int]:
    """Pool counters. The shared library keeps process-wide monotonic
    totals at every pool checkout of its cipher core: per hash-array
    tier the starter width, checkouts, constructor misses, regrow
    replacements and bytes allocated; for the scratch byte pool and the
    parallax chunk pool the checkouts, constructor misses, regrows and
    regrow bytes. Two snapshots bracketing the main loop are differenced
    into per-run hit / miss figures that tell whether a pool keeps its
    items warm between calls or evicts them across GC cycles. The slot
    layout is read from the library: slot 0 carries the tier count T,
    tier i occupies the five slots at 1 + 5*i, and the two byte pools
    occupy the eight slots at 1 + 5*T; the vector is sized from the
    binding's length query, never from a constant."""
    try:
        return itb.pool_stats()
    except itb.ItbError:
        return []


class PoolDelta:
    """The differenced pool figures of one run."""

    def __init__(self, warmup: list[int], steady: list[int]) -> None:
        self.tiers = 0
        self.starter: list[int] = []
        self.get: list[int] = []
        self.new: list[int] = []
        self.regrow: list[int] = []
        self.new_bytes: list[int] = []
        self.buf = (0, 0, 0, 0)
        self.chunk = (0, 0, 0, 0)
        if not warmup or not steady or len(steady) < 9 or len(warmup) != len(steady):
            return
        tiers = steady[0]
        if tiers < 0 or 1 + 5 * tiers + 8 > len(steady):
            return
        self.tiers = tiers
        for i in range(tiers):
            base = 1 + 5 * i
            self.starter.append(steady[base])
            self.get.append(steady[base + 1] - warmup[base + 1])
            self.new.append(steady[base + 2] - warmup[base + 2])
            self.regrow.append(steady[base + 3] - warmup[base + 3])
            self.new_bytes.append(steady[base + 4] - warmup[base + 4])
        tail = 1 + 5 * tiers
        self.buf = tuple(steady[tail + i] - warmup[tail + i] for i in range(4))
        self.chunk = tuple(steady[tail + 4 + i] - warmup[tail + 4 + i] for i in range(4))


def _miss_percent(miss: int, get: int) -> float:
    """Misses over checkouts as a percentage; zero when nothing was
    checked out."""
    if get <= 0:
        return 0.0
    return 100.0 * miss / get


def _effective_gogc(flag: int) -> int:
    """The effective GC percentage as the runtime reports it: the query
    form of the setter (a set-and-restore round trip inside the library)
    so the field is the same whether the value came from the flag, the
    environment, or the runtime default."""
    if flag > 0:
        return flag
    return int(itb.set_gc_percent(-1))


def final_summary(r: RunState, elapsed_ns: int) -> int:
    """Output contract. Both renderings are shared with the Go harness
    and every other binding's loop utility field for field: the same
    lines in the same order, the same keys in the same order, floats
    with a fixed number of decimals so the JSON is byte-identical across
    implementations. The Go harness alone adds its runtime-internal
    lines after rss: and its runtime-internal keys after
    parallax_chunk_pool; nothing here reproduces them because nothing
    they read is reachable through the C ABI."""
    cfg = r.cfg
    workers = r.workers[: cfg.workers]
    total_iters = sum(w.iters for w in workers)
    total_enc = sum(w.bytes_enc for w in workers)
    total_dec = sum(w.bytes_dec for w in workers)
    nanos_enc = sum(w.nanos_enc for w in workers)
    nanos_dec = sum(w.nanos_dec for w in workers)
    errors = [w.error for w in workers if w.failed]

    # Throughput. Per-direction throughput divides the sum of every
    # worker's wall time in that direction by the worker count — the
    # equivalent single-stream wall time under N-way concurrency — so
    # each direction reports the aggregate rate it sustained rather than
    # collapsing to combined/2 (every iteration moves equal encrypt and
    # decrypt bytes, so a total-elapsed denominator would give both
    # directions the same figure). The combined rate keeps total elapsed
    # as the one-glance overall figure.
    avg_enc = nanos_enc // cfg.workers if nanos_enc > 0 else 0
    avg_dec = nanos_dec // cfg.workers if nanos_dec > 0 else 0

    rss_delta = r.rss_final - r.rss_warmup
    rss_growth = 100.0 * rss_delta / r.rss_warmup if r.rss_warmup > 0 else 0.0

    pd = PoolDelta(r.pool_warmup, r.pool_steady)
    passed = not errors
    gomaxprocs = int(itb.set_gomaxprocs(0))
    stream_profile = r.stream_profile if r.stream_pipe is not None else ""
    msg_profile = r.msg_profile if r.msg_pipe is not None else ""

    if cfg.json_output:
        _emit_json(
            r, elapsed_ns, workers, total_iters, total_enc, total_dec, avg_enc,
            avg_dec, errors, passed, pd, rss_growth, gomaxprocs,
            stream_profile, msg_profile,
        )
        return 0 if passed else 1

    log_line("=== FINAL ===")
    log_line(f"  duration: {human_duration((elapsed_ns + 500_000) // 1_000_000 * 1_000_000)}")
    parts = " + ".join(str(w.iters) for w in workers)
    log_line(f"  iterations: {parts} = {total_iters} total")
    log_line(
        f"  throughput: encrypt {human_rate(total_enc, avg_enc)}, "
        f"decrypt {human_rate(total_dec, avg_dec)}, "
        f"combined {human_rate(total_enc + total_dec, elapsed_ns)}"
    )
    log_line(f"  bytes: {human_bytes(total_enc)} encrypted, {human_bytes(total_dec)} decrypted")
    log_line(f"  data integrity: {total_iters}/{total_iters} PASS")
    log_line(
        f"  concurrency: {CONCURRENCY}, workers {cfg.workers} "
        f"(requested {cfg.workers_requested})"
    )
    log_line(
        f"  rss: warmup {human_bytes(r.rss_warmup)}, peak {human_bytes(r.rss_peak)}, "
        f"final {human_bytes(r.rss_final)} "
        f"(delta {human_bytes_signed(rss_delta)}, {rss_growth:.1f}% growth)"
    )
    for i in range(pd.tiers):
        if pd.starter[i] == 0:
            continue
        miss = pd.new[i] + pd.regrow[i]
        log_line(
            f"  hash pool tier {i} (starter {pd.starter[i]}): get {pd.get[i]}, "
            f"miss {miss} (new {pd.new[i]} + regrow {pd.regrow[i]}), "
            f"miss {_miss_percent(miss, pd.get[i]):.2f}%, "
            f"{human_bytes(pd.new_bytes[i])} allocated"
        )
    log_line(
        f"  buf pool: get {pd.buf[0]}, regrow {pd.buf[2]} (of which fresh {pd.buf[1]}), "
        f"miss {_miss_percent(pd.buf[2], pd.buf[0]):.2f}%, {human_bytes(pd.buf[3])} regrown"
    )
    log_line(
        f"  parallax chunk pool: get {pd.chunk[0]}, regrow {pd.chunk[2]} "
        f"(of which fresh {pd.chunk[1]}), "
        f"miss {_miss_percent(pd.chunk[2], pd.chunk[0]):.2f}%, "
        f"{human_bytes(pd.chunk[3])} regrown"
    )
    if r.rekeys > 0:
        log_line(f"  rekeys: {r.rekeys}")
    if r.blob_cycles > 0:
        log_line(f"  blob cycles: {r.blob_cycles}")
    for text in errors:
        log_line(f"  ERROR: {text}")
    if passed:
        log_line("  verdict: PASS")
        return 0
    log_line(f"  verdict: FAIL (errors={len(errors)})")
    return 1


def _js(s: str) -> str:
    """Renders s as a JSON string literal with the escapes JSON
    requires."""
    return json.dumps(s, ensure_ascii=False)


def _emit_json(
    r: RunState, elapsed_ns: int, workers: list, total_iters: int, total_enc: int,
    total_dec: int, avg_enc: int, avg_dec: int, errors: list[str], passed: bool,
    pd: PoolDelta, rss_growth: float, gomaxprocs: int,
    stream_profile: str, msg_profile: str,
) -> None:
    """One compact object on one line, keys in the contract's order,
    floats with the contract's decimal counts and never in exponent
    form."""
    cfg = r.cfg
    tiers = [
        '{"tier":%d,"starter":%d,"get":%d,"new":%d,"regrow":%d,"new_bytes":%d,'
        '"miss_percent":%.2f}'
        % (
            i, pd.starter[i], pd.get[i], pd.new[i], pd.regrow[i], pd.new_bytes[i],
            _miss_percent(pd.new[i] + pd.regrow[i], pd.get[i]),
        )
        for i in range(pd.tiers)
        if pd.starter[i] != 0
    ]
    out = (
        '{"duration_seconds":%.3f' % (elapsed_ns / 1e9)
        + ',"iterations":%d' % total_iters
        + ',"per_worker_iterations":[%s]' % ",".join(str(w.iters) for w in workers)
        + ',"bytes_encrypted":%d' % total_enc
        + ',"bytes_decrypted":%d' % total_dec
        + ',"encrypt_mb_per_sec":%.1f' % mb_per_sec(total_enc, avg_enc)
        + ',"decrypt_mb_per_sec":%.1f' % mb_per_sec(total_dec, avg_dec)
        + ',"combined_mb_per_sec":%.1f' % mb_per_sec(total_enc + total_dec, elapsed_ns)
        + ',"rekeys":%d' % r.rekeys
        + ',"blob_cycles":%d' % r.blob_cycles
        + ',"worker_errors":[%s]' % ",".join(_js(e) for e in errors)
        + ',"verdict":"%s"' % ("PASS" if passed else "FAIL")
        + ',"shape":"%s"' % SHAPE_NAMES[cfg.shape]
        + ',"stream_profile":%s' % _js(stream_profile)
        + ',"message_profile":%s' % _js(msg_profile)
        + ',"hash":%s' % _js(cfg.hash)
        + ',"mac":%s' % _js(cfg.mac)
        + ',"payload_bytes":%d' % cfg.payload
        + ',"payload_mode":"%s"' % payload_mode_name(cfg.payload_mode)
        + ',"seed":%d' % cfg.seed
        + ',"key_bits":%d' % cfg.key_bits
        + ',"nonce_bits":%d' % cfg.nonce_bits
        + ',"blob_mode":%d' % cfg.blob_mode
        + ',"drbg":%s' % _js(cfg.drbg)
        + ',"drbg_auto_tier":%s' % _js(itb.drbg_auto_tier())
        + ',"chunk_size_bytes":%d' % cfg.chunk_size
        + ',"barrier_fill":%d' % cfg.barrier_fill
        + ',"parallax":"%s"' % on_off(cfg.parallax)
        + ',"wrapper":"%s"' % on_off(cfg.wrapper)
        + ',"goroutines_requested":%d' % cfg.workers_requested
        + ',"goroutines":%d' % cfg.workers
        + ',"concurrency":"%s"' % CONCURRENCY
        + ',"gogc":"%d"' % _effective_gogc(cfg.gogc)
        + ',"memlimit_bytes":%d' % cfg.memlimit
        + ',"gomaxprocs":%d' % gomaxprocs
        + ',"microbatch_tiers":%s' % _js(policy_label(os.environ.get("ITB_MICROBATCH_TIERS")))
        + ',"hashpool_starters":%s' % _js(policy_label(os.environ.get("ITB_HASHPOOL_STARTERS")))
        + ',"rss_warmup_bytes":%d' % r.rss_warmup
        + ',"rss_peak_bytes":%d' % r.rss_peak
        + ',"rss_final_bytes":%d' % r.rss_final
        + ',"rss_growth_percent":%.2f' % rss_growth
        + ',"hash_pool_tiers":[%s]' % ",".join(tiers)
        + ',"buf_pool":{"get":%d,"new":%d,"regrow":%d,"regrow_bytes":%d,"miss_percent":%.2f}'
        % (pd.buf[0], pd.buf[1], pd.buf[2], pd.buf[3], _miss_percent(pd.buf[2], pd.buf[0]))
        + ',"parallax_chunk_pool":{"get":%d,"new":%d,"regrow":%d,"regrow_bytes":%d,'
        '"miss_percent":%.2f}'
        % (pd.chunk[0], pd.chunk[1], pd.chunk[2], pd.chunk[3],
           _miss_percent(pd.chunk[2], pd.chunk[0]))
        + "}\n"
    )
    sys.stdout.write(out)
    sys.stdout.flush()
