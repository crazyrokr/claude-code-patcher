"""Automatic oracle-verified binding for a build that has no registry entry.

The pipeline (every step a blackhole measurement, never a guess).
Independent probes run concurrently - every probe invocation owns its
endpoint port and working directory (run_probe.sh); the sequential chain
only keeps the measurements that depend on earlier results:
  1. baseline+all  probe the unpatched binary (the two 60 s classifier
                  waits must be observable, ~121 s total) and the all-sites
                  artifact (every int32 60000 code site in the back half ->
                  20000; if the wait does not move, the driver is not an
                  int32 60000 slot here) - concurrently
  2. bisection     halve the site set until a single site still moves both
                  waits; both halves of a round are measured concurrently,
                  and the half that is no longer decisive is canceled as
                  soon as the other half's verdict decides the round (an
                  effective half alone decides; a no-effect or crashed half
                  does not - a canceled run is not a measurement, so a
                  round costs the effective half's ~41 s, not the
                  no-effect half's ~121 s); a half that crashes (a rewritten
                  slot that is not a plain int32 constant) is kept only
                  while the other half is measured no-effect, halved until
                  the driver is isolated or the contradiction refuses the
                  binding
  3. ceiling       the nearest int32 120000 sites are all probed
                  concurrently as the wait ceiling (wait =
                  min(ceiling, driver)): the nearest one that lets a 130000
                  driver value produce two 130 s waits is the ceiling
  4. boundary      with the ceiling at INT32_MAX, probe driver values: if
                  INT32_MAX still waits, that is the target; otherwise all
                  coarse values are probed concurrently (a signal that is
                  not monotone in value refuses instead of guessing) and
                  sequential bisection finds the largest measured waiting
                  value (the 217M build caps waits below INT32_MAX)
  5. final         the recorded targets (driver -> max working value,
                  ceiling -> INT32_MAX) must still wait at the 150 s probe cap
  6. registry      the entry (key = the binary's file name; matching is by
                  size, as always) is written to verified_sites.json

Generic over versions: the target binary comes from --binary, never from a
hardcoded file name. Probe harness: any script with the run_probe.sh
contract (1: binary, 2: label, 3: timeout in seconds; prints
" label rc=N elapsed=Xs"; an optional 4th argument is an early status
check point, used by patch.sh --fast-verify); override with --probe (or
CLASSIFIER_PROBE_SCRIPT through patch.sh). Wall time: ~17 min when
INT32_MAX still waits, up to ~50 min when the build caps waits below it
(the boundary bisection is inherently sequential).
"""

import argparse
import hashlib
import json
import os
import re
import struct
import subprocess
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor

INT32_MAX = 2147483647  # largest value a 4-byte little-endian int32 slot holds

# Measured signal model (baseline ~121 s = 2 x 60 s waits + ~1.5 s overhead;
# a rewritten driver at 20000 drops both waits to ~41 s).
BASELINE_WINDOW = (100, 140)   # the unpatched baseline must land here
EFFECTIVE_MAX_S = 90           # below this, the waits moved to ~20 s each
NO_EFFECT_MAX_S = 145          # at or below this, the waits did not move
CEILING_MIN_S = 250            # two 130 s waits (~261.5 s): the ceiling moved
NOT_CEILING_MIN_S = 225        # two 120 s waits (~241.5 s): still clamped
IMMEDIATE_MAX_S = 30           # a zero-wait run completes in ~1-2 s
CANCEL_GRACE_S = 30           # how long a canceled probe may take to stop
                              # before the binder moves on (the probe script
                              # exits promptly on TERM)

DRIVER_ROLE = ("per-attempt classifier wall-clock base "
               "(JZe in Din(e)=min(z9, JZe+n*1e4)); drives both classifier attempts")
CAP_ROLE = ("per-attempt classifier wait ceiling "
            "(z9 in Din(e)=min(z9, JZe+n*1e4)); clamps the base site to 120000 ms")

COARSE_BOUNDARY_VALUES = (1000000, 16777216, 268435456, 536870912, 1073741824)
PROBE_CAP_S = 150  # the end-to-end test's cap: a run killed at this point
                   # (rc=124) is still inside the classifier wait, so the
                   # recorded targets really hold

EVIDENCE_HARNESS = ("tools/binder/run_probe.sh + "
                   "fake_endpoint.py (BLACKHOLE=1, marker-based "
                   "classifier blackhole; wait boundaries read from "
                   "the probe rc/elapsed)")
EVIDENCE_BOUNDARY_METHOD = ("150 s run-timeout probes (ceiling at INT32_MAX): "
                           "rc=124 (killed still waiting) = the value waits; "
                           "rc=0 in ~1-2 s = zero wait")

RESULT_RE = re.compile(r" rc=(\d+) elapsed=([0-9]+(?:\.[0-9]+)?)s")


class BindRefused(Exception):
    """A measured signal that does not match the model; the no-guess invariant
    blocks the binding (no registry write)."""


def rec_dir() -> str:
    return os.path.dirname(os.path.abspath(__file__))


def root() -> str:
    return os.path.dirname(os.path.dirname(rec_dir()))


def default_registry_path() -> str:
    return os.path.join(root(), "verified_sites.json")


def default_probe_path() -> str:
    return os.path.join(rec_dir(), "run_probe.sh")


def text_density(data: bytes, off: int, radius: int = 32) -> float:
    lo = max(0, off - radius)
    hi = min(len(data), off + 4 + radius)
    seg = data[lo:hi]
    printable = sum(
        1 for b in seg if 0x20 <= b < 0x7f or b in (0x09, 0x0a, 0x0d)
    )
    return printable / len(seg) if seg else 0.0


def find_sites(data: bytes, value: int, win_lo: int, win_hi: int) -> list:
    """4-aligned int32 slots holding `value` in [win_lo, win_hi) whose
    64-byte neighborhood reads as code (coincidental patterns inside embedded
    source or string pools are not code sites)."""
    needle = struct.pack("<i", value)
    sites, off = [], 0
    while True:
        j = data.find(needle, off)
        if j == -1 or j >= win_hi:
            break
        if j >= win_lo and j % 4 == 0 and text_density(data, j) <= 0.5:
            sites.append(j)
        off = j + 1
    return sites


def parse_probe_result(stdout: str):
    """The last ' rc=N elapsed=Xs' result line -> (rc, elapsed); None when the
    harness produced no result (the artifact did not run)."""
    matches = list(RESULT_RE.finditer(stdout))
    if not matches:
        return None
    match = matches[-1]
    return int(match.group(1)), float(match.group(2))


def probe_via_script(probe_path: str):
    """The default probe: `bash <probe> <artifact> <label> <timeout>` with the
    run_probe.sh contract; every invocation owns its endpoint port and
    working directory, so independent probes may run concurrently (the
    binder relies on that for its parallel phases). A probe started with a
    cancel event may be stopped from another thread: when the event is set,
    the script is TERMed (it stops its run and endpoint and exits without a
    result line - a canceled run is not a measurement); a run that finished
    before the cancel still yields its measured result."""
    def probe(artifact: str, label: str, timeout: int,
              cancel: threading.Event = None):
        try:
            proc = subprocess.Popen(
                ["bash", probe_path, artifact, label, str(timeout)],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
            )
        except OSError:
            return None
        if cancel is not None:
            def watch():
                if cancel.wait(timeout + 120) and proc.poll() is None:
                    proc.terminate()
            threading.Thread(target=watch, daemon=True).start()
        try:
            out, err = proc.communicate(timeout=timeout + 120)
        except (subprocess.TimeoutExpired, OSError):
            proc.kill()
            try:
                proc.communicate(timeout=30)
            except OSError:
                pass
            return None
        return parse_probe_result(out + "\n" + err)

    return probe


def fmt(el):
    return "?" if el is None else f"{el:.1f}s"


def write_registry_doc(path: str, doc: dict) -> None:
    """Write the registry in the shape the binders have always written
    (2-space indent, trailing newline), so a re-run of the CI recorder
    is byte-identical on an already-bound build."""
    with open(path, "w", encoding="utf-8") as f:
        json.dump(doc, f, indent=2)
        f.write("\n")


class _ProbeRunner:
    """The probe machinery shared by the binder and the candidate
    fallback. Every probe artifact is a full copy of the binary with the
    candidate changes applied (a slot that no longer holds a recorded
    site value refuses - the build drifted since the scan); every probe
    invocation owns its endpoint port and working directory (the probe
    script's contract), so independent probes may run concurrently."""

    def __init__(self, binary_path: str, data: bytes, bin_dir: str,
                 base: str, probe, made: list):
        self.binary_path = binary_path
        self.data = data
        self.bin_dir = bin_dir
        self.base = base
        self.probe = probe
        self.made = made

    def artifact(self, label: str, changes: dict) -> str:
        buf = bytearray(self.data)
        for off, new in sorted(changes.items()):
            cur = struct.unpack_from("<i", buf, off)[0]
            if cur not in (60000, 120000):
                raise BindRefused(
                    f"slot @{off} holds {cur}, not a recorded site value; "
                    "the build drifted since the scan, refusing"
                )
            buf[off:off + 4] = struct.pack("<i", new)
        path = os.path.join(self.bin_dir, f"{self.base}.bind_{label}")
        with open(path, "wb") as f:
            f.write(bytes(buf))
        os.chmod(path, 0o755)
        self.made.append(path)
        return path

    def run_jobs(self, jobs):
        """Probe several (label, changes, timeout) jobs concurrently and
        return the (rc, elapsed) results in job order. Each job owns its
        .bind_<label> artifact and its probe owns its endpoint port, so
        the jobs share no state; a slot-drift refusal in any artifact
        raises before the probes start. (Bisection rounds instead use
        decided_round: the same concurrency, plus the cancel-on-decision.)
        """
        prepared = []
        for label, changes, timeout in jobs:
            art = self.artifact(label, changes) if changes else self.binary_path
            prepared.append((label, art, timeout))
        if len(prepared) == 1:
            label, art, timeout = prepared[0]
            results = [self.probe(art, label, timeout)]
        else:
            with ThreadPoolExecutor(max_workers=len(prepared)) as pool:
                futures = [
                    pool.submit(self.probe, art, label, timeout)
                    for label, art, timeout in prepared
                ]
                results = [f.result() for f in futures]
        out = []
        for (label, _art, _t), res in zip(prepared, results):
            rc, elapsed = res if res is not None else (None, None)
            print(f"  probe {label}: rc={rc} elapsed={fmt(elapsed)}")
            out.append((rc, elapsed))
        return out

    def run(self, label: str, changes: dict, timeout: int):
        return self.run_jobs([(label, changes, timeout)])[0]

    def decided_round(self, a_label, a_changes, b_label, b_changes, timeout):
        """Probe both halves of a bisection round concurrently and cancel
        the half that is no longer decisive as soon as the other half's
        verdict decides the round: an 'effective' half decides alone (the
        measured model has exactly one effective half), a 'no_effect' or
        crashed half does not, so it is waited out (its result stays a
        measurement). Returns (res_a, res_b, canceled_a, canceled_b); each
        result is (rc, elapsed) when the half was measured, (None, None)
        when its probe was canceled or produced no result before finishing
        (a canceled run is not a measurement)."""
        art_a = self.artifact(a_label, a_changes)
        art_b = self.artifact(b_label, b_changes)
        cancel_a, cancel_b = threading.Event(), threading.Event()
        box = {}
        lock = threading.Lock()
        first = threading.Event()
        first_key = []

        def run_half(key, art, label, cancel):
            try:
                box[key] = self.probe(art, label, timeout, cancel)
            except Exception:
                box[key] = None
            with lock:
                if not first_key:
                    first_key.append(key)
                first.set()

        ta = threading.Thread(target=run_half,
                              args=("a", art_a, a_label, cancel_a),
                              daemon=True)
        tb = threading.Thread(target=run_half,
                              args=("b", art_b, b_label, cancel_b),
                              daemon=True)
        ta.start()
        tb.start()
        first.wait()
        with lock:
            first_res = box[first_key[0]]
            first_was_a = first_key[0] == "a"
        if first_res is not None and \
                classify(first_res[0], first_res[1]) == "effective":
            (cancel_b if first_was_a else cancel_a).set()
        ta.join(CANCEL_GRACE_S)
        tb.join(CANCEL_GRACE_S)
        norm = lambda r: (None, None) if r is None else r
        return (norm(box.get("a")), norm(box.get("b")),
                cancel_a.is_set(), cancel_b.is_set())


def measure_ceiling(runner: _ProbeRunner, driver: int, sites120: list,
                    nearest: int = 5):
    """Binder stage 4, as a reusable step: the nearest `nearest` 120000
    sites are all probed concurrently as the wait ceiling (driver=130000,
    each cap=200000, 300 s cap) and evaluated in proximity order: the
    first cap that lets the 130000 driver produce two 130 s waits
    (elapsed >= CEILING_MIN_S) is the ceiling (wait = min(ceiling,
    driver)). Returns (ceiling, log); raises BindRefused when none of the
    nearest caps clamps the wait or on a signal that does not match the
    measured model (the caller decides what a refusal means: the binder
    refuses the binding, the candidate fallback tries the next value)."""
    caps_by_distance = sorted(sites120, key=lambda o: abs(o - driver))[:max(1, nearest)]
    log = []
    results = runner.run_jobs([
        (f"cap{i}", {driver: 130000, cap: 200000}, 300)
        for i, cap in enumerate(caps_by_distance)
    ])
    for i, (cap, (rc, el)) in enumerate(zip(caps_by_distance, results)):
        if rc == 0 and el is not None and el >= CEILING_MIN_S:
            log.append(
                f"driver @{driver} -> 130000 with 120000@{cap} -> 200000: "
                f"{el:.1f} s (two 130.000 s waits): the ceiling site is "
                f"@{cap} (+{abs(cap - driver)} B from the driver, the "
                f"nearest 120000 matches the source var table JZe=60000,z9=120000)"
            )
            return cap, log
        if rc == 0 and el is not None and el >= NOT_CEILING_MIN_S:
            log.append(
                f"driver -> 130000 with 120000@{cap} -> 200000: {el:.1f} s "
                "(still clamped at 120 s): not the ceiling"
            )
            continue
        raise BindRefused(f"cap probe {i}: rc={rc} elapsed={fmt(el)}; unexpected signal")
    raise BindRefused(
        f"none of the {len(caps_by_distance)} nearest 120000 sites clamps the "
        "wait; the ceiling is not an int32 120000 slot, refusing to guess"
    )


def measure_boundary(runner: _ProbeRunner, driver: int, ceiling: int,
                     driver_values: dict):
    """Binder stage 5, as a reusable step: with the ceiling at INT32_MAX,
    find the largest driver value that still waits at the 150 s end-to-end
    test (PROBE_CAP_S): INT32_MAX first - if it still waits (rc=124), it
    is the target; otherwise all coarse values are probed concurrently
    (a signal that is not monotone in value refuses instead of guessing),
    sequential bisection brackets the boundary, and a final probe at the
    recorded max working value must still wait (rc=124) or the
    measurement refuses. Every probe result lands in driver_values
    (evidence); returns (max_working, boundary_ms)."""
    def boundary_probe(value: int, label: str) -> str:
        rc, el = runner.run(label, {driver: value, ceiling: INT32_MAX}, PROBE_CAP_S)
        if rc == 124:
            return "waiting"
        if rc == 0 and el is not None and el < IMMEDIATE_MAX_S:
            return "immediate"
        raise BindRefused(
            f"boundary probe {value}: rc={rc} elapsed={fmt(el)}; neither "
            "a wait nor an immediate exit, refusing"
        )

    verdict = boundary_probe(INT32_MAX, "bmax")
    driver_values[str(INT32_MAX)] = verdict
    if verdict == "waiting":
        return INT32_MAX, ("no cap below INT32_MAX observed; INT32_MAX "
                           "(~24.8 days) still waits")
    # 60000 waits (the measured baseline); INT32_MAX is immediate.
    lo, hi = 60000, INT32_MAX
    coarse = [v for v in COARSE_BOUNDARY_VALUES if lo < v < hi]
    coarse_results = runner.run_jobs([
        (f"bnd{len(driver_values) + i}", {driver: v, ceiling: INT32_MAX}, PROBE_CAP_S)
        for i, v in enumerate(coarse)
    ])
    for v, (rc, el) in zip(coarse, coarse_results):
        if rc == 124:
            vverdict = "waiting"
        elif rc == 0 and el is not None and el < IMMEDIATE_MAX_S:
            vverdict = "immediate"
        else:
            raise BindRefused(
                f"boundary probe {v}: rc={rc} elapsed={fmt(el)}; "
                "neither a wait nor an immediate exit, refusing"
            )
        driver_values[str(v)] = vverdict
    waiting_values = [v for v in coarse if driver_values[str(v)] == "waiting"]
    immediate_values = [v for v in coarse
                        if driver_values[str(v)] == "immediate"]
    if waiting_values and immediate_values and \
            max(waiting_values) >= min(immediate_values):
        raise BindRefused(
            f"boundary signal not monotone: {max(waiting_values):,} ms "
            f"waits while {min(immediate_values):,} ms does not; the "
            "measured model is violated, refusing to guess"
        )
    for v in coarse:
        if not lo < v < hi:
            continue
        lo, hi = (v, hi) if driver_values[str(v)] == "waiting" else (lo, v)
    while hi - lo > 1:
        mid = (lo + hi) // 2
        verdict = boundary_probe(mid, f"bnd{len(driver_values)}")
        driver_values[str(mid)] = verdict
        lo, hi = (mid, hi) if verdict == "waiting" else (lo, mid)
    max_working = lo
    boundary_ms = (f"in ({lo}, {hi}) ms; values at or above ~{hi} "
                   "produce a zero wait on this build")
    rc, el = runner.run("final", {driver: max_working, ceiling: INT32_MAX}, PROBE_CAP_S)
    if rc != 124:
        raise BindRefused(
            f"final probe: rc={rc} elapsed={fmt(el)}; the recorded "
            "max working value does not actually wait, refusing"
        )
    return max_working, boundary_ms


def classify(rc, elapsed) -> str:
    """effective / no_effect / crash, from the measured signal model."""
    if rc is None or elapsed is None or rc != 0:
        return "crash"
    if elapsed < EFFECTIVE_MAX_S:
        return "effective"
    if elapsed <= NO_EFFECT_MAX_S:
        return "no_effect"
    return "crash"


def load_registry_doc(path: str) -> dict:
    try:
        with open(path, "r", encoding="utf-8") as f:
            doc = json.load(f)
    except FileNotFoundError:
        return {}
    if not isinstance(doc, dict):
        raise ValueError("registry: top level must be an object")
    return doc


def bind(binary_path: str, registry_path: str, probe, nearest: int = 5,
         state: dict = None) -> bool:
    """Run the binding pipeline; return True when the registry now holds a
    verified entry for this exact binary (recorded now, or already present),
    False when the no-guess invariant refuses (no registry write).

    `state`, when given, records the measured facts as they happen
    (sha256, size, sites60, sites120, baseline_ok, driver, ceiling,
    max_working, recorded) - the CI end-to-end gate and the candidate
    fallback (bind_candidates) consume them, and everything measured before
    a refusal is still reported."""
    binary_path = os.path.abspath(binary_path)
    base = os.path.basename(binary_path)
    bin_dir = os.path.dirname(binary_path)
    with open(binary_path, "rb") as f:
        data = f.read()
    size = len(data)
    win_lo, win_hi = size // 2, size
    made = []
    runner = _ProbeRunner(binary_path, data, bin_dir, base, probe, made)
    sha256 = hashlib.sha256(data).hexdigest()
    if state is not None:
        state.update(sha256=sha256, size=size, recorded=False)

    try:
        sites60 = find_sites(data, 60000, win_lo, win_hi)
        sites120 = find_sites(data, 120000, win_lo, win_hi)
        if state is not None:
            state.update(sites60=list(sites60), sites120=list(sites120))
        print(f"{base} size={size:,} window=[{win_lo:,}, {size:,}) "
              f"int32 60000 code sites: {len(sites60)}, "
              f"120000 code sites: {len(sites120)}")
        if not sites60:
            raise BindRefused(
                "no int32 60000 code sites in the window; the wait driver "
                "cannot be an int32 60000 slot on this build"
            )
        if not sites120:
            raise BindRefused(
                "no int32 120000 code sites in the window; no ceiling "
                "candidate to measure against"
            )

        doc = load_registry_doc(registry_path)
        existing = doc.get(base)
        if existing is not None:
            if existing.get("size") == size:
                print(f"already bound: registry entry {base!r} "
                      f"(size {size:,}); nothing to do")
                return True
            raise BindRefused(
                f"registry key {base!r} is taken by a different-size build "
                f"(size {existing.get('size')}); rename the binary or pass a "
                "different --registry"
            )

        # 1+2. baseline (the unpatched binary: the two 60 s waits must be
        # observable) and all-sites (every 60000 site -> 20000: at least
        # one driver site in the window must move the wait) - independent
        # probes, measured concurrently.
        (base_rc, base_el), (all_rc, all_el) = runner.run_jobs([
            ("base", None, 300),
            ("all", {s: 20000 for s in sites60}, 300),
        ])
        if base_rc is None:
            raise BindRefused(
                "baseline probe produced no result line (the binary does not "
                "run in the harness)"
            )
        if base_rc != 0 or not (BASELINE_WINDOW[0] <= base_el <= BASELINE_WINDOW[1]):
            raise BindRefused(
                f"baseline probe: rc={base_rc} elapsed={base_el:.1f}s; the two "
                "60 s classifier waits are not observable (expected ~121 s), "
                "refusing to bind blind"
            )
        if state is not None:
            state.update(baseline_ok=True, baseline_elapsed_s=round(base_el, 1))
        if classify(all_rc, all_el) != "effective":
            raise BindRefused(
                f"all {len(sites60)} 60000 sites -> {all_el:.1f}s rc={all_rc}: "
                "the wait did not move; the driver is not an int32 60000 "
                "slot in the window"
            )

        # 3. bisection: isolate the single site that moves both waits. Both
        # halves of a round are independent probes (measured concurrently);
        # the half that is no longer decisive is canceled as soon as the
        # other half's verdict decides the round (an 'effective' half alone
        # decides; a 'no_effect' or crashed half does not), so a round costs
        # the effective half's ~41 s, not the no-effect half's ~121 s. The
        # decision table is the sequential one.
        bisect_log = [f"all {len(sites60)} sites -> {all_el:.1f} s "
                      "(both waits moved to ~20.000 s each)"]
        cand = list(range(len(sites60)))
        single_el = all_el
        round_no = 0

        def half_line(label, idx, res, verdict, canceled):
            if res[0] is None:
                state = ("canceled (not measured)" if canceled
                         else "no result (not measured)")
                return f"{label} sites {idx[0]}-{idx[-1]} ({len(idx)}) " \
                       f"-> {state}"
            return f"{label} sites {idx[0]}-{idx[-1]} ({len(idx)}) " \
                   f"-> {fmt(res[1])} ({verdict})"

        while len(cand) > 1:
            mid = len(cand) // 2
            a_idx, b_idx = cand[:mid], cand[mid:]
            (rc, el), (rc_b, el_b), ca, cb = runner.decided_round(
                f"bis{round_no}a", {sites60[i]: 20000 for i in a_idx},
                f"bis{round_no}b", {sites60[i]: 20000 for i in b_idx},
                300)
            verdict = classify(rc, el)
            verdict_b = classify(rc_b, el_b)
            for label, res, canceled in (
                    (f"bis{round_no}a", (rc, el), ca),
                    (f"bis{round_no}b", (rc_b, el_b), cb)):
                if res[0] is None:
                    print(f"  probe {label}: "
                          f"{'canceled' if canceled else 'no result'} "
                          f"(not measured)")
                else:
                    print(f"  probe {label}: rc={res[0]} elapsed={fmt(res[1])}")
            bisect_log.append(half_line(f"bis{round_no}a", a_idx, (rc, el),
                                        verdict, ca))
            bisect_log.append(half_line(f"bis{round_no}b", b_idx,
                                        (rc_b, el_b), verdict_b, cb))
            if verdict == "effective":
                cand = a_idx
                single_el = el
            elif verdict_b == "effective":
                cand = b_idx
                single_el = el_b
            elif verdict == "no_effect" and verdict_b == "crash":
                cand = b_idx  # the crash may hide the driver; keep halving b
            elif verdict == "crash" and verdict_b == "no_effect":
                cand = a_idx  # same, for a
            else:
                raise BindRefused(
                    f"union was effective but half A is {verdict} and "
                    f"half B is {verdict_b}: contradictory or unmeasurable "
                    "signal, refusing to guess"
                )
            round_no += 1
        driver = sites60[cand[0]]
        if state is not None:
            state["driver"] = driver
        # The isolated site is verified on its own (the last bisection probe
        # may have measured it together with a crashed neighbor).
        rc, single_el = runner.run("single", {driver: 20000}, 300)
        if classify(rc, single_el) != "effective":
            raise BindRefused(
                f"single site @{driver}: rc={rc} elapsed={single_el:.1f}s; "
                "the isolated site does not move the wait, refusing"
            )
        bisect_log.append(f"single site @{driver} -> {single_el:.1f} s "
                          "(bound driver: both waits moved)")
        print(f"  driver @{driver} isolated by bisection")

        # 4. ceiling: the nearest 120000 sites, all probed concurrently
        # (independent artifacts), evaluated in order of proximity.
        ceiling, cap_log = measure_ceiling(runner, driver, sites120, nearest)
        if state is not None:
            state["ceiling"] = ceiling
        print(f"  ceiling @{ceiling} measured")

        # 5. max-wait boundary (version-specific: some builds cap waits below
        # INT32_MAX, where values at or above the boundary wait zero) and the
        # end-to-end test: the recorded targets must still wait at the 150 s
        # probe cap - the INT32_MAX probe itself when it waits, a final
        # probe of the measured max working value otherwise.
        driver_values = {}
        max_working, boundary_ms = measure_boundary(runner, driver, ceiling,
                                                   driver_values)
        if state is not None:
            state["max_working"] = max_working
        print(f"  max working value: {max_working:,}")

        # 6/7. record the binding (evidence first: the registry is written
        # only after every site and target is measurement-defined).
        entry = {
            "size": size,
            "sha256": sha256,
            "sites": [
                {"offset": driver, "old": 60000, "role": DRIVER_ROLE,
                 "target": max_working},
                {"offset": ceiling, "old": 120000, "role": CAP_ROLE,
                 "target": INT32_MAX},
            ],
            "evidence": {
                "date": time.strftime("%Y-%m-%d"),
                "harness": EVIDENCE_HARNESS,
                "baseline_elapsed_s": round(base_el, 1),
                "all_sites_elapsed_s": round(all_el, 1),
                "single_site_elapsed_s": round(single_el, 1),
                "bisect": bisect_log,
                "ceiling": cap_log,
                "max_driver_boundary": {
                    "method": EVIDENCE_BOUNDARY_METHOD,
                    "driver_values": driver_values,
                    "boundary_ms": boundary_ms,
                    "max_working_value": max_working,
                },
                "note": (f"{len(sites60)} int32 60000 sites and {len(sites120)} "
                         f"int32 120000 sites in the window [{win_lo}, {size}) "
                         "(back half of the binary, text-neighborhood filter); "
                         f"the driver @{driver} is isolated by bisection and the "
                         f"ceiling @{ceiling} by the cap probe. Bound by "
                         "oracle_bind_auto.py (no-guess invariant: every site "
                         "and target is measurement-defined). Default apply "
                         "uses the recorded per-site targets. sha256 records "
                         "the exact binary this binding was measured on - a "
                         "byte-identical local build applies without a local "
                         "probe (the end-to-end test was paid on the runner)."),
            },
        }
        doc[base] = entry
        write_registry_doc(registry_path, doc)
        if state is not None:
            state["recorded"] = True
        print(f"registry: recorded entry {base!r} (size {size:,}) in {registry_path}")
        print(f"binding complete: driver @{driver} -> {max_working:,}, "
              f"ceiling @{ceiling} -> INT32_MAX")
        return True
    except BindRefused as exc:
        print(f"\nREFUSED: {exc}")
        print("no registry entry was written (no-guess invariant).")
        return False
    finally:
        for p in made:
            try:
                os.remove(p)
            except OSError:
                pass


def bind_candidates(binary_path: str, registry_path: str, probe,
                    max_candidates: int = 5, nearest: int = 5,
                    skip_driver: int = None, state: dict = None) -> bool:
    """The CI candidate fallback: when the primary pipeline refused, or when
    its recorded entry failed the end-to-end test, try the OTHER found
    values. For each candidate driver site (file order, the primary's
    measured driver first when it was measured, `skip_driver` excluded - a
    combo that already failed its end-to-end test is not re-tested, up to
    `max_candidates`): the candidate's ceiling is measured (the nearest-
    `nearest` 120000 sites, the binder's cap probe), then the end-to-end
    test runs at the candidate's targets (the 150 s cap probe: rc=124,
    killed still waiting, is the pass; when INT32_MAX does not wait, the
    boundary walk measures the capped target and re-probes it). The first
    candidate that passes is recorded (the same entry shape as bind, with
    sha256 and a candidates_tried evidence log); when every candidate
    fails - or the harness cannot measure the baseline at all - nothing is
    written (False, no-guess invariant).

    `state` may carry the primary attempt's facts: a measured
    baseline_ok=True skips the re-probe, a measured driver orders the
    candidates, and sha256 is reused when present."""
    binary_path = os.path.abspath(binary_path)
    base = os.path.basename(binary_path)
    bin_dir = os.path.dirname(binary_path)
    with open(binary_path, "rb") as f:
        data = f.read()
    size = len(data)
    win_lo, win_hi = size // 2, size
    made = []
    runner = _ProbeRunner(binary_path, data, bin_dir, base, probe, made)
    sha256 = hashlib.sha256(data).hexdigest()

    try:
        sites60 = find_sites(data, 60000, win_lo, win_hi)
        sites120 = find_sites(data, 120000, win_lo, win_hi)
        print(f"candidate fallback: {len(sites60)} 60000 sites, "
              f"{len(sites120)} 120000 sites (up to {max_candidates} "
              f"candidate drivers, the end-to-end test per candidate)")
        if not sites60:
            raise BindRefused(
                "no int32 60000 code sites in the window; no candidate "
                "driver to try"
            )
        if not sites120:
            raise BindRefused(
                "no int32 120000 code sites in the window; no ceiling "
                "candidate to measure against"
            )

        doc = load_registry_doc(registry_path)
        existing = doc.get(base)
        if existing is not None:
            if existing.get("size") == size:
                print(f"already bound: registry entry {base!r} "
                      f"(size {size:,}); nothing to do")
                return True
            raise BindRefused(
                f"registry key {base!r} is taken by a different-size build "
                f"(size {existing.get('size')}); rename the binary or pass a "
                "different --registry"
            )

        # The probes below are meaningless when the harness cannot measure
        # the unpatched waits: the baseline (the two 60 s waits) is checked
        # first - a baseline the primary attempt already measured is reused.
        if state is not None and state.get("baseline_ok"):
            base_el = state.get("baseline_elapsed_s")
            print(f"  baseline re-used from the primary attempt ({base_el} s)")
        else:
            base_rc, base_el = runner.run("base", None, 300)
            if base_rc is None or base_rc != 0 or \
                    not (BASELINE_WINDOW[0] <= base_el <= BASELINE_WINDOW[1]):
                raise BindRefused(
                    f"baseline probe: rc={base_rc} elapsed={fmt(base_el)}; the "
                    "two 60 s classifier waits are not observable (expected "
                    "~121 s), refusing to try candidates blind"
                )

        cands = list(sites60)
        if skip_driver in cands:
            cands.remove(skip_driver)
        measured = state.get("driver") if state is not None else None
        if measured in cands:
            cands.remove(measured)
            cands.insert(0, measured)
        cands = cands[:max(0, max_candidates)]
        if not cands:
            raise BindRefused("no candidate driver sites left to try")

        tried = []
        for i, cand in enumerate(cands):
            print(f"== candidate {i + 1}/{len(cands)}: driver @{cand} ==")
            try:
                ceiling, cap_log = measure_ceiling(runner, cand, sites120,
                                                   nearest)
                driver_values = {}
                max_working, boundary_ms = measure_boundary(runner, cand,
                                                           ceiling,
                                                           driver_values)
            except BindRefused as exc:
                tried.append(f"driver @{cand}: refused ({exc}); "
                             "trying the next found value")
                continue
            print(f"  candidate driver @{cand} passed the end-to-end test "
                  f"(ceiling @{ceiling}, max working value {max_working:,})")
            entry = {
                "size": size,
                "sha256": sha256,
                "sites": [
                    {"offset": cand, "old": 60000, "role": DRIVER_ROLE,
                     "target": max_working},
                    {"offset": ceiling, "old": 120000, "role": CAP_ROLE,
                     "target": INT32_MAX},
                ],
                "evidence": {
                    "date": time.strftime("%Y-%m-%d"),
                    "harness": EVIDENCE_HARNESS,
                    "method": ("ci candidate fallback: the primary binding "
                               "refused or failed the end-to-end test; this "
                               "candidate's ceiling was measured and its "
                               "targets passed the 150 s end-to-end test on "
                               "the runner"),
                    "candidates_tried": tried + [
                        f"driver @{cand}: PASSED the end-to-end test "
                        f"(recorded)"
                    ],
                    "ceiling": cap_log,
                    "max_driver_boundary": {
                        "method": EVIDENCE_BOUNDARY_METHOD,
                        "driver_values": driver_values,
                        "boundary_ms": boundary_ms,
                        "max_working_value": max_working,
                    },
                    "note": (f"{len(sites60)} int32 60000 sites and "
                             f"{len(sites120)} int32 120000 sites in the "
                             f"window [{win_lo:,}, {size:,}); the candidate "
                             f"driver @{cand} and ceiling @{ceiling} were "
                             "measured per candidate (cap probe + 150 s "
                             "end-to-end test). Recorded by "
                             "oracle_bind_auto.bind_candidates (no-guess "
                             "invariant: every site and target is "
                             "measurement-defined, the end-to-end test "
                             "passed)."),
                },
            }
            doc[base] = entry
            write_registry_doc(registry_path, doc)
            if state is not None:
                state.update(driver=cand, ceiling=ceiling,
                             max_working=max_working, recorded=True)
            print(f"registry: recorded entry {base!r} (size {size:,}) "
                  f"from candidate {i + 1} in {registry_path}")
            return True
        print(f"\nREFUSED: all {len(cands)} candidate drivers failed the "
              "end-to-end test or could not be measured:")
        for line in tried:
            print(f"  {line}")
        print("no registry entry was written (no-guess invariant).")
        return False
    except BindRefused as exc:
        print(f"\nREFUSED: {exc}")
        print("no registry entry was written (no-guess invariant).")
        return False
    finally:
        for p in made:
            try:
                os.remove(p)
            except OSError:
                pass


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    ap.add_argument("--binary", required=True,
                    help="SFE binary to bind")
    ap.add_argument("--registry", default=default_registry_path(),
                    help="verified_sites registry to record into (default: "
                         "verified_sites.json at the repo root)")
    ap.add_argument("--probe", default=default_probe_path(),
                    help="probe script with the run_probe.sh contract "
                         "(default: tools/binder/run_probe.sh)")
    ap.add_argument("--nearest", type=int, default=5,
                    help="how many nearest 120000 sites to try as the ceiling "
                         "(default 5)")
    args = ap.parse_args(argv)
    if not os.path.isfile(args.binary):
        print(f"error: binary {args.binary} not found", file=sys.stderr)
        return 2
    if not os.path.isfile(args.probe):
        print(f"error: probe script {args.probe} not found", file=sys.stderr)
        return 2
    if args.nearest < 1:
        print("error: --nearest must be at least 1", file=sys.stderr)
        return 2
    try:
        ok = bind(args.binary, args.registry, probe_via_script(args.probe),
                  nearest=args.nearest)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
