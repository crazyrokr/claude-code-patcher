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


def bind(binary_path: str, registry_path: str, probe, nearest: int = 5) -> bool:
    """Run the binding pipeline; return True when the registry now holds a
    verified entry for this exact binary (recorded now, or already present),
    False when the no-guess invariant refuses (no registry write)."""
    binary_path = os.path.abspath(binary_path)
    base = os.path.basename(binary_path)
    bin_dir = os.path.dirname(binary_path)
    with open(binary_path, "rb") as f:
        data = f.read()
    size = len(data)
    win_lo, win_hi = size // 2, size
    made = []

    def artifact(label: str, changes: dict) -> str:
        buf = bytearray(data)
        for off, new in sorted(changes.items()):
            cur = struct.unpack_from("<i", buf, off)[0]
            if cur not in (60000, 120000):
                raise BindRefused(
                    f"slot @{off} holds {cur}, not a recorded site value; "
                    "the build drifted since the scan, refusing"
                )
            buf[off:off + 4] = struct.pack("<i", new)
        path = os.path.join(bin_dir, f"{base}.bind_{label}")
        with open(path, "wb") as f:
            f.write(bytes(buf))
        os.chmod(path, 0o755)
        made.append(path)
        return path

    def fmt(el):
        return "?" if el is None else f"{el:.1f}s"

    def run_jobs(jobs):
        """Probe several (label, changes, timeout) jobs concurrently and
        return the (rc, elapsed) results in job order. Each job owns its
        .bind_<label> artifact and its probe owns its endpoint port, so the
        jobs share no state; a slot-drift refusal in any artifact raises
        before the probes start. (Bisection rounds instead use
        decided_round: the same concurrency, plus the cancel-on-decision.)
        """
        prepared = []
        for label, changes, timeout in jobs:
            art = artifact(label, changes) if changes else binary_path
            prepared.append((label, art, timeout))
        if len(prepared) == 1:
            label, art, timeout = prepared[0]
            results = [probe(art, label, timeout)]
        else:
            with ThreadPoolExecutor(max_workers=len(prepared)) as pool:
                futures = [
                    pool.submit(probe, art, label, timeout)
                    for label, art, timeout in prepared
                ]
                results = [f.result() for f in futures]
        out = []
        for (label, _art, _t), res in zip(prepared, results):
            rc, elapsed = res if res is not None else (None, None)
            print(f"  probe {label}: rc={rc} elapsed={fmt(elapsed)}")
            out.append((rc, elapsed))
        return out

    def run(label: str, changes: dict, timeout: int):
        return run_jobs([(label, changes, timeout)])[0]

    def decided_round(a_label, a_changes, b_label, b_changes, timeout):
        """Probe both halves of a bisection round concurrently and cancel
        the half that is no longer decisive as soon as the other half's
        verdict decides the round: an 'effective' half decides alone (the
        measured model has exactly one effective half), a 'no_effect' or
        crashed half does not, so it is waited out (its result stays a
        measurement). Returns (res_a, res_b, canceled_a, canceled_b); each
        result is (rc, elapsed) when the half was measured, (None, None)
        when its probe was canceled or produced no result before finishing
        (a canceled run is not a measurement)."""
        art_a = artifact(a_label, a_changes)
        art_b = artifact(b_label, b_changes)
        cancel_a, cancel_b = threading.Event(), threading.Event()
        box = {}
        lock = threading.Lock()
        first = threading.Event()
        first_key = []

        def run_half(key, art, label, cancel):
            try:
                box[key] = probe(art, label, timeout, cancel)
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

    try:
        sites60 = find_sites(data, 60000, win_lo, win_hi)
        sites120 = find_sites(data, 120000, win_lo, win_hi)
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
        (base_rc, base_el), (all_rc, all_el) = run_jobs([
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
            (rc, el), (rc_b, el_b), ca, cb = decided_round(
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
        # The isolated site is verified on its own (the last bisection probe
        # may have measured it together with a crashed neighbor).
        rc, single_el = run("single", {driver: 20000}, 300)
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
        caps_by_distance = sorted(sites120, key=lambda o: abs(o - driver))[:max(1, nearest)]
        cap_log = []
        ceiling = None
        cap_results = run_jobs([
            (f"cap{i}", {driver: 130000, cap: 200000}, 300)
            for i, cap in enumerate(caps_by_distance)
        ])
        for i, (cap, (rc, el)) in enumerate(zip(caps_by_distance, cap_results)):
            if rc == 0 and el is not None and el >= CEILING_MIN_S:
                ceiling = cap
                cap_log.append(
                    f"driver @{driver} -> 130000 with 120000@{cap} -> 200000: "
                    f"{el:.1f} s (two 130.000 s waits): the ceiling site is "
                    f"@{cap} (+{abs(cap - driver)} B from the driver, the "
                    f"nearest 120000 matches the source var table JZe=60000,z9=120000)"
                )
                break
            if rc == 0 and el is not None and el >= NOT_CEILING_MIN_S:
                cap_log.append(
                    f"driver -> 130000 with 120000@{cap} -> 200000: {el:.1f} s "
                    "(still clamped at 120 s): not the ceiling"
                )
                continue
            raise BindRefused(
                f"cap probe {i}: rc={rc} elapsed={fmt(el)}; unexpected signal"
            )
        if ceiling is None:
            raise BindRefused(
                f"none of the {len(caps_by_distance)} nearest 120000 sites "
                "clamps the wait; the ceiling is not an int32 120000 slot, "
                "refusing to guess"
            )
        print(f"  ceiling @{ceiling} measured")

        # 5. max-wait boundary (version-specific: some builds cap waits below
        # INT32_MAX, where values at or above the boundary wait zero).
        def boundary_probe(value: int, label: str) -> str:
            rc, el = run(label, {driver: value, ceiling: INT32_MAX}, 150)
            if rc == 124:
                return "waiting"
            if rc == 0 and el is not None and el < IMMEDIATE_MAX_S:
                return "immediate"
            raise BindRefused(
                f"boundary probe {value}: rc={rc} elapsed={fmt(el)}; neither "
                "a wait nor an immediate exit, refusing"
            )

        driver_values = {}
        verdict = boundary_probe(INT32_MAX, "bmax")
        driver_values[str(INT32_MAX)] = verdict
        if verdict == "waiting":
            max_working = INT32_MAX
            boundary_ms = ("no cap below INT32_MAX observed; INT32_MAX "
                           "(~24.8 days) still waits")
        else:
            # 60000 waits (the measured baseline); INT32_MAX is immediate.
            lo, hi = 60000, INT32_MAX
            # All coarse values are independent probes (measured
            # concurrently); the lo/hi walk below then brackets the
            # boundary. A signal that is not monotone in value violates
            # the measured model and refuses (a sequential walk would
            # silently skip out-of-interval values instead).
            coarse = [v for v in COARSE_BOUNDARY_VALUES if lo < v < hi]
            coarse_results = run_jobs([
                (f"bnd{len(driver_values) + i}", {driver: v, ceiling: INT32_MAX}, 150)
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
            rc, el = run("final", {driver: max_working, ceiling: INT32_MAX}, 150)
            if rc != 124:
                raise BindRefused(
                    f"final probe: rc={rc} elapsed={fmt(el)}; the recorded "
                    "max working value does not actually wait, refusing"
                )
        print(f"  max working value: {max_working:,}")

        # 6/7. record the binding (evidence first: the registry is written
        # only after every site and target is measurement-defined).
        entry = {
            "size": size,
            "sites": [
                {"offset": driver, "old": 60000, "role": DRIVER_ROLE,
                 "target": max_working},
                {"offset": ceiling, "old": 120000, "role": CAP_ROLE,
                 "target": INT32_MAX},
            ],
            "evidence": {
                "date": time.strftime("%Y-%m-%d"),
                "harness": ("tools/binder/run_probe.sh + "
                           "fake_endpoint.py (BLACKHOLE=1, marker-based "
                           "classifier blackhole; wait boundaries read from "
                           "the probe rc/elapsed)"),
                "baseline_elapsed_s": round(base_el, 1),
                "all_sites_elapsed_s": round(all_el, 1),
                "single_site_elapsed_s": round(single_el, 1),
                "bisect": bisect_log,
                "ceiling": cap_log,
                "max_driver_boundary": {
                    "method": ("150 s run-timeout probes (ceiling at INT32_MAX): "
                               "rc=124 (killed still waiting) = the value waits; "
                               "rc=0 in ~1-2 s = zero wait"),
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
                         "uses the recorded per-site targets."),
            },
        }
        doc[base] = entry
        with open(registry_path, "w", encoding="utf-8") as f:
            json.dump(doc, f, indent=2)
            f.write("\n")
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
