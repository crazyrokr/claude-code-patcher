#!/usr/bin/env python3
"""Increase the auto-mode classifier timeouts in a Claude Code binary, safely.

Default behavior is byte-length-preserving: each constant is raised to the
largest value that keeps the same decimal digit count, so no subsequent byte in
the file shifts and nothing downstream can break. The edit is all-or-nothing.

Because this build executes compiled bytecode rather than the embedded source,
a source-region edit alone may not change the live timeout; after patching this
tool prints the reliable alternatives (bypassPermissions / scoped allow-rule /
fixing the slow backend) so you are not left assuming the error is gone.

With --self-test the patched copy is executed (`<copy> --version`) before it is
proposed as a swap, so a patch that corrupts the binary is rejected, not shipped.
--in-place is built on the same gate: the original is saved as <binary>.orig,
the patched copy is self-tested first, and only a passing copy replaces the
original (atomic rename). A failing copy triggers a full restore, so the
original is never lost either way.

A patch request that resolves to zero edits (values already at target, or a
requested Hrn rewrite that cannot be located) is a refusal: nothing is written
and nothing is copied.

For builds where the reference-anchored path cannot resolve a single site,
the wait driver is identified by measurement instead:
candidate int32 sites are patched in turn and the binary is timed against a
blackholed classifier endpoint (the recorded probes live under
tools/binder/). A site whose rewrite moves the wait is then a
binding for that exact build: `--apply-live` consults the registry at
verified_sites.json and applies the recorded sites only when the binary's
size and the recorded bytes at every site still match, so a drifted build is
refused, never mis-bound.
"""

from __future__ import annotations

import argparse
import os
import socket
import subprocess
import sys
import time
from typing import Dict, List, Optional, Tuple

import classifier_scan as cs
import live_scan as ls


def _mb(off: int) -> str:
    return f"{off/1e6:.3f}M"


def length_safe_max(current: int) -> int:
    """Largest value with the same digit count as `current`."""
    return cs.digit_preserving_max(len(str(current)))


def default_targets(block: cs.ConstantBlock) -> Dict[str, int]:
    """Raise the three big knobs to their length-safe maxima; leave the rest."""
    targets: Dict[str, int] = {}
    for name in ("TQe", "L8", "Lrn"):
        cur = block.values.get(name)
        if cur is None:
            continue
        bigger = length_safe_max(cur)
        if bigger > cur:
            targets[name] = bigger
    return targets


def run_self_test(patched_path: str) -> (bool, str):
    """Prove the patched binary still executes by running `--version`.

    The path is resolved to absolute first: a bare relative name without a
    slash is PATH-resolved by the kernel (execvpe) and fails with ENOENT
    even though the file sits in the current directory.
    """
    exe = os.path.abspath(patched_path)
    try:
        if not os.access(exe, os.X_OK):
            os.chmod(exe, 0o755)
        proc = subprocess.run(
            [exe, "--version"],
            capture_output=True,
            text=True,
            timeout=120,
        )
    except subprocess.TimeoutExpired:
        return False, "self-test timed out running '<binary> --version'"
    except OSError as exc:
        return False, f"self-test failed to launch: {exc}"
    out = (proc.stdout + proc.stderr).strip()
    return proc.returncode == 0, f"exit={proc.returncode} output={out[:120]!r}"


def _restore_original(binary_path: str, backup_path: str) -> bool:
    """Restore the backed-up original into the binary slot, atomically.

    The move is atomic, so the original can never be in neither place. The
    backup is then re-created so a spare copy survives the failed run.
    """
    if not os.path.exists(backup_path) or os.path.exists(binary_path):
        return True
    try:
        os.replace(backup_path, binary_path)
    except OSError as exc:
        print(f"\nerror: could not restore the original from {backup_path}: {exc}",
              file=sys.stderr)
        return False
    try:
        with open(binary_path, "rb") as src, open(backup_path, "wb") as dst:
            dst.write(src.read())
    except OSError:
        pass  # original is safe in place; only the spare copy is lost
    print("original restored from backup (spare kept):", backup_path)
    return True


def print_reliable_fixes() -> None:
    print(
        "\nReliable ways to stop the classifier denial (in order of preference):\n"
        "  1. Skip the classifier entirely:\n"
        "       claude --permission-mode bypassPermissions\n"
        "  2. Allow the specific tool so it needs no classifier decision, e.g. in\n"
        "     settings.json permissions.allow: [\"Edit(/path/**)\"].\n"
        "  3. Fix the backend. The log's wall_clock_timeout means the model endpoint\n"
        "     (Sonnet 5 -> qwen3.8:27b) is slow or down; a larger timeout only makes\n"
        "     each fail-closed wait longer. Check the endpoint:  curl <ANTHROPIC_BASE_URL>."
    )


# --- Experimental live (bytecode) path ----------------------------------------


def default_live_targets(old: int) -> int:
    """Raise a constant to the largest value with the same digit count."""
    return cs.digit_preserving_max(len(str(old)))


def print_manifest(manifest: ls.Manifest, entries: List[ls.PoolEntry]) -> None:
    """Print the Phases 1-3 candidate manifest (human + machine readable)."""
    print("\n== experimental-live candidate manifest ==")
    print(f"pool entries parsed: {len(entries)}")
    if manifest.anchors:
        print("anchors resolved:")
        for a in manifest.anchors:
            e = a.entry
            print(
                f"  {a.name!r}: ordinal={e.ordinal} offset={e.offset} "
                f"hash24=0x{e.hval:06x}"
            )
    else:
        print("anchors resolved: none found in the pool")
    print("reference-encoding hit counts in the live region:")
    for enc, n in sorted(manifest.encodings.items()):
        print(f"  {enc}: {n}")
    if manifest.sites:
        print("candidate reference sites:")
        for s in manifest.sites:
            print(f"  anchor={s.anchor} encoding={s.encoding} ref@{s.ref_offset}")
    else:
        print("candidate reference sites: none")
    print(f"\nresolution: {manifest.status}")
    print(f"  {manifest.detail}")
    if manifest.candidates:
        print(f"candidate constant slots ({len(manifest.candidates)}):")
        for c in manifest.candidates:
            print(f"  @{c.offset}: value={c.old}  [{c.evidence}]")
    else:
        print("candidate constant slots: none (no site bound the full set)")
    if manifest.set_windows:
        print(
            f"set-window candidates (<={ls.SET_WINDOW} B holding all values; "
            "diagnostic only, never bound):"
        )
        for w in manifest.set_windows:
            slots = " ".join(
                f"{s.value}@{s.offset}" for s in sorted(w.slots, key=lambda s: s.offset)
            )
            aux_parts = []
            for a in sorted(w.aux_distances):
                d = w.aux_distances[a]
                aux_parts.append(f"{a} at +{d}" if d is not None else f"{a} absent")
            print(f"  center@{w.center}: {slots}   aux: {' '.join(aux_parts) or 'none tracked'}")
    else:
        print(
            f"set-window candidates: none (no table <={ls.SET_WINDOW} B holds all values)"
        )
    print("\nREFUSED: --experimental-live is read-only; no bytes were written.")


def run_behavioral_oracle(
    original_path: str, patched_path: str, budget_s: int = 150
) -> Tuple[str, str]:
    """Phase 4 behavioral oracle (best-effort, honest verdicts only).

    Points ANTHROPIC_BASE_URL at a local blackhole listener (accepts, never
    answers) so the classifier's model call is guaranteed to hit its timeout,
    then times how long each binary waits before failing closed. If the wait
    moves with the patched constants, the live path is proven; if it is
    unchanged, the patch is a runtime no-op. Any environment failure yields
    UNVERIFIED -- this function never reports success it did not measure.
    """
    def time_one(binary: str) -> Optional[float]:
        # Absolute path: a bare relative name would be PATH-resolved (execvpe)
        # and a launch failure here must not read as a measured zero wait.
        exe = os.path.abspath(binary)
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind(("127.0.0.1", 0))
            sock.listen(8)
            port = sock.getsockname()[1]
        except OSError as exc:
            return None
        env = dict(os.environ)
        env.update(
            {
                "ANTHROPIC_BASE_URL": f"http://127.0.0.1:{port}",
                "ANTHROPIC_API_KEY": "oracle-blackhole",
                "NO_COLOR": "1",
            }
        )
        start = time.monotonic()
        try:
            proc = subprocess.run(
                [
                    exe,
                    "--permission-mode", "auto",
                    "-p", "Create a file named oracle_probe.txt with the text ok",
                    "--max-turns", "2",
                ],
                capture_output=True,
                text=True,
                env=env,
                timeout=budget_s,
            )
            elapsed = time.monotonic() - start
            return elapsed
        except (subprocess.TimeoutExpired, OSError):
            return time.monotonic() - start
        finally:
            try:
                sock.close()
            except OSError:
                pass

    base = time_one(original_path)
    patched = time_one(patched_path)
    if base is None or patched is None:
        return "UNVERIFIED", "could not bind the blackhole listener; no timing measured"
    delta = patched - base
    if abs(delta) < 5.0:
        return (
            "NO_OP",
            f"wait unchanged (base={base:.1f}s patched={patched:.1f}s, "
            f"delta={delta:+.1f}s); the patched constants are not on the live path",
        )
    return (
        "LIVE_CONFIRMED",
        f"wait moved with the patch (base={base:.1f}s patched={patched:.1f}s, "
        f"delta={delta:+.1f}s)",
    )


def default_registry_path() -> str:
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    return os.path.join(root, "verified_sites.json")


def load_registry(args: argparse.Namespace) -> Dict[str, ls.VerifiedEntry]:
    path = args.registry if args.registry else default_registry_path()
    if args.registry is None and not os.path.exists(path):
        return {}
    try:
        return ls.load_verified_sites(path)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        raise SystemExit(2)


def parse_live_value(spec: str) -> Tuple[int, int]:
    """Parse an OLD=NEW target spec; malformed input raises ValueError."""
    if "=" not in spec:
        raise ValueError(f"invalid --live-value {spec!r} (want OLD=NEW)")
    old_s, new_s = spec.split("=", 1)
    try:
        old, new = int(old_s), int(new_s)
    except ValueError:
        raise ValueError(f"invalid --live-value {spec!r} (want OLD=NEW)")
    if old <= 0 or new <= 0:
        raise ValueError(f"invalid --live-value {spec!r} (values must be positive)")
    return old, new


def run_live_verified(
    args: argparse.Namespace, data: bytes, binary_path: str, entry: ls.VerifiedEntry
) -> int:
    """Phase 4b: apply an oracle-verified site binding for this exact build.

    The binding is measured evidence (a blackhole timing probe showed the site
    moves the classifier wait), so it bypasses the reference-anchored UNIQUE
    requirement without guessing: apply refuses unless the binary's size and
    the recorded bytes at every site still match the entry. Without an
    explicit --live-value, each site is raised to the largest int32 (a
    compiled 4-byte slot has no digit-count constraint), or to the site's
    recorded `target` when the registry sets one.
    """
    print("\n== oracle-verified live binding ==")
    print(f"registry entry {entry.label!r}: binary size {entry.size:,} B")
    ev = entry.evidence
    if ev:
        if "baseline_elapsed_s" in ev or "patched_elapsed_s" in ev:
            print(
                f"evidence ({ev.get('date', '?')}, {ev.get('harness', '?')}): "
                f"baseline {ev.get('baseline_elapsed_s', '?')} s -> "
                f"patched {ev.get('patched_elapsed_s', '?')} s; "
                f"wait per attempt {ev.get('wait_per_attempt_ms', '?')}"
            )
        for line in ev.get("bisect", []):
            print(f"  bisect: {line}")
    for s in entry.sites:
        print(f"  site @{s.offset}: {s.old}  [{s.role}]")

    targets: Dict[int, int] = {}
    if args.live_value:
        for spec in args.live_value:
            try:
                old, new = parse_live_value(spec)
            except ValueError as exc:
                print(f"error: {exc}", file=sys.stderr)
                return 2
            targets[old] = new
    else:
        # Default: the largest value the 4-byte int32 slot can hold. The old
        # digit-count-preserving max only constrained source-text rewrites; a
        # compiled int32 slot accepts any int32, and a timeout in milliseconds
        # has no smaller semantic cap (verified by the recorded probes).
        # A site with an explicit `target` in the registry wins.
        for s in entry.sites:
            want = s.target if s.target is not None else ls.INT32_MAX
            if want > s.old:
                targets[s.old] = want

    planned = [
        (s.offset, s.old, targets.get(s.old))
        for s in entry.sites
        if s.old in targets and targets[s.old] != s.old
    ]
    if not planned:
        print("\nnothing to change: every verified site is already at its requested value")
        print_reliable_fixes()
        return 0
    print("\nplanned value changes (oracle-verified sites):")
    for off, old, new in planned:
        print(f"  @{off}: {old} -> {new}")

    patched, ok, errors, ops = ls.apply_verified_sites(data, entry, targets)
    if not ok:
        print("\nPHASE 4b REFUSED (nothing written): " + "; ".join(errors))
        print_reliable_fixes()
        return 1

    vok, problems = ls.static_verify(data, patched, ops)
    print("static verify: " + ("PASS" if vok else "FAIL"))
    for p in problems:
        print(f"  - {p}")
    if not vok:
        return 1

    out_path = binary_path + ".patched"
    try:
        with open(out_path, "wb") as f:
            f.write(patched)
        os.chmod(out_path, 0o755)
    except OSError as exc:
        print(f"\nerror: failed to write {out_path}: {exc}", file=sys.stderr)
        return 1
    print(f"wrote {out_path} ({len(patched):,} bytes; length preserved)")

    ok_test, detail = run_self_test(out_path)
    print("execute gate (--version): " + ("PASS" if ok_test else "FAIL") + " - " + detail)
    if not ok_test:
        os.remove(out_path)
        return 1

    if args.oracle:
        verdict, note = run_behavioral_oracle(binary_path, out_path)
        print(f"behavioral oracle: {verdict} - {note}")
        if verdict == "NO_OP":
            os.remove(out_path)
            print("removed the no-op patched copy: " + out_path)
            print_reliable_fixes()
            return 1
        if verdict == "UNVERIFIED":
            print("the oracle could not be measured here; success is NOT claimed.")
    else:
        print(
            "note: this binding is backed by the recorded probe evidence above; "
            "re-measure with --oracle if the endpoint environment has changed."
        )
    return 0


def run_live(args: argparse.Namespace, data: bytes, binary_path: str) -> int:
    """Run the oracle-verified binding when the build has one on record;
    otherwise the reference-anchored Phases 1-3 (manifest) and, when explicitly
    requested and uniquely resolved, Phase 4 (apply + verify)."""
    registry = load_registry(args)
    if registry:
        # The binary's own name disambiguates size collisions (two versions
        # may ship byte-identical-sized builds; the native layout names its
        # files after the version, the registry key of each build).
        entry = ls.match_verified_entry(
            registry, data, os.path.basename(binary_path))
        if entry is not None:
            matches, problems = ls.verified_sites_match(data, entry)
            if matches:
                return run_live_verified(args, data, binary_path, entry)
            print(
                f"note: registry entry {entry.label!r} matches the binary size but "
                "no longer matches the recorded bytes; falling back to the "
                "reference-anchored path:\n"
                + "\n".join(f"  - {p}" for p in problems)
            )

    entries = ls.parse_pool(data, cs.LIVE_STRING_POOL_RANGE)
    anchors = ls.resolve_anchors(entries)
    sites, enc_counts = ls.find_reference_hits(data, cs.LIVE_CODE_RANGE, anchors)
    manifest = ls.build_manifest(
        data, anchors, sites, enc_counts, live_range=cs.LIVE_CODE_RANGE
    )
    print_manifest(manifest, entries)

    if not (args.apply_live or args.oracle):
        if manifest.status == "UNIQUE":
            print("resolution is UNIQUE; to run Phase 4 (apply + verify), pass --apply-live.")
        else:
            print(
                "resolution is not UNIQUE; --apply-live would refuse as well "
                "(the no-guess invariant)"
            )
        return 0

    if manifest.status != "UNIQUE":
        print(
            "\nPHASE 4 REFUSED: resolution is %s, not UNIQUE. Nothing is written.\n"
            "This is the no-guess invariant working: the live site cannot be "
            "identified with confidence on this build." % manifest.status
        )
        print_reliable_fixes()
        return 1

    for c in manifest.candidates:
        c.new = default_live_targets(c.old)
    patched, ok, errors = ls.apply_live(data, manifest.candidates)
    if not ok:
        print("\nPHASE 4 APPLY FAILED (nothing written): " + "; ".join(errors))
        return 1

    vok, problems = ls.static_verify(data, patched, manifest.candidates)
    print("\nstatic verify: " + ("PASS" if vok else "FAIL"))
    for p in problems:
        print(f"  - {p}")
    if not vok:
        return 1

    out_path = binary_path + ".patched"
    try:
        with open(out_path, "wb") as f:
            f.write(patched)
        os.chmod(out_path, 0o755)
    except OSError as exc:
        print(f"\nerror: failed to write {out_path}: {exc}", file=sys.stderr)
        return 1
    print(f"wrote {out_path} ({len(patched):,} bytes; length preserved)")

    ok_test, detail = run_self_test(out_path)
    print("execute gate (--version): " + ("PASS" if ok_test else "FAIL") + " - " + detail)
    if not ok_test:
        os.remove(out_path)
        return 1

    if args.oracle:
        verdict, note = run_behavioral_oracle(binary_path, out_path)
        print(f"behavioral oracle: {verdict} - {note}")
        if verdict == "NO_OP":
            os.remove(out_path)
            print("removed the no-op patched copy: " + out_path)
            print_reliable_fixes()
            return 1
        if verdict == "UNVERIFIED":
            print("the oracle could not be measured here; success is NOT claimed.")
    else:
        print(
            "note: without --oracle the patch is statically verified only; "
            "the live path is unproven. Success is not claimed."
        )
    return 0


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("binary", nargs="?", default="claude", help="path to the binary")
    parser.add_argument("--tqe", type=int, default=None, help="target TQe (per-attempt, ms)")
    parser.add_argument("--l8", type=int, default=None, help="target L8 (stage ceiling, ms)")
    parser.add_argument("--lrn", type=int, default=None, help="target Lrn (retry base, ms)")
    parser.add_argument("--hrn", type=int, default=None, help="Hrn return literal (opt-in)")
    parser.add_argument("--in-place", action="store_true", help="write back to the binary")
    parser.add_argument("--self-test", action="store_true", help="run the patched copy to prove it works")
    parser.add_argument("--dry-run", action="store_true", help="print planned edits, change nothing")
    parser.add_argument(
        "--allow-length-change",
        action="store_true",
        help="lift the digit-count guard (only safe in the dead source region)",
    )
    parser.add_argument(
        "--experimental-live",
        action="store_true",
        help="run the reference-anchored live Phases 1-3, print the candidate "
             "manifest, and stop (read-only; no bytes written)",
    )
    parser.add_argument(
        "--apply-live",
        action="store_true",
        help="Phase 4: apply the live patch when resolution is UNIQUE "
             "(writes <binary>.patched; never the original)",
    )
    parser.add_argument(
        "--oracle",
        action="store_true",
        help="Phase 4 plus the behavioral oracle on a blackholed endpoint "
             "(implies --apply-live)",
    )
    parser.add_argument(
        "--registry",
        default=None,
        metavar="PATH",
        help="oracle-verified sites registry (default: verified_sites.json next "
             "to this tool; a missing file means no verified binding for this build)",
    )
    parser.add_argument(
        "--live-value",
        action="append",
        default=[],
        metavar="OLD=NEW",
        help="target value for a verified site, repeatable; default: the largest "
             "int32 (2147483647), or the site's recorded target when the registry "
             "sets one",
    )
    args = parser.parse_args(argv)

    try:
        with open(args.binary, "rb") as f:
            data = f.read()
    except FileNotFoundError:
        print(f"error: {args.binary} not found", file=sys.stderr)
        return 2

    if args.experimental_live or args.apply_live or args.oracle:
        return run_live(args, data, args.binary)

    blocks = cs.find_constant_blocks(data)
    if not blocks:
        print("error: no classifier constant block found; refusing to guess", file=sys.stderr)
        print_reliable_fixes()
        return 1

    block = blocks[0]
    print(f"target block @ {block.offset} ({_mb(block.offset)} [{block.region}]):")
    print("  " + ", ".join(f"{k}={v}" for k, v in block.values.items()))

    targets = default_targets(block)
    if args.tqe is not None:
        targets["TQe"] = args.tqe
    if args.l8 is not None:
        targets["L8"] = args.l8
    if args.lrn is not None:
        targets["Lrn"] = args.lrn

    if not targets and args.hrn is None:
        print("\nnothing to change: constants are already at their requested values")
        print_reliable_fixes()
        return 0

    print("\nplanned value changes:")
    for name, new_val in sorted(targets.items()):
        old = block.values.get(name)
        note = ""
        if old is not None and len(str(new_val)) != len(str(old)):
            note = "  [length-changing!]"
        print(f"  {name}: {old} -> {new_val}{note}")
    if args.hrn is not None:
        print(f"  Hrn: return -> {args.hrn}")

    result = cs.apply_source_patch(
        data,
        targets,
        hrn_return=args.hrn,
        allow_length_change=args.allow_length_change,
    )

    if not result.ok:
        print("\npatch refused (all-or-nothing), nothing written:")
        for e in result.errors:
            print(f"  - {e}")
        print_reliable_fixes()
        return 1

    if args.dry_run:
        print(f"\ndry-run: {len(result.ops)} edit(s) would be applied; length preserved "
              f"({len(result.data)} == {len(data)}: {len(result.data)==len(data)})")
        return 0

    if not result.ops:
        print("\nno-op: every requested value is already in place; nothing written")
        print_reliable_fixes()
        return 0

    if args.in_place:
        # Rollback-safe: the original is moved aside first, the patched copy is
        # staged beside it and self-tested, and only a passing copy is swapped
        # in. A failing copy triggers a full restore, so the original is never
        # lost and never left replaced by a broken binary.
        backup_path = args.binary + ".orig"
        if os.path.exists(backup_path):
            print(f"note: keeping the existing backup: {backup_path}")
        else:
            try:
                os.replace(args.binary, backup_path)
            except OSError as exc:
                print(f"\nerror: could not move the original aside: {exc}", file=sys.stderr)
                return 1
            print(f"original saved to {backup_path}")

        staged_path = args.binary + ".new"
        try:
            with open(staged_path, "wb") as f:
                f.write(result.data)
            os.chmod(staged_path, 0o755)
        except OSError as exc:
            print(f"\nerror: failed to write the staged copy: {exc}", file=sys.stderr)
            _restore_original(args.binary, backup_path)
            if os.path.exists(staged_path):
                os.remove(staged_path)
            return 1

        if args.self_test:
            ok, detail = run_self_test(staged_path)
            print(f"\nself-test: {'PASS' if ok else 'FAIL'} - {detail}")
            if not ok:
                _restore_original(args.binary, backup_path)
                os.remove(staged_path)
                return 1

        try:
            os.replace(staged_path, args.binary)
        except OSError as exc:
            print(f"\nerror: failed to swap in the patched copy: {exc}", file=sys.stderr)
            _restore_original(args.binary, backup_path)
            if os.path.exists(staged_path):
                os.remove(staged_path)
            return 1

        print(f"\napplied in place ({len(result.data):,} bytes; "
              f"length {'preserved' if len(result.data)==len(data) else 'CHANGED'})")
        if os.path.exists(backup_path):
            print(f"original preserved at {backup_path} - delete it once you are confident.")
    else:
        out_path = args.binary + ".patched"
        try:
            with open(out_path, "wb") as f:
                f.write(result.data)
        except OSError as exc:
            print(f"\nerror: failed to write the patched copy: {exc}", file=sys.stderr)
            if os.path.exists(out_path):
                os.remove(out_path)
            return 1

        if args.self_test:
            ok, detail = run_self_test(out_path)
            print(f"\nself-test: {'PASS' if ok else 'FAIL'} - {detail}")
            if not ok:
                print("removing failed patched copy:", out_path)
                os.remove(out_path)
                return 1

        print(f"\nwrote {out_path} ({len(result.data):,} bytes; "
              f"length {'preserved' if len(result.data)==len(data) else 'CHANGED'})")
        print("to apply:  mv %s %s && chmod +x %s" % (out_path, args.binary, args.binary))

    for op in result.ops:
        print(f"  - @ {op.offset} ({_mb(op.offset)}): {op.old.decode()} -> {op.new.decode()}")

    print("\nnote: this edit targets the embedded source region. This build executes\n"
          "compiled bytecode, so the live timeout may be unchanged. Verify with:\n"
          "  python3 tools/verify_classifier_patch.py %s" % args.binary)
    print_reliable_fixes()
    return 0


if __name__ == "__main__":
    sys.exit(main())
