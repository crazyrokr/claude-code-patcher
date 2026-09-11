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
"""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
from typing import Dict

import classifier_scan as cs


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
    """Prove the patched binary still executes by running `--version`."""
    if not os.access(patched_path, os.X_OK):
        os.chmod(patched_path, 0o755)
    try:
        proc = subprocess.run(
            [patched_path, "--version"],
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
    args = parser.parse_args(argv)

    try:
        with open(args.binary, "rb") as f:
            data = f.read()
    except FileNotFoundError:
        print(f"error: {args.binary} not found", file=sys.stderr)
        return 2

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

    out_path = args.binary if args.in_place else args.binary + ".patched"
    with open(out_path, "wb") as f:
        f.write(result.data)
    print(f"\nwrote {out_path} ({len(result.data):,} bytes; "
          f"length {'preserved' if len(result.data)==len(data) else 'CHANGED'})")
    for op in result.ops:
        print(f"  - @ {op.offset} ({_mb(op.offset)}): {op.old.decode()} -> {op.new.decode()}")

    if args.self_test:
        ok, detail = run_self_test(out_path)
        print(f"\nself-test: {'PASS' if ok else 'FAIL'} - {detail}")
        if not ok and not args.in_place:
            print("removing failed patched copy:", out_path)
            os.remove(out_path)
            return 1

    if args.in_place:
        print("applied in place.")
    else:
        print("to apply:  mv %s %s && chmod +x %s" % (out_path, args.binary, args.binary))

    print("\nnote: this edit targets the embedded source region. This build executes\n"
          "compiled bytecode, so the live timeout may be unchanged. Verify with:\n"
          "  python3 verify_classifier_patch.py %s" % args.binary)
    print_reliable_fixes()
    return 0


if __name__ == "__main__":
    sys.exit(main())
