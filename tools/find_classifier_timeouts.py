#!/usr/bin/env python3
"""Report every auto-mode classifier timeout site in a Claude Code binary.

Prints the classifier's numeric timeout block (TQe/L8/Lrn/...), the Hrn step
function, the identifiers, and the signature strings, each with its exact byte
offset and the region it lives in (live bytecode vs. dead source vs. native).
Read-only: it never modifies the target file.
"""

from __future__ import annotations

import argparse
import sys

import classifier_scan as cs


def _mb(off: int) -> str:
    return f"{off/1e6:.3f}M"


def print_report(rep: cs.Report) -> None:
    print("Measured region layout (this build):")
    for label in ("native", "live_string_pool", "live_code", "source"):
        rng = rep.layout.get(label)
        if rng:
            print(f"  {label:<16} {_mb(rng[0])} .. {_mb(rng[1])}")
    print()

    print("Classifier timeout constant blocks:")
    if not rep.constant_blocks:
        print("  (none found)")
    for b in rep.constant_blocks:
        vals = ", ".join(f"{k}={v}" for k, v in b.values.items())
        patched = cs.is_source_patched(b)
        tag = "PATCHED" if patched else "original"
        print(f"  @ {b.offset:>12} ({_mb(b.offset)} [{b.region}]) {tag}: {vals}")
    print()

    print("Hrn step functions:")
    if not rep.hrn_bodies:
        print("  (none found)")
    for h in rep.hrn_bodies:
        rv = h.return_value
        preview = h.body.strip().decode("latin1")[:60]
        print(f"  @ {h.offset:>12} ({_mb(h.offset)} [{h.region}]) return={rv}  {preview!r}")
    print()

    print("Signature strings (anchor the classifier code):")
    for s, offsets in rep.signature_strings.items():
        where = ", ".join(f"{_mb(o)}" for o in offsets[:5]) + (" ..." if len(offsets) > 5 else "")
        print(f"  {s:<34} {len(offsets):>3}  @ {where}")
    print()

    print("Identifier occurrences (word-boundary):")
    for name, offsets in rep.identifiers.items():
        if not offsets:
            continue
        regions = sorted({cs.classify_offset(o, rep.layout) for o in offsets})
        where = ", ".join(f"{_mb(o)}" for o in offsets[:4]) + (" ..." if len(offsets) > 4 else "")
        print(f"  {name:<6} {len(offsets):>3}  regions={','.join(regions)}  @ {where}")


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", nargs="?", default="claude", help="path to the binary")
    args = parser.parse_args(argv)

    try:
        with open(args.binary, "rb") as f:
            data = f.read()
    except FileNotFoundError:
        print(f"error: {args.binary} not found", file=sys.stderr)
        return 2

    report = cs.collect_report(data)
    print_report(report)
    return 0


if __name__ == "__main__":
    sys.exit(main())
