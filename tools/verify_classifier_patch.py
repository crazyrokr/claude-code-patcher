#!/usr/bin/env python3
"""Verify the auto-mode classifier timeout state of a Claude Code binary.

Unlike a naive "is the source value different from 60000" check, this reports
whether the patch is actually in the region the runtime executes. The SFE runs
compiled bytecode (the live region); the plaintext source region is a fallback
that is not read at runtime. A patch that only touches the source therefore does
not change the live timeout, and this tool says so instead of reporting success.

Exit codes:
  0  patched and confirmed in the live (executed) region
  1  unpatched, OR patched only in the dead source region (runtime no-op)
  2  inconclusive (no classifier constant block could be located)
"""

from __future__ import annotations

import argparse
import sys
from typing import List, Optional

import classifier_scan as cs

VERDICT_UNPATCHED = "UNPATCHED"
VERDICT_SOURCE_ONLY = "SOURCE_PATCHED_LIVE_UNVERIFIED"
VERDICT_LIVE = "PATCHED_LIVE"
VERDICT_UNKNOWN = "UNKNOWN"


def _mb(off: int) -> str:
    return f"{off/1e6:.3f}M"


def pick_source_block(blocks: List[cs.ConstantBlock]) -> Optional[cs.ConstantBlock]:
    """The plaintext declaration that lives in the (dead) source region."""
    for b in blocks:
        if b.region == "source":
            return b
    return blocks[0] if blocks else None


def pick_live_block(blocks: List[cs.ConstantBlock]) -> Optional[cs.ConstantBlock]:
    """A classifier block, if one were found inside the live bytecode region.

    The live region is compiled bytecode, so a plaintext `var TQe=...` match here
    would be unexpected; we surface it only to be explicit when it happens.
    """
    for b in blocks:
        if b.region in ("live_code", "live_string_pool"):
            return b
    return None


def evaluate(blocks: List[cs.ConstantBlock]) -> (str, Optional[cs.ConstantBlock], List[str]):
    """Return (verdict, source_block, notes) for a set of discovered blocks."""
    if not blocks:
        return VERDICT_UNKNOWN, None, ["no classifier constant block located"]

    src = pick_source_block(blocks)
    live = pick_live_block(blocks)
    notes: List[str] = []

    if live is not None:
        if cs.is_source_patched(live):
            return VERDICT_LIVE, src, ["classifier block in live region is patched"]
        notes.append("classifier block in live region still carries original values")

    if src is not None and cs.is_source_patched(src):
        notes.append(
            "source region is patched, but the runtime executes the compiled "
            "bytecode region, so the live timeout is NOT confirmed to have changed"
        )
        return VERDICT_SOURCE_ONLY, src, notes

    notes.append("source region still carries the shipped original timeout values")
    return VERDICT_UNPATCHED, src, notes


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

    blocks = cs.find_constant_blocks(data)
    verdict, src, notes = evaluate(blocks)

    print(f"binary   : {args.binary}")
    print(f"size     : {len(data):,} bytes")
    print(f"verdict  : {verdict}")
    print()

    if src is not None:
        print(f"source block @ {src.offset} ({_mb(src.offset)} [{src.region}]):")
        print(f"  {'const':<6} {'shipped':>10} {'current':>10}   status")
        for name, orig in cs.ORIGINAL_VALUES.items():
            cur = src.values.get(name)
            if cur is None:
                continue
            status = "CHANGED" if cur != orig else "same"
            print(f"  {name:<6} {orig:>10} {cur:>10}   {status}")

    for n in notes:
        print(f"note     : {n}")

    print()
    if verdict == VERDICT_UNKNOWN:
        print("result   : inconclusive - could not locate the classifier constants")
        return 2

    if verdict == VERDICT_UNPATCHED:
        print("result   : original timeouts in effect; run "
              "tools/patch_classifier_timeout.py")
        return 1

    if verdict == VERDICT_SOURCE_ONLY:
        print(
            "result   : the source region is patched, but in this build the runtime\n"
            "           executes compiled bytecode, so this is a runtime NO-OP.\n"
            "           The classifier will keep timing out. Reliable fixes:\n"
            "             * --permission-mode bypassPermissions (skip the classifier)\n"
            "             * add an explicit permissions allow-rule for the tool in use\n"
            "             * fix the backend: wall_clock_timeout means the model endpoint\n"
            "               is slow/down, which a larger timeout only lengthens"
        )
        return 1

    print("result   : patch is present in the executed region; live timeouts changed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
