"""Oracle-verified binding, step 1: is any 60000 in the live bytecode region
the classifier wait driver?

Enumerates every little-endian int32 --old in [--win-lo, --win-hi)
(default window: the whole file - the constant pool's location moved
between builds, 2.1.310's driver slots sit in the front half), dumps
context for each, and writes <binary>.all<old> with all of them rewritten
to --new.
run_probe.sh on that binary then tells us:
  elapsed ~41 s (--new 20000) -> at least one driver site is in the window
                                 (bisect next)
  elapsed ~121 s -> the wait is computed or lives outside the window

Generic over versions: the target binary comes from --binary, never from a
hardcoded file name.
"""

import argparse
import os
import struct

from binder_common import all_hits


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--binary", required=True, help="SFE binary to scan")
    ap.add_argument(
        "--win-lo", type=int, default=None, help="window start (default: 0)"
    )
    ap.add_argument(
        "--win-hi", type=int, default=None, help="window end, exclusive (default: size)"
    )
    ap.add_argument(
        "--old",
        type=int,
        default=60000,
        help="int32 value to enumerate (default 60000)",
    )
    ap.add_argument(
        "--new",
        type=int,
        default=20000,
        help="int32 value to write at every site (default 20000)",
    )
    args = ap.parse_args()

    path = os.path.abspath(args.binary)
    with open(path, "rb") as f:
        data = f.read()
    size = len(data)
    win_lo = args.win_lo if args.win_lo is not None else 0
    win_hi = args.win_hi if args.win_hi is not None else size
    sites = all_hits(data, struct.pack("<i", args.old), win_lo, win_hi)
    aligned = [s for s in sites if s % 4 == 0]
    print(
        f"{os.path.basename(path)} window {args.old} sites: {len(sites)}  "
        f"(4-aligned: {len(aligned)})"
    )
    for s in sites:
        tag = "A" if s % 4 == 0 else "."
        print(f"  [{tag}] @{s}: " + " ".join(f"{b:02x}" for b in data[s - 12 : s + 16]))

    dst = f"{path}.all{args.old}"
    buf = bytearray(data)
    for s in sites:
        buf[s : s + 4] = struct.pack("<i", args.new)
    with open(dst, "wb") as f:
        f.write(buf)
    os.chmod(dst, 0o755)
    print(f"\nwrote {dst} ({len(buf):,} B, {len(sites)} slots)")


if __name__ == "__main__":
    main()
