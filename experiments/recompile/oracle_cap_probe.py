"""Cap-site probe, generic over versions.

Finds the ceiling that clamps the driver wait: rewrite the oracle-bound
driver site to a value above the suspected cap and the cap-candidate int32
120000 sites to a value above that, then run the blackhole timing probe.

Signal model (wait = min(cap, driver), two classifier waits per run):
  cap site patched and it is the ceiling -> waits follow the driver value
  cap site patched and it is not          -> waits stay at the old ceiling
  (all cap sites patched, still capped    -> the ceiling is not an int32
    120000 data site; it is a bytecode immediate or another constant)
"""

import argparse
import os
import struct
import subprocess


def root() -> str:
    return os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def text_density(data: bytes, off: int, radius: int = 32) -> float:
    lo = max(0, off - radius)
    hi = min(len(data), off + 4 + radius)
    seg = data[lo:hi]
    printable = sum(
        1 for b in seg if 0x20 <= b < 0x7f or b in (0x09, 0x0a, 0x0d)
    )
    return printable / len(seg) if seg else 0.0


def find_sites(data: bytes, value: int, win_lo: int, win_hi: int) -> list:
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


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--binary", required=True,
                    help="SFE binary to patch")
    ap.add_argument("--driver", type=int, required=True,
                    help="offset of the oracle-bound driver site")
    ap.add_argument("--driver-old", type=int, default=60000,
                    help="value currently at the driver site (default 60000)")
    ap.add_argument("--caps", required=True,
                    help="comma-separated cap-site offsets, or 'all120k'")
    ap.add_argument("--cap-old", type=int, default=120000,
                    help="value currently at the cap sites (default 120000)")
    ap.add_argument("--win-lo", type=int, default=None,
                    help="window start for 'all120k' (default: size // 2)")
    ap.add_argument("--win-hi", type=int, default=None,
                    help="window end for 'all120k', exclusive (default: size)")
    ap.add_argument("--driver-new", type=int, default=130000,
                    help="value written at the driver site (default 130000)")
    ap.add_argument("--cap-new", type=int, default=200000,
                    help="value written at the cap sites (default 200000)")
    ap.add_argument("--label", required=True)
    ap.add_argument("--timeout", type=int, default=300,
                    help="probe run timeout in seconds (default 300)")
    ap.add_argument("--no-probe", action="store_true",
                    help="only build the binary, do not run the probe")
    args = ap.parse_args()

    path = os.path.abspath(args.binary)
    data = open(path, "rb").read()
    size = len(data)
    win_lo = args.win_lo if args.win_lo is not None else size // 2
    win_hi = args.win_hi if args.win_hi is not None else size

    if args.caps == "all120k":
        caps = find_sites(data, args.cap_old, win_lo, win_hi)
    else:
        caps = [int(x) for x in args.caps.split(",") if x]
    assert len(caps) > 0, "no cap sites selected"

    buf = bytearray(data)
    if buf[args.driver:args.driver + 4] != struct.pack("<i", args.driver_old):
        raise SystemExit(
            f"driver @{args.driver} is not {args.driver_old}: "
            f"{buf[args.driver:args.driver+4].hex()}")
    buf[args.driver:args.driver + 4] = struct.pack("<i", args.driver_new)
    for s in caps:
        if buf[s:s + 4] != struct.pack("<i", args.cap_old):
            raise SystemExit(f"cap @{s} is not {args.cap_old}: {buf[s:s+4].hex()}")
        buf[s:s + 4] = struct.pack("<i", args.cap_new)

    dst = os.path.join(os.path.dirname(path), f"{os.path.basename(path)}.bind_{args.label}")
    with open(dst, "wb") as f:
        f.write(buf)
    os.chmod(dst, 0o755)
    print(f"wrote {dst} (driver @{args.driver}->{args.driver_new}, "
          f"{len(caps)} cap sites ->{args.cap_new}: "
          + ", ".join(str(s) for s in caps))

    if args.no_probe:
        return
    probe = os.path.join(root(), "experiments", "recompile", "run_probe.sh")
    subprocess.run(["bash", probe, dst, args.label, str(args.timeout)])


if __name__ == "__main__":
    main()
