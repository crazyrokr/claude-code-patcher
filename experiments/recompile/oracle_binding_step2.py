"""Oracle-verified binding, step N: bisect rounds. Generic over versions.

Enumerates 4-byte-aligned int32 sites holding --old in [win_lo, win_hi)
(default window: the back half of the binary — past the native code and
string pool, covering the live bytecode and any dead source), drops sites
whose 64-byte neighborhood reads as text (coincidental int32 patterns inside
embedded source or string pools are not code sites), rewrites the chosen
index subset to --new, and runs the blackhole probe on the result.

Signal model (baseline 121 s = 2 x 60 s waits + ~1 s):
  every driver wait that becomes NEW drops elapsed by (60000-NEW) ms:
    ~121 s -> no driver wait in the patched subset
    ~81  s -> exactly one of the two waits driven by the subset
    ~41  s (NEW=20000) -> both waits driven by the subset
  a crashed binary (rc != 0 or no 'Probe finished.') means a patched site is
  not a plain int32 constant; exclude it and rerun the round without it.
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


def find_sites(data: bytes, old: int, win_lo: int, win_hi: int) -> list:
    needle = struct.pack("<i", old)
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
                    help="SFE binary to scan and patch")
    ap.add_argument("--win-lo", type=int, default=None,
                    help="window start (default: size // 2)")
    ap.add_argument("--win-hi", type=int, default=None,
                    help="window end, exclusive (default: size)")
    ap.add_argument("--old", type=int, default=60000,
                    help="int32 value to enumerate (default 60000)")
    ap.add_argument("--indices", required=True,
                    help="comma-separated 0-based site indices or a-b ranges "
                         "(e.g. 0,5-17,80), or 'all'")
    ap.add_argument("--label", required=True)
    ap.add_argument("--new", type=int, default=20000,
                    help="int32 value to write at the chosen sites (default 20000)")
    ap.add_argument("--timeout", type=int, default=300,
                    help="probe run timeout in seconds (default 300; raise for "
                         "long-wait probes, e.g. 900 for a 300000 ms site)")
    ap.add_argument("--no-probe", action="store_true",
                    help="only build the binary, do not run the probe")
    args = ap.parse_args()

    path = os.path.abspath(args.binary)
    data = open(path, "rb").read()
    size = len(data)
    win_lo = args.win_lo if args.win_lo is not None else size // 2
    win_hi = args.win_hi if args.win_hi is not None else size
    sites = find_sites(data, args.old, win_lo, win_hi)
    print(f"{os.path.basename(path)} size={size} window=[{win_lo}, {win_hi}) "
          f"int32 {args.old} code sites: {len(sites)}")
    if args.indices == "all":
        chosen = list(range(len(sites)))
    else:
        chosen = set()
        for part in args.indices.split(","):
            if not part:
                continue
            if "-" in part:
                a, b = part.split("-", 1)
                chosen.update(range(int(a), int(b) + 1))
            else:
                chosen.add(int(part))
        chosen = sorted(chosen)
    if any(i >= len(sites) for i in chosen):
        raise SystemExit(f"index out of range: {max(chosen)} >= {len(sites)}")
    chosen_sites = [sites[i] for i in chosen]
    print("patching {} sites -> {}: ".format(len(chosen_sites), args.new)
          + ", ".join(str(s) for s in chosen_sites))

    buf = bytearray(data)
    for s in chosen_sites:
        if buf[s:s + 4] != struct.pack("<i", args.old):
            raise SystemExit(f"slot @{s} is not {args.old}: {buf[s:s+4].hex()}")
        buf[s:s + 4] = struct.pack("<i", args.new)

    dst = os.path.join(os.path.dirname(path), f"{os.path.basename(path)}.bind_{args.label}")
    with open(dst, "wb") as f:
        f.write(buf)
    os.chmod(dst, 0o755)
    print(f"wrote {dst}")

    if args.no_probe:
        return
    probe = os.path.join(root(), "experiments", "recompile", "run_probe.sh")
    subprocess.run(["bash", probe, dst, args.label, str(args.timeout)])


if __name__ == "__main__":
    main()
