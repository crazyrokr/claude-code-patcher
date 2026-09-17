"""Decompress every zstd frame candidate in a binary and search the
decompressed content for the classifier module.

A real frame at a magic offset decompresses cleanly; false positives in
dense data fail. Decompressed outputs are stored under outdir keyed by
source offset and grepped for:
  - the classifier declaration (exact names JZe/z9/Rin)
  - the value pattern =60000, ... 120000 ... 60000,
  - tengu_disable_live_host_context (classifier module neighbor)
  - /$bunfs/root/chunk- (bunfs chunk headers)
"""

import argparse
import os
import subprocess

MAGIC = b"\x28\xb5\x2f\xfd"
CHUNK = 512 * 1024
OUTDIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "zstd_frames")

NEEDLES = {
    "decl_JZe": b"var JZe=60000,z9=120000,Rin=60000",
    "val_pattern": b"=60000,",
    "tengu_live_host": b"tengu_disable_live_host_context",
    "host_context_live": b"host_context_live",
    "bunfs_chunk": b"/$bunfs/root/chunk-",
    "result_from": b"result_from",
}


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--binary", required=True, help="SFE binary to scan")
    args = ap.parse_args()
    path = os.path.abspath(args.binary)
    os.makedirs(OUTDIR, exist_ok=True)
    with open(path, "rb") as f:
        data = f.read()

    offs = []
    off = 0
    while True:
        j = data.find(MAGIC, off)
        if j == -1:
            break
        offs.append(j)
        off = j + 1
    print(f"magic hits: {len(offs)}")

    good, bad = 0, 0
    hits = {}
    sizes = {}
    for i, o in enumerate(offs):
        seg = data[o:o + CHUNK]
        proc = subprocess.run(
            ["zstd", "-d", "-c", "--no-progress"],
            input=seg, capture_output=True)
        # a window may hold several frames or a frame followed by garbage:
        # accept whatever decompressed prefix zstd was able to produce
        if not proc.stdout:
            bad += 1
            continue
        out = proc.stdout
        good += 1
        sizes[o] = len(out)
        path = os.path.join(OUTDIR, f"{o}.bin")
        with open(path, "wb") as f2:
            f2.write(out)
        for label, needle in NEEDLES.items():
            if needle in out:
                hits.setdefault(label, []).append(o)
        if i % 500 == 0:
            print(f"  {i}/{len(offs)} good={good} bad={bad}")

    print(f"\nvalid frames: {good}  invalid: {bad}")
    print("\nneedles found:")
    for label, found in hits.items():
        print(f"  {label}: {len(found)} frame(s): {found[:16]}")

    print("\nlargest decompressed frames (offset -> size):")
    for o, s in sorted(sizes.items(), key=lambda kv: -kv[1])[:15]:
        print(f"  @{o}: {s:,} B")
    total = sum(sizes.values())
    print(f"total decompressed bytes: {total:,}")


if __name__ == "__main__":
    main()
