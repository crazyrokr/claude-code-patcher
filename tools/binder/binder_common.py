"""Site enumeration shared by the oracle binder and the manual binding
recipes (oracle_binding_step1/step2, oracle_cap_probe).

The 4-aligned int32 site scan with the text-neighborhood filter is the
"code site" definition the no-guess pipeline records evidence against;
every script that enumerates sites must use this one implementation, so a
filter or window change lands in exactly one place.
"""

import os
import struct


def root() -> str:
    return os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def all_hits(data: bytes, needle: bytes, lo: int, hi: int) -> list:
    """Every offset of `needle` in [lo, hi) (no alignment or text filter)."""
    out = []
    off = max(0, lo)
    while True:
        j = data.find(needle, off)
        if j == -1 or j >= hi:
            break
        out.append(j)
        off = j + 1
    return out


def text_density(data: bytes, off: int, radius: int = 32) -> float:
    lo = max(0, off - radius)
    hi = min(len(data), off + 4 + radius)
    seg = data[lo:hi]
    printable = sum(1 for b in seg if 0x20 <= b < 0x7F or b in (0x09, 0x0A, 0x0D))
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
