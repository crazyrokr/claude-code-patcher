"""Reference-anchored discovery for the *live* (bytecode) classifier timeouts.

`classifier_scan` handles the plaintext source copy. This module targets the
compiled copy the runtime actually executes, using a different strategy: instead
of matching numeric literals (which are shared app-wide), it anchors on
classifier-unique strings that live in the SFE string pool, finds the code that
references them, and binds the numeric constant slots to that code.

Phases (matching the ADR):
  1. Anchor resolution   -- parse the string pool, resolve each classifier-unique
                            anchor to its entry (ordinal + stored hash).
  2. Site isolation      -- sweep the live region for code that references those
                            anchors (by a candidate u32 encoding).
  3. Constant-slot bind  -- within each candidate site's neighborhood, collect the
                            int32 slots carrying the classifier's values and resolve
                            to UNIQUE / AMBIGUOUS / EMPTY.  More than one surviving
                            neighborhood is a refusal, never a guess.
  4. Apply + verify      -- byte-length-preserving int32 rewrite (all-or-nothing),
                            static re-discovery, and an optional behavioral oracle.

Every public function is pure (operates on a `bytes` buffer and returns new data
plus a report) so the logic is unit-tested against synthetic buffers where the
pool layout and reference encoding are under our control.
"""

from __future__ import annotations

import bisect
import struct
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

# Classifier-unique anchors: strings that appear only in classifier code.
ANCHOR_STRINGS = (
    "classifierStage",
    "wall_clock_timeout",
    "probe demotion",
    "cannot determine the safety of",
)

# The numeric values the classifier timeout block carries (unpatched). A candidate
# site whose neighborhood contains *all* of these is a strong classifier match.
CONSTRAINT_VALUES: Tuple[int, ...] = (60000, 120000, 2000, 10000)

# How far, in bytes either side of a reference hit, to search for constant slots.
NEIGHBORHOOD = 4096

# An encoding is a "plausible reference" only if it yields at least one but not a
# flood of hits; more than this many hits in the live region means the u32 is not a
# string reference (it is some other repeated constant).
MAX_PLAUSIBLE_HITS = 64

# Set-window diagnostic: the largest span (bytes, each side of the anchor
# occurrence) a compact constant table is allowed to span. On real builds the
# only tables that qualify are app-wide settings/limits tables, never the
# classifier's own per-function constant array -- hence the result is
# report-only and never feeds slot binding or apply.
SET_WINDOW = 64

# Extra classifier values (the 50000 backoff step) tracked for context: a real
# classifier constant table should also carry it nearby; the settings/limits
# tables found so far never do.
AUX_VALUES: Tuple[int, ...] = (50000,)

# How far from a set-window candidate to search for the aux values.
AUX_RADIUS = 4096


@dataclass
class PoolEntry:
    offset: int      # absolute offset of the entry's length byte
    ordinal: int     # index among the parsed pool entries, in file order
    length: int      # byte length of the stored string
    string: bytes    # the stored string (no NUL)
    hash3: bytes     # the three stored hash bytes
    hval: int        # hash3 interpreted as a little-endian 24-bit integer


@dataclass
class Anchor:
    name: str
    entry: PoolEntry


@dataclass
class SiteHit:
    anchor: str
    encoding: str
    ref_offset: int   # offset of the u32 reference in the live region


@dataclass
class ConstantSlot:
    offset: int       # offset of the int32 slot
    value: int        # current int32 value


@dataclass
class CandidateOp:
    offset: int       # int32 slot to rewrite
    old: int          # current value
    new: int          # target value
    evidence: str     # which site / anchor bound this slot


@dataclass
class SetWindowCandidate:
    center: int                                    # anchor occurrence that qualified the window
    slots: List[ConstantSlot]                      # nearest slot per wanted value
    aux_distances: Dict[int, Optional[int]]        # aux value -> nearest distance, None if absent


@dataclass
class Manifest:
    status: str                       # "UNIQUE" | "AMBIGUOUS" | "EMPTY"
    anchors: List[Anchor] = field(default_factory=list)
    encodings: Dict[str, int] = field(default_factory=dict)   # encoding -> hit count
    sites: List[SiteHit] = field(default_factory=list)
    slots_by_site: Dict[int, List[ConstantSlot]] = field(default_factory=dict)
    candidates: List[CandidateOp] = field(default_factory=list)
    set_windows: List[SetWindowCandidate] = field(default_factory=list)
    detail: str = ""


# --- Phase 1: pool parse + anchor resolution ----------------------------------


def parse_pool(data: bytes, pool_range: Tuple[int, int]) -> List[PoolEntry]:
    """Walk the string pool and return every well-formed entry, in file order.

    Entry layout (empirically confirmed on this build):
        [len:u8] [00 00 80] [hash:3 bytes] [00] [chars:len] [NUL] [zero pad...]
    A header at `off` is valid iff `data[off+1:off+4] == 00 00 80`, `len` is in
    1..120, the next `len` bytes are non-NUL printable, and the byte after them
    is NUL.
    """
    lo, hi = pool_range
    out: List[PoolEntry] = []
    off = lo
    idx = 0
    while off < hi - 12:
        i = data.find(b"\x00\x00\x80", off)
        if i == -1 or i >= hi:
            break
        cand = i - 1
        ln = data[cand]
        if 1 <= ln <= 120:
            chars = data[i + 7 : i + 7 + ln]
            if (
                len(chars) == ln
                and 0 not in chars
                and data[i + 7 + ln] == 0
                and all(8 <= b < 127 for b in chars)
            ):
                hash3 = data[cand + 4 : cand + 7]
                hval = struct.unpack("<I", hash3 + b"\x00")[0]
                out.append(
                    PoolEntry(
                        offset=cand,
                        ordinal=idx,
                        length=ln,
                        string=bytes(chars),
                        hash3=bytes(hash3),
                        hval=hval,
                    )
                )
                idx += 1
        off = i + 1
    return out


def resolve_anchors(
    entries: List[PoolEntry], anchor_strings: Tuple[str, ...] = ANCHOR_STRINGS
) -> List[Anchor]:
    """Phase 1: map each classifier-unique anchor string to its pool entry.

    Returns only anchors that were found; a missing anchor is reported by the
    caller (an unresolved anchor is a refusal, not a guess).
    """
    by_string: Dict[bytes, PoolEntry] = {}
    for e in entries:
        by_string.setdefault(e.string, e)
    anchors: List[Anchor] = []
    for name in anchor_strings:
        e = by_string.get(name.encode())
        if e is not None:
            anchors.append(Anchor(name=name, entry=e))
    return anchors


# --- Phase 2: site isolation --------------------------------------------------


def reference_encodings(entry: PoolEntry) -> Dict[str, bytes]:
    """Candidate u32 encodings under which a reference to `entry` might be stored.

    The exact encoding is build-dependent, so we probe a small set and let the
    hit counts decide. Each value is the 4-byte little-endian form to search for.
    """
    return {
        "hash24": struct.pack("<I", entry.hval),
        "hash24_flag80": struct.pack("<I", entry.hval | 0x00800000),
        "ordinal": struct.pack("<I", entry.ordinal),
        "ordinal+1": struct.pack("<I", entry.ordinal + 1),
        "offset": struct.pack("<I", entry.offset),
    }


def count_occurrences(data: bytes, needle: bytes, lo: int, hi: int) -> int:
    n = 0
    i = data.find(needle, lo)
    while i != -1 and i < hi:
        n += 1
        i = data.find(needle, i + 1)
    return n


def find_reference_hits(
    data: bytes,
    live_range: Tuple[int, int],
    anchors: List[Anchor],
    max_hits: int = MAX_PLAUSIBLE_HITS,
) -> Tuple[List[SiteHit], Dict[str, int]]:
    """Phase 2: for each anchor, find u32 references to it in the live region.

    Returns (hits, encoding_counts). `encoding_counts` maps each encoding name to
    its total hit count across all anchors (for the manifest). A reference is
    plausible only if its encoding yields 1..max_hits occurrences; zero means the
    encoding is not the reference form, and a flood means the u32 is an unrelated
    repeated constant.
    """
    lo, hi = live_range
    hits: List[SiteHit] = []
    enc_counts: Dict[str, int] = {}
    for anchor in anchors:
        for enc, needle in reference_encodings(anchor.entry).items():
            n = count_occurrences(data, needle, lo, hi)
            enc_counts[enc] = enc_counts.get(enc, 0) + n
            if 1 <= n <= max_hits:
                off = lo
                while True:
                    i = data.find(needle, off)
                    if i == -1 or i >= hi:
                        break
                    hits.append(SiteHit(anchor=anchor.name, encoding=enc, ref_offset=i))
                    off = i + 1
    return hits, enc_counts


# --- Phase 3: constant-slot binding -------------------------------------------


def int32_values_in_window(
    data: bytes, center: int, window: int = NEIGHBORHOOD,
    wanted: Tuple[int, ...] = CONSTRAINT_VALUES,
) -> List[ConstantSlot]:
    """Collect int32 slots holding a wanted value within [center-window, center+window]."""
    lo = max(0, center - window)
    hi = min(len(data) - 4, center + window)
    slots: List[ConstantSlot] = []
    for wanted in wanted:
        needle = struct.pack("<I", wanted)
        off = lo
        while True:
            i = data.find(needle, off)
            if i == -1 or i > hi:
                break
            slots.append(ConstantSlot(offset=i, value=wanted))
            off = i + 1
    slots.sort(key=lambda s: s.offset)
    return slots


def _slots_for_sites(
    data: bytes, sites: List[SiteHit], wanted: Tuple[int, ...]
) -> Dict[int, List[ConstantSlot]]:
    """Map each site to the wanted-value slots found in its neighborhood."""
    return {
        site.ref_offset: int32_values_in_window(data, site.ref_offset, NEIGHBORHOOD, wanted)
        for site in sites
    }


# --- Phase 3b: set-window diagnostic (report-only) ---------------------------


def _occurrences(data: bytes, needle: bytes, lo: int, hi: int) -> List[int]:
    """Sorted offsets of every complete 4-byte occurrence of `needle` in [lo, hi)."""
    out: List[int] = []
    off = max(0, lo)
    while True:
        i = data.find(needle, off)
        if i == -1 or i + 4 > hi:
            break
        out.append(i)
        off = i + 1
    return out


def _nearest_occurrence(
    occ: List[int], center: int, radius: int
) -> Optional[Tuple[int, int]]:
    """Closest entry of sorted `occ` within +/-radius of `center`, as (offset,
    distance); None if no entry qualifies."""
    if not occ:
        return None
    idx = bisect.bisect_left(occ, center - radius)
    best: Optional[Tuple[int, int]] = None
    for j in (idx - 1, idx):
        if 0 <= j < len(occ):
            d = abs(occ[j] - center)
            if d <= radius and (best is None or d < best[1]):
                best = (occ[j], d)
    return best


def find_set_windows(
    data: bytes,
    live_range: Tuple[int, int],
    wanted: Tuple[int, ...] = CONSTRAINT_VALUES,
    window: int = SET_WINDOW,
    aux: Tuple[int, ...] = AUX_VALUES,
    aux_radius: int = AUX_RADIUS,
) -> List[SetWindowCandidate]:
    """Set-window diagnostic: find compact int32 tables that hold *all* `wanted`
    values within +/-`window` bytes of a single anchor occurrence.

    These are the only sites that could be a per-function constant array, so a
    future build that isolates the classifier's constants into one such table
    will surface here. On the builds surveyed so far the qualifying tables are
    app-wide settings/limits tables (mixed durations, counts, year fields,
    INT32_MAX sentinels, table-relative pointers) whose ownership cannot be
    statically proven -- which is exactly why this result is report-only: it
    never feeds slot binding, the UNIQUE/AMBIGUOUS status, or apply.

    A candidate is deduped by the frozenset of slot offsets it uses (several
    anchor occurrences may qualify the same table); the aux distances are
    measured from the first qualifying anchor occurrence.
    """
    occ: Dict[int, List[int]] = {
        v: _occurrences(data, struct.pack("<I", v), *live_range) for v in wanted
    }
    aux_occ: Dict[int, List[int]] = {
        a: _occurrences(data, struct.pack("<I", a), *live_range) for a in aux
    }
    out: List[SetWindowCandidate] = []
    seen: set = set()
    for v in wanted:
        for center in occ[v]:
            slots: List[ConstantSlot] = []
            for u in wanted:
                hit = _nearest_occurrence(occ[u], center, window)
                if hit is None:
                    slots = []
                    break
                slots.append(ConstantSlot(offset=hit[0], value=u))
            if len(slots) != len(wanted):
                continue
            key = frozenset(s.offset for s in slots)
            if key in seen:
                continue
            seen.add(key)
            aux_distances: Dict[int, Optional[int]] = {}
            for a in aux:
                hit = _nearest_occurrence(aux_occ[a], center, aux_radius)
                aux_distances[a] = hit[1] if hit is not None else None
            out.append(SetWindowCandidate(center=center, slots=slots, aux_distances=aux_distances))
    out.sort(key=lambda c: c.center)
    return out


def _add_set_window_diagnostic(
    m: Manifest,
    data: bytes,
    live_range: Optional[Tuple[int, int]],
    wanted: Tuple[int, ...],
) -> Manifest:
    """Attach the report-only set-window diagnostic and its detail suffix.

    `live_range=None` (the pre-diagnostic call form) leaves the manifest
    untouched, so existing callers and their manifests are byte-identical.
    """
    if live_range is None:
        return m
    m.set_windows = find_set_windows(data, live_range, wanted)
    if m.set_windows:
        m.detail += (
            f" | set-window diagnostic: {len(m.set_windows)} compact table(s) within "
            f"{SET_WINDOW} B hold all {len(wanted)} values (report-only, never bound)"
        )
    else:
        m.detail += (
            f" | set-window diagnostic: no table within {SET_WINDOW} B holds all "
            f"{len(wanted)} values"
        )
    return m


def build_manifest(
    data: bytes,
    anchors: List[Anchor],
    sites: List[SiteHit],
    enc_counts: Dict[str, int],
    wanted: Tuple[int, ...] = CONSTRAINT_VALUES,
    live_range: Optional[Tuple[int, int]] = None,
) -> Manifest:
    """Phase 3: resolve candidate sites to UNIQUE / AMBIGUOUS / EMPTY.

    UNIQUE    -- exactly one site contains the full constant set; its slots are
                 the rewrite candidates.
    AMBIGUOUS -- two or more sites contain the full set (or none does but some
                 sites exist): refuse and report the candidates.
    EMPTY     -- no site references an anchor: refuse, nothing to bind.

    When `live_range` is given, the report-only set-window diagnostic is also
    attached (a tripwire for a future build that isolates the constants into a
    single compact table); it never influences the status above.
    """
    m = Manifest(
        status="EMPTY",
        anchors=anchors,
        encodings=enc_counts,
        sites=sites,
    )
    if not sites:
        m.detail = "no live-region reference to any anchor was found (reference encoding unresolved)"
        return _add_set_window_diagnostic(m, data, live_range, wanted)

    m.slots_by_site = _slots_for_sites(data, sites, wanted)
    surviving = [
        site for site in sites
        if set(wanted) <= {s.value for s in m.slots_by_site[site.ref_offset]}
    ]

    def _add_candidates(site: SiteHit) -> None:
        for s in m.slots_by_site[site.ref_offset]:
            m.candidates.append(
                CandidateOp(
                    offset=s.offset,
                    old=s.value,
                    new=s.value,  # filled by the caller with the target value
                    evidence=f"anchor={site.anchor} encoding={site.encoding} ref@{site.ref_offset}",
                )
            )

    if len(surviving) == 1:
        site = surviving[0]
        m.status = "UNIQUE"
        _add_candidates(site)
        m.detail = (
            f"single site (anchor={site.anchor}, encoding={site.encoding}, "
            f"ref@{site.ref_offset}) contains all {len(wanted)} constraint values"
        )
        return _add_set_window_diagnostic(m, data, live_range, wanted)

    m.status = "AMBIGUOUS"
    for site in surviving:
        _add_candidates(site)
    if surviving:
        m.detail = (
            f"{len(surviving)} sites each contain the full constraint set; "
            "refusing to guess which is the classifier (no-guess invariant)"
        )
    else:
        m.detail = (
            f"{len(sites)} candidate site(s) were found but none contains the full "
            f"{len(wanted)}-value constraint set; refusing to guess (no-guess invariant)"
        )
    return _add_set_window_diagnostic(m, data, live_range, wanted)


# --- Phase 4: apply + verify --------------------------------------------------


def apply_live(
    data: bytes, candidates: List[CandidateOp]
) -> Tuple[bytes, bool, List[str]]:
    """Phase 4 apply: rewrite each candidate int32 in place (all-or-nothing).

    Length is preserved by construction (4 bytes in, 4 bytes out). If any slot is
    out of range or cannot be written, nothing is changed and `ok` is False.
    """
    if not candidates:
        return data, False, ["no candidate slots to apply"]
    out = bytearray(data)
    errors: List[str] = []
    for c in candidates:
        if c.new == c.old:
            continue
        if c.offset + 4 > len(out):
            errors.append(f"slot @{c.offset} out of range")
            return data, False, errors
        try:
            struct.pack_into("<i", out, c.offset, c.new)
        except struct.error as exc:
            errors.append(f"slot @{c.offset}: {exc}")
            return data, False, errors
    return bytes(out), True, []


def static_verify(
    original: bytes,
    patched: bytes,
    candidates: List[CandidateOp],
) -> Tuple[bool, List[str]]:
    """Phase 4 static check: length identical, target slots carry the new value,
    and every other byte is unchanged."""
    problems: List[str] = []
    if len(original) != len(patched):
        problems.append(
            f"length changed ({len(original)} -> {len(patched)}); "
            "a live patch must be length-preserving"
        )
        return False, problems

    touched = {c.offset for c in candidates if c.new != c.old}
    differing = [
        i for i in range(len(original)) if original[i] != patched[i]
    ]
    differing_set = set()
    for i in differing:
        differing_set.add(i)
    # every differing byte must belong to a touched 4-byte slot
    for off in sorted(touched):
        for b in range(off, off + 4):
            differing_set.discard(b)
    if differing_set:
        first = min(differing_set)
        problems.append(
            f"{len(differing_set)} unexpected byte(s) changed, first @{first}; "
            "the patch must touch only the bound slots"
        )
    for c in candidates:
        if c.new == c.old:
            continue
        got = struct.unpack_from("<i", patched, c.offset)[0]
        if got != c.new:
            problems.append(f"slot @{c.offset} reads {got}, expected {c.new}")
    return (not problems), problems


# --- Phase 4b: oracle-verified site binding ------------------------------------
#
# Some builds do not let Phases 1-3 resolve UNIQUE: the
# classifier strings are not referenced in the live region by any known u32
# encoding, so no site can be statically bound. On those builds the wait driver
# can still be identified by *measurement*: patch candidate int32 slots in
# turn and time the binary against a blackholed classifier endpoint. A slot
# whose rewrite moves the wait is then bound for that build forever -- the
# binding is data (offset + expected bytes + the recorded probe evidence), not
# a guess, so it satisfies the no-guess invariant. The verified sites are kept
# in a JSON registry; apply below refuses unless the binary's size and the
# recorded bytes at every site still match.


INT32_MAX = 2147483647  # largest value a 4-byte little-endian int32 slot holds


@dataclass
class VerifiedSite:
    offset: int
    old: int          # int32 value recorded at verification time
    role: str         # human label, e.g. the constant the site drives
    target: Optional[int] = None  # explicit target; None = int32 max (timeouts)


@dataclass
class VerifiedEntry:
    label: str        # registry key, e.g. the build version
    size: int         # exact binary size the entry was measured on
    sites: List[VerifiedSite]
    evidence: Dict[str, object] = field(default_factory=dict)


def load_verified_sites(path: str) -> Dict[str, VerifiedEntry]:
    """Parse the verified-sites registry. Malformed input raises ValueError;
    a missing file yields an empty registry (the caller falls back to the
    reference-anchored path)."""
    import json

    try:
        with open(path, "r", encoding="utf-8") as f:
            doc = json.load(f)
    except FileNotFoundError:
        return {}
    if not isinstance(doc, dict):
        raise ValueError("registry: top level must be an object")

    out: Dict[str, VerifiedEntry] = {}
    for label, raw in doc.items():
        if not isinstance(raw, dict):
            raise ValueError(f"registry[{label!r}]: must be an object")
        size = raw.get("size")
        # JSON true/false deserialize to bools, which are ints in Python.
        if isinstance(size, bool) or not isinstance(size, int) or size <= 0:
            raise ValueError(f"registry[{label!r}]: size must be a positive int")
        sites_raw = raw.get("sites")
        if not isinstance(sites_raw, list) or not sites_raw:
            raise ValueError(f"registry[{label!r}]: sites must be a non-empty list")
        evidence = raw.get("evidence", {})
        if not isinstance(evidence, dict):
            raise ValueError(f"registry[{label!r}]: evidence must be an object")
        sites: List[VerifiedSite] = []
        for s in sites_raw:
            if not isinstance(s, dict):
                raise ValueError(f"registry[{label!r}]: each site must be an object")
            off = s.get("offset")
            old = s.get("old")
            if isinstance(off, bool) or not isinstance(off, int) or off < 4:
                raise ValueError(f"registry[{label!r}]: bad site offset {off!r}")
            if isinstance(old, bool) or not isinstance(old, int):
                raise ValueError(f"registry[{label!r}]: bad site value {old!r}")
            tgt = s.get("target", None)
            if tgt is not None and (
                isinstance(tgt, bool) or not isinstance(tgt, int) or tgt <= 0
            ):
                raise ValueError(f"registry[{label!r}]: bad site target {tgt!r}")
            sites.append(VerifiedSite(
                offset=off, old=old, role=str(s.get("role", "")), target=tgt
            ))
        out[label] = VerifiedEntry(
            label=label, size=size, sites=sites, evidence=evidence
        )
    return out


def match_verified_entry(
    registry: Dict[str, VerifiedEntry], data: bytes,
    label: Optional[str] = None,
) -> Optional[VerifiedEntry]:
    """The registry entry for this binary, never a guess.

    Two different versions may ship byte-identical-sized binaries (2.1.275
    and 2.1.276 both record 232,059,192 B), so size equality alone cannot
    tell them apart: first the entry keyed by `label` (the binary's own name;
    the native claude layout names its files after the version, which is
    exactly how the registry keys its entries) is matched when its recorded
    size equals the binary's size - the size is always part of the predicate,
    a name never matches without it - then the UNIQUE entry whose recorded
    size equals the binary's size.

    verified_sites_match (and apply_verified_sites) then re-check the
    recorded bytes at every site, so a different build that shares the name
    or the size still refuses instead of mis-binding.
    """
    if label is not None:
        named = registry.get(label)
        if named is not None and named.size == len(data):
            return named
    matches = [e for e in registry.values() if e.size == len(data)]
    if len(matches) > 1:
        raise ValueError(
            "registry: multiple entries claim size %d" % len(data)
        )
    return matches[0] if matches else None


def verified_sites_match(
    data: bytes, entry: VerifiedEntry
) -> Tuple[bool, List[str]]:
    """Check every site still holds its recorded int32 (build-drift check).

    Returns (True, []) when all sites match, otherwise (False, problems)."""
    problems: List[str] = []
    if len(data) != entry.size:
        return False, [f"binary size {len(data)} != recorded {entry.size}"]
    for site in entry.sites:
        if site.offset + 4 > len(data):
            problems.append(f"site @{site.offset} out of range")
            continue
        cur = struct.unpack_from("<i", data, site.offset)[0]
        if cur != site.old:
            problems.append(
                f"site @{site.offset} ({site.role}) reads {cur}, "
                f"recorded {site.old}"
            )
    return (not problems), problems


def apply_verified_sites(
    data: bytes, entry: VerifiedEntry, targets: Dict[int, int]
) -> Tuple[bytes, bool, List[str], List[CandidateOp]]:
    """Apply a verified entry: rewrite every site whose recorded `old` value
    has a target, all-or-nothing, length-preserving.

    Refuses (ok=False, data returned unchanged) if the binary size does not
    match the entry, if any site no longer holds its recorded bytes (the build
    drifted), or if the targets change nothing. Returns
    (patched, ok, errors, ops).
    """
    errors: List[str] = []
    if len(data) != entry.size:
        return data, False, [
            f"binary size {len(data)} != recorded {entry.size}"
        ], []

    ops: List[CandidateOp] = []
    for site in entry.sites:
        if site.offset + 4 > len(data):
            return data, False, [f"site @{site.offset} out of range"], []
        cur = struct.unpack_from("<i", data, site.offset)[0]
        if cur != site.old:
            return data, False, [
                f"site @{site.offset} ({site.role}) reads {cur}, "
                f"recorded {site.old}; the build drifted, refusing"
            ], []
        if site.old in targets and targets[site.old] != site.old:
            ops.append(
                CandidateOp(
                    offset=site.offset,
                    old=site.old,
                    new=targets[site.old],
                    evidence=f"oracle-verified site ({site.role})",
                )
            )
    if not ops:
        return data, False, ["no verified site has a target to apply"], []

    patched = bytearray(data)
    for op in ops:
        struct.pack_into("<i", patched, op.offset, op.new)
    return bytes(patched), True, [], ops
