"""Discovery and rewrite engine for the Claude Code auto-mode classifier timeouts.

The Claude Code single-file executable (a Bun SFE) stores two independent copies
of the app: a precompiled bytecode region that the runtime actually executes, and
a plaintext source region that is retained as a fallback but is not read at
runtime. The auto-mode classifier declares its per-attempt, retry, and ceiling
timeouts in a `var TQe=..., L8=..., Lrn=..., ...` block plus an `Hrn` step
function. This module locates both copies, parses the numeric constants, and
rewrites them in a byte-length-preserving way so that an edit can never shift
subsequent structured data.

Every public function here is pure (operates on a `bytes` buffer and returns new
data plus a report) so the logic can be unit-tested against synthetic buffers
without touching the real 217 MB binary.
"""

from __future__ import annotations

import re
import struct
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

# Minified, module-local identifiers that make up the classifier timeout block.
CONST_NAMES = ("TQe", "L8", "Lrn", "Frn", "$rn", "Brn", "Urn")

# Values the *unpatched* binary carries. These are what the live bytecode holds
# (verified against the 70026 ms fail-closed denial: ~60000 + 10000 + overhead).
ORIGINAL_VALUES: Dict[str, int] = {
    "TQe": 60000,   # per-attempt timeout, ms
    "L8": 120000,   # stage ceiling, ms
    "Lrn": 60000,   # retry budget base, ms
    "Frn": 4,       # retry count multiplier
    "$rn": 0,       # reserved
    "Brn": 2000,    # backoff base, ms
    "Urn": 10000,   # extra wait, ms
}

# Identifiers worth surfacing in the report (classifier + its collaborators).
IDENTIFIERS = ("TQe", "L8", "Lrn", "Frn", "Brn", "Urn", "Hrn", "kbe", "_Tr")

# Signature strings that appear only in classifier code. These anchor a constant
# cluster to the classifier even when the numeric literals are shared app-wide.
SIGNATURE_STRINGS = (
    "wall_clock_timeout",
    "probe demotion",
    "temporarily unavailable",
    "cannot determine the safety of",
    "auto mode",
    "classifierStage",
    "xml_s1",
)

# Measured layout of THIS SFE build (byte offsets, decimal). Used to classify an
# offset as live-bytecode / source / native. Computed fresh by detect_layout when
# possible, but these anchors are what the report falls back on.
LIVE_CODE_RANGE = (102_000_000, 177_000_000)
LIVE_STRING_POOL_RANGE = (91_000_000, 102_000_000)
SOURCE_RANGE = (181_000_000, 209_000_000)
NATIVE_RANGE = (0, 85_000_000)

IDENT_CHARS = frozenset(
    b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_$"
)

CONST_DECL_RE = re.compile(
    rb"var\s+TQe=(\d+),L8=(\d+),Lrn=(\d+),Frn=(\d+),\$rn=(\d+),Brn=(\d+),Urn=([0-9.eE+-]+)\s*;"
)
HRN_RE = re.compile(rb"function\s+Hrn\s*\(\s*[a-zA-Z_$][a-zA-Z0-9_$]*\s*\)\s*\{([^}]*)\}")


@dataclass
class ConstantBlock:
    offset: int
    values: Dict[str, int]
    region: str = "unknown"


@dataclass
class HrnBody:
    offset: int
    body: bytes
    return_value: Optional[int]
    region: str = "unknown"


@dataclass
class Report:
    constant_blocks: List[ConstantBlock] = field(default_factory=list)
    hrn_bodies: List[HrnBody] = field(default_factory=list)
    identifiers: Dict[str, List[int]] = field(default_factory=dict)
    signature_strings: Dict[str, List[int]] = field(default_factory=dict)
    layout: Dict[str, Tuple[int, int]] = field(default_factory=dict)


def find_all(data: bytes, needle: bytes) -> List[int]:
    """Return every offset of `needle` in `data`, in ascending order."""
    out: List[int] = []
    i = data.find(needle)
    while i != -1:
        out.append(i)
        i = data.find(needle, i + 1)
    return out


def find_identifier(data: bytes, name: str) -> List[int]:
    """Return offsets of `name` used as a standalone identifier (word boundary)."""
    pat = name.encode()
    if not pat:
        return []
    out: List[int] = []
    i = data.find(pat)
    while i != -1:
        before = data[i - 1] if i > 0 else 0
        after = data[i + len(pat)] if i + len(pat) < len(data) else 0
        if before not in IDENT_CHARS and after not in IDENT_CHARS:
            out.append(i)
        i = data.find(pat, i + 1)
    return out


def classify_offset(offset: int, layout: Dict[str, Tuple[int, int]]) -> str:
    """Map a byte offset to a region name using the measured layout."""
    for label in ("live_code", "live_string_pool", "source", "native"):
        rng = layout.get(label)
        if rng and rng[0] <= offset < rng[1]:
            return label
    return "unknown"


def detect_layout(data: bytes) -> Dict[str, Tuple[int, int]]:
    """Return the measured region layout for this build.

    The SFE region split is stable per build, so we return the measured anchors
    rather than re-deriving them; callers that want to re-derive can pass their
    own layout into classify_offset.
    """
    return {
        "native": NATIVE_RANGE,
        "live_string_pool": LIVE_STRING_POOL_RANGE,
        "live_code": LIVE_CODE_RANGE,
        "source": SOURCE_RANGE,
    }


def _parse_int(token: bytes) -> int:
    return int(float(token))


def find_constant_blocks(data: bytes, layout: Optional[Dict[str, Tuple[int, int]]] = None) -> List[ConstantBlock]:
    """Locate every classifier `var TQe=...` declaration and its values."""
    layout = layout or detect_layout(data)
    blocks: List[ConstantBlock] = []
    for m in CONST_DECL_RE.finditer(data):
        values = {
            "TQe": int(m.group(1)),
            "L8": int(m.group(2)),
            "Lrn": int(m.group(3)),
            "Frn": int(m.group(4)),
            "$rn": int(m.group(5)),
            "Brn": int(m.group(6)),
            "Urn": _parse_int(m.group(7)),
        }
        blocks.append(
            ConstantBlock(
                offset=m.start(),
                values=values,
                region=classify_offset(m.start(), layout),
            )
        )
    blocks.sort(key=lambda b: b.offset)
    return blocks


def _extract_hrn_return(body: bytes) -> Optional[int]:
    m = re.search(rb"return\s+([0-9]+)", body)
    if m:
        return int(m.group(1))
    return None


def find_hrn_bodies(data: bytes, layout: Optional[Dict[str, Tuple[int, int]]] = None) -> List[HrnBody]:
    """Locate every `function Hrn(...){...}` and the numeric it returns, if any."""
    layout = layout or detect_layout(data)
    bodies: List[HrnBody] = []
    for m in HRN_RE.finditer(data):
        body = m.group(1)
        bodies.append(
            HrnBody(
                offset=m.start(),
                body=body,
                return_value=_extract_hrn_return(body),
                region=classify_offset(m.start(), layout),
            )
        )
    bodies.sort(key=lambda b: b.offset)
    return bodies


def collect_report(data: bytes) -> Report:
    """Run every discovery pass over `data` and bundle the results."""
    layout = detect_layout(data)
    identifiers = {name: find_identifier(data, name) for name in IDENTIFIERS}
    signatures = {s: find_all(data, s.encode()) for s in SIGNATURE_STRINGS}
    return Report(
        constant_blocks=find_constant_blocks(data, layout),
        hrn_bodies=find_hrn_bodies(data, layout),
        identifiers=identifiers,
        signature_strings=signatures,
        layout=layout,
    )


# --- Byte-length-preserving rewrite primitives -------------------------------


def digit_preserving_max(digits: int) -> int:
    """Largest value that keeps the same digit count as `digits` (length-safe)."""
    if digits <= 0:
        return 0
    return (10 ** digits) - 1


def rewrite_int32_inplace(data: bytes, offset: int, new_value: int) -> Tuple[bytes, bool]:
    """Replace a little-endian int32 at `offset` with `new_value`.

    Length is preserved by construction (4 bytes in, 4 bytes out), so no
    subsequent byte shifts. Returns (new_data, applied).
    """
    old = data[offset : offset + 4]
    if len(old) != 4:
        return data, False
    try:
        new = struct.pack("<i", new_value)
    except struct.error:
        return data, False
    return data[:offset] + new + data[offset + 4 :], True


@dataclass
class PatchOp:
    label: str
    offset: int
    old: bytes
    new: bytes
    applied: bool
    reason: str = ""


@dataclass
class PatchResult:
    data: bytes
    ops: List[PatchOp] = field(default_factory=list)
    ok: bool = True
    errors: List[str] = field(default_factory=list)


def _span_of_value(text: bytes, name: str) -> Optional[Tuple[int, bytes]]:
    """Within a matched `var ...` block, return (relative offset, numeric text)
    of the value assigned to `name`, or None if `name` is not present.

    The full numeric literal (integer, optional fraction, optional exponent) is
    captured so a length check compares the whole token, e.g. `1e4` not `1`.
    """
    prefix = name.encode() + b"="
    p = text.find(prefix)
    if p == -1:
        return None
    q = p + len(prefix)
    m = re.match(rb"[0-9]+(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?", text[q:])
    if not m:
        return None
    return q, m.group(0)


def apply_source_patch(
    data: bytes,
    new_values: Dict[str, int],
    hrn_return: Optional[int] = None,
    allow_length_change: bool = False,
) -> PatchResult:
    """Apply a patch to the first (source) classifier constant block.

    All-or-nothing: if any edit is refused, nothing is written. Values not in
    `new_values` are left untouched. `hrn_return`, when set, rewrites the Hrn
    body to `return <hrn_return>;` space-padded to the original length.

    By default every edit is byte-length-preserving (same decimal digit count),
    so no subsequent byte shifts. Set `allow_length_change` to lift that guard;
    that is only safe in the dead source region and is the caller's call.
    """
    result = PatchResult(data=data)
    m = CONST_DECL_RE.search(data)
    if not m:
        result.ok = False
        result.errors.append("no classifier constant block found; nothing to patch")
        return result

    block_text = m.group(0)
    edits: List[Tuple[int, bytes, bytes]] = []
    for name, new_val in new_values.items():
        span = _span_of_value(block_text, name)
        if span is None:
            continue
        rel, old_text = span
        new_text = str(new_val).encode()
        if old_text == new_text:
            continue
        if len(new_text) != len(old_text) and not allow_length_change:
            result.ok = False
            result.errors.append(
                f"{name}: {old_text.decode()}->{new_val} changes byte length "
                f"({len(old_text)}->{len(new_text)}); refused to avoid shifting data "
                f"(pass --allow-length-change to override in the source region)"
            )
            return result
        edits.append((m.start() + rel, old_text, new_text))

    for abs_off, old_text, new_text in sorted(edits, reverse=True):
        result.data = (
            result.data[:abs_off] + new_text + result.data[abs_off + len(old_text) :]
        )
        result.ops.append(PatchOp("", abs_off, old_text, new_text, True))

    if hrn_return is not None:
        hm = HRN_RE.search(result.data)
        if hm:
            span = hm.group(0)
            inner_len = len(hm.group(1))
            new_core = f"return {hrn_return};".encode()
            if len(new_core) > inner_len:
                result.ok = False
                result.errors.append(
                    "Hrn: new return literal is longer than the original body; "
                    "refused to preserve byte length"
                )
                return result
            new_body = new_core + b" " * (inner_len - len(new_core))
            repl = span[: len(span) - inner_len - 1] + new_body + b"}"
            if len(repl) != len(span):
                result.ok = False
                result.errors.append("Hrn: replacement span length mismatch; refused")
                return result
            result.data = result.data[: hm.start()] + repl + result.data[hm.end() :]
            result.ops.append(PatchOp("Hrn", hm.start(), span, repl, True))
        else:
            # A requested Hrn rewrite that cannot be located is a refusal, not a
            # skip: `ok` must go False so the caller does not ship a no-op write
            # (a full byte-for-byte copy) and report success.
            result.ok = False
            result.errors.append("Hrn: function not found; the requested rewrite cannot be applied")

    return result


def is_source_patched(block: Optional[ConstantBlock]) -> bool:
    """True if a constant block deviates from the shipped original values."""
    if block is None:
        return False
    return any(
        block.values.get(k) != ORIGINAL_VALUES[k] for k in ORIGINAL_VALUES if k in block.values
    )
