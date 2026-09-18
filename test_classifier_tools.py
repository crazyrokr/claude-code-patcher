#!/usr/bin/env python3
"""Unit tests for the classifier timeout tooling (classifier_scan + CLIs).

Stdlib-only (unittest). Every test follows Given-When-Then. Includes the
false-positive scenarios: the bridge `function TQe(...)` overload, a
non-classifier `var TQe=...` block, and length-changing rewrites that must be
refused by default.

Run:  python3 -m unittest test_classifier_tools -v
"""

from __future__ import annotations

import contextlib
import io
import json
import os
import re
import shutil
import socket
import struct
import subprocess
import sys
import tarfile
import tempfile
import threading
import time
import unittest
from typing import Dict
from unittest import mock

sys.path.insert(
    0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "tools")
)

import classifier_scan as cs  # noqa: E402
import find_classifier_timeouts as fct  # noqa: E402
import live_scan as ls  # noqa: E402
import patch_classifier_timeout as pcp  # noqa: E402
import verify_classifier_patch as vcp  # noqa: E402

sys.path.insert(
    0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "tools", "binder")
)
import oracle_bind_auto as oba  # noqa: E402


def make_block(
    values: Dict[str, int] | None = None,
    offset: int = 0,
    region: str = "source",
) -> cs.ConstantBlock:
    vals = dict(cs.ORIGINAL_VALUES)
    if values is not None:
        vals.update(values)
    return cs.ConstantBlock(offset=offset, values=vals, region=region)


SYNTH_BLOCK = b"var TQe=60000,L8=120000,Lrn=60000,Frn=4,$rn=0,Brn=2000,Urn=10000;"
SYNTH_HRN = b"function Hrn(e){return 30000;}"
SOURCE_LAYOUT = {
    "native": (0, 1),
    "live_string_pool": (0, 1),
    "live_code": (0, 1),
    "source": (0, 10 ** 9),
}


class TestFindAll(unittest.TestCase):
    def test_finds_all_occurrences_in_order(self) -> None:
        # Given: a buffer with three occurrences of a needle.
        data = b"aXXbXXcXXd"
        # When: every occurrence is requested.
        out = cs.find_all(data, b"XX")
        # Then: offsets are returned in ascending order.
        self.assertEqual(out, [1, 4, 7])

    def test_absent_needle(self) -> None:
        # Given: a buffer without the needle.
        data = b"hello"
        # When: the needle is searched.
        out = cs.find_all(data, b"zz")
        # Then: no offsets are reported.
        self.assertEqual(out, [])


class TestFindIdentifier(unittest.TestCase):
    def test_word_boundary_match(self) -> None:
        # Given: TQe used standalone.
        data = b"var TQe=60000;TQe()"
        # When: the identifier is located.
        out = cs.find_identifier(data, "TQe")
        # Then: both standalone uses are found.
        self.assertEqual(len(out), 2)

    def test_boundary_chars_excluded(self) -> None:
        # Given: an identifier with punctuation boundaries.
        data = b"(TQe);[L8]"
        # When: both are located.
        out_tqe = cs.find_identifier(data, "TQe")
        out_l8 = cs.find_identifier(data, "L8")
        # Then: punctuation is a valid boundary for both (L8 sits at offset 7).
        self.assertEqual(out_tqe, [1])
        self.assertEqual(out_l8, [7])

    def test_embedded_occurrence_is_rejected(self) -> None:
        # Given: TQe only inside longer identifiers (false-positive trap).
        data = b"xyTQe=1;TQe2=2;$TQe=3;TQee=4"
        # When: the identifier is located with word boundaries enforced.
        out = cs.find_identifier(data, "TQe")
        # Then: none of the embedded forms count.
        self.assertEqual(out, [])

    def test_dollar_and_underscore_are_identifier_chars(self) -> None:
        # Given: an identifier adjacent to $ and _.
        data = b"$L8=1;L8_=2;=L8;"
        # When: L8 is located.
        out = cs.find_identifier(data, "L8")
        # Then: only the bare `=L8;` occurrence matches (offset 13).
        self.assertEqual(out, [13])


class TestClassifyOffset(unittest.TestCase):
    def test_each_region_label(self) -> None:
        layout = {
            "native": (0, 100),
            "live_string_pool": (100, 200),
            "live_code": (200, 300),
            "source": (300, 400),
        }
        # Given/When/Then: one offset per region, plus one beyond every range.
        self.assertEqual(cs.classify_offset(50, layout), "native")
        self.assertEqual(cs.classify_offset(150, layout), "live_string_pool")
        self.assertEqual(cs.classify_offset(250, layout), "live_code")
        self.assertEqual(cs.classify_offset(350, layout), "source")
        self.assertEqual(cs.classify_offset(450, layout), "unknown")

    def test_default_layout_detects_source_region(self) -> None:
        layout = cs.detect_layout(b"")
        # Given: the measured layout anchors.
        # When: an offset inside the real source window is classified.
        # Then: it is labelled source, and a native one is native.
        self.assertEqual(cs.classify_offset(190_000_000, layout), "source")
        self.assertEqual(cs.classify_offset(5_000_000, layout), "native")


class TestFindConstantBlocks(unittest.TestCase):
    def test_synthetic_block_parsed_with_all_values(self) -> None:
        # Given: one canonical classifier declaration.
        data = b"\x00" * 10 + SYNTH_BLOCK
        # When: blocks are located.
        blocks = cs.find_constant_blocks(data, SOURCE_LAYOUT)
        # Then: exactly one block, at the right offset, with all values.
        self.assertEqual(len(blocks), 1)
        self.assertEqual(blocks[0].offset, 10)
        self.assertEqual(blocks[0].values, cs.ORIGINAL_VALUES)
        self.assertEqual(blocks[0].region, "source")

    def test_incomplete_declaration_is_not_matched(self) -> None:
        # Given: a var block that is missing classifier fields (false positive).
        data = b"var TQe=60000,L8=120000;"
        # When: blocks are located.
        blocks = cs.find_constant_blocks(data, SOURCE_LAYOUT)
        # Then: it is not treated as the classifier block.
        self.assertEqual(blocks, [])

    def test_exponential_literal_is_captured_whole(self) -> None:
        # Given: Urn written as 1e4 (exponential form).
        data = (
            b"var TQe=60000,L8=120000,Lrn=60000,Frn=4,$rn=0,Brn=2000,Urn=1e4;"
        )
        # When: blocks are located.
        blocks = cs.find_constant_blocks(data, SOURCE_LAYOUT)
        # Then: Urn is 10000, not the leading `1`.
        self.assertEqual(blocks[0].values["Urn"], 10000)

    def test_multiple_blocks_sorted_by_offset(self) -> None:
        # Given: two declarations (e.g. source + a live copy).
        filler = b"filler-padding-" * 4
        data = SYNTH_BLOCK + filler + SYNTH_BLOCK
        # When: blocks are located.
        blocks = cs.find_constant_blocks(data, SOURCE_LAYOUT)
        # Then: they come back in ascending offset order.
        self.assertEqual(len(blocks), 2)
        self.assertLess(blocks[0].offset, blocks[1].offset)


class TestFindHrnBodies(unittest.TestCase):
    def test_body_and_return_extracted(self) -> None:
        # Given: a Hrn step function with a numeric return.
        data = b"function Hrn(e){return 30000;}"
        # When: Hrn bodies are located.
        bodies = cs.find_hrn_bodies(data, SOURCE_LAYOUT)
        # Then: the body text and return literal are both captured.
        self.assertEqual(len(bodies), 1)
        self.assertEqual(bodies[0].body, b"return 30000;")
        self.assertEqual(bodies[0].return_value, 30000)

    def test_non_numeric_return_is_none(self) -> None:
        # Given: a Hrn body that returns an identifier.
        data = b"function Hrn(e){return kbe();}"
        # When: bodies are located.
        bodies = cs.find_hrn_bodies(data, SOURCE_LAYOUT)
        # Then: the return value is reported as unknown, not guessed.
        self.assertIsNone(bodies[0].return_value)


class TestDigitPreservingMax(unittest.TestCase):
    def test_known_widths(self) -> None:
        # Given/When/Then: maxima for digit counts 0, 1, 5, 7.
        self.assertEqual(cs.digit_preserving_max(0), 0)
        self.assertEqual(cs.digit_preserving_max(1), 9)
        self.assertEqual(cs.digit_preserving_max(5), 99999)
        self.assertEqual(cs.digit_preserving_max(7), 9999999)


class TestRewriteInt32(unittest.TestCase):
    def test_replace_preserves_length(self) -> None:
        # Given: a 4-byte little-endian 60000.
        data = b"\x00" * 8 + struct.pack("<i", 60000)
        # When: it is rewritten to 99999 in place.
        new_data, applied = cs.rewrite_int32_inplace(data, 8, 99999)
        # Then: length is unchanged and the value round-trips.
        self.assertTrue(applied)
        self.assertEqual(len(new_data), len(data))
        self.assertEqual(struct.unpack("<i", new_data[8:12])[0], 99999)

    def test_out_of_range_offset_refused(self) -> None:
        # Given: a buffer too short for the write.
        data = b"\x00" * 2
        # When: a rewrite is attempted past the end.
        new_data, applied = cs.rewrite_int32_inplace(data, 0, 1)
        # Then: it is refused and the data is untouched.
        self.assertFalse(applied)
        self.assertEqual(new_data, data)

    def test_oversized_value_refused(self) -> None:
        # Given: a value outside int32 range.
        data = b"\x00" * 4
        # When: the value cannot be packed.
        new_data, applied = cs.rewrite_int32_inplace(data, 0, 2 ** 40)
        # Then: struct.error is absorbed, nothing applied.
        self.assertFalse(applied)
        self.assertEqual(new_data, data)


class TestSpanOfValue(unittest.TestCase):
    def test_plain_integer_span(self) -> None:
        # Given: a block text with a plain integer value.
        text = b"TQe=60000,L8=120000;"
        # When: the span of TQe's value is requested.
        span = cs._span_of_value(text, "TQe")
        # Then: the relative offset lands on the digits.
        self.assertEqual(span, (4, b"60000"))

    def test_exponential_span_is_whole(self) -> None:
        # Given: a value in exponential form.
        text = b"Urn=1e4;"
        # When: the span is requested.
        span = cs._span_of_value(text, "Urn")
        # Then: the whole literal is captured, not just `1`.
        self.assertEqual(span, (4, b"1e4"))

    def test_fractional_span(self) -> None:
        # Given: a fractional value.
        text = b"L8=120000.5;"
        # When: the span is requested.
        span = cs._span_of_value(text, "L8")
        # Then: fraction included.
        self.assertEqual(span, (3, b"120000.5"))

    def test_absent_name_is_none(self) -> None:
        # Given: text without the named field.
        text = b"Brn=2000;"
        # When: a different name is requested.
        span = cs._span_of_value(text, "Urn")
        # Then: no span is reported.
        self.assertIsNone(span)


class TestApplySourcePatch(unittest.TestCase):
    def test_default_raises_all_three_to_length_safe_max(self) -> None:
        # Given: an unpatched classifier block plus Hrn.
        data = SYNTH_BLOCK + b" " + SYNTH_HRN
        # When: TQe/L8/Lrn are raised to their digit-count maxima.
        res = cs.apply_source_patch(
            data, {"TQe": 99999, "L8": 999999, "Lrn": 99999}
        )
        # Then: applied, byte length preserved, values replaced in place.
        self.assertTrue(res.ok)
        self.assertEqual(len(res.data), len(data))
        self.assertIn(b"TQe=99999,", res.data)
        self.assertIn(b"L8=999999,", res.data)
        self.assertIn(b"Lrn=99999,", res.data)
        self.assertNotIn(b"60000", res.data)

    def test_idempotent_when_values_already_target(self) -> None:
        # Given: a buffer already at the target values.
        data = (
            b"var TQe=99999,L8=999999,Lrn=99999,Frn=4,$rn=0,Brn=2000,Urn=10000;"
        )
        # When: the same targets are requested.
        res = cs.apply_source_patch(data, {"TQe": 99999, "L8": 999999, "Lrn": 99999})
        # Then: no edits, data byte-identical.
        self.assertTrue(res.ok)
        self.assertEqual(res.ops, [])
        self.assertEqual(res.data, data)

    def test_length_change_refused_by_default(self) -> None:
        # Given: an unpatched block (false-positive-safe trap: tempting bump).
        data = SYNTH_BLOCK
        # When: TQe is raised to a 6-digit value without the override flag.
        res = cs.apply_source_patch(data, {"TQe": 600000})
        # Then: refused all-or-nothing, data untouched.
        self.assertFalse(res.ok)
        self.assertEqual(res.data, data)
        self.assertEqual(res.ops, [])

    def test_length_change_allowed_with_flag(self) -> None:
        # Given: an unpatched block.
        data = SYNTH_BLOCK
        # When: the caller explicitly allows a length change.
        res = cs.apply_source_patch(
            data, {"TQe": 600000}, allow_length_change=True
        )
        # Then: applied, and the length grew by exactly one byte.
        self.assertTrue(res.ok)
        self.assertIn(b"TQe=600000,", res.data)
        self.assertEqual(len(res.data), len(data) + 1)

    def test_all_or_nothing_when_one_edit_refused(self) -> None:
        # Given: two requested edits, one of which changes byte length.
        data = SYNTH_BLOCK
        # When: TQe is fine but L8 is bumped to 7 digits without the flag.
        res = cs.apply_source_patch(data, {"TQe": 99999, "L8": 9999999})
        # Then: nothing is applied, not even the good edit.
        self.assertFalse(res.ok)
        self.assertEqual(res.data, data)

    def test_unknown_name_is_ignored(self) -> None:
        # Given: an unpatched block.
        data = SYNTH_BLOCK
        # When: a name that is not part of the declaration is requested.
        res = cs.apply_source_patch(data, {"zzz": 1})
        # Then: ok, no ops, data unchanged.
        self.assertTrue(res.ok)
        self.assertEqual(res.ops, [])
        self.assertEqual(res.data, data)

    def test_no_block_found_is_refused(self) -> None:
        # Given: a buffer with no classifier declaration.
        data = b"nothing to see here"
        # When: a patch is requested.
        res = cs.apply_source_patch(data, {"TQe": 99999})
        # Then: refused with an explanatory error.
        self.assertFalse(res.ok)
        self.assertTrue(res.errors)
        self.assertEqual(res.data, data)

    def test_hrn_rewrite_preserves_byte_length(self) -> None:
        # Given: Hrn body `return 30000;` (12 chars inside the braces).
        data = SYNTH_BLOCK + b" " + SYNTH_HRN
        # When: the return is swapped for an equal-length value.
        res = cs.apply_source_patch(data, {}, hrn_return=99999)
        # Then: applied, total length preserved, no padding needed.
        self.assertTrue(res.ok)
        self.assertEqual(len(res.data), len(data))
        self.assertIn(b"return 99999;}", res.data)

    def test_hrn_rewrite_refused_when_new_value_longer(self) -> None:
        # Given: a short Hrn body.
        data = b"function Hrn(e){return 30;}"
        # When: the new literal does not fit the original body.
        res = cs.apply_source_patch(data, {}, hrn_return=999999999)
        # Then: refused to preserve byte length.
        self.assertFalse(res.ok)
        self.assertEqual(res.data, data)

    def test_hrn_rewrite_pads_with_spaces(self) -> None:
        # Given: block plus Hrn body `return 30000;` (12 chars inside braces).
        data = SYNTH_BLOCK + b" " + SYNTH_HRN
        # When: the return is swapped for a shorter literal (11 chars).
        res = cs.apply_source_patch(data, {}, hrn_return=9999)
        # Then: space-padded to the original length before the closing brace.
        self.assertTrue(res.ok)
        self.assertEqual(len(res.data), len(data))
        self.assertIn(b"return 9999; }", res.data)

    def test_combined_value_and_hrn_edits(self) -> None:
        # Given: block + Hrn together.
        data = SYNTH_BLOCK + b" " + SYNTH_HRN
        # When: both value edits and the Hrn rewrite are requested.
        res = cs.apply_source_patch(data, {"TQe": 99999}, hrn_return=45678)
        # Then: both edits land, length preserved, two ops recorded.
        self.assertTrue(res.ok)
        self.assertEqual(len(res.data), len(data))
        self.assertIn(b"TQe=99999,", res.data)
        self.assertIn(b"return 45678;}", res.data)
        self.assertEqual(len(res.ops), 2)


class TestIsSourcePatched(unittest.TestCase):
    def test_original_values_are_unpatched(self) -> None:
        # Given/When/Then: shipped values -> not patched.
        self.assertFalse(cs.is_source_patched(make_block()))

    def test_deviation_is_patched(self) -> None:
        # Given: a single changed constant.
        block = make_block(values={"TQe": 99999})
        # When: it is classified.
        patched = cs.is_source_patched(block)
        # Then: it counts as patched.
        self.assertTrue(patched)

    def test_none_block_is_unpatched(self) -> None:
        # Given: no block at all.
        # When/Then: safe default, no crash.
        self.assertFalse(cs.is_source_patched(None))


class TestVerifyEvaluate(unittest.TestCase):
    def test_no_blocks_is_unknown(self) -> None:
        # Given: no constant blocks located.
        verdict, src, notes = vcp.evaluate([])
        # When/Then: verdict is UNKNOWN with an explanatory note.
        self.assertEqual(verdict, vcp.VERDICT_UNKNOWN)
        self.assertIsNone(src)
        self.assertTrue(notes)

    def test_source_unpatched_is_unpatched(self) -> None:
        # Given: only a source block with shipped values.
        blocks = [make_block(region="source")]
        # When: the state is evaluated.
        verdict, _, _ = vcp.evaluate(blocks)
        # Then: UNPATCHED.
        self.assertEqual(verdict, vcp.VERDICT_UNPATCHED)

    def test_source_only_patch_is_flagged_as_no_op(self) -> None:
        # Given: the source block is patched but no live block exists
        # (the user's current binary state).
        blocks = [make_block(values={"TQe": 99999}, region="source")]
        # When: the state is evaluated.
        verdict, src, notes = vcp.evaluate(blocks)
        # Then: SOURCE_ONLY, with a note that the live timeout is unconfirmed.
        self.assertEqual(verdict, vcp.VERDICT_SOURCE_ONLY)
        self.assertIsNotNone(src)
        self.assertTrue(any("NOT confirmed" in n for n in notes))

    def test_live_block_patched_wins(self) -> None:
        # Given: a patched block inside the live bytecode region.
        blocks = [
            make_block(region="source"),
            make_block(values={"L8": 999999}, region="live_code"),
        ]
        # When: the state is evaluated.
        verdict, _, notes = vcp.evaluate(blocks)
        # Then: PATCHED_LIVE regardless of the source copy.
        self.assertEqual(verdict, vcp.VERDICT_LIVE)
        self.assertTrue(any("patched" in n for n in notes))

    def test_live_unpatched_source_unpatched(self) -> None:
        # Given: both copies still carry shipped values.
        blocks = [
            make_block(region="source"),
            make_block(region="live_code"),
        ]
        # When: the state is evaluated.
        verdict, _, notes = vcp.evaluate(blocks)
        # Then: UNPATCHED, and the live copy is called out explicitly.
        self.assertEqual(verdict, vcp.VERDICT_UNPATCHED)
        self.assertTrue(any("live region" in n for n in notes))

    def test_pick_source_prefers_source_region(self) -> None:
        # Given: two blocks, one per region.
        blocks = [
            make_block(offset=1, region="live_code"),
            make_block(offset=2, region="source"),
        ]
        # When/Then: the source one is selected.
        self.assertEqual(vcp.pick_source_block(blocks).offset, 2)

    def test_pick_source_falls_back_to_first(self) -> None:
        # Given: no block is in the source region.
        blocks = [make_block(offset=1, region="live_code")]
        # When/Then: the first block is used, not None.
        self.assertEqual(vcp.pick_source_block(blocks).offset, 1)


class TestPatcherHelpers(unittest.TestCase):
    def test_length_safe_max_for_classifier_values(self) -> None:
        # Given: the shipped classifier values.
        # When: their length-safe maxima are computed.
        # Then: 60000->99999, 120000->999999.
        self.assertEqual(pcp.length_safe_max(60000), 99999)
        self.assertEqual(pcp.length_safe_max(120000), 999999)

    def test_default_targets_raise_only_the_big_three(self) -> None:
        # Given: an unpatched block.
        block = make_block()
        # When: default targets are derived.
        targets = pcp.default_targets(block)
        # Then: exactly TQe/L8/Lrn, all larger, none length-changing.
        self.assertEqual(set(targets), {"TQe", "L8", "Lrn"})
        for name, new_val in targets.items():
            old = block.values[name]
            self.assertGreater(new_val, old)
            self.assertEqual(len(str(new_val)), len(str(old)))

    def test_default_targets_empty_when_already_max(self) -> None:
        # Given: a block already at its maxima.
        block = make_block(values={"TQe": 99999, "L8": 999999, "Lrn": 99999})
        # When: default targets are derived.
        targets = pcp.default_targets(block)
        # Then: nothing to raise.
        self.assertEqual(targets, {})


class TestPatcherMain(unittest.TestCase):
    def _synthetic_binary(self, tmp: str) -> str:
        path = os.path.join(tmp, "fake-binary")
        payload = b"PRE" + SYNTH_BLOCK + b" " + SYNTH_HRN + b"POST"
        with open(path, "wb") as f:
            f.write(payload)
        return path

    def test_dry_run_changes_nothing(self) -> None:
        # Given: a synthetic binary with the classifier block.
        with tempfile.TemporaryDirectory() as tmp:
            path = self._synthetic_binary(tmp)
            before = open(path, "rb").read()
            # When: a dry-run is requested.
            with contextlib.redirect_stdout(io.StringIO()) as out:
                code = pcp.main([path, "--dry-run"])
            # Then: exit 0, the file is byte-identical, no .patched copy.
            self.assertEqual(code, 0)
            self.assertEqual(open(path, "rb").read(), before)
            self.assertFalse(os.path.exists(path + ".patched"))
            self.assertIn("dry-run", out.getvalue())

    def test_rejects_length_change_by_default(self) -> None:
        # Given: a synthetic binary.
        with tempfile.TemporaryDirectory() as tmp:
            path = self._synthetic_binary(tmp)
            before = open(path, "rb").read()
            # When: TQe is requested at 6 digits without the override flag.
            with contextlib.redirect_stdout(io.StringIO()) as out:
                code = pcp.main([path, "--tqe", "600000"])
            # Then: refused, nothing written, guidance still printed.
            self.assertEqual(code, 1)
            self.assertEqual(open(path, "rb").read(), before)
            self.assertFalse(os.path.exists(path + ".patched"))
            self.assertIn("bypassPermissions", out.getvalue())

    def test_writes_patched_copy_with_length_preserved(self) -> None:
        # Given: a synthetic binary.
        with tempfile.TemporaryDirectory() as tmp:
            path = self._synthetic_binary(tmp)
            before = open(path, "rb").read()
            # When: default targets are applied without --in-place.
            with contextlib.redirect_stdout(io.StringIO()):
                code = pcp.main([path])
            # Then: a same-length .patched copy with the raised values.
            self.assertEqual(code, 0)
            patched = open(path + ".patched", "rb").read()
            self.assertEqual(len(patched), len(before))
            self.assertIn(b"TQe=99999,", patched)
            self.assertIn(b"L8=999999,", patched)
            self.assertEqual(before, open(path, "rb").read())

    def test_allow_length_change_flag_lifts_guard(self) -> None:
        # Given: a synthetic binary.
        with tempfile.TemporaryDirectory() as tmp:
            path = self._synthetic_binary(tmp)
            before = open(path, "rb").read()
            # When: a 6-digit TQe is requested with the explicit override.
            with contextlib.redirect_stdout(io.StringIO()) as out:
                code = pcp.main([path, "--tqe", "600000", "--allow-length-change"])
            # Then: applied, and the length change is disclosed.
            self.assertEqual(code, 0)
            patched = open(path + ".patched", "rb").read()
            self.assertIn(b"TQe=600000,", patched)
            self.assertIn("CHANGED", out.getvalue())

    def test_in_place_writes_original_path(self) -> None:
        # Given: a synthetic binary.
        with tempfile.TemporaryDirectory() as tmp:
            path = self._synthetic_binary(tmp)
            # When: --in-place is used.
            with contextlib.redirect_stdout(io.StringIO()):
                code = pcp.main([path, "--in-place"])
            # Then: the original path now carries the patch, no copy.
            self.assertEqual(code, 0)
            self.assertIn(b"TQe=99999,", open(path, "rb").read())
            self.assertFalse(os.path.exists(path + ".patched"))

    def test_missing_binary_exit_2(self) -> None:
        # Given: a nonexistent path.
        # When: main is invoked.
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            code = pcp.main(["/nonexistent/binary"])
        # Then: usage error code 2 and a clear message.
        self.assertEqual(code, 2)
        self.assertIn("not found", err.getvalue())

    def test_no_block_refuses_instead_of_guessing(self) -> None:
        # Given: a buffer without the classifier declaration.
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "no-block")
            with open(path, "wb") as f:
                f.write(b"just some bytes")
            # When: a patch is requested.
            stdout, stderr = io.StringIO(), io.StringIO()
            with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                code = pcp.main([path])
            # Then: refused (message on stderr), reliable fixes still on stdout.
            self.assertEqual(code, 1)
            self.assertIn("refusing to guess", stderr.getvalue())
            self.assertIn("bypassPermissions", stdout.getvalue())

    def test_already_at_targets_is_noop(self) -> None:
        # Given: a synthetic binary already at the maxima.
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "at-max")
            payload = (
                b"var TQe=99999,L8=999999,Lrn=99999,Frn=4,$rn=0,Brn=2000,Urn=10000;"
            )
            with open(path, "wb") as f:
                f.write(payload)
            # When: defaults are computed against it.
            with contextlib.redirect_stdout(io.StringIO()) as out:
                code = pcp.main([path])
            # Then: nothing to change, no output file.
            self.assertEqual(code, 0)
            self.assertIn("nothing to change", out.getvalue())
            self.assertFalse(os.path.exists(path + ".patched"))


class TestInPlaceRollback(unittest.TestCase):
    """Regression tests for the two patched defects: --in-place used to
    corrupt the original on a failed self-test with no rollback, and a
    requested Hrn rewrite that could not be located used to be swallowed into
    a successful byte-for-byte no-op copy."""

    def _synthetic_binary(self, tmp: str, name: str = "fake-binary") -> str:
        path = os.path.join(tmp, name)
        payload = b"PRE" + SYNTH_BLOCK + b" " + SYNTH_HRN + b"POST"
        with open(path, "wb") as f:
            f.write(payload)
        return path

    def test_failed_self_test_restores_original_in_place(self) -> None:
        # Given: a synthetic binary and a self-test that reports failure.
        with tempfile.TemporaryDirectory() as tmp:
            path = self._synthetic_binary(tmp)
            original = open(path, "rb").read()
            with mock.patch.object(
                pcp, "run_self_test", return_value=(False, "exit=137 output='crash'")
            ):
                # When: an in-place patch with the self-test gate is requested.
                with contextlib.redirect_stdout(io.StringIO()) as out:
                    code = pcp.main([path, "--in-place", "--self-test"])
            # Then: the original is back byte-for-byte, the failed staged copy
            # is gone, the backup is intact, and the exit code is a failure.
            self.assertEqual(code, 1)
            self.assertEqual(open(path, "rb").read(), original)
            self.assertEqual(open(path + ".orig", "rb").read(), original)
            self.assertCountEqual(os.listdir(tmp), ["fake-binary", "fake-binary.orig"])
            self.assertIn("self-test: FAIL", out.getvalue())

    def test_passing_self_test_swaps_patched_binary_in_place(self) -> None:
        # Given: a "binary" that is a valid stub script (executes, exits 0)
        # whose classifier block lives after the exit line.
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "fake-binary")
            script = b'#!/bin/sh\necho "9.9.9 (stub)"\nexit 0\n'
            with open(path, "wb") as f:
                f.write(script + SYNTH_BLOCK + b" " + SYNTH_HRN + b"POST\n")
            os.chmod(path, 0o755)
            original = open(path, "rb").read()
            # When: an in-place patch runs its real self-test gate.
            with contextlib.redirect_stdout(io.StringIO()) as out:
                code = pcp.main([path, "--in-place", "--self-test"])
            # Then: the patched values are live at the original path, the file
            # still executes, and the original is preserved in the backup.
            self.assertEqual(code, 0)
            self.assertIn(b"TQe=99999,", open(path, "rb").read())
            self.assertEqual(open(path + ".orig", "rb").read(), original)
            self.assertIn("self-test: PASS", out.getvalue())
            proc = subprocess.run(
                [path, "--version"], capture_output=True, text=True, timeout=30
            )
            self.assertEqual(proc.returncode, 0)
            self.assertIn("9.9.9", proc.stdout)

    def test_non_inplace_failed_self_test_removes_copy(self) -> None:
        # Given: a synthetic binary and a self-test that reports failure.
        with tempfile.TemporaryDirectory() as tmp:
            path = self._synthetic_binary(tmp)
            original = open(path, "rb").read()
            with mock.patch.object(
                pcp, "run_self_test", return_value=(False, "exit=1 output='crash'")
            ):
                # When: a copy-based patch with the self-test gate is requested.
                with contextlib.redirect_stdout(io.StringIO()) as out:
                    code = pcp.main([path, "--self-test"])
            # Then: exit 1, the failed copy is removed, the original is intact.
            self.assertEqual(code, 1)
            self.assertEqual(open(path, "rb").read(), original)
            self.assertFalse(os.path.exists(path + ".patched"))
            self.assertIn("removing failed patched copy", out.getvalue())

    def test_hrn_not_found_is_a_refusal(self) -> None:
        # Given: data that carries the constant block but no Hrn function.
        data = SYNTH_BLOCK
        # When: a Hrn rewrite is requested at the engine level.
        result = cs.apply_source_patch(data, {}, hrn_return=5)
        # Then: the whole patch is refused and nothing is applied.
        self.assertFalse(result.ok)
        self.assertEqual(result.ops, [])
        self.assertTrue(any("Hrn" in e for e in result.errors))
        self.assertEqual(result.data, data)

    def test_cli_hrn_not_found_writes_nothing(self) -> None:
        # Given: a synthetic binary with the block but no Hrn function.
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "no-hrn")
            with open(path, "wb") as f:
                f.write(SYNTH_BLOCK)
            original = open(path, "rb").read()
            # When: a Hrn rewrite is requested through the CLI.
            with contextlib.redirect_stdout(io.StringIO()) as out:
                code = pcp.main([path, "--hrn", "5"])
            # Then: refused, nothing written, and the Hrn error is surfaced.
            self.assertEqual(code, 1)
            self.assertEqual(open(path, "rb").read(), original)
            self.assertFalse(os.path.exists(path + ".patched"))
            self.assertIn("Hrn", out.getvalue())
            self.assertIn("bypassPermissions", out.getvalue())

    def test_explicit_values_already_present_is_noop(self) -> None:
        # Given: a synthetic binary at the shipped values.
        with tempfile.TemporaryDirectory() as tmp:
            path = self._synthetic_binary(tmp)
            original = open(path, "rb").read()
            # When: every target is requested at exactly its current value.
            with contextlib.redirect_stdout(io.StringIO()) as out:
                code = pcp.main(
                    [path, "--tqe", "60000", "--l8", "120000", "--lrn", "60000"]
                )
            # Then: no byte-for-byte no-op copy is shipped; exit 0 with notice.
            self.assertEqual(code, 0)
            self.assertEqual(open(path, "rb").read(), original)
            self.assertFalse(os.path.exists(path + ".patched"))
            self.assertIn("no-op", out.getvalue())

    def test_preexisting_backup_is_not_clobbered(self) -> None:
        # Given: a synthetic binary plus a backup from an earlier run holding
        # different bytes.
        with tempfile.TemporaryDirectory() as tmp:
            path = self._synthetic_binary(tmp)
            backup = path + ".orig"
            sentinel = b"earlier original"
            with open(backup, "wb") as f:
                f.write(sentinel)
            # When: an in-place patch is applied.
            with contextlib.redirect_stdout(io.StringIO()):
                code = pcp.main([path, "--in-place"])
            # Then: the patch lands and the earlier backup is left untouched.
            self.assertEqual(code, 0)
            self.assertIn(b"TQe=99999,", open(path, "rb").read())
            self.assertEqual(open(backup, "rb").read(), sentinel)


class TestVerifyMain(unittest.TestCase):
    def test_unpatched_synthetic_binary_exit_1(self) -> None:
        # Given: a binary carrying the shipped classifier values.
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "bin")
            with open(path, "wb") as f:
                f.write(SYNTH_BLOCK)
            # When: the verifier runs.
            with contextlib.redirect_stdout(io.StringIO()) as out:
                code = vcp.main([path])
            # Then: exit 1 with UNPATCHED.
            self.assertEqual(code, 1)
            self.assertIn("UNPATCHED", out.getvalue())

    def test_source_only_synthetic_binary_exit_1(self) -> None:
        # Given: a binary whose block is patched but in the source region
        # (exactly the user's current, no-op state).
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "bin")
            payload = (
                b"var TQe=99999,L8=999999,Lrn=99999,Frn=4,$rn=0,Brn=2000,Urn=10000;"
            )
            with open(path, "wb") as f:
                f.write(payload)
            # When: the verifier runs.
            with contextlib.redirect_stdout(io.StringIO()) as out:
                code = vcp.main([path])
            # Then: exit 1, verdict exposes the runtime no-op.
            self.assertEqual(code, 1)
            self.assertIn(vcp.VERDICT_SOURCE_ONLY, out.getvalue())

    def test_missing_binary_exit_2(self) -> None:
        # Given/When: a nonexistent path.
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            code = vcp.main(["/nonexistent/binary"])
        # Then: exit 2.
        self.assertEqual(code, 2)


class TestFinderMain(unittest.TestCase):
    def test_report_prints_regions_and_blocks(self) -> None:
        # Given: a synthetic binary with one classifier block.
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "bin")
            with open(path, "wb") as f:
                f.write(SYNTH_BLOCK)
            # When: the finder runs.
            with contextlib.redirect_stdout(io.StringIO()) as out:
                code = fct.main([path])
            # Then: exit 0, and the block values plus the layout are shown.
            self.assertEqual(code, 0)
            text = out.getvalue()
            self.assertIn("TQe=60000", text)
            self.assertIn("Measured region layout", text)

    def test_missing_binary_exit_2(self) -> None:
        # Given/When: a nonexistent path.
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            code = fct.main(["/nonexistent/binary"])
        # Then: exit 2.
        self.assertEqual(code, 2)


class TestEndToEnd(unittest.TestCase):
    def test_find_verify_patch_roundtrip_on_synthetic_binary(self) -> None:
        # Given: a synthetic binary with original values.
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "bin")
            with open(path, "wb") as f:
                f.write(b"PRE" + SYNTH_BLOCK + b" " + SYNTH_HRN + b"POST")
            # When: the full pipeline runs — find, verify (unpatched), patch.
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(fct.main([path]), 0)
                self.assertEqual(vcp.main([path]), 1)
                self.assertEqual(pcp.main([path, "--in-place"]), 0)
            # Then: the verifier now reads the patched values in the same file.
            data = open(path, "rb").read()
            self.assertIn(b"TQe=99999,", data)
            with contextlib.redirect_stdout(io.StringIO()) as out:
                code = vcp.main([path])
            self.assertEqual(code, 1)
            self.assertIn(vcp.VERDICT_SOURCE_ONLY, out.getvalue())


# --- Reference-anchored live scan (live_scan.py) -----------------------------

# Two 24-bit hashes chosen so no LE 4-byte form of them, of the constraint
# values, or of small ordinal/offset indices equals another's. Filler byte 0xee
# (absent from every value below) breaks zero-runs so the only 4-byte matches
# in the live region are the deliberately planted references.
HA = 0x123456
HB = 0x234567
FILLER = b"\xee"
CONSTRAINTS = (60000, 120000, 2000, 10000)


def _pool_entry(name: str, hval: int) -> bytes:
    body = name.encode()
    return (
        bytes([len(body)])
        + b"\x00\x00\x80"
        + (hval & 0xFFFFFF).to_bytes(3, "little")
        + b"\x00"
        + body
        + b"\x00"
    )


def _packed(values) -> bytes:
    return b"".join(struct.pack("<i", v) + FILLER for v in values)


class TestParsePool(unittest.TestCase):
    def test_parses_valid_entry(self) -> None:
        # Given: one well-formed pool entry.
        data = _pool_entry("classifierStage", HA)
        # When: the pool is parsed over its full extent.
        entries = ls.parse_pool(data, (0, len(data)))
        # Then: a single entry with ordinal 0, the string, and the 24-bit hash.
        self.assertEqual(len(entries), 1)
        e = entries[0]
        self.assertEqual(e.ordinal, 0)
        self.assertEqual(e.string, b"classifierStage")
        self.assertEqual(e.hval, HA)
        self.assertEqual(e.length, len(b"classifierStage"))

    def test_rejects_len_zero_header(self) -> None:
        # Given: a header whose length byte is 0.
        data = b"\x00\x00\x00\x80" + b"\x11\x22\x33" + b"\x00" + b"abc" + b"\x00"
        # When: parsed.
        entries = ls.parse_pool(data, (0, len(data)))
        # Then: rejected (len must be >= 1).
        self.assertEqual(entries, [])

    def test_rejects_non_printable_chars(self) -> None:
        # Given: a header with a control byte in the string body.
        data = bytes([3]) + b"\x00\x00\x80" + b"\x11\x22\x33" + b"\x00" + b"a\x01c" + b"\x00"
        # When: parsed.
        entries = ls.parse_pool(data, (0, len(data)))
        # Then: rejected (chars must be printable).
        self.assertEqual(entries, [])

    def test_rejects_missing_trailing_nul(self) -> None:
        # Given: a header whose string is not NUL-terminated.
        data = bytes([3]) + b"\x00\x00\x80" + b"\x11\x22\x33" + b"\x00" + b"abc" + b"X"
        # When: parsed.
        entries = ls.parse_pool(data, (0, len(data)))
        # Then: rejected.
        self.assertEqual(entries, [])

    def test_multiple_entries_get_sequential_ordinals(self) -> None:
        # Given: two well-formed entries.
        data = _pool_entry("classifierStage", HA) + _pool_entry("wall_clock_timeout", HB)
        # When: parsed.
        entries = ls.parse_pool(data, (0, len(data)))
        # Then: ordinals are 0 and 1, in file order.
        self.assertEqual([e.ordinal for e in entries], [0, 1])
        self.assertEqual(entries[0].string, b"classifierStage")
        self.assertEqual(entries[1].string, b"wall_clock_timeout")

    def test_ignores_bytes_outside_range(self) -> None:
        # Given: an entry, but the parse range excludes it.
        data = _pool_entry("classifierStage", HA)
        # When: parsed over an empty range.
        entries = ls.parse_pool(data, (0, 0))
        # Then: nothing is found.
        self.assertEqual(entries, [])


class TestResolveAnchors(unittest.TestCase):
    def test_resolves_present_anchors(self) -> None:
        # Given: a pool holding two of the four anchor strings.
        data = _pool_entry("classifierStage", HA) + _pool_entry("wall_clock_timeout", HB)
        entries = ls.parse_pool(data, (0, len(data)))
        # When: anchors are resolved.
        anchors = ls.resolve_anchors(entries)
        # Then: exactly the present ones, in ANCHOR_STRINGS order.
        self.assertEqual([a.name for a in anchors], ["classifierStage", "wall_clock_timeout"])

    def test_skips_missing_anchors(self) -> None:
        # Given: a pool with a non-anchor string.
        data = _pool_entry("someUnrelatedString", HA)
        entries = ls.parse_pool(data, (0, len(data)))
        # When: anchors are resolved.
        anchors = ls.resolve_anchors(entries)
        # Then: none match.
        self.assertEqual(anchors, [])

    def test_empty_pool_yields_no_anchors(self) -> None:
        # Given: no entries.
        # When: resolved.
        anchors = ls.resolve_anchors([])
        # Then: empty.
        self.assertEqual(anchors, [])


class TestReferenceEncodings(unittest.TestCase):
    def test_produces_five_distinct_encodings(self) -> None:
        # Given: one pool entry.
        e = ls.PoolEntry(offset=0, ordinal=0, length=5, string=b"hello",
                         hash3=b"\x56\x34\x12", hval=HA)
        # When: reference encodings are computed.
        encs = ls.reference_encodings(e)
        # Then: five named, 4-byte encodings; hash24 is the LE form of the hash.
        self.assertEqual(set(encs), {"hash24", "hash24_flag80", "ordinal", "ordinal+1", "offset"})
        self.assertEqual(encs["hash24"], struct.pack("<I", HA))
        self.assertEqual(encs["ordinal"], struct.pack("<I", 0))
        self.assertEqual(encs["ordinal+1"], struct.pack("<I", 1))


class TestFindReferenceHits(unittest.TestCase):
    def _pool(self, *names_hvals):
        return b"".join(_pool_entry(n, h) for n, h in names_hvals)

    def test_finds_planted_hash24_reference(self) -> None:
        # Given: one anchor and a live region with exactly one planted hash24 ref.
        pool = self._pool(("classifierStage", HA))
        live = struct.pack("<I", HA) + FILLER
        data = pool + live
        anchors = ls.resolve_anchors(ls.parse_pool(data, (0, len(pool))))
        # When: the live region is swept for references.
        sites, counts = ls.find_reference_hits(data, (len(pool), len(data)), anchors)
        # Then: one site via the hash24 encoding.
        self.assertEqual(len(sites), 1)
        self.assertEqual(sites[0].encoding, "hash24")
        self.assertEqual(counts["hash24"], 1)

    def test_no_hits_when_reference_absent(self) -> None:
        # Given: an anchor but a live region without its reference.
        pool = self._pool(("classifierStage", HA))
        live = FILLER * 8
        data = pool + live
        anchors = ls.resolve_anchors(ls.parse_pool(data, (0, len(pool))))
        # When: swept.
        sites, counts = ls.find_reference_hits(data, (len(pool), len(data)), anchors)
        # Then: no sites.
        self.assertEqual(sites, [])

    def test_flood_of_hits_is_excluded(self) -> None:
        # Given: a reference encoding that occurs more than MAX_PLAUSIBLE_HITS times.
        pool = self._pool(("classifierStage", HA))
        live = (struct.pack("<I", HA) + FILLER) * (ls.MAX_PLAUSIBLE_HITS + 1)
        data = pool + live
        anchors = ls.resolve_anchors(ls.parse_pool(data, (0, len(pool))))
        # When: swept.
        sites, counts = ls.find_reference_hits(data, (len(pool), len(data)), anchors)
        # Then: the flood is not treated as a reference.
        self.assertEqual(sites, [])
        self.assertGreater(counts["hash24"], ls.MAX_PLAUSIBLE_HITS)


class TestInt32Window(unittest.TestCase):
    def test_finds_wanted_values_in_window(self) -> None:
        # Given: all four constraint values near a center point.
        data = b"\x00" * 8 + _packed(CONSTRAINTS)
        # When: the window around the first slot is scanned.
        slots = ls.int32_values_in_window(data, 8, 4096, CONSTRAINTS)
        # Then: every wanted value is collected.
        self.assertEqual({s.value for s in slots}, set(CONSTRAINTS))

    def test_excludes_values_outside_window(self) -> None:
        # Given: a wanted value far beyond the window.
        data = b"\x00" * 8 + struct.pack("<i", 60000) + b"\x00" * 6000 + struct.pack("<i", 120000)
        # When: a small window is scanned around the first slot.
        slots = ls.int32_values_in_window(data, 8, 64, (60000, 120000))
        # Then: only the near value is present.
        self.assertEqual({s.value for s in slots}, {60000})


class TestSetWindows(unittest.TestCase):
    def test_detects_tight_table_and_dedupes_centers(self) -> None:
        # Given: a compact table holding all four values within 64 B (family-B
        # shape), so several anchor occurrences each qualify the window.
        data = b"\x00" * 1024 + _packed(CONSTRAINTS) + b"\x00" * 1024
        base = 1024
        # When: the live region is scanned for set windows.
        cands = ls.find_set_windows(data, (0, len(data)))
        # Then: exactly one candidate (deduped across qualifying centers),
        # holding one slot per value, and the absent aux value maps to None.
        self.assertEqual(len(cands), 1)
        cand = cands[0]
        self.assertEqual(
            {s.value: s.offset for s in cand.slots},
            {v: base + 5 * i for i, v in enumerate(CONSTRAINTS)},
        )
        self.assertIsNone(cand.aux_distances[50000])

    def test_no_candidate_when_values_are_scattered(self) -> None:
        # Given: all four values, but each more than 64 B from every other.
        data = (
            b"\x00" * 64
            + struct.pack("<i", 60000)
            + b"\x00" * 300
            + struct.pack("<i", 120000)
            + b"\x00" * 300
            + struct.pack("<i", 2000)
            + b"\x00" * 300
            + struct.pack("<i", 10000)
            + b"\x00" * 64
        )
        # When: scanned.
        cands = ls.find_set_windows(data, (0, len(data)))
        # Then: no window holds the full set -> no candidate (false-positive guard).
        self.assertEqual(cands, [])

    def test_boundary_distance_is_excluded(self) -> None:
        # Given: two values exactly 65 B apart (one beyond the window), the
        # other two tight next to the far one.
        data = (
            b"\x00" * 64
            + struct.pack("<i", 60000)
            + b"\x00" * 61
            + struct.pack("<i", 120000)
            + b"\x00" * 5
            + struct.pack("<i", 2000)
            + b"\x00" * 5
            + struct.pack("<i", 10000)
            + b"\x00" * 64
        )
        # When: scanned.
        cands = ls.find_set_windows(data, (0, len(data)))
        # Then: no single anchor occurrence sees all four -> no candidate.
        self.assertEqual(cands, [])

    def test_aux_distance_reported_when_near(self) -> None:
        # Given: the tight table plus 50000, 100 B from the first value
        # (60000@64 ... 10000@79, then 80 pad bytes, then 50000@164).
        data = (
            b"\x00" * 64
            + _packed(CONSTRAINTS)
            + b"\x00" * 80
            + struct.pack("<i", 50000)
            + b"\x00" * 64
        )
        # When: scanned.
        cands = ls.find_set_windows(data, (0, len(data)))
        # Then: one candidate, and the aux distance is measured from the first
        # qualifying anchor occurrence (60000@64 -> 50000@164).
        self.assertEqual(len(cands), 1)
        self.assertEqual(cands[0].aux_distances[50000], 100)

    def test_aux_beyond_radius_is_none(self) -> None:
        # Given: the tight table, with 50000 ~4.9 KB away (past the 4096 B radius).
        data = (
            b"\x00" * 64
            + _packed(CONSTRAINTS)
            + b"\x00" * 4900
            + struct.pack("<i", 50000)
            + b"\x00" * 64
        )
        # When: scanned.
        cands = ls.find_set_windows(data, (0, len(data)))
        # Then: one candidate, but the aux value is reported absent.
        self.assertEqual(len(cands), 1)
        self.assertIsNone(cands[0].aux_distances[50000])

    def test_occurrences_outside_range_are_ignored(self) -> None:
        # Given: three values inside the live range and the fourth outside it.
        data = (
            b"\x00" * 16
            + struct.pack("<i", 60000)
            + b"\xee"
            + struct.pack("<i", 120000)
            + b"\xee"
            + struct.pack("<i", 2000)
            + b"\x00" * 40
            + struct.pack("<i", 10000)
        )
        # When: scanned over a range that excludes the fourth value.
        cands = ls.find_set_windows(data, (0, 30))
        # Then: the full set is not in-range -> no candidate.
        self.assertEqual(cands, [])


class TestBuildManifest(unittest.TestCase):
    def _data_with_ref_and_constants(self, refs, const_gap=0):
        pool = self._pool(("classifierStage", HA), ("wall_clock_timeout", HB))
        live = b"".join(struct.pack("<I", r) for r in refs)
        live += b"\x00" * const_gap
        live += _packed(CONSTRAINTS)
        return pool + live, len(pool)

    def _pool(self, *names_hvals):
        return b"".join(_pool_entry(n, h) for n, h in names_hvals)

    def test_unique_single_full_site(self) -> None:
        # Given: one reference site whose neighborhood holds all four values.
        data, pool_len = self._data_with_ref_and_constants([HA])
        site = ls.SiteHit(anchor="classifierStage", encoding="hash24", ref_offset=pool_len)
        # When: the manifest is built.
        m = ls.build_manifest(data, [], [site], {})
        # Then: UNIQUE with four candidate slots.
        self.assertEqual(m.status, "UNIQUE")
        self.assertEqual(len(m.candidates), 4)
        self.assertEqual({c.old for c in m.candidates}, set(CONSTRAINTS))

    def test_ambiguous_two_full_sites(self) -> None:
        # Given: two reference sites, both near the full constant set.
        data, pool_len = self._data_with_ref_and_constants([HA, HB])
        sites = [
            ls.SiteHit(anchor="classifierStage", encoding="hash24", ref_offset=pool_len),
            ls.SiteHit(anchor="wall_clock_timeout", encoding="hash24", ref_offset=pool_len + 4),
        ]
        # When: the manifest is built.
        m = ls.build_manifest(data, [], sites, {})
        # Then: AMBIGUOUS (more than one survivor -> no-guess refusal).
        self.assertEqual(m.status, "AMBIGUOUS")

    def test_empty_when_no_sites(self) -> None:
        # Given: no reference sites at all.
        data, _ = self._data_with_ref_and_constants([])
        # When: the manifest is built with no sites.
        m = ls.build_manifest(data, [], [], {})
        # Then: EMPTY.
        self.assertEqual(m.status, "EMPTY")

    def test_ambiguous_when_site_lacks_full_set(self) -> None:
        # Given: one site, but its neighborhood holds only one of the four values.
        data, pool_len = self._data_with_ref_and_constants([HA], const_gap=6000)
        site = ls.SiteHit(anchor="classifierStage", encoding="hash24", ref_offset=pool_len)
        # When: the manifest is built.
        m = ls.build_manifest(data, [], [site], {})
        # Then: AMBIGUOUS (a site exists but none is fully bound).
        self.assertEqual(m.status, "AMBIGUOUS")

    def test_false_positive_shape_stays_refused_with_set_window(self) -> None:
        # Given: the multi-build false-positive shape -- a reference site
        # exists, but no site's
        # neighborhood holds the full set, while a separate compact table
        # (> 4096 B away from every site) holds all four values.
        pool = self._pool(("classifierStage", HA), ("wall_clock_timeout", HB))
        pool_len = len(pool)
        data = pool + struct.pack("<I", HA) + b"\x00" * 5000 + _packed(CONSTRAINTS)
        site = ls.SiteHit(anchor="classifierStage", encoding="hash24", ref_offset=pool_len)
        # When: the manifest is built with a live range (diagnostic enabled).
        m = ls.build_manifest(data, [], [site], {}, live_range=(pool_len, len(data)))
        # Then: still AMBIGUOUS with zero apply candidates (no-guess), while the
        # diagnostic records the compact table as a set-window candidate.
        self.assertEqual(m.status, "AMBIGUOUS")
        self.assertEqual(m.candidates, [])
        self.assertEqual(len(m.set_windows), 1)
        self.assertIn("set-window", m.detail)

    def test_unique_build_also_reports_set_windows(self) -> None:
        # Given: a UNIQUE synthetic binary (full set within the site's neighborhood).
        data, pool_len = self._data_with_ref_and_constants([HA])
        site = ls.SiteHit(anchor="classifierStage", encoding="hash24", ref_offset=pool_len)
        # When: the manifest is built with a live range.
        m = ls.build_manifest(data, [], [site], {}, live_range=(pool_len, len(data)))
        # Then: still UNIQUE with its four apply candidates, and the same table
        # is additionally reported as a set-window candidate.
        self.assertEqual(m.status, "UNIQUE")
        self.assertEqual(len(m.candidates), 4)
        self.assertEqual(len(m.set_windows), 1)
        self.assertIn("set-window", m.detail)

    def test_no_live_range_means_no_set_windows(self) -> None:
        # Given: the pre-existing build_manifest call form (no live range).
        data, pool_len = self._data_with_ref_and_constants([HA])
        site = ls.SiteHit(anchor="classifierStage", encoding="hash24", ref_offset=pool_len)
        # When: the manifest is built exactly as before.
        m = ls.build_manifest(data, [], [site], {})
        # Then: no set-window diagnostic at all (backward compatible).
        self.assertEqual(m.set_windows, [])
        self.assertNotIn("set-window", m.detail)


class TestApplyLive(unittest.TestCase):
    def test_applies_new_values(self) -> None:
        # Given: a buffer with a 60000 slot and a candidate raising it to 99999.
        data = b"\x00" * 4 + struct.pack("<i", 60000)
        c = ls.CandidateOp(offset=4, old=60000, new=99999, evidence="test")
        # When: applied.
        patched, ok, errors = ls.apply_live(data, [c])
        # Then: applied, same length, new value in place, no errors.
        self.assertTrue(ok)
        self.assertEqual(errors, [])
        self.assertEqual(len(patched), len(data))
        self.assertEqual(struct.unpack_from("<i", patched, 4)[0], 99999)

    def test_no_candidates_is_refused(self) -> None:
        # Given: no candidates.
        data = b"\x00" * 8
        # When: applied.
        patched, ok, errors = ls.apply_live(data, [])
        # Then: refused, data unchanged.
        self.assertFalse(ok)
        self.assertIs(patched, data)
        self.assertTrue(errors)

    def test_out_of_range_slot_is_refused_all_or_nothing(self) -> None:
        # Given: one valid slot and one out-of-range slot.
        data = b"\x00" * 4 + struct.pack("<i", 60000)
        good = ls.CandidateOp(offset=4, old=60000, new=99999, evidence="g")
        bad = ls.CandidateOp(offset=len(data) + 100, old=1, new=2, evidence="b")
        # When: applied together.
        patched, ok, errors = ls.apply_live(data, [good, bad])
        # Then: refused as a whole; even the good slot is left untouched.
        self.assertFalse(ok)
        self.assertIs(patched, data)


class TestStaticVerify(unittest.TestCase):
    def test_passes_when_only_touched_slots_changed(self) -> None:
        # Given: an original, a patched copy differing only in one slot, and the candidate.
        data = b"\x00" * 4 + struct.pack("<i", 60000)
        patched = bytearray(data)
        struct.pack_into("<i", patched, 4, 99999)
        c = ls.CandidateOp(offset=4, old=60000, new=99999, evidence="t")
        # When: verified.
        ok, problems = ls.static_verify(data, bytes(patched), [c])
        # Then: passes with no problems.
        self.assertTrue(ok)
        self.assertEqual(problems, [])

    def test_fails_on_length_change(self) -> None:
        # Given: a patched copy of a different length.
        data = b"\x00" * 4 + struct.pack("<i", 60000)
        c = ls.CandidateOp(offset=4, old=60000, new=99999, evidence="t")
        # When: verified against a longer buffer.
        ok, problems = ls.static_verify(data, data + b"X", [c])
        # Then: fails, citing the length change.
        self.assertFalse(ok)
        self.assertTrue(any("length" in p for p in problems))

    def test_fails_on_unexpected_byte(self) -> None:
        # Given: a patched copy that also flips an unrelated byte.
        data = b"\x00" * 4 + struct.pack("<i", 60000)
        patched = bytearray(data)
        struct.pack_into("<i", patched, 4, 99999)
        patched[0] = 0x7f  # unexpected byte
        c = ls.CandidateOp(offset=4, old=60000, new=99999, evidence="t")
        # When: verified.
        ok, problems = ls.static_verify(data, bytes(patched), [c])
        # Then: fails, citing the unexpected byte.
        self.assertFalse(ok)
        self.assertTrue(any("unexpected" in p for p in problems))

    def test_fails_when_slot_still_reads_old(self) -> None:
        # Given: a patched copy that never changed the target slot.
        data = b"\x00" * 4 + struct.pack("<i", 60000)
        c = ls.CandidateOp(offset=4, old=60000, new=99999, evidence="t")
        # When: verified against the unchanged buffer.
        ok, problems = ls.static_verify(data, data, [c])
        # Then: fails, citing the stale slot value.
        self.assertFalse(ok)
        self.assertTrue(any("expected 99999" in p for p in problems))


class TestLiveCli(unittest.TestCase):
    def _write(self, tmp: str, data: bytes) -> str:
        path = os.path.join(tmp, "bin")
        with open(path, "wb") as f:
            f.write(data)
        return path

    def _ranges(self, data: bytes, pool_len: int):
        return (0, pool_len), (pool_len, len(data))

    def test_experimental_live_is_read_only(self) -> None:
        # Given: a UNIQUE synthetic binary.
        pool = _pool_entry("classifierStage", HA)
        data = pool + struct.pack("<I", HA) + FILLER + _packed(CONSTRAINTS)
        with tempfile.TemporaryDirectory() as tmp:
            path = self._write(tmp, data)
            before = open(path, "rb").read()
            pool_len, live_len = (0, len(pool)), (len(pool), len(data))
            # When: --experimental-live is requested (Phases 1-3 only).
            with mock.patch.object(cs, "LIVE_STRING_POOL_RANGE", pool_len), \
                 mock.patch.object(cs, "LIVE_CODE_RANGE", live_len), \
                 contextlib.redirect_stdout(io.StringIO()) as out:
                code = pcp.main([path, "--experimental-live"])
            # Then: exit 0, refused by default, nothing written, original intact.
            self.assertEqual(code, 0)
            self.assertIn("REFUSED", out.getvalue())
            self.assertEqual(open(path, "rb").read(), before)
            self.assertFalse(os.path.exists(path + ".patched"))

    def test_apply_live_refuses_ambiguous(self) -> None:
        # Given: an AMBIGUOUS synthetic binary (two full sites).
        pool = _pool_entry("classifierStage", HA) + _pool_entry("wall_clock_timeout", HB)
        data = pool + struct.pack("<I", HA) + struct.pack("<I", HB) + _packed(CONSTRAINTS)
        with tempfile.TemporaryDirectory() as tmp:
            path = self._write(tmp, data)
            before = open(path, "rb").read()
            # When: --apply-live is requested on a non-UNIQUE resolution.
            with mock.patch.object(cs, "LIVE_STRING_POOL_RANGE", (0, len(pool))), \
                 mock.patch.object(cs, "LIVE_CODE_RANGE", (len(pool), len(data))), \
                 contextlib.redirect_stdout(io.StringIO()) as out:
                code = pcp.main([path, "--apply-live"])
            # Then: refused (no-guess), nothing written, original intact.
            self.assertEqual(code, 1)
            self.assertIn("PHASE 4 REFUSED", out.getvalue())
            self.assertEqual(open(path, "rb").read(), before)
            self.assertFalse(os.path.exists(path + ".patched"))

    def test_apply_live_refuses_empty(self) -> None:
        # Given: a binary whose live region has no reference (EMPTY).
        pool = _pool_entry("classifierStage", HA)
        data = pool + FILLER * 8
        with tempfile.TemporaryDirectory() as tmp:
            path = self._write(tmp, data)
            # When: --apply-live is requested on an EMPTY resolution.
            with mock.patch.object(cs, "LIVE_STRING_POOL_RANGE", (0, len(pool))), \
                 mock.patch.object(cs, "LIVE_CODE_RANGE", (len(pool), len(data))), \
                 contextlib.redirect_stdout(io.StringIO()) as out:
                code = pcp.main([path, "--apply-live"])
            # Then: refused, nothing written.
            self.assertEqual(code, 1)
            self.assertIn("PHASE 4 REFUSED", out.getvalue())
            self.assertFalse(os.path.exists(path + ".patched"))

    def test_experimental_live_prints_set_window_section(self) -> None:
        # Given: a UNIQUE synthetic binary whose compact table also qualifies
        # as a set-window candidate.
        pool = _pool_entry("classifierStage", HA)
        data = pool + struct.pack("<I", HA) + FILLER + _packed(CONSTRAINTS)
        with tempfile.TemporaryDirectory() as tmp:
            path = self._write(tmp, data)
            pool_len = len(pool)
            # When: --experimental-live is run with the live range covering the code.
            with mock.patch.object(cs, "LIVE_STRING_POOL_RANGE", (0, pool_len)), \
                 mock.patch.object(cs, "LIVE_CODE_RANGE", (pool_len, len(data))), \
                 contextlib.redirect_stdout(io.StringIO()) as out:
                code = pcp.main([path, "--experimental-live"])
            text = out.getvalue()
            # Then: exit 0, the diagnostic section is printed, and it remains read-only.
            self.assertEqual(code, 0)
            self.assertIn("set-window candidates", text)
            self.assertIn("REFUSED", text)
            self.assertFalse(os.path.exists(path + ".patched"))


# --- Phase 4b: oracle-verified site binding ------------------------------------


def _verified_registry_doc(size: int, sites: list, label: str = "9.9.9") -> dict:
    return {
        label: {
            "size": size,
            "sites": sites,
            "evidence": {
                "date": "2026-09-13",
                "harness": "test harness",
                "baseline_elapsed_s": 121.1,
                "patched_elapsed_s": 41.4,
                "bisect": ["all sites -> 41.5 s"],
            },
        }
    }


def _write_json(path: str, doc: object) -> None:
    with open(path, "w", encoding="utf-8") as f:
        json.dump(doc, f)


class TestVerifiedRegistry(unittest.TestCase):
    def _write(self, doc: object) -> str:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        path = os.path.join(tmp.name, "registry.json")
        _write_json(path, doc)
        return path

    def test_loads_valid_registry(self) -> None:
        # Given: a well-formed registry with one entry and one site.
        path = self._write(_verified_registry_doc(
            128, [{"offset": 124, "old": 60000, "role": "test driver"}]))
        # When: it is loaded.
        reg = ls.load_verified_sites(path)
        # Then: every recorded field survives the round trip.
        self.assertEqual(set(reg), {"9.9.9"})
        entry = reg["9.9.9"]
        self.assertEqual(entry.size, 128)
        self.assertEqual(len(entry.sites), 1)
        self.assertEqual(entry.sites[0].offset, 124)
        self.assertEqual(entry.sites[0].old, 60000)
        self.assertEqual(entry.sites[0].role, "test driver")
        self.assertIsNone(entry.sites[0].target)
        self.assertEqual(entry.evidence["baseline_elapsed_s"], 121.1)

    def test_missing_file_yields_empty_registry(self) -> None:
        # Given: a registry path that does not exist.
        path = os.path.join(tempfile.gettempdir(), "no-such-registry.json")
        # When: it is loaded.
        reg = ls.load_verified_sites(path)
        # Then: the caller falls back (empty registry, no error).
        self.assertEqual(reg, {})

    def test_top_level_must_be_object(self) -> None:
        # Given: a registry whose top level is a list.
        path = self._write([1, 2, 3])
        # When: it is loaded.
        with self.assertRaises(ValueError):
            ls.load_verified_sites(path)

    def test_entry_must_be_object(self) -> None:
        # Given: a registry entry that is not an object.
        path = self._write({"9.9.9": [1]})
        # When: it is loaded.
        with self.assertRaises(ValueError):
            ls.load_verified_sites(path)

    def test_size_must_be_positive_int(self) -> None:
        # Given: entries whose size is zero, a string, or a JSON boolean.
        for bad in (0, "128", True):
            path = self._write(_verified_registry_doc(bad, [{"offset": 124, "old": 60000}]))
            # When: the registry is loaded.
            with self.assertRaises(ValueError, msg=f"size={bad!r}"):
                ls.load_verified_sites(path)

    def test_sites_must_be_nonempty_list(self) -> None:
        # Given: entries whose sites are empty or not a list.
        for bad in ([], "nope"):
            doc = _verified_registry_doc(128, None)
            doc["9.9.9"]["sites"] = bad
            path = self._write(doc)
            # When: the registry is loaded.
            with self.assertRaises(ValueError, msg=f"sites={bad!r}"):
                ls.load_verified_sites(path)

    def test_site_must_be_object(self) -> None:
        # Given: a site entry that is not an object.
        path = self._write(_verified_registry_doc(128, [42]))
        # When: the registry is loaded.
        with self.assertRaises(ValueError):
            ls.load_verified_sites(path)

    def test_site_offset_must_be_int_at_least_4(self) -> None:
        # Given: sites whose offset is below the 4-byte minimum or not an int.
        for bad in (0, 2, "124", True):
            path = self._write(_verified_registry_doc(
                128, [{"offset": bad, "old": 60000}]))
            # When: the registry is loaded.
            with self.assertRaises(ValueError, msg=f"offset={bad!r}"):
                ls.load_verified_sites(path)

    def test_site_old_must_be_int(self) -> None:
        # Given: a site whose recorded value is a string or a JSON boolean.
        for bad in ("60000", False):
            path = self._write(_verified_registry_doc(
                128, [{"offset": 124, "old": bad}]))
            # When: the registry is loaded.
            with self.assertRaises(ValueError, msg=f"old={bad!r}"):
                ls.load_verified_sites(path)

    def test_missing_role_defaults_to_empty(self) -> None:
        # Given: a site without a role.
        path = self._write(_verified_registry_doc(128, [{"offset": 124, "old": 60000}]))
        # When: it is loaded.
        entry = ls.load_verified_sites(path)["9.9.9"]
        # Then: the role is the empty string (printing stays safe).
        self.assertEqual(entry.sites[0].role, "")

    def test_site_target_parsed(self) -> None:
        # Given: a registry with one site carrying an explicit target and one
        # without.
        doc = _verified_registry_doc(
            128,
            [
                {"offset": 120, "old": 120000, "role": "ceiling", "target": 123456},
                {"offset": 124, "old": 60000, "role": "driver"},
            ],
        )
        path = self._write(doc)
        # When: the registry is loaded.
        a, b = ls.load_verified_sites(path)["9.9.9"].sites
        # Then: the explicit target survives and the absent one is None
        # (None means "int32 max" at apply time).
        self.assertEqual(a.target, 123456)
        self.assertIsNone(b.target)

    def test_site_target_must_be_positive_int(self) -> None:
        # Given: sites whose target is a JSON boolean, zero, negative, or a
        # string.
        for bad in (True, 0, -5, "123456"):
            doc = _verified_registry_doc(
                128,
                [{"offset": 124, "old": 60000, "role": "d", "target": bad}],
            )
            path = self._write(doc)
            # When: the registry is loaded.
            with self.assertRaises(ValueError, msg=f"target={bad!r}"):
                ls.load_verified_sites(path)

    def test_missing_evidence_defaults_to_empty(self) -> None:
        # Given: an entry without an evidence object.
        doc = _verified_registry_doc(128, [{"offset": 124, "old": 60000}])
        del doc["9.9.9"]["evidence"]
        path = self._write(doc)
        # When: it is loaded.
        entry = ls.load_verified_sites(path)["9.9.9"]
        # Then: evidence is an empty dict.
        self.assertEqual(entry.evidence, {})

    def test_evidence_must_be_object(self) -> None:
        # Given: an entry whose evidence is a list (would crash the printer).
        doc = _verified_registry_doc(128, [{"offset": 124, "old": 60000}])
        doc["9.9.9"]["evidence"] = ["not", "an object"]
        path = self._write(doc)
        # When: the registry is loaded.
        with self.assertRaises(ValueError):
            ls.load_verified_sites(path)


class TestVerifiedMatch(unittest.TestCase):
    def test_unique_size_match(self) -> None:
        # Given: a registry with two entries of different sizes.
        reg = {
            "a": ls.VerifiedEntry("a", 100, [ls.VerifiedSite(4, 60000, "")]),
            "b": ls.VerifiedEntry("b", 200, [ls.VerifiedSite(4, 60000, "")]),
        }
        # When: the binary is 200 bytes.
        entry = ls.match_verified_entry(reg, b"\x00" * 200)
        # Then: the size-matching entry is returned.
        self.assertIsNotNone(entry)
        self.assertEqual(entry.label, "b")

    def test_no_match_returns_none(self) -> None:
        # Given: a registry whose entry size differs from the binary's size.
        reg = {"a": ls.VerifiedEntry("a", 100, [ls.VerifiedSite(4, 60000, "")])}
        # When: the binary is 101 bytes.
        entry = ls.match_verified_entry(reg, b"\x00" * 101)
        # Then: nothing matches.
        self.assertIsNone(entry)

    def test_multiple_size_match_raises(self) -> None:
        # Given: two entries claiming the same size (a registry corruption).
        reg = {
            "a": ls.VerifiedEntry("a", 100, [ls.VerifiedSite(4, 60000, "")]),
            "b": ls.VerifiedEntry("b", 100, [ls.VerifiedSite(4, 60000, "")]),
        }
        # When: the binary is 100 bytes.
        with self.assertRaises(ValueError):
            ls.match_verified_entry(reg, b"\x00" * 100)

    def test_same_size_entries_disambiguated_by_binary_name(self) -> None:
        # Given: two different versions that shipped byte-identical-sized
        # binaries (2.1.275 and 2.1.276 both record the same size), both
        # bound in the registry.
        reg = {
            "v1": ls.VerifiedEntry("v1", 100, [ls.VerifiedSite(4, 60000, "")]),
            "v2": ls.VerifiedEntry("v2", 100, [ls.VerifiedSite(4, 60000, "")]),
        }
        # When: the binary is 100 bytes and named after one of the keys.
        entry = ls.match_verified_entry(reg, b"\x00" * 100, "v2")
        # Then: the entry keyed by the name (at the same size) is returned -
        # the size collision is disambiguated, never guessed.
        self.assertEqual(entry.label, "v2")
        self.assertEqual(
            ls.match_verified_entry(reg, b"\x00" * 100, "v1").label, "v1")

    def test_named_entry_with_wrong_size_falls_back_to_size_match(self) -> None:
        # Given: a name whose entry has a different recorded size, and a
        # different entry at the binary's size.
        reg = {
            "v1": ls.VerifiedEntry("v1", 200, [ls.VerifiedSite(4, 60000, "")]),
            "v2": ls.VerifiedEntry("v2", 100, [ls.VerifiedSite(4, 60000, "")]),
        }
        # When: the binary is 100 bytes but named after the wrong-size entry.
        entry = ls.match_verified_entry(reg, b"\x00" * 100, "v1")
        # Then: the name is a hint, not the predicate - the unique size match
        # still wins (a name never matches without the size).
        self.assertEqual(entry.label, "v2")

    def test_name_not_in_registry_does_not_lift_the_size_guard(self) -> None:
        # Given: two entries claiming the same size and a name that is not a
        # registry key.
        reg = {
            "a": ls.VerifiedEntry("a", 100, [ls.VerifiedSite(4, 60000, "")]),
            "b": ls.VerifiedEntry("b", 100, [ls.VerifiedSite(4, 60000, "")]),
        }
        # When: the binary is 100 bytes under a non-key name.
        # Then: the collision is unresolved - the guard still refuses.
        with self.assertRaises(ValueError):
            ls.match_verified_entry(reg, b"\x00" * 100, "other")


class TestVerifiedSitesMatch(unittest.TestCase):
    def test_all_sites_still_match(self) -> None:
        # Given: a binary whose site still holds the recorded int32.
        data = bytearray(b"\x00" * 128)
        struct.pack_into("<i", data, 124, 60000)
        entry = ls.VerifiedEntry("9.9.9", 128, [ls.VerifiedSite(124, 60000, "driver")])
        # When: the recorded bytes are checked.
        ok, problems = ls.verified_sites_match(bytes(data), entry)
        # Then: everything matches.
        self.assertTrue(ok)
        self.assertEqual(problems, [])

    def test_size_mismatch_fails(self) -> None:
        # Given: a binary one byte shorter than the recorded size.
        data = b"\x00" * 127
        entry = ls.VerifiedEntry("9.9.9", 128, [ls.VerifiedSite(124, 60000, "driver")])
        # When: the recorded bytes are checked.
        ok, problems = ls.verified_sites_match(bytes(data), entry)
        # Then: the size problem is reported.
        self.assertFalse(ok)
        self.assertEqual(problems, ["binary size 127 != recorded 128"])

    def test_byte_drift_is_detected(self) -> None:
        # Given: a binary whose site was rewritten to a different int32.
        data = bytearray(b"\x00" * 128)
        struct.pack_into("<i", data, 124, 42000)
        entry = ls.VerifiedEntry("9.9.9", 128, [ls.VerifiedSite(124, 60000, "driver")])
        # When: the recorded bytes are checked.
        ok, problems = ls.verified_sites_match(bytes(data), entry)
        # Then: the drift is reported with both values.
        self.assertFalse(ok)
        self.assertEqual(len(problems), 1)
        self.assertIn("reads 42000", problems[0])
        self.assertIn("recorded 60000", problems[0])

    def test_site_out_of_range(self) -> None:
        # Given: a site whose last byte falls past the end of the binary.
        entry = ls.VerifiedEntry(
            "9.9.9", 128, [ls.VerifiedSite(126, 60000, "driver")]
        )
        # When: the recorded bytes are checked against a 128-byte binary.
        ok, problems = ls.verified_sites_match(b"\x00" * 128, entry)
        # Then: the out-of-range problem is reported.
        self.assertFalse(ok)
        self.assertIn("out of range", problems[0])


class TestApplyVerifiedSites(unittest.TestCase):
    def _entry(self, data: bytes) -> ls.VerifiedEntry:
        return ls.VerifiedEntry(
            "9.9.9", len(data),
            [ls.VerifiedSite(len(data) - 8, 120000, "ceiling"),
             ls.VerifiedSite(len(data) - 4, 60000, "driver")],
        )

    def test_applies_all_targets_length_preserving(self) -> None:
        # Given: a binary with the two recorded int32 values in place.
        data = bytearray(b"\x00" * 128)
        struct.pack_into("<i", data, 120, 120000)
        struct.pack_into("<i", data, 124, 60000)
        entry = self._entry(bytes(data))
        # When: both values are targeted for change.
        patched, ok, errors, ops = ls.apply_verified_sites(
            bytes(data), entry, {60000: 99999, 120000: 999999})
        # Then: every site is rewritten, the length is preserved, and each op
        # carries its oracle-verified evidence.
        self.assertTrue(ok, errors)
        self.assertEqual(errors, [])
        self.assertEqual(len(patched), len(data))
        self.assertEqual(struct.unpack_from("<i", patched, 120)[0], 999999)
        self.assertEqual(struct.unpack_from("<i", patched, 124)[0], 99999)
        self.assertEqual(len(ops), 2)
        for op in ops:
            self.assertTrue(op.evidence.startswith("oracle-verified site"))

    def test_untouched_bytes_are_preserved(self) -> None:
        # Given: a binary with a marker at a non-site offset.
        data = bytearray(b"\x00" * 128)
        data[10] = 0xAB
        struct.pack_into("<i", data, 124, 60000)
        entry = ls.VerifiedEntry("9.9.9", 128, [ls.VerifiedSite(124, 60000, "driver")])
        # When: only the site is targeted.
        patched, ok, errors, ops = ls.apply_verified_sites(bytes(data), entry, {60000: 20000})
        # Then: the marker and every other byte are unchanged (60000 -> 20000
        # touches only the low two bytes of the little-endian slot).
        self.assertTrue(ok, errors)
        self.assertEqual(patched[10], 0xAB)
        differing = [i for i in range(128) if data[i] != patched[i]]
        self.assertEqual(differing, [124, 125])

    def test_size_mismatch_refuses(self) -> None:
        # Given: a binary one byte longer than the recorded size.
        data = b"\x00" * 129
        entry = ls.VerifiedEntry("9.9.9", 128, [ls.VerifiedSite(124, 60000, "driver")])
        # When: the entry is applied.
        out, ok, errors, ops = ls.apply_verified_sites(data, entry, {60000: 20000})
        # Then: nothing is written and the size problem is reported.
        self.assertFalse(ok)
        self.assertIs(out, data)
        self.assertEqual(ops, [])
        self.assertIn("129", errors[0])

    def test_byte_drift_refuses(self) -> None:
        # Given: a binary whose site no longer holds the recorded value.
        data = bytearray(b"\x00" * 128)
        struct.pack_into("<i", data, 124, 42000)
        entry = ls.VerifiedEntry("9.9.9", 128, [ls.VerifiedSite(124, 60000, "driver")])
        # When: the entry is applied.
        out, ok, errors, ops = ls.apply_verified_sites(bytes(data), entry, {60000: 20000})
        # Then: the build drift is refused and the data is returned unchanged.
        self.assertFalse(ok)
        self.assertEqual(out, bytes(data))
        self.assertEqual(ops, [])
        self.assertIn("drifted", errors[0])

    def test_no_target_refuses(self) -> None:
        # Given: a valid binary but targets for a value no site records.
        data = bytearray(b"\x00" * 128)
        struct.pack_into("<i", data, 124, 60000)
        entry = ls.VerifiedEntry("9.9.9", 128, [ls.VerifiedSite(124, 60000, "driver")])
        # When: only 42000 is targeted.
        out, ok, errors, ops = ls.apply_verified_sites(bytes(data), entry, {42000: 1})
        # Then: the no-op request is refused (nothing to apply).
        self.assertFalse(ok)
        self.assertEqual(ops, [])
        self.assertIn("no verified site has a target", errors[0])

    def test_noop_value_refuses(self) -> None:
        # Given: a valid binary whose target equals the recorded value.
        data = bytearray(b"\x00" * 128)
        struct.pack_into("<i", data, 124, 60000)
        entry = ls.VerifiedEntry("9.9.9", 128, [ls.VerifiedSite(124, 60000, "driver")])
        # When: 60000 is targeted to 60000.
        out, ok, errors, ops = ls.apply_verified_sites(bytes(data), entry, {60000: 60000})
        # Then: the changeless request is refused.
        self.assertFalse(ok)
        self.assertEqual(ops, [])
        self.assertIn("no verified site has a target", errors[0])

    def test_int32_max_target_applies(self) -> None:
        # Given: a valid binary and the largest-int32 target for its site
        # (the Phase 4b default for timeout sites).
        data = bytearray(b"\x00" * 128)
        struct.pack_into("<i", data, 124, 60000)
        entry = ls.VerifiedEntry("9.9.9", 128, [ls.VerifiedSite(124, 60000, "driver")])
        # When: the site is raised to the largest int32.
        patched, ok, errors, ops = ls.apply_verified_sites(
            bytes(data), entry, {60000: ls.INT32_MAX})
        # Then: the max value is stored length-preserving and the static
        # check passes.
        self.assertTrue(ok, errors)
        self.assertEqual(struct.unpack_from("<i", patched, 124)[0], ls.INT32_MAX)
        vok, problems = ls.static_verify(bytes(data), patched, ops)
        self.assertTrue(vok, problems)

class TestLiveValueParsing(unittest.TestCase):
    def test_parses_valid_spec(self) -> None:
        # Given: a well-formed OLD=NEW spec.
        # When: it is parsed.
        old, new = pcp.parse_live_value("60000=12345")
        # Then: both values come back as ints.
        self.assertEqual((old, new), (60000, 12345))

    def test_rejects_missing_equals(self) -> None:
        # Given: a spec without an '='.
        with self.assertRaises(ValueError):
            pcp.parse_live_value("60000")

    def test_rejects_non_numeric_values(self) -> None:
        # Given: specs whose values are not integers.
        for bad in ("abc=1", "60000=1.5", "60000="):
            with self.assertRaises(ValueError, msg=bad):
                pcp.parse_live_value(bad)

    def test_rejects_extra_equals(self) -> None:
        # Given: a spec with a second '=' (the NEW half is not an int).
        with self.assertRaises(ValueError):
            pcp.parse_live_value("1=2=3")

    def test_rejects_non_positive_values(self) -> None:
        # Given: specs with a zero or negative component.
        for bad in ("0=60000", "60000=0", "-5=10"):
            with self.assertRaises(ValueError, msg=bad):
                pcp.parse_live_value(bad)


class TestVerifiedCli(unittest.TestCase):
    def _write_binary(self, tmp: str, value: int = 60000, fail_version: bool = False) -> str:
        """An executable shell script (passes `--version`) with the recorded
        int32 value at the last 4 bytes, after the final `exit` line."""
        script = b"#!/bin/sh\necho fake 1.0\n" + (b"exit 1\n" if fail_version else b"exit 0\n")
        data = bytearray(script + b"\x00" * 16)
        struct.pack_into("<i", data, len(data) - 4, value)
        path = os.path.join(tmp, "bin")
        with open(path, "wb") as f:
            f.write(bytes(data))
        os.chmod(path, 0o755)
        return path

    def _write_registry(self, tmp: str, size: int, old: int, site: int) -> str:
        path = os.path.join(tmp, "registry.json")
        _write_json(path, _verified_registry_doc(size, [{"offset": site, "old": old, "role": "test driver"}]))
        return path

    def test_apply_live_uses_verified_binding(self) -> None:
        # Given: an executable fake binary whose recorded site holds 60000, and
        # a registry entry for exactly this binary.
        with tempfile.TemporaryDirectory() as tmp:
            path = self._write_binary(tmp)
            before = open(path, "rb").read()
            site = len(before) - 4
            reg = self._write_registry(tmp, len(before), 60000, site)
            # When: --apply-live is requested with the registry.
            with contextlib.redirect_stdout(io.StringIO()) as out:
                code = pcp.main([path, "--apply-live", "--registry", reg])
            # Then: the verified site is raised to the digit-preserving max,
            # the copy passes the execute gate, and the original is intact.
            self.assertEqual(code, 0)
            text = out.getvalue()
            self.assertIn("oracle-verified live binding", text)
            self.assertIn("static verify: PASS", text)
            self.assertIn("execute gate (--version): PASS", text)
            patched = open(path + ".patched", "rb").read()
            self.assertEqual(len(patched), len(before))
            self.assertEqual(struct.unpack_from("<i", patched, site)[0], ls.INT32_MAX)
            self.assertEqual(open(path, "rb").read(), before)

    def test_apply_live_disambiguates_same_size_entries_by_binary_name(self) -> None:
        # Given: two registry entries claiming the same size (the 2.1.275 /
        # 2.1.276 shape) and a binary named after one of the keys, holding
        # the recorded site value.
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "v2")
            script = b"#!/bin/sh\necho fake 1.0\nexit 0\n"
            data = bytearray(script + b"\x00" * 16)
            site = len(data) - 4
            struct.pack_into("<i", data, site, 60000)
            with open(path, "wb") as f:
                f.write(bytes(data))
            os.chmod(path, 0o755)
            reg_path = os.path.join(tmp, "registry.json")
            _write_json(reg_path, {
                "v1": {"size": len(data),
                       "sites": [{"offset": site, "old": 60000, "role": "driver"}],
                       "evidence": {}},
                "v2": {"size": len(data),
                       "sites": [{"offset": site, "old": 60000, "role": "driver"}],
                       "evidence": {}},
            })
            # When: --apply-live is requested with the registry.
            with contextlib.redirect_stdout(io.StringIO()) as out:
                code = pcp.main([path, "--apply-live", "--registry", reg_path])
            # Then: the binary's own key resolves the size collision and the
            # verified site is rewritten (before the fix this raised
            # "multiple entries claim size" instead).
            self.assertEqual(code, 0, out.getvalue())
            patched = open(path + ".patched", "rb").read()
            self.assertEqual(struct.unpack_from("<i", patched, site)[0], ls.INT32_MAX)

    def test_apply_live_named_entry_with_drifted_bytes_falls_back(self) -> None:
        # Given: two same-size entries, the binary named after one of them,
        # but the bytes at that entry's site drifted (a renamed or different
        # build) while the OTHER entry's sites still hold.
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "v2")
            script = b"#!/bin/sh\necho fake 1.0\nexit 0\n"
            data = bytearray(script + b"\x00" * 16)
            site = len(data) - 4
            struct.pack_into("<i", data, site, 12345)
            with open(path, "wb") as f:
                f.write(bytes(data))
            os.chmod(path, 0o755)
            reg_path = os.path.join(tmp, "registry.json")
            _write_json(reg_path, {
                "v1": {"size": len(data),
                       "sites": [{"offset": site, "old": 12345, "role": "driver"}],
                       "evidence": {}},
                "v2": {"size": len(data),
                       "sites": [{"offset": site, "old": 60000, "role": "driver"}],
                       "evidence": {}},
            })
            # When: --apply-live is requested with the registry.
            with contextlib.redirect_stdout(io.StringIO()) as out:
                code = pcp.main([path, "--apply-live", "--registry", reg_path])
            # Then: the name-resolved entry's recorded bytes do not hold, so
            # no verified binding applies (the no-guess invariant keeps
            # refusing; nothing is written).
            text = out.getvalue()
            self.assertNotIn("oracle-verified live binding", text)
            self.assertFalse(os.path.exists(path + ".patched"))

    def test_apply_live_verified_multi_site_entry(self) -> None:
        # Given: a registry entry with two verified sites (60000 and 120000).
        with tempfile.TemporaryDirectory() as tmp:
            path = self._write_binary(tmp, value=60000)
            before = open(path, "rb").read()
            s1, s2 = len(before) - 4, len(before) - 8
            data = bytearray(before)
            struct.pack_into("<i", data, s2, 120000)
            with open(path, "wb") as f:
                f.write(bytes(data))
            reg_path = os.path.join(tmp, "registry.json")
            _write_json(reg_path, _verified_registry_doc(len(data), [
                {"offset": s1, "old": 60000, "role": "driver"},
                {"offset": s2, "old": 120000, "role": "ceiling"},
            ]))
            # When: --apply-live is requested with the registry.
            with contextlib.redirect_stdout(io.StringIO()) as out:
                code = pcp.main([path, "--apply-live", "--registry", reg_path])
            # Then: both sites are rewritten to the largest int32 (a 4-byte
            # slot has no digit-count constraint).
            self.assertEqual(code, 0)
            patched = open(path + ".patched", "rb").read()
            self.assertEqual(struct.unpack_from("<i", patched, s1)[0], ls.INT32_MAX)
            self.assertEqual(struct.unpack_from("<i", patched, s2)[0], ls.INT32_MAX)

    def test_apply_live_verified_site_target_overrides_int32_max(self) -> None:
        # Given: a registry whose site carries an explicit target, so the
        # int32-max default must not apply to it.
        with tempfile.TemporaryDirectory() as tmp:
            path = self._write_binary(tmp, value=60000)
            before = open(path, "rb").read()
            site = len(before) - 4
            reg_path = os.path.join(tmp, "registry.json")
            _write_json(reg_path, _verified_registry_doc(
                len(before),
                [{"offset": site, "old": 60000, "role": "driver", "target": 123456}],
            ))
            # When: --apply-live is requested.
            with contextlib.redirect_stdout(io.StringIO()) as out:
                code = pcp.main([path, "--apply-live", "--registry", reg_path])
            # Then: the recorded target wins over the int32-max default.
            self.assertEqual(code, 0)
            patched = open(path + ".patched", "rb").read()
            self.assertEqual(struct.unpack_from("<i", patched, site)[0], 123456)

    def test_apply_live_verified_live_value_override(self) -> None:
        # Given: a verified binary and an explicit target for its site.
        with tempfile.TemporaryDirectory() as tmp:
            path = self._write_binary(tmp)
            before = open(path, "rb").read()
            site = len(before) - 4
            reg = self._write_registry(tmp, len(before), 60000, site)
            # When: --apply-live overrides the default target.
            with contextlib.redirect_stdout(io.StringIO()) as out:
                code = pcp.main([path, "--apply-live", "--registry", reg,
                                 "--live-value", "60000=12345"])
            # Then: the override wins.
            self.assertEqual(code, 0)
            patched = open(path + ".patched", "rb").read()
            self.assertEqual(struct.unpack_from("<i", patched, site)[0], 12345)

    def test_apply_live_verified_malformed_live_value_refuses(self) -> None:
        # Given: a verified binary and a malformed --live-value spec.
        with tempfile.TemporaryDirectory() as tmp:
            path = self._write_binary(tmp)
            before = open(path, "rb").read()
            reg = self._write_registry(tmp, len(before), 60000, len(before) - 4)
            # When: --apply-live is requested with the bad spec.
            with contextlib.redirect_stdout(io.StringIO()), \
                 contextlib.redirect_stderr(io.StringIO()) as err:
                code = pcp.main([path, "--apply-live", "--registry", reg,
                                 "--live-value", "abc=1"])
            # Then: exit 2, nothing written, original intact.
            self.assertEqual(code, 2)
            self.assertIn("invalid --live-value", err.getvalue())
            self.assertFalse(os.path.exists(path + ".patched"))
            self.assertEqual(open(path, "rb").read(), before)

    def test_apply_live_verified_noop_request_writes_nothing(self) -> None:
        # Given: a verified binary whose site is targeted to its own value.
        with tempfile.TemporaryDirectory() as tmp:
            path = self._write_binary(tmp)
            before = open(path, "rb").read()
            reg = self._write_registry(tmp, len(before), 60000, len(before) - 4)
            # When: --apply-live is requested with a no-op target.
            with contextlib.redirect_stdout(io.StringIO()) as out:
                code = pcp.main([path, "--apply-live", "--registry", reg,
                                 "--live-value", "60000=60000"])
            # Then: exit 0, nothing written, the reliable fixes are offered.
            self.assertEqual(code, 0)
            text = out.getvalue()
            self.assertIn("nothing to change", text)
            self.assertIn("Reliable ways", text)
            self.assertFalse(os.path.exists(path + ".patched"))
            self.assertEqual(open(path, "rb").read(), before)

    def test_apply_live_verified_size_mismatch_falls_back(self) -> None:
        # Given: a registry entry whose recorded size differs from the binary's.
        with tempfile.TemporaryDirectory() as tmp:
            path = self._write_binary(tmp)
            before = open(path, "rb").read()
            reg = self._write_registry(tmp, len(before) + 1, 60000, len(before) - 4)
            # When: --apply-live is requested (the fallback path is deterministic
            # on this script-like binary: no pool entries, EMPTY resolution).
            with mock.patch.object(ls, "parse_pool", return_value=[]), \
                 mock.patch.object(cs, "LIVE_STRING_POOL_RANGE", (0, len(before) // 2)), \
                 mock.patch.object(cs, "LIVE_CODE_RANGE", (len(before) // 2, len(before))), \
                 contextlib.redirect_stdout(io.StringIO()) as out:
                code = pcp.main([path, "--apply-live", "--registry", reg])
            # Then: the reference-anchored path refuses (no-guess), nothing written.
            self.assertEqual(code, 1)
            self.assertIn("PHASE 4 REFUSED", out.getvalue())
            self.assertFalse(os.path.exists(path + ".patched"))
            self.assertEqual(open(path, "rb").read(), before)

    def test_apply_live_verified_byte_drift_falls_back(self) -> None:
        # Given: a registry whose size matches but whose recorded bytes no
        # longer match the binary (the build drifted).
        with tempfile.TemporaryDirectory() as tmp:
            path = self._write_binary(tmp, value=42000)
            before = open(path, "rb").read()
            reg = self._write_registry(tmp, len(before), 60000, len(before) - 4)
            # When: --apply-live is requested.
            with mock.patch.object(ls, "parse_pool", return_value=[]), \
                 mock.patch.object(cs, "LIVE_STRING_POOL_RANGE", (0, len(before) // 2)), \
                 mock.patch.object(cs, "LIVE_CODE_RANGE", (len(before) // 2, len(before))), \
                 contextlib.redirect_stdout(io.StringIO()) as out:
                code = pcp.main([path, "--apply-live", "--registry", reg])
            # Then: the drift is reported, the fallback refuses, nothing written.
            self.assertEqual(code, 1)
            text = out.getvalue()
            self.assertIn("no longer matches the recorded bytes", text)
            self.assertIn("PHASE 4 REFUSED", text)
            self.assertFalse(os.path.exists(path + ".patched"))
            self.assertEqual(open(path, "rb").read(), before)

    def test_apply_live_verified_self_test_failure_removes_copy(self) -> None:
        # Given: a fake binary whose --version exits nonzero.
        with tempfile.TemporaryDirectory() as tmp:
            path = self._write_binary(tmp, fail_version=True)
            before = open(path, "rb").read()
            reg = self._write_registry(tmp, len(before), 60000, len(before) - 4)
            # When: --apply-live is requested.
            with contextlib.redirect_stdout(io.StringIO()) as out:
                code = pcp.main([path, "--apply-live", "--registry", reg])
            # Then: the failing copy is removed and exit 1 is returned.
            self.assertEqual(code, 1)
            self.assertIn("execute gate (--version): FAIL", out.getvalue())
            self.assertFalse(os.path.exists(path + ".patched"))
            self.assertEqual(open(path, "rb").read(), before)

    def test_apply_live_default_registry_path_is_used(self) -> None:
        # Given: no --registry flag, and a default registry file next to the
        # tool that records exactly this binary.
        with tempfile.TemporaryDirectory() as tmp:
            path = self._write_binary(tmp)
            before = open(path, "rb").read()
            reg = self._write_registry(tmp, len(before), 60000, len(before) - 4)
            # When: --apply-live is requested.
            with mock.patch.object(pcp, "default_registry_path", return_value=reg), \
                 contextlib.redirect_stdout(io.StringIO()) as out:
                code = pcp.main([path, "--apply-live"])
            # Then: the verified binding is applied from the default registry.
            self.assertEqual(code, 0)
            self.assertIn("oracle-verified live binding", out.getvalue())
            patched = open(path + ".patched", "rb").read()
            self.assertEqual(
                struct.unpack_from("<i", patched, len(before) - 4)[0], ls.INT32_MAX
            )

    def test_apply_live_missing_default_registry_falls_back(self) -> None:
        # Given: no --registry flag and no default registry file on disk.
        with tempfile.TemporaryDirectory() as tmp:
            path = self._write_binary(tmp)
            before = open(path, "rb").read()
            missing = os.path.join(tmp, "no-registry.json")
            # When: --apply-live is requested.
            with mock.patch.object(pcp, "default_registry_path", return_value=missing), \
                 mock.patch.object(ls, "parse_pool", return_value=[]), \
                 mock.patch.object(cs, "LIVE_STRING_POOL_RANGE", (0, len(before) // 2)), \
                 mock.patch.object(cs, "LIVE_CODE_RANGE", (len(before) // 2, len(before))), \
                 contextlib.redirect_stdout(io.StringIO()) as out:
                code = pcp.main([path, "--apply-live"])
            # Then: the reference-anchored path refuses, nothing written,
            # the original is intact.
            self.assertEqual(code, 1)
            self.assertIn("PHASE 4 REFUSED", out.getvalue())
            self.assertFalse(os.path.exists(path + ".patched"))
            self.assertEqual(open(path, "rb").read(), before)

    def test_apply_live_malformed_registry_exits_2(self) -> None:
        # Given: a registry file whose top level is a list.
        with tempfile.TemporaryDirectory() as tmp:
            path = self._write_binary(tmp)
            bad = os.path.join(tmp, "bad-registry.json")
            _write_json(bad, [1, 2, 3])
            # When: --apply-live is requested with that registry.
            with contextlib.redirect_stdout(io.StringIO()), \
                 contextlib.redirect_stderr(io.StringIO()) as err:
                with self.assertRaises(SystemExit) as ctx:
                    pcp.main([path, "--apply-live", "--registry", bad])
            # Then: exit 2 and the parse error is reported.
            self.assertEqual(ctx.exception.code, 2)
            self.assertIn("top level must be an object", err.getvalue())

    def test_apply_live_verified_relative_binary_path(self) -> None:
        # Given: the binary is invoked by a bare relative name (no slash),
        # so the self-test launch would be PATH-resolved without the fix.
        with tempfile.TemporaryDirectory() as tmp:
            path = self._write_binary(tmp)
            before = open(path, "rb").read()
            reg = self._write_registry(tmp, len(before), 60000, len(before) - 4)
            old_cwd = os.getcwd()
            os.chdir(tmp)
            self.addCleanup(os.chdir, old_cwd)
            # When: --apply-live is requested with the relative name.
            with contextlib.redirect_stdout(io.StringIO()) as out:
                code = pcp.main(["bin", "--apply-live", "--registry",
                                 os.path.join(tmp, "registry.json")])
            # Then: the verified binding is applied and the copy passes the
            # execute gate (launched from the current directory, not PATH).
            self.assertEqual(code, 0)
            self.assertIn("execute gate (--version): PASS", out.getvalue())
            patched_path = os.path.join(tmp, "bin.patched")
            patched = open(patched_path, "rb").read()
            self.assertEqual(len(patched), len(before))
            self.assertEqual(
                struct.unpack_from("<i", patched, len(before) - 4)[0], ls.INT32_MAX
            )


class TestSelfTestLaunch(unittest.TestCase):
    def _write_exec(self, tmp: str, name: str = "bin") -> None:
        path = os.path.join(tmp, name)
        with open(path, "wb") as f:
            f.write(b"#!/bin/sh\necho fake 1.0\nexit 0\n")
        os.chmod(path, 0o755)

    def test_bare_relative_name_is_not_path_resolved(self) -> None:
        # Given: the current directory holds an executable named `bin` (a
        # bare name that would be PATH-resolved by execvpe).
        with tempfile.TemporaryDirectory() as tmp:
            self._write_exec(tmp)
            old_cwd = os.getcwd()
            os.chdir(tmp)
            self.addCleanup(os.chdir, old_cwd)
            # When: the self test runs the bare relative name.
            ok, detail = pcp.run_self_test("bin")
            # Then: the file in the current directory is executed.
            self.assertTrue(ok, detail)
            self.assertIn("fake 1.0", detail)

    def test_bare_relative_name_missing_file_reports_launch_failure(self) -> None:
        # Given: a bare relative name that does not exist anywhere on PATH or
        # in the current directory.
        with tempfile.TemporaryDirectory() as tmp:
            old_cwd = os.getcwd()
            os.chdir(tmp)
            self.addCleanup(os.chdir, old_cwd)
            # When: the self test runs the missing name.
            ok, detail = pcp.run_self_test("no-such-binary")
            # Then: the launch failure is reported, not a silent pass.
            self.assertFalse(ok)
            self.assertIn("failed to launch", detail)

    def test_failing_version_exit_is_reported(self) -> None:
        # Given: an executable whose --version exits nonzero.
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "bin")
            with open(path, "wb") as f:
                f.write(b"#!/bin/sh\necho fake 1.0\nexit 3\n")
            os.chmod(path, 0o755)
            # When: the self test runs it.
            ok, detail = pcp.run_self_test(os.path.join(tmp, "bin"))
            # Then: the nonzero exit is reported as a failure.
            self.assertFalse(ok)
            self.assertIn("exit=3", detail)


_PATCH_SCRIPT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "patch.sh")
_CI_SCRIPT = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "tools", "ci_bind_new_version.py"
)


class PatchScriptOneLineTests(unittest.TestCase):
    """The one-line patch script (patch.sh): apply + verify orchestration."""

    def _write_binary(self, tmp: str, body: bytes, value: int) -> str:
        data = bytearray(body + b"\x00" * 16)
        struct.pack_into("<i", data, len(data) - 4, value)
        path = os.path.join(tmp, "bin")
        with open(path, "wb") as f:
            f.write(bytes(data))
        os.chmod(path, 0o755)
        return path

    def _write_registry(self, tmp: str, size: int, sites: list) -> str:
        path = os.path.join(tmp, "registry.json")
        with open(path, "w") as f:
            json.dump({"tiny": {"size": size, "sites": sites, "evidence": {}}}, f)
        return path

    def _run_script(self, *args: object, timeout: int = 180,
                    env_extra: dict = None) -> subprocess.CompletedProcess:
        env = dict(os.environ)
        if env_extra:
            env.update(env_extra)
        return subprocess.run(
            ["bash", _PATCH_SCRIPT, *[str(a) for a in args]],
            capture_output=True,
            text=True,
            timeout=timeout,
            env=env,
        )

    def test_apply_only_writes_patched_at_int32_max(self) -> None:
        # Given: an executable fake binary holding 60000 at its last 4 bytes,
        # and a registry entry for exactly this binary.
        with tempfile.TemporaryDirectory() as tmp:
            path = self._write_binary(tmp, b"#!/bin/sh\necho fake 1.0\nexit 0\n", 60000)
            before = open(path, "rb").read()
            reg = self._write_registry(
                tmp, len(before),
                [{"offset": len(before) - 4, "old": 60000, "role": "driver"}],
            )
            # When: the one-line script is invoked with --no-verify.
            proc = self._run_script(path, "--no-verify", "--registry", reg)
            # Then: exit 0, the .patched slot holds the int32 max, and the
            # original bytes are intact.
            self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
            patched = open(path + ".patched", "rb").read()
            self.assertEqual(len(patched), len(before))
            self.assertEqual(struct.unpack_from("<i", patched, len(before) - 4)[0], ls.INT32_MAX)
            self.assertEqual(open(path, "rb").read(), before)
            self.assertIn("applied", proc.stdout)

    def test_apply_only_respects_the_recorded_site_target(self) -> None:
        # Given: a registry entry whose site carries the measured capped-build
        # target instead of the int32-max default.
        with tempfile.TemporaryDirectory() as tmp:
            path = self._write_binary(tmp, b"#!/bin/sh\necho fake 1.0\nexit 0\n", 60000)
            before = open(path, "rb").read()
            reg = self._write_registry(
                tmp, len(before),
                [{"offset": len(before) - 4, "old": 60000, "role": "driver", "target": 425000000}],
            )
            # When: the one-line script is invoked with --no-verify.
            proc = self._run_script(path, "--no-verify", "--registry", reg)
            # Then: the recorded target wins over the int32-max default.
            self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
            patched = open(path + ".patched", "rb").read()
            self.assertEqual(struct.unpack_from("<i", patched, len(before) - 4)[0], 425000000)

    def test_unbound_build_refused_with_auto_bind_disabled(self) -> None:
        # Given: a binary whose size has no registry entry (an unbound build).
        with tempfile.TemporaryDirectory() as tmp:
            path = self._write_binary(tmp, b"#!/bin/sh\necho fake 1.0\nexit 0\n", 60000)
            before = open(path, "rb").read()
            reg = self._write_registry(
                tmp, len(before) + 4,
                [{"offset": len(before) - 4, "old": 60000, "role": "driver"}],
            )
            before_doc = json.load(open(reg))
            # When: the one-line script is invoked with automatic binding off.
            proc = self._run_script(path, "--no-verify", "--no-auto-bind", "--registry", reg)
            # Then: it refuses (exit 1), writes nothing, leaves the registry
            # untouched, and points at the automatic oracle binding instead of
            # guessing.
            self.assertEqual(proc.returncode, 1, proc.stdout + proc.stderr)
            self.assertFalse(os.path.exists(path + ".patched"))
            self.assertIn("bind it first", proc.stdout)
            self.assertIn("oracle_bind_auto.py", proc.stdout)
            self.assertEqual(json.load(open(reg)), before_doc)

    def test_usage_errors_exit_two(self) -> None:
        # Given: a valid fake binary.
        with tempfile.TemporaryDirectory() as tmp:
            path = self._write_binary(tmp, b"#!/bin/sh\necho fake 1.0\nexit 0\n", 60000)
            # When: no binary argument is given.
            proc = self._run_script()
            # Then: exit 2 with the usage text.
            self.assertEqual(proc.returncode, 2)
            self.assertIn("Usage", proc.stderr)
            # When: an unknown option is given.
            proc = self._run_script(path, "--bogus")
            self.assertEqual(proc.returncode, 2)
            # When: a non-numeric timeout is given.
            proc = self._run_script(path, "--timeout", "abc")
            self.assertEqual(proc.returncode, 2)
            # When: a timeout below the floor is given.
            proc = self._run_script(path, "--timeout", "10")
            self.assertEqual(proc.returncode, 2)

    def test_verify_marks_a_fast_exit_not_verified(self) -> None:
        # Given: a bound fake binary that exits immediately (a zero wait).
        with tempfile.TemporaryDirectory() as tmp:
            path = self._write_binary(tmp, b"#!/bin/sh\necho fake 1.0\nexit 0\n", 60000)
            with open(path, "rb") as f:
                before = f.read()
            reg = self._write_registry(
                tmp, len(before),
                [{"offset": len(before) - 4, "old": 60000, "role": "driver"}],
            )
            # When: the one-line script runs the blackhole verification probe.
            proc = self._run_script(path, "--timeout", "15", "--registry", reg)
            # Then: apply succeeded but the verify fails - the patched run
            # ended on its own before the probe cap (rc=0), so it is reported
            # as NOT VERIFIED.
            self.assertEqual(proc.returncode, 1, proc.stdout + proc.stderr)
            self.assertIn("NOT VERIFIED", proc.stdout)
            self.assertIn("rc=0", proc.stdout)

    def test_verify_passes_when_the_run_still_waits_at_the_timeout(self) -> None:
        # Given: a bound fake binary that answers --version but hangs past the
        # probe timeout in probe mode (simulating a long classifier wait).
        body = (
            b"#!/bin/sh\n"
            b'if [ "$1" = "--version" ]; then echo fake 1.0; exit 0; fi\n'
            b"sleep 30\n"
        )
        with tempfile.TemporaryDirectory() as tmp:
            path = self._write_binary(tmp, body, 60000)
            with open(path, "rb") as f:
                before = f.read()
            reg = self._write_registry(
                tmp, len(before),
                [{"offset": len(before) - 4, "old": 60000, "role": "driver"}],
            )
            # When: the one-line script runs the verification probe (3 s cap;
            # the floor is lowered by the test hook CLAUDE_PATCHER_TIMEOUT_FLOOR,
            # so the cap is reached in seconds, not in 15 s).
            proc = self._run_script(path, "--timeout", "3", "--registry", reg,
                                    env_extra={"CLAUDE_PATCHER_TIMEOUT_FLOOR": "3"},
                                    timeout=120)
            # Then: the patched run is still waiting at the probe timeout
            # (killed, rc=124), so it is reported VERIFIED and the script
            # exits 0 - with no in-place replacement: the original bytes
            # are byte-identical (never renamed, no .original) and the
            # patched bytes live in the .patched artifact next to it.
            self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
            self.assertIn("VERIFIED", proc.stdout)
            self.assertIn("rc=124", proc.stdout)
            self.assertEqual(open(path, "rb").read(), before)
            patched = open(path + ".patched", "rb").read()
            self.assertEqual(struct.unpack_from("<i", patched, len(before) - 4)[0], ls.INT32_MAX)
            self.assertFalse(os.path.exists(path + ".original"))

    def test_timeout_floor_is_a_test_hook(self) -> None:
        # Given: a bound fake binary (the floor check happens at argument
        # parsing, before any probe or apply).
        with tempfile.TemporaryDirectory() as tmp:
            path = self._write_binary(
                tmp, b"#!/bin/sh\necho fake 1.0\nexit 0\n", 60000)
            with open(path, "rb") as f:
                before = f.read()
            reg = self._write_registry(
                tmp, len(before),
                [{"offset": len(before) - 4, "old": 60000, "role": "driver"}],
            )
            env = {"CLAUDE_PATCHER_TIMEOUT_FLOOR": "3"}
            # When: the floor is lowered by the test hook.
            proc = self._run_script(path, "--timeout", "3", "--no-verify",
                                    "--registry", reg, env_extra=env)
            proc2 = self._run_script(path, "--timeout", "2", "--no-verify",
                                     "--registry", reg, env_extra=env)
            # Then: the 3 s cap is accepted (nothing is probed) and the
            # 2 s cap is refused below the lowered floor.
            self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
            self.assertEqual(proc2.returncode, 2, proc2.stdout + proc2.stderr)
            self.assertIn("floor", proc2.stderr)


_ORACLE_DIR = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "tools", "binder"
)


class OracleScriptGenericTests(unittest.TestCase):
    """The oracle binding scripts must not depend on any specific binary
    name: the target comes from --binary (or is refused), never from a
    hardcoded file name at the repo root."""

    def _script(self, name: str) -> str:
        return os.path.join(_ORACLE_DIR, name)

    def _synthetic_binary(self, tmp: str, values: dict) -> str:
        # A 64-byte "binary": int32 slots at 4-aligned offsets inside the
        # default size//2 window, zero (non-text) neighborhood elsewhere.
        data = bytearray(64)
        for off, v in values.items():
            struct.pack_into("<i", data, off, v)
        path = os.path.join(tmp, "bin")
        with open(path, "wb") as f:
            f.write(bytes(data))
        os.chmod(path, 0o755)
        return path

    def _run(self, *args: object, timeout: int = 30) -> subprocess.CompletedProcess:
        return subprocess.run(
            ["python3", *[str(a) for a in args]],
            capture_output=True, text=True, timeout=timeout,
        )

    def test_step2_requires_explicit_binary(self) -> None:
        # Given: the step-2 bisection script.
        # When: it runs without --binary (the other required args given).
        proc = self._run(self._script("oracle_binding_step2.py"),
                        "--indices", "all", "--label", "r1", "--no-probe")
        # Then: a clean argparse usage error (exit 2), no traceback.
        self.assertEqual(proc.returncode, 2, proc.stderr)
        self.assertIn("--binary", proc.stderr)
        self.assertNotIn("Traceback", proc.stderr)

    def test_step2_no_probe_patches_generic_binary(self) -> None:
        # Given: a synthetic 64-byte binary with int32 60000 at offset 36
        # (4-aligned, inside the default size//2 window, non-text).
        with tempfile.TemporaryDirectory() as tmp:
            path = self._synthetic_binary(tmp, {36: 60000})
            with open(path, "rb") as f:
                before = f.read()
            # When: step 2 rewrites every enumerated site without probing.
            proc = self._run(self._script("oracle_binding_step2.py"),
                             "--binary", path, "--indices", "all",
                             "--new", "20000", "--label", "r1", "--no-probe")
            # Then: exit 0, exactly one code site found, the .bind_r1 copy
            # holds 20000 at the site, and the original is untouched.
            self.assertEqual(proc.returncode, 0, proc.stderr)
            self.assertIn("code sites: 1", proc.stdout)
            copy = open(path + ".bind_r1", "rb").read()
            self.assertEqual(len(copy), len(before))
            self.assertEqual(struct.unpack_from("<i", copy, 36)[0], 20000)
            self.assertEqual(open(path, "rb").read(), before)

    def test_cap_probe_no_probe_patches_driver_and_cap(self) -> None:
        # Given: a synthetic binary with driver 60000 @36 and the cap
        # candidate 120000 @44.
        with tempfile.TemporaryDirectory() as tmp:
            path = self._synthetic_binary(tmp, {36: 60000, 44: 120000})
            # When: the cap probe rewrites driver and cap without probing.
            proc = self._run(self._script("oracle_cap_probe.py"),
                             "--binary", path, "--driver", "36", "--caps", "44",
                             "--driver-new", "130000", "--cap-new", "200000",
                             "--label", "c1", "--no-probe")
            # Then: exit 0, and the copy holds both new values in place.
            self.assertEqual(proc.returncode, 0, proc.stderr)
            copy = open(path + ".bind_c1", "rb").read()
            self.assertEqual(struct.unpack_from("<i", copy, 36)[0], 130000)
            self.assertEqual(struct.unpack_from("<i", copy, 44)[0], 200000)

    def test_step1_writes_all_sites_copy_of_generic_binary(self) -> None:
        # Given: a synthetic binary with int32 60000 at offset 36.
        with tempfile.TemporaryDirectory() as tmp:
            path = self._synthetic_binary(tmp, {36: 60000})
            with open(path, "rb") as f:
                before = f.read()
            # When: step 1 enumerates and rewrites every 60000 site.
            proc = self._run(self._script("oracle_binding_step1.py"),
                             "--binary", path)
            # Then: exit 0, exactly one site found, the .all60000 copy
            # holds 20000 at the site, and the original is untouched.
            self.assertEqual(proc.returncode, 0, proc.stderr)
            self.assertIn("60000 sites: 1", proc.stdout)
            copy = open(path + ".all60000", "rb").read()
            self.assertEqual(len(copy), len(before))
            self.assertEqual(struct.unpack_from("<i", copy, 36)[0], 20000)
            self.assertEqual(open(path, "rb").read(), before)

    def test_decompress_scan_requires_explicit_binary(self) -> None:
        # Given: the frame-scan script.
        # When: it runs without --binary.
        proc = self._run(self._script("decompress_scan.py"))
        # Then: a clean argparse usage error (exit 2), no traceback.
        self.assertEqual(proc.returncode, 2, proc.stderr)
        self.assertIn("--binary", proc.stderr)
        self.assertNotIn("Traceback", proc.stderr)


class OracleBindAutoTests(unittest.TestCase):
    """oracle_bind_auto.py: the fully-automatic binding pipeline.

    Every site and target comes from an injected probe stand-in that emulates
    the measured signal model (wait per attempt = min(ceiling, driver); a
    capped build produces a zero wait above its measured boundary). A signal
    that does not match the model (crash, no effect, contradiction) must be a
    refusal with no registry write - never a guess.
    """

    DRIVER_OFF = 136
    CAP_OFF = 144
    DECOYS = (152, 160, 168)

    def _synthetic(self, tmp: str, values: dict) -> str:
        # A 256-byte fake binary: a runnable shell header (so the apply
        # --version self-test still passes), zero padding, and int32 slots
        # at 4-aligned offsets inside the default size//2 window
        # (256 // 2 = 128; slots at 136/144/152/160/168, non-text).
        hdr = b"#!/bin/sh\necho 1;exit\n"
        data = bytearray(hdr + b"\x00" * (256 - len(hdr)))
        for off, v in values.items():
            struct.pack_into("<i", data, off, v)
        path = os.path.join(tmp, "synth")
        with open(path, "wb") as f:
            f.write(bytes(data))
        os.chmod(path, 0o755)
        return path

    def _registry(self, tmp: str, doc: dict) -> str:
        path = os.path.join(tmp, "registry.json")
        with open(path, "w", encoding="utf-8") as f:
            json.dump(doc, f, indent=2)
        return path

    @staticmethod
    def _i32(data: bytes, off: int) -> int:
        return struct.unpack_from("<i", data, off)[0]

    def _stub_probe(self, boundary: int = None, crash=None) -> object:
        """Probe stand-in implementing the measured signal model.

        boundary: when set, driver values above it produce a zero wait
        (a capped build, like the 217M one); None = every value waits.
        crash: predicate on the artifact bytes; True = the probe yields no
        result line (the artifact does not run).
        cancel: the optional binder cancel event (the bisection rounds pass
        one); the stub finishes instantly, so there is nothing to cancel.
        """
        def probe(artifact: str, label: str, timeout: int, cancel=None):
            try:
                with open(artifact, "rb") as f:
                    d = f.read()
            except OSError:
                return None
            if len(d) != 256 or (crash is not None and crash(d)):
                return None
            vd = self._i32(d, self.DRIVER_OFF)
            vc = self._i32(d, self.CAP_OFF)
            if vd == 60000:
                return 0, 2 * min(vc, 60000) / 1000 + 1.5
            if boundary is not None and vd > boundary:
                return 0, 2.0
            w = min(vc, vd)
            secs = 2 * w / 1000 + 1.5
            if secs < timeout:
                return 0, secs
            return 124, float(timeout)

        return probe

    def _bound_sites(self, doc: dict) -> dict:
        sites = {s["offset"]: s for s in doc["synth"]["sites"]}
        return sites

    def test_uncapped_build_binds_and_records(self) -> None:
        # Given: an unbound synthetic build (driver 60000, ceiling 120000,
        # one decoy 60000) and an empty registry; every value waits
        # (INT32_MAX included, like the 218M/219M builds).
        with tempfile.TemporaryDirectory() as tmp:
            path = self._synthetic(tmp, {136: 60000, 144: 120000, 152: 60000})
            before = open(path, "rb").read()
            reg = self._registry(tmp, {})
            calls = []
            probe = self._stub_probe()
            # When: the auto binder runs against the unbound build.
            ok = oba.bind(path, reg,
                          lambda a, l, t, c=None: (calls.append(l), probe(a, l, t))[1])
            doc = json.load(open(reg))
            # Then: the registry records the measured binding keyed by the
            # file name, both sites get their targets, the evidence is
            # complete, the original is intact, and the intermediates are
            # cleaned up.
            self.assertTrue(ok)
            self.assertEqual(set(doc), {"synth"})
            self.assertEqual(doc["synth"]["size"], 256)
            sites = self._bound_sites(doc)
            self.assertEqual(set(sites), {136, 144})
            self.assertEqual(sites[136]["old"], 60000)
            self.assertEqual(sites[136]["target"], 2147483647)
            self.assertEqual(sites[144]["old"], 120000)
            self.assertEqual(sites[144]["target"], 2147483647)
            ev = doc["synth"]["evidence"]
            for key in ("date", "harness", "baseline_elapsed_s", "bisect",
                        "ceiling", "max_driver_boundary"):
                self.assertIn(key, ev)
            self.assertEqual(ev["max_driver_boundary"]["max_working_value"], 2147483647)
            self.assertEqual(open(path, "rb").read(), before)
            self.assertEqual([n for n in os.listdir(tmp) if n.startswith("synth.bind_")], [])
            for expected in ("base", "all", "single", "cap0", "bmax"):
                self.assertIn(expected, calls)
            self.assertNotIn("verify", calls)  # the verify probe is patch.sh's job

    def test_capped_build_finds_max_working_value(self) -> None:
        # Given: an unbound synthetic build whose wait is zero above
        # 425000000 ms (a capped build, like the 217M one).
        with tempfile.TemporaryDirectory() as tmp:
            path = self._synthetic(tmp, {136: 60000, 144: 120000, 152: 60000})
            reg = self._registry(tmp, {})
            probe = self._stub_probe(boundary=425000000)
            # When: the auto binder runs.
            ok = oba.bind(path, reg, probe)
            doc = json.load(open(reg))
            # Then: the boundary search records the largest measured
            # waiting value as the driver target (never INT32_MAX, which
            # would produce a zero wait on this build).
            self.assertTrue(ok)
            sites = self._bound_sites(doc)
            self.assertEqual(sites[136]["target"], 425000000)
            self.assertEqual(sites[144]["target"], 2147483647)
            values = doc["synth"]["evidence"]["max_driver_boundary"]["driver_values"]
            self.assertEqual(values["2147483647"], "immediate")
            self.assertEqual(values["425000000"], "waiting")

    def test_refuses_when_no_driver_sites_in_window(self) -> None:
        # Given: a synthetic build with no int32 60000 code sites in the
        # window (the driver cannot be one).
        with tempfile.TemporaryDirectory() as tmp:
            path = self._synthetic(tmp, {144: 120000})
            reg = self._registry(tmp, {})
            probe = self._stub_probe()
            # When: the auto binder runs.
            ok = oba.bind(path, reg, probe)
            # Then: it refuses before probing, and the registry stays empty.
            self.assertFalse(ok)
            self.assertEqual(json.load(open(reg)), {})
            self.assertEqual([n for n in os.listdir(tmp) if n.startswith("synth.bind_")], [])

    def test_refuses_when_signal_not_observable(self) -> None:
        # Given: an unbound synthetic build; two broken signals: the
        # baseline probe produces no result line (the binary does not run
        # in the harness), and a harness that never observes the wait
        # (every probe completes in 121 s, waits never move).
        with tempfile.TemporaryDirectory() as tmp:
            path = self._synthetic(tmp, {136: 60000, 144: 120000, 152: 60000})
            reg = self._registry(tmp, {})
            # When: the binder runs against the crashed baseline.
            ok = oba.bind(path, reg, lambda a, l, t, c=None: None)
            self.assertFalse(ok)
            self.assertEqual(json.load(open(reg)), {})
            # When: the binder runs against the dead-signal harness.
            ok = oba.bind(path, reg, lambda a, l, t, c=None: (0, 121.5))
            # Then: both are refusals; no entry is recorded.
            self.assertFalse(ok)
            self.assertEqual(json.load(open(reg)), {})

    def test_crashing_subset_is_excluded_and_driver_still_found(self) -> None:
        # Given: four 60000 sites (driver + three decoys) and a probe that
        # yields no result whenever decoy @152 is rewritten while decoy
        # @160 is not (one of the sites is not a plain int32 constant).
        with tempfile.TemporaryDirectory() as tmp:
            path = self._synthetic(tmp, {136: 60000, 144: 120000,
                                         152: 60000, 160: 60000, 168: 60000})
            before = open(path, "rb").read()
            reg = self._registry(tmp, {})
            crash = lambda d: (self._i32(d, 152) == 20000
                               and self._i32(d, 160) == 60000)
            probe = self._stub_probe(crash=crash)
            # When: the auto binder runs (its bisection half @136+@152
            # crashes; the other half is measured no-effect, so the
            # crashed half is kept and halved until the driver is isolated).
            ok = oba.bind(path, reg, probe)
            # Then: the driver is still bound by measurement, the ceiling
            # recorded, and the original intact.
            self.assertTrue(ok)
            doc = json.load(open(reg))
            sites = self._bound_sites(doc)
            self.assertEqual(set(sites), {136, 144})
            self.assertEqual(sites[136]["target"], 2147483647)
            self.assertEqual(open(path, "rb").read(), before)

    def test_refuses_contradictory_half_signals(self) -> None:
        # Given: a probe whose only effective result is the all-sites probe;
        # every bisection half is measured no-effect (contradicts the
        # effective union).
        with tempfile.TemporaryDirectory() as tmp:
            path = self._synthetic(tmp, {136: 60000, 144: 120000, 152: 60000})
            reg = self._registry(tmp, {})
            def probe(artifact, label, timeout, cancel=None):
                if label == "all":
                    return 0, 41.5
                return 0, 121.5
            # When: the auto binder runs.
            ok = oba.bind(path, reg, probe)
            # Then: it refuses on the contradiction; no entry, no artifacts.
            self.assertFalse(ok)
            self.assertEqual(json.load(open(reg)), {})
            self.assertEqual([n for n in os.listdir(tmp) if n.startswith("synth.bind_")], [])

    def test_preserves_existing_entries_and_creates_file_if_missing(self) -> None:
        # Given: a registry that already holds a different build, and a
        # second, missing registry file.
        with tempfile.TemporaryDirectory() as tmp:
            existing = {"9.9.9": {
                "size": 123,
                "sites": [{"offset": 8, "old": 60000, "role": "x"}],
                "evidence": {"date": "2026-01-01"},
            }}
            reg = self._registry(tmp, existing)
            path = self._synthetic(tmp, {136: 60000, 144: 120000, 152: 60000})
            probe = self._stub_probe()
            # When: the binder records the new build.
            ok = oba.bind(path, reg, probe)
            doc = json.load(open(reg))
            # Then: the existing entry survives byte-for-byte (as parsed
            # data) and the new one is added.
            self.assertTrue(ok)
            self.assertEqual(doc["9.9.9"], existing["9.9.9"])
            self.assertIn("synth", doc)
            # When: the registry file does not exist yet.
            reg2 = os.path.join(tmp, "missing.json")
            ok = oba.bind(path, reg2, probe)
            # Then: it is created with exactly the new entry.
            self.assertTrue(ok)
            self.assertEqual(set(json.load(open(reg2))), {"synth"})

    def test_refuses_when_boundary_probe_does_not_run(self) -> None:
        # Given: an unbound build whose INT32_MAX artifact does not run
        # (no result line at the boundary stage).
        with tempfile.TemporaryDirectory() as tmp:
            path = self._synthetic(tmp, {136: 60000, 144: 120000, 152: 60000})
            reg = self._registry(tmp, {})
            base = self._stub_probe()
            def probe(artifact, label, timeout, cancel=None):
                with open(artifact, "rb") as f:
                    if self._i32(f.read(), 136) == 2147483647:
                        return None
                return base(artifact, label, timeout)
            # When: the auto binder runs.
            ok = oba.bind(path, reg, probe)
            # Then: it refuses cleanly (no traceback), no registry entry.
            self.assertFalse(ok)
            self.assertEqual(json.load(open(reg)), {})

    def test_key_collision_and_already_bound(self) -> None:
        # Given: two registry states for the same file name: one records a
        # different-size build under the same key (collision), the other
        # records exactly this build (already bound).
        with tempfile.TemporaryDirectory() as tmp:
            path = self._synthetic(tmp, {136: 60000, 144: 120000, 152: 60000})
            before = open(path, "rb").read()
            collision = {"synth": {"size": 257, "sites": [{"offset": 8, "old": 60000}]}}
            reg = self._registry(tmp, collision)
            # When: the binder runs against the colliding registry.
            ok = oba.bind(path, reg, self._stub_probe())
            # Then: it refuses to overwrite a different build's key,
            # leaving the file untouched.
            self.assertFalse(ok)
            self.assertEqual(json.load(open(reg)), collision)
            # Given: the registry already records this exact build.
            bound = {"synth": {
                "size": 256,
                "sites": [
                    {"offset": 136, "old": 60000, "target": 2147483647},
                    {"offset": 144, "old": 120000, "target": 2147483647},
                ],
                "evidence": {},
            }}
            reg2 = self._registry(tmp, bound)
            file_before = open(reg2, "rb").read()
            def boom(artifact, label, timeout):
                raise AssertionError("no probe may run for an already-bound build")
            # When: the binder runs on the already-bound build.
            ok = oba.bind(path, reg2, boom)
            # Then: it is a no-op success: no probes, file byte-identical.
            self.assertTrue(ok)
            self.assertEqual(open(reg2, "rb").read(), file_before)
            self.assertEqual(open(path, "rb").read(), before)


class PatchAutoBindTests(unittest.TestCase):
    """patch.sh end-to-end on unbound builds: one command binds (measured via
    a probe stand-in with the real run_probe.sh contract), applies, and
    verifies - no manual binding steps."""

    def _bytes(self, values: dict) -> bytes:
        hdr = b"#!/bin/sh\necho 1;exit\n"
        data = bytearray(hdr + b"\x00" * (256 - len(hdr)))
        for off, v in values.items():
            struct.pack_into("<i", data, off, v)
        return bytes(data)

    def _synthetic(self, tmp: str, values: dict, name: str = "synth") -> str:
        path = os.path.join(tmp, name)
        with open(path, "wb") as f:
            f.write(self._bytes(values))
        os.chmod(path, 0o755)
        return path

    def _registry(self, tmp: str, doc: dict) -> str:
        path = os.path.join(tmp, "registry.json")
        with open(path, "w", encoding="utf-8") as f:
            json.dump(doc, f, indent=2)
        return path

    def _stub_probe_script(self, tmp: str) -> str:
        # A run_probe.sh stand-in: same 3-argument contract, same result
        # line format, wait model read from the binary's int32 slots
        # (driver @136, ceiling @144). STUB_BOUNDARY=425000000 switches it
        # to the capped-build model (zero wait above the boundary).
        path = os.path.join(tmp, "probe_stub.sh")
        with open(path, "w", encoding="utf-8") as f:
            f.write(
                "#!/bin/bash\n"
                'B="$1"; L="$2"; T="${3:-300}"\n'
                'if [ -n "${STUB_LOG:-}" ]; then echo "$L $B" >> "$STUB_LOG"; fi\n'
                'python3 - "$B" "$T" <<\'PY\'\n'
                "import os\n"
                "import struct\n"
                "import sys\n"
                "\n"
                "d = open(sys.argv[1], \"rb\").read()\n"
                "t = float(sys.argv[2])\n"
                'b = os.environ.get("STUB_BOUNDARY", "")\n'
                "vd = struct.unpack_from(\"<i\", d, 136)[0]\n"
                "vc = struct.unpack_from(\"<i\", d, 144)[0]\n"
                "if vd == 60000:\n"
                "    rc, e = 0, 2 * min(vc, 60000) / 1000 + 1.5\n"
                'elif b == "425000000" and vd > 425000000:\n'
                "    rc, e = 0, 2.0\n"
                "else:\n"
                "    w = min(vc, vd)\n"
                "    secs = 2 * w / 1000 + 1.5\n"
                "    if secs < t:\n"
                "        rc, e = 0, secs\n"
                "    else:\n"
                "        rc, e = 124, t\n"
                "print(\"STUB rc=%d elapsed=%.1fs\" % (rc, e))\n"
                "PY\n"
            )
        os.chmod(path, 0o755)
        return path

    def _run_script(self, *args: object, env_extra: dict = None, timeout: int = 120) -> subprocess.CompletedProcess:
        env = dict(os.environ)
        if env_extra:
            env.update(env_extra)
        return subprocess.run(
            ["bash", _PATCH_SCRIPT, *[str(a) for a in args]],
            capture_output=True, text=True, timeout=timeout, env=env,
        )

    def _labels(self, log: str) -> list:
        if not os.path.exists(log):
            return []
        return [line.split()[0] for line in open(log)]

    def test_unbound_build_binds_applies_and_verifies(self) -> None:
        # Given: an unbound synthetic build (uncapped wait model) and a
        # probe stand-in standing in for the blackhole harness.
        with tempfile.TemporaryDirectory() as tmp:
            path = self._synthetic(tmp, {136: 60000, 144: 120000, 152: 60000})
            before = open(path, "rb").read()
            reg = self._registry(tmp, {})
            stub = self._stub_probe_script(tmp)
            log = os.path.join(tmp, "probe.log")
            env = {"CLASSIFIER_PROBE_SCRIPT": stub, "STUB_LOG": log}
            # When: the one-line script is invoked.
            proc = self._run_script(path, "--timeout", "15", "--registry", reg, env_extra=env)
            doc = json.load(open(reg))
            # Then: the whole pipeline ran in one command - the build was
            # bound (measured), the patch applied from the registry, and the
            # artifact verified as still waiting.
            self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
            self.assertIn("VERIFIED", proc.stdout)
            sites = {s["offset"]: s for s in doc["synth"]["sites"]}
            self.assertEqual(doc["synth"]["size"], 256)
            self.assertEqual(sites[136]["target"], 2147483647)
            self.assertEqual(sites[144]["target"], 2147483647)
            self.assertEqual(open(path, "rb").read(), before)
            patched = open(path + ".patched", "rb").read()
            self.assertEqual(struct.unpack_from("<i", patched, 136)[0], 2147483647)
            self.assertEqual(struct.unpack_from("<i", patched, 144)[0], 2147483647)
            self.assertEqual(struct.unpack_from("<i", patched, 152)[0], 60000)
            self.assertFalse(os.path.exists(path + ".original"))
            labels = self._labels(log)
            for expected in ("base", "all", "single", "cap0", "bmax", "verify"):
                self.assertIn(expected, labels)
            self.assertEqual([n for n in os.listdir(tmp) if n.startswith("synth.bind_")], [])

    def _collision_registry(self, tmp: str, size: int) -> str:
        # Two registry entries claiming ONE size (two versions shipped at
        # byte-identical size, the 2.1.275/2.1.276 shape), each recording the
        # two sites a synthetic build holds (driver @136, ceiling @144).
        doc = {
            key: {
                "size": size,
                "sites": [
                    {"offset": 136, "old": 60000, "role": "driver"},
                    {"offset": 144, "old": 120000, "role": "ceiling"},
                ],
                "evidence": {},
            }
            for key in ("v1", "v2")
        }
        return self._registry(tmp, doc)

    def test_same_size_collision_bound_build_applies_by_name(self) -> None:
        # Given: a build whose size is claimed by TWO registry entries, the
        # binary named after its own key (the 2.1.276 failure: the
        # size-only lookup saw two candidates and refused).
        with tempfile.TemporaryDirectory() as tmp:
            path = self._synthetic(tmp, {136: 60000, 144: 120000}, name="v2")
            before = open(path, "rb").read()
            reg = self._collision_registry(tmp, len(before))
            # When: the script applies from the registry (auto-bind off - no
            # probe involved).
            proc = self._run_script(path, "--no-verify", "--no-auto-bind",
                                    "--registry", reg)
            # Then: the binary's own key disambiguates the collision, the
            # binding applies, and the artifact holds the int32 max.
            self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
            patched = open(path + ".patched", "rb").read()
            self.assertEqual(struct.unpack_from("<i", patched, 136)[0], 2147483647)
            self.assertEqual(struct.unpack_from("<i", patched, 144)[0], 2147483647)
            self.assertEqual(open(path, "rb").read(), before)

    def test_same_size_collision_bound_build_applies_with_auto_bind(self) -> None:
        # Given: the same collision, but the default invocation (auto-bind on)
        # - the exact 2.1.276 failure shape, where the binder's "already
        # bound" fast path reported success while the size-only lookup
        # refused the entry ("binding reported success but the registry has
        # no matching entry").
        with tempfile.TemporaryDirectory() as tmp:
            path = self._synthetic(tmp, {136: 60000, 144: 120000}, name="v2")
            before = open(path, "rb").read()
            reg = self._collision_registry(tmp, len(before))
            doc_before = json.load(open(reg))
            stub = self._stub_probe_script(tmp)
            env = {"CLASSIFIER_PROBE_SCRIPT": stub}
            # When: the one-liner runs with its default flags.
            proc = self._run_script(path, "--no-verify", "--registry", reg,
                                    env_extra=env)
            # Then: no binding run at all (the lookup resolves the collision
            # by name), the patch applies, the registry is untouched, and the
            # artifact holds the int32 max.
            self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
            self.assertNotIn("binding now", proc.stdout)
            patched = open(path + ".patched", "rb").read()
            self.assertEqual(struct.unpack_from("<i", patched, 136)[0], 2147483647)
            self.assertEqual(struct.unpack_from("<i", patched, 144)[0], 2147483647)
            self.assertEqual(open(path, "rb").read(), before)
            self.assertEqual(json.load(open(reg)), doc_before)

    def test_unbound_capped_build_binds_at_measured_boundary(self) -> None:
        # Given: an unbound synthetic build whose wait is zero above
        # 425000000 ms (the capped-build model, like the 217M build).
        with tempfile.TemporaryDirectory() as tmp:
            path = self._synthetic(tmp, {136: 60000, 144: 120000, 152: 60000})
            before = open(path, "rb").read()
            reg = self._registry(tmp, {})
            stub = self._stub_probe_script(tmp)
            log = os.path.join(tmp, "probe.log")
            env = {"CLASSIFIER_PROBE_SCRIPT": stub, "STUB_LOG": log,
                   "STUB_BOUNDARY": "425000000"}
            # When: the one-line script is invoked.
            proc = self._run_script(path, "--timeout", "15", "--registry", reg, env_extra=env)
            doc = json.load(open(reg))
            # Then: the boundary search ran, the driver target is the
            # largest measured waiting value (not the int32 max, which
            # would zero the wait), and the artifact verifies.
            self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
            self.assertIn("VERIFIED", proc.stdout)
            sites = {s["offset"]: s for s in doc["synth"]["sites"]}
            self.assertEqual(sites[136]["target"], 425000000)
            self.assertEqual(sites[144]["target"], 2147483647)
            self.assertEqual(open(path, "rb").read(), before)
            patched = open(path + ".patched", "rb").read()
            self.assertEqual(struct.unpack_from("<i", patched, 136)[0], 425000000)
            self.assertEqual(struct.unpack_from("<i", patched, 144)[0], 2147483647)
            self.assertFalse(os.path.exists(path + ".original"))
            self.assertTrue(any(l.startswith("bnd") for l in self._labels(log)))

    def test_already_bound_build_skips_the_binder(self) -> None:
        # Given: a synthetic build that already has a registry entry (the
        # probe stand-in logs every call it is asked to make).
        with tempfile.TemporaryDirectory() as tmp:
            path = self._synthetic(tmp, {136: 60000, 144: 120000, 152: 60000})
            before = open(path, "rb").read()
            reg = self._registry(tmp, {"synth": {
                "size": 256,
                "sites": [
                    {"offset": 136, "old": 60000, "target": 2147483647},
                    {"offset": 144, "old": 120000, "target": 2147483647},
                ],
                "evidence": {},
            }})
            stub = self._stub_probe_script(tmp)
            log = os.path.join(tmp, "probe.log")
            env = {"CLASSIFIER_PROBE_SCRIPT": stub, "STUB_LOG": log}
            # When: the one-line script is invoked.
            proc = self._run_script(path, "--timeout", "15", "--registry", reg, env_extra=env)
            # Then: it applies straight from the registry and verifies -
            # the binder (base/all/bis/cap/bmax probes) never ran.
            self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
            self.assertIn("VERIFIED", proc.stdout)
            labels = self._labels(log)
            self.assertEqual(labels, ["verify"])
            self.assertEqual(open(path, "rb").read(), before)
            patched = open(path + ".patched", "rb").read()
            self.assertEqual(struct.unpack_from("<i", patched, 136)[0], 2147483647)
            self.assertEqual(struct.unpack_from("<i", patched, 144)[0], 2147483647)
            self.assertFalse(os.path.exists(path + ".original"))

    def _bound_registry(self, tmp: str) -> str:
        return self._registry(tmp, {"synth": {
            "size": 256,
            "sites": [
                {"offset": 136, "old": 60000, "target": 2147483647},
                {"offset": 144, "old": 120000, "target": 2147483647},
            ],
            "evidence": {},
        }})

    def test_symlink_resolves_to_real_path_and_name(self) -> None:
        # Given: an unbound synthetic build under the name `realbin` and a
        # symlink `link` pointing at it (the user passes the symlink).
        with tempfile.TemporaryDirectory() as tmp:
            real = self._synthetic(tmp, {136: 60000, 144: 120000, 152: 60000}, name="realbin")
            before = open(real, "rb").read()
            link = os.path.join(tmp, "link")
            os.symlink("realbin", link)
            reg = self._registry(tmp, {})
            stub = self._stub_probe_script(tmp)
            log = os.path.join(tmp, "probe.log")
            env = {"CLASSIFIER_PROBE_SCRIPT": stub, "STUB_LOG": log}
            # When: the one-line script is invoked with the symlink path.
            proc = self._run_script(link, "--timeout", "15", "--registry", reg, env_extra=env)
            doc = json.load(open(reg))
            # Then: everything ran on the REAL path with the real target
            # name - the registry key and the .patched artifact all use
            # `realbin`, never the link name - the original is byte-
            # identical, and the symlink still serves the original.
            self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
            self.assertIn("symlink:", proc.stdout)
            self.assertIn("realbin", doc)
            self.assertNotIn("link", doc)
            self.assertTrue(os.path.islink(link))
            self.assertEqual(open(real, "rb").read(), before)
            patched = open(real + ".patched", "rb").read()
            self.assertEqual(struct.unpack_from("<i", patched, 136)[0], 2147483647)
            self.assertEqual(struct.unpack_from("<i", patched, 144)[0], 2147483647)
            self.assertEqual(open(link, "rb").read(), before)
            for absent in (link + ".patched", real + ".original", link + ".original"):
                self.assertFalse(os.path.exists(absent))
            self.assertEqual([n for n in os.listdir(tmp) if n.endswith(".bind_")], [])

    def test_preexisting_patched_artifact_is_regenerated(self) -> None:
        # Given: a bound build whose .patched artifact already exists from
        # an earlier run with DIFFERENT content (a stale artifact).
        with tempfile.TemporaryDirectory() as tmp:
            path = self._synthetic(tmp, {136: 60000, 144: 120000, 152: 60000})
            before = open(path, "rb").read()
            stale = b"stale artifact" + b"\x00" * 20
            with open(path + ".patched", "wb") as f:
                f.write(stale)
            reg = self._bound_registry(tmp)
            stub = self._stub_probe_script(tmp)
            env = {"CLASSIFIER_PROBE_SCRIPT": stub}
            # When: the one-line script is invoked.
            proc = self._run_script(path, "--timeout", "15", "--registry", reg, env_extra=env)
            # Then: the run verifies, the .patched artifact is rewritten
            # from the current binary's bytes (the stale content is gone),
            # and the original is untouched.
            self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
            self.assertIn("VERIFIED", proc.stdout)
            patched = open(path + ".patched", "rb").read()
            self.assertEqual(struct.unpack_from("<i", patched, 136)[0], 2147483647)
            self.assertEqual(struct.unpack_from("<i", patched, 144)[0], 2147483647)
            self.assertNotEqual(patched, stale)
            self.assertEqual(open(path, "rb").read(), before)

    def test_refused_apply_leaves_preexisting_patched_untouched(self) -> None:
        # Given: a binary whose recorded site bytes no longer match the
        # binding (same size, different content at a site - the file
        # changed under the registry entry), with a stale .patched
        # artifact beside it.
        with tempfile.TemporaryDirectory() as tmp:
            path = self._synthetic(tmp, {136: 60000, 144: 77777, 152: 60000})
            before = open(path, "rb").read()
            stale = b"stale artifact" + b"\x00" * 20
            with open(path + ".patched", "wb") as f:
                f.write(stale)
            reg = self._bound_registry(tmp)
            stub = self._stub_probe_script(tmp)
            env = {"CLASSIFIER_PROBE_SCRIPT": stub}
            # When: the one-line script is invoked.
            proc = self._run_script(path, "--timeout", "15", "--registry", reg, env_extra=env)
            # Then: the apply is refused (the recorded site bytes no
            # longer match), the stale .patched is left UNTOUCHED (it may
            # predate the current bytes; the message says so), and the
            # binary is intact.
            self.assertEqual(proc.returncode, 1, proc.stdout + proc.stderr)
            self.assertIn("refused", proc.stdout)
            self.assertIn(".patched", proc.stdout)
            self.assertEqual(open(path, "rb").read(), before)
            self.assertEqual(open(path + ".patched", "rb").read(), stale)

    def test_no_verify_does_not_replace_the_binary(self) -> None:
        # Given: a bound build; the run skips the verification probe.
        with tempfile.TemporaryDirectory() as tmp:
            path = self._synthetic(tmp, {136: 60000, 144: 120000, 152: 60000})
            before = open(path, "rb").read()
            reg = self._bound_registry(tmp)
            # When: the one-line script is invoked with --no-verify.
            proc = self._run_script(path, "--no-verify", "--registry", reg)
            # Then: the patch is applied to the .patched artifact only -
            # the binary is never modified by design (no .original, no
            # rename).
            self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
            self.assertIn("verification skipped", proc.stdout)
            patched = open(path + ".patched", "rb").read()
            self.assertEqual(struct.unpack_from("<i", patched, 136)[0], 2147483647)
            self.assertEqual(open(path, "rb").read(), before)
            self.assertFalse(os.path.exists(path + ".original"))

    def test_replaced_binary_is_refused_when_bytes_differ(self) -> None:
        # Given: a binary whose bytes are the PATCHED content (moved over
        # the original by hand) and the registry entry recorded for the
        # original bytes (same size, different site values).
        with tempfile.TemporaryDirectory() as tmp:
            original = self._bytes({136: 60000, 144: 120000, 152: 60000})
            patched = self._bytes({136: 2147483647, 144: 2147483647, 152: 60000})
            path = os.path.join(tmp, "synth")
            with open(path, "wb") as f:
                f.write(patched)
            os.chmod(path, 0o755)
            reg = self._bound_registry(tmp)
            stub = self._stub_probe_script(tmp)
            env = {"CLASSIFIER_PROBE_SCRIPT": stub}
            # When: the one-line script is invoked on the replaced binary.
            proc = self._run_script(path, "--timeout", "15", "--registry", reg, env_extra=env)
            # Then: the apply is refused (the recorded site bytes no longer
            # match - patching a patched binary is a no-guess refusal),
            # nothing is written or renamed, and the message carries no
            # .original hint (that contract is retired).
            self.assertEqual(proc.returncode, 1, proc.stdout + proc.stderr)
            self.assertIn("refused", proc.stdout)
            self.assertNotIn(".original", proc.stdout)
            self.assertEqual(open(path, "rb").read(), patched)
            self.assertFalse(os.path.exists(path + ".patched"))


_INSTALL_SCRIPT = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "install.sh"
)


class InstallWrapperTests(unittest.TestCase):
    """install.sh / claude-wrapper.sh: the launcher interceptor that patches
    a changed claude binary before booting it. The interceptor lives on a
    NEW claude-patched link - the native claude link is never touched - and
    the wrapper execs the patcher's <binary>.patched artifact when it
    exists."""

    def _fake_home(self, tmp: str) -> tuple:
        # A claude-native layout: bin link -> versions file, one file per
        # version, one *.bak backup (newer mtime than 2.1.269, must never
        # be picked), newest by mtime = 2.1.270.
        home = os.path.join(tmp, "home")
        bin_dir = os.path.join(home, ".local", "bin")
        versions = os.path.join(home, ".local", "share", "claude", "versions")
        os.makedirs(bin_dir)
        os.makedirs(versions)

        def binary(name: str, tag: str, mtime: int) -> str:
            path = os.path.join(versions, name)
            with open(path, "wb") as f:
                f.write(f"#!/bin/sh\necho FAKECLAUDE-{tag} $*\n".encode())
            os.chmod(path, 0o755)
            os.utime(path, (mtime, mtime))
            return path

        binary("2.1.269", "269", 1757000000)
        binary("2.1.269.bak", "269bak", 1757000100)
        target = binary("2.1.270", "270", 1757000200)
        os.symlink(target, os.path.join(bin_dir, "claude"))
        return home, bin_dir, versions, target

    def _stub_patcher(self, tmp: str, fail: int = 0) -> str:
        # Emulates the real patcher's artifact contract: on success it
        # leaves a <binary>.patched file next to the target - with a
        # DIFFERENT marker, so a boot of the artifact is distinguishable
        # from a boot of the unpatched binary - and never touches the
        # original. On failure it leaves nothing.
        path = os.path.join(tmp, "stub_patcher.sh")
        with open(path, "w", encoding="utf-8") as f:
            f.write(
                "#!/bin/bash\n"
                'echo "STUBPATCHER $@" >> "${STUB_LOG:-/dev/null}"\n'
                f'if [ "{fail}" -eq 0 ] && [ -n "${{1:-}}" ]; then\n'
                "  printf '#!/bin/sh\\necho PATCHED-OF-%s $*\\n' \"\\$(basename \"$1\")\" > \"$1.patched\"\n"
                '  chmod +x "$1.patched"\n'
                "fi\n"
                f"exit {fail}\n"
            )
        os.chmod(path, 0o755)
        return path

    def _run(self, *args: object, env_extra: dict = None, timeout: int = 60) -> subprocess.CompletedProcess:
        env = dict(os.environ)
        if env_extra:
            env.update(env_extra)
        return subprocess.run(
            ["bash", *[str(a) for a in args]],
            capture_output=True, text=True, timeout=timeout, env=env,
        )

    def _install(self, home: str, patcher: str) -> subprocess.CompletedProcess:
        return self._run(_INSTALL_SCRIPT, env_extra={"HOME": home, "CLAUDE_PATCHER_SCRIPT": patcher})

    def _state(self, home: str) -> dict:
        doc = {}
        path = os.path.join(home, ".local", "share", "claude", ".last_known_version")
        if os.path.exists(path):
            with open(path) as f:
                for line in f:
                    k, _, v = line.rstrip("\n").partition("=")
                    doc[k] = v
        return doc

    def test_install_points_claude_patched_and_first_launch_patches(self) -> None:
        # Given: a fake home with the native layout and a stub patcher.
        with tempfile.TemporaryDirectory() as tmp:
            home, bin_dir, versions, target = self._fake_home(tmp)
            stub = self._stub_patcher(tmp)
            log = os.path.join(tmp, "stub.log")
            before = open(target, "rb").read()
            # When: the installer runs, then claude-patched is launched for
            # the first time.
            inst = self._install(home, stub)
            # Then: the NEW claude-patched link points at the wrapper, the
            # native claude link is untouched, and the state was
            # initialized - no recorded hash yet (the first launch counts
            # as "changed").
            self.assertEqual(inst.returncode, 0, inst.stdout + inst.stderr)
            claude = os.path.join(bin_dir, "claude")
            claude_patched = os.path.join(bin_dir, "claude-patched")
            self.assertEqual(os.readlink(claude_patched), os.path.join(bin_dir, "claude-wrapper.sh"))
            self.assertEqual(os.readlink(claude), target)
            fresh = self._state(home)
            self.assertEqual(fresh["versions_dir"], versions)
            self.assertEqual(fresh["origin"], target)
            self.assertEqual(fresh["origin_link_target"], target)
            self.assertEqual(fresh["hash"], "")
            # When: the first launch happens.
            boot = self._run(claude_patched, "--flag", env_extra={"HOME": home, "STUB_LOG": log})
            # Then: the never-recorded binary was detected, the patcher ran
            # on the REAL target (not the link), the boot came from the
            # patched ARTIFACT (the original file is byte-identical), and
            # the identity was recorded.
            self.assertEqual(boot.returncode, 0, boot.stdout + boot.stderr)
            self.assertIn("PATCHED-OF-2.1.270 --flag", boot.stdout)
            self.assertIn("new/changed claude binary detected", boot.stdout)
            self.assertEqual(open(log).read().splitlines(), [f"STUBPATCHER {target}"])
            self.assertEqual(open(target, "rb").read(), before)
            self.assertTrue(os.path.exists(target + ".patched"))
            recorded = self._state(home)
            self.assertNotEqual(recorded["hash"], "")
            self.assertEqual(recorded["binary"], target)
            self.assertEqual(recorded["version"], "2.1.270")

    def test_second_launch_does_not_repatch(self) -> None:
        # Given: the wrapper is installed and the binary was patched +
        # recorded on the first launch (the versions dir now also holds
        # the .patched artifact, newer than the binary itself).
        with tempfile.TemporaryDirectory() as tmp:
            home, bin_dir, versions, target = self._fake_home(tmp)
            stub = self._stub_patcher(tmp)
            log = os.path.join(tmp, "stub.log")
            claude_patched = os.path.join(bin_dir, "claude-patched")
            env = {"HOME": home, "STUB_LOG": log}
            self._install(home, stub)
            self._run(claude_patched, env_extra=env)
            # When: claude-patched is launched again (nothing changed).
            boot = self._run(claude_patched, "--x", env_extra=env)
            # Then: no patcher call, no change message, the boot comes
            # from the existing artifact (zero cost: the size+mtime fast
            # path matches the record; the scan skipped the artifact).
            self.assertEqual(boot.returncode, 0, boot.stdout + boot.stderr)
            self.assertIn("PATCHED-OF-2.1.270 --x", boot.stdout)
            self.assertNotIn("new/changed", boot.stdout)
            self.assertEqual(open(log).read().splitlines(), [f"STUBPATCHER {target}"])

    def test_new_version_is_detected_and_patched(self) -> None:
        # Given: an installed wrapper that recorded 2.1.270; then a new
        # version file 2.1.271 (newest mtime) appears in the versions dir.
        with tempfile.TemporaryDirectory() as tmp:
            home, bin_dir, versions, target = self._fake_home(tmp)
            stub = self._stub_patcher(tmp)
            log = os.path.join(tmp, "stub.log")
            claude_patched = os.path.join(bin_dir, "claude-patched")
            env = {"HOME": home, "STUB_LOG": log}
            self._install(home, stub)
            self._run(claude_patched, env_extra=env)
            with open(os.path.join(versions, "2.1.271"), "wb") as f:
                f.write(b"#!/bin/sh\necho FAKECLAUDE-271 $*\n")
            os.chmod(os.path.join(versions, "2.1.271"), 0o755)
            os.utime(os.path.join(versions, "2.1.271"), (1757000300, 1757000300))
            # When: claude-patched is launched.
            boot = self._run(claude_patched, "--y", env_extra=env)
            # Then: the new newest file is targeted, patched, recorded,
            # and booted through its artifact.
            self.assertEqual(boot.returncode, 0, boot.stdout + boot.stderr)
            self.assertIn("PATCHED-OF-2.1.271 --y", boot.stdout)
            calls = open(log).read().splitlines()
            self.assertEqual(calls, [f"STUBPATCHER {target}",
                                      f"STUBPATCHER {os.path.join(versions, '2.1.271')}"])
            state = self._state(home)
            self.assertEqual(state["binary"], os.path.join(versions, "2.1.271"))
            self.assertEqual(state["version"], "2.1.271")

    def test_versions_scan_never_picks_a_patched_artifact(self) -> None:
        # Given: an installed wrapper that patched 2.1.270 on the first
        # launch (the versions dir now holds 2.1.270.patched); then a real
        # new version 2.1.271 appears, and the stale artifact keeps the
        # NEWEST mtime in the dir (a scan that forgot the filter would
        # target the artifact, not the new binary).
        with tempfile.TemporaryDirectory() as tmp:
            home, bin_dir, versions, target = self._fake_home(tmp)
            stub = self._stub_patcher(tmp)
            log = os.path.join(tmp, "stub.log")
            claude_patched = os.path.join(bin_dir, "claude-patched")
            env = {"HOME": home, "STUB_LOG": log}
            self._install(home, stub)
            first = self._run(claude_patched, env_extra=env)
            self.assertEqual(first.returncode, 0, first.stdout + first.stderr)
            artifact = os.path.join(versions, "2.1.270.patched")
            self.assertTrue(os.path.exists(artifact))
            os.utime(artifact, (1757000400, 1757000400))
            with open(os.path.join(versions, "2.1.271"), "wb") as f:
                f.write(b"#!/bin/sh\necho FAKECLAUDE-271 $*\n")
            os.chmod(os.path.join(versions, "2.1.271"), 0o755)
            os.utime(os.path.join(versions, "2.1.271"), (1757000300, 1757000300))
            # When: claude-patched is launched.
            boot = self._run(claude_patched, "--q", env_extra=env)
            # Then: the newest REAL binary is the target (patched,
            # recorded, booted through its artifact) - the stale artifact
            # was not considered at all.
            self.assertEqual(boot.returncode, 0, boot.stdout + boot.stderr)
            self.assertIn("PATCHED-OF-2.1.271 --q", boot.stdout)
            state = self._state(home)
            self.assertEqual(state["binary"], os.path.join(versions, "2.1.271"))
            self.assertEqual(state["version"], "2.1.271")

    def test_identical_content_replacement_does_not_repatch(self) -> None:
        # Given: an installed wrapper that recorded 2.1.270 (its .patched
        # artifact exists); then the SAME file is replaced in place with
        # byte-identical content (a re-download that keeps the name - the
        # mtime changes, the hash does not).
        with tempfile.TemporaryDirectory() as tmp:
            home, bin_dir, versions, target = self._fake_home(tmp)
            stub = self._stub_patcher(tmp)
            log = os.path.join(tmp, "stub.log")
            claude_patched = os.path.join(bin_dir, "claude-patched")
            env = {"HOME": home, "STUB_LOG": log}
            self._install(home, stub)
            first = self._run(claude_patched, env_extra=env)
            self.assertEqual(first.returncode, 0)
            content = open(target, "rb").read()
            with open(target, "wb") as f:
                f.write(content)
            os.chmod(target, 0o755)
            os.utime(target, (1757000300, 1757000300))
            # When: claude-patched is launched.
            boot = self._run(claude_patched, env_extra=env)
            # Then: the size matches and the sha256 matches the record (the
            # mtime check forced the hash) - no patcher call, the existing
            # artifact boots, and the new mtime is re-recorded.
            self.assertEqual(boot.returncode, 0, boot.stdout + boot.stderr)
            self.assertIn("PATCHED-OF-2.1.270", boot.stdout)
            self.assertNotIn("new/changed", boot.stdout)
            self.assertEqual(open(log).read().splitlines(), [f"STUBPATCHER {target}"])
            state = self._state(home)
            self.assertEqual(state["binary"], target)
            self.assertEqual(state["mtime"], "1757000300")

    def test_removed_artifact_is_regenerated(self) -> None:
        # Given: an installed wrapper that patched + recorded 2.1.270 (the
        # .patched artifact exists next to the binary); then the user
        # deletes the artifact (the binary itself is untouched).
        with tempfile.TemporaryDirectory() as tmp:
            home, bin_dir, versions, target = self._fake_home(tmp)
            stub = self._stub_patcher(tmp)
            log = os.path.join(tmp, "stub.log")
            claude_patched = os.path.join(bin_dir, "claude-patched")
            env = {"HOME": home, "STUB_LOG": log}
            self._install(home, stub)
            first = self._run(claude_patched, env_extra=env)
            self.assertEqual(first.returncode, 0, first.stdout + first.stderr)
            self.assertTrue(os.path.exists(target + ".patched"))
            os.remove(target + ".patched")
            # When: claude-patched is launched.
            boot = self._run(claude_patched, env_extra=env)
            # Then: the missing artifact counts as changed - the patcher ran
            # again on the UNCHANGED binary, the artifact is back, and the
            # launch booted it.
            self.assertEqual(boot.returncode, 0, boot.stdout + boot.stderr)
            self.assertIn("PATCHED-OF-2.1.270", boot.stdout)
            self.assertTrue(os.path.exists(target + ".patched"))
            self.assertEqual(open(log).read().splitlines(),
                             [f"STUBPATCHER {target}", f"STUBPATCHER {target}"])

    def test_patcher_failure_still_boots_the_binary(self) -> None:
        # Given: an installed wrapper whose patcher fails (exit 1).
        with tempfile.TemporaryDirectory() as tmp:
            home, bin_dir, versions, target = self._fake_home(tmp)
            stub = self._stub_patcher(tmp, fail=1)
            log = os.path.join(tmp, "stub.log")
            claude_patched = os.path.join(bin_dir, "claude-patched")
            env = {"HOME": home, "STUB_LOG": log}
            self._install(home, stub)
            # When: claude-patched is launched.
            boot = self._run(claude_patched, "--z", env_extra=env)
            # Then: the patch was attempted, the failure is reported, but
            # the UNPATCHED binary still boots (the wrapper never blocks
            # claude; no artifact exists or is booted).
            self.assertEqual(boot.returncode, 0, boot.stdout + boot.stderr)
            self.assertIn("FAKECLAUDE-270 --z", boot.stdout)
            self.assertIn("exited non-zero", boot.stdout)
            self.assertNotIn("PATCHED-OF", boot.stdout)
            self.assertFalse(os.path.exists(target + ".patched"))
            # When: claude-patched is launched again.
            second = self._run(claude_patched, "--z", env_extra=env)
            # Then: the missing artifact counts as changed, so the failing
            # patch is RETRIED (it will be, every launch, until the patcher
            # succeeds) - but the UNPATCHED binary still boots and the
            # failure is reported again; claude is never blocked.
            self.assertEqual(second.returncode, 0, second.stdout + second.stderr)
            self.assertIn("FAKECLAUDE-270 --z", second.stdout)
            self.assertIn("exited non-zero", second.stdout)
            self.assertEqual(open(log).read().splitlines(),
                             [f"STUBPATCHER {target}", f"STUBPATCHER {target}"])

    def test_no_patch_env_var_skips_and_defers_the_patcher(self) -> None:
        # Given: an installed wrapper, and the escape-hatch env var set.
        with tempfile.TemporaryDirectory() as tmp:
            home, bin_dir, versions, target = self._fake_home(tmp)
            stub = self._stub_patcher(tmp)
            log = os.path.join(tmp, "stub.log")
            claude_patched = os.path.join(bin_dir, "claude-patched")
            env = {"HOME": home, "STUB_LOG": log, "CLAUDE_WRAPPER_NO_PATCH": "1"}
            self._install(home, stub)
            # When: claude-patched is launched with the skip flag...
            skip = self._run(claude_patched, env_extra=env)
            self.assertEqual(skip.returncode, 0, skip.stdout + skip.stderr)
            self.assertIn("FAKECLAUDE-270", skip.stdout)
            self.assertIn("patch skipped", skip.stdout)
            self.assertFalse(os.path.exists(log))
            # ...the identity is NOT recorded (the skip is a temporary
            # escape, not an acceptance of the new binary)...
            self.assertEqual(self._state(home)["hash"], "")
            # ...and a normal launch right after still patches it (and
            # boots the artifact).
            normal = self._run(claude_patched, env_extra={"HOME": home, "STUB_LOG": log})
            self.assertEqual(normal.returncode, 0, normal.stdout + normal.stderr)
            self.assertIn("PATCHED-OF-2.1.270", normal.stdout)
            self.assertEqual(open(log).read().splitlines(), [f"STUBPATCHER {target}"])
            # When: the launch is skipped again, now with a patched
            # artifact present.
            skip2 = self._run(claude_patched, env_extra=env)
            # Then: the UNPATCHED binary boots (the skip refuses the
            # artifact too).
            self.assertEqual(skip2.returncode, 0, skip2.stdout + skip2.stderr)
            self.assertIn("FAKECLAUDE-270", skip2.stdout)
            self.assertNotIn("PATCHED-OF", skip2.stdout)

    def test_uninstall_removes_claude_patched(self) -> None:
        # Given: the wrapper is installed (claude-patched over the wrapper;
        # the native claude link points at the versions file).
        with tempfile.TemporaryDirectory() as tmp:
            home, bin_dir, versions, target = self._fake_home(tmp)
            stub = self._stub_patcher(tmp)
            self._install(home, stub)
            # When: the uninstaller runs.
            un = self._run(_INSTALL_SCRIPT, "--uninstall", env_extra={"HOME": home})
            claude = os.path.join(bin_dir, "claude")
            claude_patched = os.path.join(bin_dir, "claude-patched")
            # Then: claude-patched, the wrapper, and the state are removed,
            # and the native claude link is exactly as before (it was
            # never modified - nothing to restore).
            self.assertEqual(un.returncode, 0, un.stdout + un.stderr)
            self.assertEqual(os.readlink(claude), target)
            self.assertFalse(os.path.exists(claude_patched))
            self.assertFalse(os.path.exists(os.path.join(bin_dir, "claude-wrapper.sh")))
            self.assertFalse(os.path.exists(
                os.path.join(home, ".local", "share", "claude", ".last_known_version")))

    def test_install_refuses_without_claude(self) -> None:
        # Given: a home with an empty bin dir (no claude installed).
        with tempfile.TemporaryDirectory() as tmp:
            home = os.path.join(tmp, "home")
            os.makedirs(os.path.join(home, ".local", "bin"))
            # When: the installer runs.
            inst = self._install(home, self._stub_patcher(tmp))
            # Then: it refuses with exit 2 and changes nothing.
            self.assertEqual(inst.returncode, 2, inst.stdout + inst.stderr)
            self.assertIn("does not exist", inst.stdout + inst.stderr)
            self.assertFalse(os.path.exists(os.path.join(home, ".local", "bin", "claude-wrapper.sh")))

    def test_plain_file_claude_is_allowed_and_never_touched(self) -> None:
        # Given: a home where the claude bin entry is a plain file (not a
        # symlink) - the installer never touches it, so it needs no
        # renaming.
        with tempfile.TemporaryDirectory() as tmp:
            home = os.path.join(tmp, "home")
            bin_dir = os.path.join(home, ".local", "bin")
            os.makedirs(bin_dir)
            claude = os.path.join(bin_dir, "claude")
            with open(claude, "wb") as f:
                f.write(b"#!/bin/sh\necho FAKECLAUDE-plain $*\n")
            os.chmod(claude, 0o755)
            before = open(claude, "rb").read()
            stub = self._stub_patcher(tmp)
            log = os.path.join(tmp, "stub.log")
            # When: the installer runs and claude-patched is launched.
            inst = self._install(home, stub)
            self.assertEqual(inst.returncode, 0, inst.stdout + inst.stderr)
            boot = self._run(os.path.join(bin_dir, "claude-patched"), "--p",
                             env_extra={"HOME": home, "STUB_LOG": log})
            # Then: the install succeeded, the patcher ran on the claude
            # file itself (no versions dir in this layout), the boot came
            # through the patched artifact, and the claude file is
            # byte-identical.
            self.assertEqual(boot.returncode, 0, boot.stdout + boot.stderr)
            self.assertIn("PATCHED-OF-claude --p", boot.stdout)
            self.assertEqual(open(log).read().splitlines(), [f"STUBPATCHER {claude}"])
            self.assertEqual(open(claude, "rb").read(), before)
            self.assertTrue(os.path.exists(claude + ".patched"))

    def test_install_refuses_a_plain_file_claude_patched(self) -> None:
        # Given: a home with a native claude symlink and an existing
        # claude-patched that is a PLAIN FILE (a user file, not a link).
        with tempfile.TemporaryDirectory() as tmp:
            home, bin_dir, versions, target = self._fake_home(tmp)
            user_file = os.path.join(bin_dir, "claude-patched")
            with open(user_file, "wb") as f:
                f.write(b"#!/bin/sh\necho USER-FILE $*\n")
            os.chmod(user_file, 0o755)
            before = open(user_file, "rb").read()
            # When: the installer runs.
            inst = self._install(home, self._stub_patcher(tmp))
            # Then: it refuses (exit 2), the user file is untouched, and
            # nothing else was written.
            self.assertEqual(inst.returncode, 2, inst.stdout + inst.stderr)
            self.assertIn("plain file", inst.stdout + inst.stderr)
            self.assertEqual(open(user_file, "rb").read(), before)
            self.assertFalse(os.path.exists(os.path.join(bin_dir, "claude-wrapper.sh")))
            self.assertFalse(os.path.exists(
                os.path.join(home, ".local", "share", "claude", ".last_known_version")))

    def test_non_versions_symlink_layout_tracks_the_origin_file(self) -> None:
        # Given: a home where claude is a symlink to a binary file that is
        # NOT under the versions dir (the generic fallback layout).
        with tempfile.TemporaryDirectory() as tmp:
            home = os.path.join(tmp, "home")
            bin_dir = os.path.join(home, ".local", "bin")
            os.makedirs(bin_dir)
            native = os.path.join(bin_dir, "claude-native")
            with open(native, "wb") as f:
                f.write(b"#!/bin/sh\necho FAKECLAUDE-native $*\n")
            os.chmod(native, 0o755)
            before = open(native, "rb").read()
            claude = os.path.join(bin_dir, "claude")
            os.symlink(native, claude)
            stub = self._stub_patcher(tmp)
            log = os.path.join(tmp, "stub.log")
            # When: the installer runs and claude-patched is launched.
            inst = self._install(home, stub)
            self.assertEqual(inst.returncode, 0, inst.stdout + inst.stderr)
            boot = self._run(os.path.join(bin_dir, "claude-patched"), "--p",
                             env_extra={"HOME": home, "STUB_LOG": log})
            # Then: the wrapper is installed, the patcher ran on the
            # ORIGIN file (tracked by hash, no versions dir), and the boot
            # came through the origin's artifact (the origin file is
            # byte-identical).
            self.assertEqual(boot.returncode, 0, boot.stdout + boot.stderr)
            self.assertIn("PATCHED-OF-claude-native --p", boot.stdout)
            self.assertEqual(open(log).read().splitlines(), [f"STUBPATCHER {native}"])
            state = self._state(home)
            self.assertEqual(state["versions_dir"], "")
            self.assertEqual(state["origin"], native)
            self.assertEqual(state["binary"], native)
            self.assertEqual(open(native, "rb").read(), before)
            # When: the uninstaller runs.
            un = self._run(_INSTALL_SCRIPT, "--uninstall", env_extra={"HOME": home})
            # Then: claude-patched and the wrapper are gone, and the native
            # link is exactly as before.
            self.assertEqual(un.returncode, 0, un.stdout + un.stderr)
            self.assertEqual(os.readlink(claude), native)
            self.assertFalse(os.path.exists(os.path.join(bin_dir, "claude-patched")))
            self.assertFalse(os.path.exists(os.path.join(bin_dir, "claude-wrapper.sh")))


_RUN_PROBE = os.path.join(_ORACLE_DIR, "run_probe.sh")


class RunProbeScriptTests(unittest.TestCase):
    """run_probe.sh: every probe owns its endpoint port (concurrent probes
    never collide on the fake endpoint), and the optional early status check
    reports a still-waiting run (one blackholed classifier attempt) and kills
    it, while anything else runs to the natural end."""

    def _env(self, tmp: str) -> dict:
        return dict(os.environ, CLAUDE_PATCHER_PROBE_DIR=tmp)

    def _binary(self, tmp: str, body: str, name: str = "bin") -> str:
        path = os.path.join(tmp, name)
        with open(path, "w", encoding="utf-8") as f:
            f.write(body)
        os.chmod(path, 0o755)
        return path

    def _run_probe(self, tmp: str, binary: str, label: str,
                   timeout: int, check_at: int = None) -> subprocess.CompletedProcess:
        args = ["bash", _RUN_PROBE, binary, label, str(timeout)]
        if check_at is not None:
            args.append(str(check_at))
        return subprocess.run(args, capture_output=True, text=True,
                              timeout=timeout + 60, env=self._env(tmp))

    def _endpoint_port(self, tmp: str, label: str) -> int:
        log = os.path.join(tmp, f"claude-patcher-probe-{label}", "fake_endpoint.log")
        for line in open(log):
            if "listening on 127.0.0.1:" in line:
                return int(line.split("127.0.0.1:")[1].split()[0])
        self.fail(f"no listening line in {log}")

    def test_concurrent_probes_use_distinct_ports(self) -> None:
        # Given: two probe invocations that start at the same time (each
        # binary sleeps, so both endpoints are alive at the same moment).
        with tempfile.TemporaryDirectory() as tmp:
            slow = self._binary(tmp, "#!/bin/sh\nsleep 2\n")
            # When: both probes run concurrently.
            p1 = subprocess.Popen(
                ["bash", _RUN_PROBE, slow, "pa", "6"],
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                env=self._env(tmp))
            p2 = subprocess.Popen(
                ["bash", _RUN_PROBE, slow, "pb", "6"],
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                env=self._env(tmp))
            out1 = p1.communicate(timeout=60)[0].decode()
            out2 = p2.communicate(timeout=60)[0].decode()
            # Then: each probe owns a distinct endpoint port (concurrent
            # probes never collide) and both complete.
            pa = self._endpoint_port(tmp, "pa")
            pb = self._endpoint_port(tmp, "pb")
            self.assertNotEqual(pa, pb)
            self.assertIn("pa rc=0 elapsed=", out1)
            self.assertIn("pb rc=0 elapsed=", out2)

    def test_early_check_reports_and_kills_a_single_blackholed_wait(self) -> None:
        # Given: a probe binary that records ONE blackholed classifier
        # attempt in the endpoint log and then keeps waiting (a long
        # per-attempt wait, like a patched build).
        with tempfile.TemporaryDirectory() as tmp:
            slow = self._binary(
                tmp,
                "#!/bin/sh\n"
                'echo "12:00:00   -> BLACKHOLED (classifier marker matched)" '
                ">> fake_endpoint.log\n"
                "sleep 60\n",
            )
            t0 = time.monotonic()
            # When: the probe runs with a 2 s early status check.
            proc = self._run_probe(tmp, slow, "early", 60, check_at=2)
            wall = time.monotonic() - t0
            # Then: the run is reported still-waiting at the check point
            # (one blackholed attempt) and killed there - the probe
            # returns after ~2 s, not after the 60 s timeout.
            self.assertIn(" early still_waiting=1 ", proc.stdout)
            self.assertIn("blackholed=1", proc.stdout)
            self.assertLess(wall, 15)

    def test_early_check_stays_silent_with_two_attempts(self) -> None:
        # Given: a binary that records TWO blackholed attempts (the
        # per-attempt wait is back to the unpatched ~60 s: the second
        # attempt has started) and then keeps waiting.
        with tempfile.TemporaryDirectory() as tmp:
            slow = self._binary(
                tmp,
                "#!/bin/sh\n"
                'echo "12:00:00   -> BLACKHOLED (classifier marker matched)" '
                ">> fake_endpoint.log\n"
                'echo "12:01:01   -> BLACKHOLED (classifier marker matched)" '
                ">> fake_endpoint.log\n"
                "sleep 60\n",
            )
            # When: the probe runs with a 2 s early check and a 3 s cap.
            proc = self._run_probe(tmp, slow, "two", 3, check_at=2)
            # Then: no early verdict (two attempts means the wait did not
            # extend), the run is not killed early - it hits the 3 s cap
            # (rc=124) with no early line.
            self.assertNotIn(" early ", proc.stdout)
            self.assertIn("two rc=124 elapsed=", proc.stdout)

    def test_early_check_is_noop_when_the_run_already_finished(self) -> None:
        # Given: a binary that exits before the early check point.
        with tempfile.TemporaryDirectory() as tmp:
            fast = self._binary(tmp, "#!/bin/sh\nsleep 1\n")
            # When: the probe runs with a 3 s early check.
            proc = self._run_probe(tmp, fast, "fast", 30, check_at=3)
            # Then: no early line, the natural result (rc=0 in ~1 s).
            self.assertNotIn(" early ", proc.stdout)
            self.assertIn("fast rc=0 elapsed=1.", proc.stdout)

    @staticmethod
    def _pid_alive(pid: int) -> bool:
        # A process is alive only while it exists and is not a zombie
        # (the same alive() semantics run_probe.sh uses).
        try:
            out = subprocess.run(
                ["ps", "-o", "state=", "-p", str(pid)],
                capture_output=True, text=True,
            ).stdout.strip()
        except OSError:
            return False
        return bool(out) and out != "Z"

    @staticmethod
    def _port_open(port: int) -> bool:
        sock = socket.socket()
        sock.settimeout(0.5)
        try:
            sock.connect(("127.0.0.1", port))
            return True
        except (ConnectionRefusedError, socket.timeout, OSError):
            return False
        finally:
            sock.close()

    def _bin_pid(self, tmp: str, label: str) -> int:
        return int(open(os.path.join(
            tmp, f"claude-patcher-probe-{label}", "bin_pid")).read())

    def _wait_for_bin_pid(self, tmp: str, label: str,
                          deadline_s: float = 30) -> None:
        # The probe binary records its own PID at start; waiting for the
        # file (instead of a fixed sleep) lands the signal/cancel exactly
        # while the run is inside its wait, and without the fixed seconds.
        path = os.path.join(tmp, f"claude-patcher-probe-{label}", "bin_pid")
        deadline = time.monotonic() + deadline_s
        while time.monotonic() < deadline:
            if os.path.exists(path):
                return
            time.sleep(0.05)
        self.fail(f"the run never started (no {path})")

    def test_term_cancels_the_run_without_a_result_line(self) -> None:
        # Given: a probe binary that records its own PID (so the test can
        # check that it is stopped) and then keeps waiting.
        with tempfile.TemporaryDirectory() as tmp:
            slow = self._binary(
                tmp, "#!/bin/sh\necho $$ > bin_pid\nsleep 30\n")
            proc = subprocess.Popen(
                ["bash", _RUN_PROBE, slow, "canc", "60"],
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                env=self._env(tmp))
            self._wait_for_bin_pid(tmp, "canc")  # the run is in its wait
            # When: the binder cancels the probe (SIGTERM to the script).
            proc.terminate()
            out = proc.communicate(timeout=30)[0].decode()
            # Then: the script exits 143 without a result line (a
            # cancelled run is not a measurement), and it stopped its
            # binary and its endpoint (no orphaned processes).
            self.assertEqual(proc.returncode, 143)
            self.assertNotIn(" rc=", out)
            self.assertFalse(self._pid_alive(self._bin_pid(tmp, "canc")))
            self.assertFalse(self._port_open(self._endpoint_port(tmp, "canc")))

    def test_term_before_the_check_point_cancels_too(self) -> None:
        # Given: a probe with an early check point 10 s out; the signal
        # arrives shortly after the run starts, while the script waits
        # for the check point.
        with tempfile.TemporaryDirectory() as tmp:
            slow = self._binary(
                tmp, "#!/bin/sh\necho $$ > bin_pid\nsleep 30\n")
            t0 = time.monotonic()
            proc = subprocess.Popen(
                ["bash", _RUN_PROBE, slow, "canc2", "60", "10"],
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                env=self._env(tmp))
            self._wait_for_bin_pid(tmp, "canc2")  # before the 10 s check
            # When: SIGTERM arrives while the script waits for the check.
            proc.terminate()
            out = proc.communicate(timeout=30)[0].decode()
            wall = time.monotonic() - t0
            # Then: the trap cancels the run anyway - no early line, no
            # result line, binary stopped, endpoint closed. The cancel is
            # immediate: the check-point wait is interruptible, so the
            # signal is not deferred until the 10 s check point.
            self.assertLess(wall, 5)
            self.assertEqual(proc.returncode, 143)
            self.assertNotIn(" rc=", out)
            self.assertNotIn(" early ", out)
            self.assertFalse(self._pid_alive(self._bin_pid(tmp, "canc2")))
            self.assertFalse(self._port_open(self._endpoint_port(tmp, "canc2")))

    def test_probe_run_cancel_event_stops_the_script(self) -> None:
        # Given: the real probe harness through the binder's probe function
        # (run in a thread, like the binder's bisection round), a binary
        # that records its PID and keeps waiting, and a cancel event the
        # binder may set.
        with tempfile.TemporaryDirectory() as tmp:
            slow = self._binary(
                tmp, "#!/bin/sh\necho $$ > bin_pid\nsleep 60\n")
            cancel = threading.Event()
            result = []
            saved = os.environ.get("CLAUDE_PATCHER_PROBE_DIR")
            os.environ["CLAUDE_PATCHER_PROBE_DIR"] = tmp
            try:
                worker = threading.Thread(
                    target=lambda: result.append(
                        oba.probe_via_script(_RUN_PROBE)(
                            slow, "pevent", 60, cancel)),
                    daemon=True)
                # When: the probe starts, and the binder signals the cancel
                # while the run is inside its wait.
                worker.start()
                self._wait_for_bin_pid(tmp, "pevent")
                t0 = time.monotonic()
                cancel.set()
                worker.join(timeout=30)
                wall = time.monotonic() - t0
            finally:
                if saved is None:
                    os.environ.pop("CLAUDE_PATCHER_PROBE_DIR", None)
                else:
                    os.environ["CLAUDE_PATCHER_PROBE_DIR"] = saved
            # Then: the probe returns None promptly (a cancelled run is not
            # a measurement), and the harness stopped its binary and its
            # endpoint.
            self.assertFalse(worker.is_alive())
            self.assertEqual(len(result), 1)
            self.assertIsNone(result[0])
            self.assertLess(wall, 15)
            self.assertFalse(self._pid_alive(self._bin_pid(tmp, "pevent")))
            self.assertFalse(self._port_open(self._endpoint_port(tmp, "pevent")))


class PatchScriptParallelTests(unittest.TestCase):
    """patch.sh speed paths: the --baseline probe runs in parallel with the
    verify probe, and --fast-verify accepts the early still-waiting evidence
    (one blackholed classifier attempt at the check point) instead of
    waiting out the full probe cap."""

    def _synthetic(self, tmp: str, values: dict, name: str = "synth") -> str:
        hdr = b"#!/bin/sh\necho 1;exit\n"
        data = bytearray(hdr + b"\x00" * (256 - len(hdr)))
        for off, v in values.items():
            struct.pack_into("<i", data, off, v)
        path = os.path.join(tmp, name)
        with open(path, "wb") as f:
            f.write(bytes(data))
        os.chmod(path, 0o755)
        return path

    def _registry(self, tmp: str, doc: dict) -> str:
        path = os.path.join(tmp, "registry.json")
        with open(path, "w", encoding="utf-8") as f:
            json.dump(doc, f, indent=2)
        return path

    def _bound_registry(self, tmp: str, target: int = None) -> str:
        sites = [
            {"offset": 136, "old": 60000, "role": "driver"},
            {"offset": 144, "old": 120000, "role": "ceiling"},
        ]
        if target is not None:
            sites[0]["target"] = target
        return self._registry(tmp, {"synth": {
            "size": 256, "sites": sites, "evidence": {},
        }})

    def _run_script(self, *args: object, env_extra: dict = None,
                    timeout: int = 120) -> subprocess.CompletedProcess:
        env = dict(os.environ)
        if env_extra:
            env.update(env_extra)
        return subprocess.run(
            ["bash", _PATCH_SCRIPT, *[str(a) for a in args]],
            capture_output=True, text=True, timeout=timeout, env=env,
        )

    def _timing_stub(self, tmp: str, sleep_s: int) -> str:
        # A probe stand-in that sleeps per call and records start/end
        # timestamps (for overlap checks).
        path = os.path.join(tmp, "probe_stub.sh")
        with open(path, "w", encoding="utf-8") as f:
            f.write(
                "#!/bin/bash\n"
                'B="$1"; L="$2"; T="${3:-300}"\n'
                'echo "$L start $(date +%s.%N)" >> "${STUB_LOG:-/dev/null}"\n'
                f"sleep {sleep_s}\n"
                'echo "$L end $(date +%s.%N)" >> "${STUB_LOG:-/dev/null}"\n'
                f'echo "$L rc=124 elapsed={sleep_s}.0s"\n'
            )
        os.chmod(path, 0o755)
        return path

    def _fast_stub(self, tmp: str) -> str:
        # Emulates the run_probe.sh 4-argument contract: with a check point,
        # a binary whose driver slot holds the int32 max is still waiting at
        # the check with exactly one blackholed attempt (early line +
        # kill); anything else just ends. Without a check point the result
        # comes at the cap (the 3-argument contract).
        path = os.path.join(tmp, "probe_stub.sh")
        with open(path, "w", encoding="utf-8") as f:
            f.write(
                "#!/bin/bash\n"
                'B="$1"; L="$2"; T="${3:-300}"; C="${4:-}"\n'
                'VD=$(python3 -c "import struct,sys; print('
                'struct.unpack_from(\'<i\', open(sys.argv[1], \'rb\').read(), 136)[0])" "$B")\n'
                'if [ -n "$C" ]; then\n'
                '  sleep "$C"\n'
                '  if [ "$VD" = "2147483647" ]; then\n'
                '    echo "$L early still_waiting=1 elapsed=${C}s blackholed=1"\n'
                '    echo "$L rc=143 elapsed=${C}s"\n'
                "  else\n"
                '    echo "$L rc=0 elapsed=${C}s"\n'
                "  fi\n"
                "else\n"
                "  sleep 3\n"
                '  if [ "$VD" = "2147483647" ]; then\n'
                '    echo "$L rc=124 elapsed=3.0s"\n'
                "  else\n"
                '    echo "$L rc=0 elapsed=3.0s"\n'
                "  fi\n"
                "fi\n"
            )
        os.chmod(path, 0o755)
        return path

    def test_baseline_and_verify_probes_run_in_parallel(self) -> None:
        # Given: a bound build and a probe stand-in that sleeps 2 s per
        # call (sequentially that is ~4 s of wall time).
        with tempfile.TemporaryDirectory() as tmp:
            path = self._synthetic(tmp, {136: 60000, 144: 120000, 152: 60000})
            reg = self._bound_registry(tmp)
            stub = self._timing_stub(tmp, 2)
            log = os.path.join(tmp, "probe.log")
            env = {"CLASSIFIER_PROBE_SCRIPT": stub, "STUB_LOG": log}
            t0 = time.monotonic()
            # When: the one-line script runs with --baseline.
            proc = self._run_script(path, "--baseline", "--timeout", "30",
                                    "--registry", reg, env_extra=env)
            wall = time.monotonic() - t0
            # Then: both probes ran concurrently (their wall intervals
            # overlap) and the whole run took ~one probe, not two.
            self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
            self.assertIn("VERIFIED", proc.stdout)
            stamps = {}
            for line in open(log):
                label, which, ts = line.split()
                stamps.setdefault(label, {})[which] = float(ts)
            overlap = (min(stamps["base"]["end"], stamps["verify"]["end"])
                       - max(stamps["base"]["start"], stamps["verify"]["start"]))
            self.assertGreater(overlap, 1.5)
            self.assertLess(wall, 3.5)

    def test_fast_verify_accepts_early_evidence_and_returns_soon(self) -> None:
        # Given: a bound build (int32-max targets) and a probe stand-in that
        # implements the 4-argument contract (still waiting at the check
        # point with one blackholed attempt).
        with tempfile.TemporaryDirectory() as tmp:
            path = self._synthetic(tmp, {136: 60000, 144: 120000, 152: 60000})
            before = open(path, "rb").read()
            reg = self._bound_registry(tmp)
            stub = self._fast_stub(tmp)
            env = {"CLASSIFIER_PROBE_SCRIPT": stub,
                   "CLAUDE_PATCHER_FAST_FLOOR": "1"}
            t0 = time.monotonic()
            # When: the one-line script runs with a 1 s early check point.
            proc = self._run_script(path, "--fast-verify", "1", "--timeout", "30",
                                    "--registry", reg, env_extra=env)
            wall = time.monotonic() - t0
            # Then: the early evidence verifies the patch at the check
            # point (~1 s, not the 30 s cap); the patch stays in the
            # .patched artifact next to the untouched original.
            self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
            self.assertIn("VERIFIED", proc.stdout)
            self.assertIn("blackholed=1", proc.stdout)
            self.assertLess(wall, 10)
            self.assertEqual(open(path, "rb").read(), before)
            patched = open(path + ".patched", "rb").read()
            self.assertEqual(struct.unpack_from("<i", patched, 136)[0], ls.INT32_MAX)
            self.assertFalse(os.path.exists(path + ".original"))

    def test_fast_verify_without_early_evidence_is_not_verified(self) -> None:
        # Given: a bound build whose recorded target is below the int32 max
        # (the stub reports a fast exit, no early line).
        with tempfile.TemporaryDirectory() as tmp:
            path = self._synthetic(tmp, {136: 60000, 144: 120000, 152: 60000})
            before = open(path, "rb").read()
            reg = self._bound_registry(tmp, target=425000000)
            stub = self._fast_stub(tmp)
            env = {"CLASSIFIER_PROBE_SCRIPT": stub,
                   "CLAUDE_PATCHER_FAST_FLOOR": "1"}
            # When: the one-line script runs with a 1 s early check point.
            proc = self._run_script(path, "--fast-verify", "1", "--timeout", "30",
                                    "--registry", reg, env_extra=env)
            # Then: without early evidence the fast exit is NOT VERIFIED
            # and nothing is renamed (there is no in-place replacement);
            # the unmeasured artifact may sit beside the untouched
            # original.
            self.assertEqual(proc.returncode, 1, proc.stdout + proc.stderr)
            self.assertIn("NOT VERIFIED", proc.stdout)
            self.assertEqual(open(path, "rb").read(), before)
            self.assertTrue(os.path.exists(path + ".patched"))
            self.assertFalse(os.path.exists(path + ".original"))

    def test_fast_verify_degrades_to_the_full_cap_without_probe_support(self) -> None:
        # Given: a bound build and a probe stand-in that ignores the 4th
        # argument (no early line, the result comes at the cap).
        with tempfile.TemporaryDirectory() as tmp:
            path = self._synthetic(tmp, {136: 60000, 144: 120000, 152: 60000})
            reg = self._bound_registry(tmp)
            stub = self._timing_stub(tmp, 2)
            env = {"CLASSIFIER_PROBE_SCRIPT": stub,
                   "CLAUDE_PATCHER_FAST_FLOOR": "1", "STUB_LOG": "/dev/null"}
            # When: the one-line script runs with a 1 s early check point.
            proc = self._run_script(path, "--fast-verify", "1", "--timeout", "30",
                                    "--registry", reg, env_extra=env)
            # Then: no early line is available, the cap result (rc=124)
            # verifies through the original path, and the run took the
            # stub's full 2 s, not the 1 s check point.
            self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
            self.assertIn("VERIFIED", proc.stdout)
            self.assertNotIn(" early ", proc.stdout)

    def test_fast_verify_check_point_below_the_floor_refused(self) -> None:
        # Given: the default floor (65 s: the early check must outlast the
        # unpatched 60 s per-attempt wait plus startup).
        with tempfile.TemporaryDirectory() as tmp:
            path = self._synthetic(tmp, {136: 60000, 144: 120000, 152: 60000})
            reg = self._bound_registry(tmp)
            # When: a check point below the floor is requested.
            proc = self._run_script(path, "--fast-verify", "30", "--registry", reg)
            # When: --fast-verify is combined with --no-verify.
            proc2 = self._run_script(path, "--fast-verify", "70", "--no-verify",
                                     "--registry", reg)
            # Then: both are usage refusals (exit 2, nothing probed).
            self.assertEqual(proc.returncode, 2, proc.stdout + proc.stderr)
            self.assertIn("fast-verify", proc.stderr)
            self.assertEqual(proc2.returncode, 2, proc2.stdout + proc2.stderr)
            self.assertFalse(os.path.exists(path + ".patched"))


class OracleBindParallelTests(unittest.TestCase):
    """oracle_bind_auto.py parallel phases: independent probes run
    concurrently (each probe owns its endpoint port) - the baseline+all
    pair, both bisection halves, all nearest ceiling candidates, all coarse
    boundary values - while the refusal semantics stay measurement-defined
    (a non-monotone boundary signal now refuses instead of guessing)."""

    DRIVER_OFF = 136
    CAP_OFF = 144

    def _synthetic(self, tmp: str, values: dict, name: str = "synth") -> str:
        hdr = b"#!/bin/sh\necho 1;exit\n"
        data = bytearray(hdr + b"\x00" * (256 - len(hdr)))
        for off, v in values.items():
            struct.pack_into("<i", data, off, v)
        path = os.path.join(tmp, name)
        with open(path, "wb") as f:
            f.write(bytes(data))
        os.chmod(path, 0o755)
        return path

    def _registry(self, tmp: str, doc: dict) -> str:
        path = os.path.join(tmp, "registry.json")
        with open(path, "w", encoding="utf-8") as f:
            json.dump(doc, f, indent=2)
        return path

    @staticmethod
    def _i32(data: bytes, off: int) -> int:
        return struct.unpack_from("<i", data, off)[0]

    def _model_probe(self, boundary: int = None) -> object:
        """The measured signal model, read from the artifact's int32 slots
        (same model as OracleBindAutoTests._stub_probe): wait per attempt =
        min(ceiling slot, driver slot); driver values above `boundary`
        produce a zero wait (a capped build). cancel: the optional binder
        cancel event; the model finishes instantly, so nothing is
        cancellable here (the wrapper is what emulates the wall time)."""
        def probe(artifact: str, label: str, timeout: int, cancel=None):
            try:
                with open(artifact, "rb") as f:
                    d = f.read()
            except OSError:
                return None
            if len(d) != 256:
                return None
            vd = self._i32(d, self.DRIVER_OFF)
            vc = self._i32(d, self.CAP_OFF)
            if vd == 60000:
                return 0, 2 * min(vc, 60000) / 1000 + 1.5
            if boundary is not None and vd > boundary:
                return 0, 2.0
            secs = 2 * min(vc, vd) / 1000 + 1.5
            if secs < timeout:
                return 0, secs
            return 124, float(timeout)
        return probe

    def _tracked_probe(self, inner: object, sleep_s: float = 0.2,
                       delays: dict = None) -> object:
        """Wrap a probe so concurrent calls are recorded: samples holds the
        set of labels active at every probe start and at every poll tick
        (with a small sleep, overlapping probes are observable). `delays`
        emulates per-label wall time (default sleep_s for every label, like
        the real ~41 s effective and ~121 s no-effect halves). A probe whose
        cancel event is set before it finishes returns None (a cancelled run
        is not a measurement) and its label is recorded in probe.cancelled."""
        lock = threading.Lock()
        active = set()
        samples = []
        cancelled = set()
        delays = delays or {}

        def probe(artifact: str, label: str, timeout: int, cancel=None):
            with lock:
                active.add(label)
                samples.append(frozenset(active))
            try:
                end = time.monotonic() + delays.get(label, sleep_s)
                while time.monotonic() < end:
                    # A sample at every tick keeps overlapping probes
                    # observable even when the emulated delays are short.
                    with lock:
                        samples.append(frozenset(active))
                    if cancel is not None:
                        if cancel.wait(0.05):
                            with lock:
                                cancelled.add(label)
                            return None
                    else:
                        time.sleep(0.05)
                return inner(artifact, label, timeout)
            finally:
                with lock:
                    active.discard(label)

        probe.samples = samples
        probe.cancelled = cancelled
        return probe

    def test_baseline_and_all_sites_probes_run_in_parallel(self) -> None:
        # Given: an unbound synthetic build (driver + decoy 60000, one
        # ceiling) and an empty registry.
        with tempfile.TemporaryDirectory() as tmp:
            path = self._synthetic(tmp, {136: 60000, 144: 120000, 152: 60000})
            reg = self._registry(tmp, {})
            probe = self._tracked_probe(self._model_probe())
            # When: the auto binder runs.
            ok = oba.bind(path, reg, probe)
            # Then: the baseline and all-sites probes were active at the
            # same time (independent measurements, concurrent), and the
            # binding still succeeds.
            self.assertTrue(ok)
            self.assertTrue(any({"base", "all"} <= s for s in probe.samples))

    def test_bisection_halves_probe_in_parallel(self) -> None:
        # Given: an unbound synthetic build with four 60000 sites (driver
        # @136 + three decoys) and one ceiling.
        with tempfile.TemporaryDirectory() as tmp:
            path = self._synthetic(
                tmp, {136: 60000, 144: 120000, 152: 60000,
                      160: 60000, 168: 60000})
            reg = self._registry(tmp, {})
            probe = self._tracked_probe(self._model_probe())
            # When: the auto binder runs (its bisection halves are
            # independent probes).
            ok = oba.bind(path, reg, probe)
            doc = json.load(open(reg))
            # Then: both halves of a bisection round were active at the
            # same time, and the driver is still isolated by measurement.
            self.assertTrue(ok)
            self.assertTrue(any(len(s & {l for l in s if l.startswith("bis")}) >= 2
                                for s in probe.samples))
            sites = {s["offset"]: s for s in doc["synth"]["sites"]}
            self.assertEqual(set(sites), {136, 144})
            self.assertEqual(sites[136]["target"], ls.INT32_MAX)

    def test_ceiling_candidates_probe_in_parallel(self) -> None:
        # Given: an unbound synthetic build with one driver and three
        # 120000 ceiling candidates (the recorded ceiling @144 unclamps a
        # 130000 driver; the others stay clamped at 120000).
        with tempfile.TemporaryDirectory() as tmp:
            path = self._synthetic(
                tmp, {136: 60000, 144: 120000, 152: 60000,
                      160: 120000, 168: 120000})
            reg = self._registry(tmp, {})
            probe = self._tracked_probe(self._model_probe())
            # When: the auto binder runs (all nearest ceiling candidates
            # are independent probes).
            ok = oba.bind(path, reg, probe)
            doc = json.load(open(reg))
            # Then: all three candidates were active at the same time,
            # the nearest working candidate is recorded as the ceiling,
            # and the evidence log holds exactly the ceiling line.
            self.assertTrue(ok)
            self.assertTrue(any({"cap0", "cap1", "cap2"} <= s for s in probe.samples))
            sites = {s["offset"]: s for s in doc["synth"]["sites"]}
            self.assertEqual(set(sites), {136, 144})
            self.assertEqual(sites[144]["old"], 120000)
            self.assertEqual(len(doc["synth"]["evidence"]["ceiling"]), 1)

    def test_coarse_boundary_values_probe_in_parallel(self) -> None:
        # Given: an unbound synthetic build whose wait is zero above
        # 425000000 ms (a capped build).
        with tempfile.TemporaryDirectory() as tmp:
            path = self._synthetic(tmp, {136: 60000, 144: 120000, 152: 60000})
            reg = self._registry(tmp, {})
            # The boundary bisection is inherently sequential (one probe
            # per round, ~27 rounds between the coarse values): each
            # emulated round takes 0.1 s instead of the 0.2 s default,
            # since the concurrency under test is the coarse round, not
            # the bisection.
            probe = self._tracked_probe(
                self._model_probe(boundary=425000000), 0.1)
            # When: the auto binder runs (all coarse boundary values are
            # independent probes).
            ok = oba.bind(path, reg, probe)
            doc = json.load(open(reg))
            # Then: the coarse values were probed concurrently, and the
            # boundary search still records the largest measured waiting
            # value as the driver target.
            self.assertTrue(ok)
            self.assertTrue(
                any(len(s & {l for l in s if l.startswith("bnd")}) >= 3
                    for s in probe.samples))
            sites = {s["offset"]: s for s in doc["synth"]["sites"]}
            self.assertEqual(sites[136]["target"], 425000000)
            values = doc["synth"]["evidence"]["max_driver_boundary"]["driver_values"]
            self.assertEqual(values["2147483647"], "immediate")
            self.assertEqual(values["425000000"], "waiting")

    def test_non_monotone_boundary_signal_refuses(self) -> None:
        # Given: an unbound capped build whose coarse boundary signals are
        # not monotone (a LARGER value waits while a smaller one does not -
        # the measured signal model is violated).
        with tempfile.TemporaryDirectory() as tmp:
            path = self._synthetic(tmp, {136: 60000, 144: 120000, 152: 60000})
            reg = self._registry(tmp, {})
            base = self._model_probe(boundary=425000000)

            def probe(artifact: str, label: str, timeout: int, cancel=None):
                try:
                    d = open(artifact, "rb").read()
                    if len(d) == 256 and self._i32(d, 136) == 1000000:
                        return 0, 2.0
                except OSError:
                    pass
                return base(artifact, label, timeout)

            # When: the auto binder runs.
            ok = oba.bind(path, reg, probe)
            # Then: the contradiction refuses the binding (no guess, no
            # registry entry, no leftover artifacts).
            self.assertFalse(ok)
            self.assertEqual(json.load(open(reg)), {})
            self.assertEqual([n for n in os.listdir(tmp) if n.startswith("synth.bind_")], [])

    def test_bisection_cancels_the_half_that_no_longer_decides(self) -> None:
        # Given: an unbound synthetic build with four 60000 sites (driver
        # @136 + three decoys) and one ceiling, and a tracked probe in
        # which each no-effect half emulates the ~121 s wall time (1.0 s
        # here) while the effective half takes 0.2 s - waiting the
        # no-effect half out is pure waste, since the model has exactly one
        # effective half and it decides the round alone.
        with tempfile.TemporaryDirectory() as tmp:
            path = self._synthetic(
                tmp, {136: 60000, 144: 120000, 152: 60000,
                      160: 60000, 168: 60000})
            reg = self._registry(tmp, {})
            probe = self._tracked_probe(
                self._model_probe(),
                delays={"bis0b": 1.0, "bis1b": 1.0})
            # When: the auto binder runs (both halves of a bisection round
            # are independent probes).
            t0 = time.monotonic()
            ok = oba.bind(path, reg, probe)
            wall = time.monotonic() - t0
            doc = json.load(open(reg))
            # Then: each round ends when the effective half decides (the
            # slow no-effect half is cancelled and NOT measured - no
            # result for it in the evidence), the wall time is the
            # effective half's, and the driver is still isolated by
            # measurement.
            self.assertTrue(ok)
            sites = {s["offset"]: s for s in doc["synth"]["sites"]}
            self.assertEqual(set(sites), {136, 144})
            self.assertEqual(sites[136]["target"], ls.INT32_MAX)
            self.assertEqual({"bis0b", "bis1b"}, probe.cancelled)
            bisect = doc["synth"]["evidence"]["bisect"]
            for line in bisect:
                if "bis0b" in line or "bis1b" in line:
                    self.assertNotRegex(line, r"-> [0-9.]+s \(")
            self.assertTrue(any(re.search(r"bis0a .* -> 41\.5s \(effective\)", l)
                                for l in bisect))
            # Both halves were still started concurrently (only the
            # no-effect half's wait was cut short).
            self.assertTrue(any(len(s & {l for l in s if l.startswith("bis")}) >= 2
                                for s in probe.samples))
            self.assertLess(wall, 1.6)

    def test_bisection_keeps_measuring_a_half_that_is_still_decisive(self) -> None:
        # Given: an unbound synthetic build with two 60000 sites (driver
        # @136 + one decoy) and one ceiling, and a tracked probe in which
        # the NO-EFFECT half finishes first (0.2 s) and the effective half
        # later (0.8 s) - a no-effect verdict does not decide the round, so
        # cancelling here would throw away the decisive measurement.
        with tempfile.TemporaryDirectory() as tmp:
            path = self._synthetic(
                tmp, {136: 60000, 144: 120000, 152: 60000})
            reg = self._registry(tmp, {})
            probe = self._tracked_probe(
                self._model_probe(),
                delays={"bis0a": 0.8, "bis0b": 0.2})
            # When: the auto binder runs.
            ok = oba.bind(path, reg, probe)
            doc = json.load(open(reg))
            # Then: both halves are fully measured (the fast no-effect half
            # is waited out, because only an effective verdict decides),
            # nothing is cancelled, and the driver is still isolated by
            # measurement.
            self.assertTrue(ok)
            sites = {s["offset"]: s for s in doc["synth"]["sites"]}
            self.assertEqual(set(sites), {136, 144})
            self.assertEqual(sites[136]["target"], ls.INT32_MAX)
            self.assertEqual(set(), probe.cancelled)
            bisect = doc["synth"]["evidence"]["bisect"]
            self.assertTrue(any(re.search(r"bis0a .* -> 41\.5s \(effective\)", l)
                                for l in bisect))
            self.assertTrue(any(re.search(r"bis0b .* -> 121\.5s \(no_effect\)", l)
                                for l in bisect))


_JQ_FREE_PATH_CACHE: str | None = None


def _jq_free_path() -> str:
    """A PATH that resolves every tool bash/python need EXCEPT jq (the test hook
    for the Python fallback branch). Built once per process from the current
    PATH so it stays complete."""
    global _JQ_FREE_PATH_CACHE
    if _JQ_FREE_PATH_CACHE is not None:
        return _JQ_FREE_PATH_CACHE
    d = tempfile.mkdtemp(prefix="nojq_")
    for base in os.environ.get("PATH", "").split(os.pathsep):
        if not base or not os.path.isdir(base):
            continue
        for name in os.listdir(base):
            if name == "jq":
                continue
            src = os.path.join(base, name)
            if os.path.lexists(src):
                try:
                    os.symlink(src, os.path.join(d, name))
                except OSError:
                    pass
    _JQ_FREE_PATH_CACHE = d
    return d


class RegistryLookupTests(unittest.TestCase):
    """patch.sh registry_lookup: the jq fast path (and, without jq, the Python
    fallback) returns the UNIQUE size-matched label, and stays empty on no
    match, several matches (the false-positive guard), a malformed registry, or
    a missing file - the no-guess contract either way."""

    @classmethod
    def setUpClass(cls) -> None:
        cls._root = os.path.dirname(os.path.abspath(__file__))
        text = open(os.path.join(cls._root, "patch.sh"), encoding="utf-8").read()
        lines = text.splitlines()
        start = next(i for i, l in enumerate(lines) if l.startswith("registry_lookup() {"))
        end = next(i for i in range(start, len(lines)) if lines[i] == "}")
        cls._func_file = os.path.join(tempfile.mkdtemp(prefix="patchfn_"), "lookup.sh")
        with open(cls._func_file, "w", encoding="utf-8") as f:
            f.write("\n".join(lines[start:end + 1]) + "\n")

    def _lookup(self, reg_file: str, size: int, name: str = "",
                jq_free: bool = False) -> str:
        env = dict(os.environ)
        env["ROOT"] = self._root
        if jq_free:
            env["PATH"] = _jq_free_path()
        script = ("source %s\nregistry_lookup %s %s %s\n"
                  % (self._func_file, reg_file, size, name))
        proc = subprocess.run(
            ["bash", "-c", script], capture_output=True, text=True, env=env,
        )
        return proc.stdout

    def _registry(self, tmp: str, doc: object) -> str:
        path = os.path.join(tmp, "reg.json")
        with open(path, "w", encoding="utf-8") as f:
            json.dump(doc, f)
        return path

    def _entry(self, size: int) -> dict:
        return {"size": size,
                "sites": [{"offset": 4, "old": 60000, "role": "driver"}],
                "evidence": {}}

    def test_jq_unique_match_returns_the_label(self) -> None:
        # Given: a registry of two entries, one matching the size.
        with tempfile.TemporaryDirectory() as tmp:
            reg = self._registry(tmp, {"a": self._entry(1000), "b": self._entry(2000)})
            # When: the lookup runs for the matching size.
            out = self._lookup(reg, 1000)
            # Then: exactly that label is returned.
            self.assertEqual(out.strip(), "a")

    def test_jq_no_match_is_empty(self) -> None:
        # Given: a registry that does not contain the size.
        with tempfile.TemporaryDirectory() as tmp:
            reg = self._registry(tmp, {"a": self._entry(1000)})
            # When: the lookup runs for an unrecorded size.
            out = self._lookup(reg, 9999)
            # Then: nothing is returned (a miss, never a guess).
            self.assertEqual(out.strip(), "")

    def test_jq_multiple_matches_is_empty(self) -> None:
        # Given: two entries that claim the same size (a false positive).
        with tempfile.TemporaryDirectory() as tmp:
            reg = self._registry(tmp, {"a": self._entry(500), "b": self._entry(500)})
            # When: the lookup runs for that size.
            out = self._lookup(reg, 500)
            # Then: it refuses to pick one - empty, not a guess.
            self.assertEqual(out.strip(), "")

    def test_jq_malformed_registry_is_empty(self) -> None:
        # Given: a registry whose top level is not an object.
        with tempfile.TemporaryDirectory() as tmp:
            reg = os.path.join(tmp, "bad.json")
            with open(reg, "w", encoding="utf-8") as f:
                f.write("[1, 2, 3]\n")
            # When: the lookup runs.
            out = self._lookup(reg, 1000)
            # Then: the malformed registry yields no match.
            self.assertEqual(out.strip(), "")

    def test_jq_missing_file_is_empty(self) -> None:
        # Given: a registry path that does not exist.
        with tempfile.TemporaryDirectory() as tmp:
            missing = os.path.join(tmp, "nope.json")
            # When: the lookup runs against it.
            out = self._lookup(missing, 1000)
            # Then: a missing registry is a miss, not an error.
            self.assertEqual(out.strip(), "")

    def test_python_fallback_unique_match(self) -> None:
        # Given: jq is absent from PATH (the fallback branch) and a matching entry.
        with tempfile.TemporaryDirectory() as tmp:
            reg = self._registry(tmp, {"a": self._entry(1000), "b": self._entry(2000)})
            # When: the lookup runs without jq.
            out = self._lookup(reg, 1000, jq_free=True)
            # Then: the Python fallback returns the same label.
            self.assertEqual(out.strip(), "a")

    def test_python_fallback_no_match_is_empty(self) -> None:
        # Given: jq is absent and the size is unrecorded.
        with tempfile.TemporaryDirectory() as tmp:
            reg = self._registry(tmp, {"a": self._entry(1000)})
            # When: the lookup runs without jq for an unrecorded size.
            out = self._lookup(reg, 9999, jq_free=True)
            # Then: the fallback also stays empty.
            self.assertEqual(out.strip(), "")

    def test_python_fallback_multiple_matches_is_empty(self) -> None:
        # Given: jq is absent and two entries claim the same size.
        with tempfile.TemporaryDirectory() as tmp:
            reg = self._registry(tmp, {"a": self._entry(500), "b": self._entry(500)})
            # When: the lookup runs without jq for that size.
            out = self._lookup(reg, 500, jq_free=True)
            # Then: the fallback refuses to guess, too.
            self.assertEqual(out.strip(), "")

    def test_jq_name_disambiguates_same_size_entries(self) -> None:
        # Given: two entries claiming the same size (two versions shipped at
        # byte-identical size, the 2.1.275/2.1.276 shape).
        with tempfile.TemporaryDirectory() as tmp:
            reg = self._registry(tmp, {"v1": self._entry(500),
                                       "v2": self._entry(500)})
            # When: the lookup runs for that size under a registry key name.
            out = self._lookup(reg, 500, "v2")
            # Then: the name disambiguates - that key is returned.
            self.assertEqual(out.strip(), "v2")
            self.assertEqual(self._lookup(reg, 500, "v1").strip(), "v1")

    def test_jq_named_entry_with_wrong_size_falls_back_to_size_match(self) -> None:
        # Given: two same-size entries, a third entry of a different size, and
        # a name whose entry has the wrong size.
        with tempfile.TemporaryDirectory() as tmp:
            reg = self._registry(tmp, {"v1": self._entry(500),
                                       "v2": self._entry(500),
                                       "v3": self._entry(900)})
            # When: the lookup runs for 900 under the name of a 500 entry.
            out = self._lookup(reg, 900, "v1")
            # Then: the name is a hint, not the predicate - the unique size
            # match wins.
            self.assertEqual(out.strip(), "v3")

    def test_jq_name_not_in_registry_keeps_the_size_guard(self) -> None:
        # Given: two entries claiming the same size and a name that is not a
        # registry key.
        with tempfile.TemporaryDirectory() as tmp:
            reg = self._registry(tmp, {"v1": self._entry(500),
                                       "v2": self._entry(500)})
            # When: the lookup runs for that size under the non-key name.
            out = self._lookup(reg, 500, "other")
            # Then: the collision is unresolved - empty, never a guess.
            self.assertEqual(out.strip(), "")

    def test_jq_named_entry_with_malformed_size_falls_back(self) -> None:
        # Given: a registry whose named entry has a non-numeric size (malformed)
        # and a unique size match elsewhere.
        with tempfile.TemporaryDirectory() as tmp:
            doc = {"v1": {"size": "not-a-number",
                          "sites": [{"offset": 4, "old": 60000, "role": "d"}]},
                   "v2": self._entry(900)}
            reg = self._registry(tmp, doc)
            # When: the lookup runs for 900 under the malformed entry's name.
            out = self._lookup(reg, 900, "v1")
            # Then: the malformed entry is not a match - the size match wins.
            self.assertEqual(out.strip(), "v2")

    def test_python_fallback_name_disambiguates_same_size_entries(self) -> None:
        # Given: jq is absent and two entries claim the same size.
        with tempfile.TemporaryDirectory() as tmp:
            reg = self._registry(tmp, {"v1": self._entry(500),
                                       "v2": self._entry(500)})
            # When: the lookup runs without jq for that size under a key name.
            out = self._lookup(reg, 500, "v2", jq_free=True)
            # Then: the fallback disambiguates by name, too.
            self.assertEqual(out.strip(), "v2")

    def test_python_fallback_name_not_in_registry_keeps_the_size_guard(self) -> None:
        # Given: jq is absent, two same-size entries, and a non-key name.
        with tempfile.TemporaryDirectory() as tmp:
            reg = self._registry(tmp, {"v1": self._entry(500),
                                       "v2": self._entry(500)})
            # When: the lookup runs without jq for that size under the name.
            out = self._lookup(reg, 500, "other", jq_free=True)
            # Then: the fallback still refuses to guess.
            self.assertEqual(out.strip(), "")


class RegistryDownloadTests(unittest.TestCase):
    """patch.sh registry download: a build not in the local (default) registry
    but bound in the repo copy is applied from the downloaded registry with no
    local probe; a failed download falls back to the local file only; and an
    explicit --registry is never downloaded."""

    def _binary(self, tmp: str, value: int = 60000):
        body = b"#!/bin/sh\necho fake 1.0\nexit 0\n"
        data = bytearray(body + b"\x00" * 16)
        struct.pack_into("<i", data, len(data) - 4, value)
        path = os.path.join(tmp, "bin")
        with open(path, "wb") as f:
            f.write(bytes(data))
        os.chmod(path, 0o755)
        return path, len(data)

    def _remote_registry(self, tmp: str, size: int) -> str:
        path = os.path.join(tmp, "remote.json")
        with open(path, "w", encoding="utf-8") as f:
            json.dump(
                {"ci": {"size": size,
                        "sites": [{"offset": size - 4, "old": 60000, "role": "driver"}],
                        "evidence": {}}},
                f,
            )
        return path

    def _run(self, *args: object, env_extra: dict = None, timeout: int = 120) -> subprocess.CompletedProcess:
        env = dict(os.environ)
        if env_extra:
            env.update(env_extra)
        return subprocess.run(
            ["bash", _PATCH_SCRIPT, *[str(a) for a in args]],
            capture_output=True, text=True, timeout=timeout, env=env,
        )

    def test_local_miss_remote_hit_applies_without_probe(self) -> None:
        # Given: a build not in the local default registry, but bound in a repo
        # copy (CLAUDE_PATCHER_REGISTRY_URL points at a local stand-in).
        with tempfile.TemporaryDirectory() as tmp:
            path, size = self._binary(tmp)
            remote = self._remote_registry(tmp, size)
            env = {"CLAUDE_PATCHER_REGISTRY_URL": remote}
            # When: the script runs against the DEFAULT registry (no --registry).
            proc = self._run(path, "--no-verify", env_extra=env)
            # Then: it applies from the downloaded copy, no local probe, and the
            # artifact holds the int32-max default.
            self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
            self.assertIn("downloaded", proc.stdout)
            patched = open(path + ".patched", "rb").read()
            self.assertEqual(struct.unpack_from("<i", patched, size - 4)[0], ls.INT32_MAX)
            self.assertEqual(open(path, "rb").read()[:size - 4], open(path + ".patched", "rb").read()[:size - 4])

    def test_download_failure_falls_back_to_local_and_refuses(self) -> None:
        # Given: a build in no registry, and a download that fails.
        with tempfile.TemporaryDirectory() as tmp:
            path, _ = self._binary(tmp)
            env = {"CLAUDE_PATCHER_REGISTRY_URL": os.path.join(tmp, "nope.json")}
            # When: the script runs (default registry, auto-bind off).
            proc = self._run(path, "--no-verify", "--no-auto-bind", env_extra=env)
            # Then: it refuses (no binding anywhere) and writes nothing.
            self.assertEqual(proc.returncode, 1, proc.stdout + proc.stderr)
            self.assertIn("apply refused", proc.stdout)
            self.assertFalse(os.path.exists(path + ".patched"))

    def test_explicit_registry_is_never_downloaded(self) -> None:
        # Given: an explicit --registry that misses, and a remote that would hit.
        with tempfile.TemporaryDirectory() as tmp:
            path, size = self._binary(tmp)
            local = os.path.join(tmp, "local.json")
            with open(local, "w", encoding="utf-8") as f:
                json.dump({}, f)
            remote = self._remote_registry(tmp, size)
            env = {"CLAUDE_PATCHER_REGISTRY_URL": remote}
            # When: the script runs with the explicit (missing) registry.
            proc = self._run(path, "--no-verify", "--no-auto-bind", "--registry", local,
                             env_extra=env)
            # Then: the explicit registry is honored exactly - no download, so it
            # is refused (it would have succeeded only by downloading).
            self.assertEqual(proc.returncode, 1, proc.stdout + proc.stderr)
            self.assertNotIn("downloaded", proc.stdout)
            self.assertIn("apply refused", proc.stdout)
            self.assertFalse(os.path.exists(path + ".patched"))


class CiBindTests(unittest.TestCase):
    """ci_bind_new_version.py (the CI recorder): a fresh build is bound and
    recorded into the registry (measured, never guessed); a re-run is a no-op
    ("already bound"); the download path names the record after the version;
    and every unmeasurable or underspecified input is refused without a
    registry write."""

    def _bytes(self, values: dict) -> bytes:
        hdr = b"#!/bin/sh\necho 1;exit\n"
        data = bytearray(hdr + b"\x00" * (256 - len(hdr)))
        for off, v in values.items():
            struct.pack_into("<i", data, off, v)
        return bytes(data)

    def _synthetic(self, tmp: str, values: dict, name: str = "synth") -> str:
        path = os.path.join(tmp, name)
        with open(path, "wb") as f:
            f.write(self._bytes(values))
        os.chmod(path, 0o755)
        return path

    def _registry(self, tmp: str, doc: dict) -> str:
        path = os.path.join(tmp, "registry.json")
        with open(path, "w", encoding="utf-8") as f:
            json.dump(doc, f, indent=2)
        return path

    def _stub_probe_script(self, tmp: str) -> str:
        # A run_probe.sh stand-in: same 3-argument contract, same result line
        # format, wait model read from the binary's int32 slots (driver @136,
        # ceiling @144).
        path = os.path.join(tmp, "probe_stub.sh")
        with open(path, "w", encoding="utf-8") as f:
            f.write(
                "#!/bin/bash\n"
                'B="$1"; L="$2"; T="${3:-300}"\n'
                'python3 - "$B" "$T" <<\'PY\'\n'
                "import os\n"
                "import struct\n"
                "import sys\n"
                "\n"
                "d = open(sys.argv[1], \"rb\").read()\n"
                "t = float(sys.argv[2])\n"
                "vd = struct.unpack_from(\"<i\", d, 136)[0]\n"
                "vc = struct.unpack_from(\"<i\", d, 144)[0]\n"
                "if vd == 60000:\n"
                "    rc, e = 0, 2 * min(vc, 60000) / 1000 + 1.5\n"
                "else:\n"
                "    w = min(vc, vd)\n"
                "    secs = 2 * w / 1000 + 1.5\n"
                "    if secs < t:\n"
                "        rc, e = 0, secs\n"
                "    else:\n"
                "        rc, e = 124, t\n"
                "print(\"STUB rc=%d elapsed=%.1fs\" % (rc, e))\n"
                "PY\n"
            )
        os.chmod(path, 0o755)
        return path

    def _run_ci(self, *args: object, env_extra: dict = None,
                timeout: int = 120) -> subprocess.CompletedProcess:
        env = dict(os.environ)
        if env_extra:
            env.update(env_extra)
        return subprocess.run(
            [sys.executable, _CI_SCRIPT, *[str(a) for a in args]],
            capture_output=True, text=True, timeout=timeout, env=env,
        )

    def test_bind_records_an_entry_keyed_by_basename(self) -> None:
        # Given: an unbound synthetic build and an empty registry.
        with tempfile.TemporaryDirectory() as tmp:
            path = self._synthetic(tmp, {136: 60000, 144: 120000, 152: 60000})
            reg = self._registry(tmp, {})
            stub = self._stub_probe_script(tmp)
            # When: the CI recorder binds it (probe stand-in, no download).
            proc = self._run_ci("--binary", path, "--probe", stub,
                                "--registry", reg)
            doc = json.load(open(reg))
            # Then: exit 0 and the registry now records the build under its
            # basename (size 256, driver + ceiling targets at int32 max).
            self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
            entry = doc.get("synth")
            self.assertIsNotNone(entry)
            self.assertEqual(entry["size"], 256)
            sites = {s["offset"]: s for s in entry["sites"]}
            self.assertEqual(sites[136]["target"], ls.INT32_MAX)
            self.assertEqual(sites[144]["target"], ls.INT32_MAX)
            self.assertIn("recorded", proc.stdout)

    def test_rebind_same_build_is_a_noop(self) -> None:
        # Given: a build already recorded in the registry (bound just now).
        with tempfile.TemporaryDirectory() as tmp:
            path = self._synthetic(tmp, {136: 60000, 144: 120000, 152: 60000})
            reg = self._registry(tmp, {})
            stub = self._stub_probe_script(tmp)
            first = self._run_ci("--binary", path, "--probe", stub,
                                 "--registry", reg)
            self.assertEqual(first.returncode, 0, first.stdout + first.stderr)
            before = open(reg, "rb").read()
            # When: the recorder runs again on the same build.
            second = self._run_ci("--binary", path, "--probe", stub,
                                  "--registry", reg)
            # Then: "already bound", exit 0, and the registry file is byte-
            # identical (nothing re-measured, nothing rewritten).
            self.assertEqual(second.returncode, 0, second.stdout + second.stderr)
            self.assertIn("already bound", second.stdout)
            self.assertEqual(open(reg, "rb").read(), before)

    def test_download_path_records_under_version_name(self) -> None:
        # Given: a build available "remotely" (a file:// stand-in URL) and an
        # empty registry; the version label names the record.
        with tempfile.TemporaryDirectory() as tmp:
            remote_bin = self._synthetic(tmp, {136: 60000, 144: 120000, 152: 60000},
                                         name="2.1.999")
            reg = self._registry(tmp, {})
            stub = self._stub_probe_script(tmp)
            url = "file://" + remote_bin
            # When: the recorder downloads and binds that version.
            proc = self._run_ci("--version", "2.1.999", "--download-url", url,
                                "--probe", stub, "--registry", reg)
            doc = json.load(open(reg))
            # Then: the record is keyed by the version (the downloaded file's
            # basename), with the measured binding.
            self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
            entry = doc.get("2.1.999")
            self.assertIsNotNone(entry)
            self.assertEqual(entry["size"], 256)
            self.assertIn("binding version 2.1.999", proc.stdout)

    def test_missing_binary_refused(self) -> None:
        # Given: a --binary path that does not exist.
        with tempfile.TemporaryDirectory() as tmp:
            reg = self._registry(tmp, {})
            # When: the recorder is asked to bind it.
            proc = self._run_ci("--binary", os.path.join(tmp, "nope"),
                                "--registry", reg)
            # Then: it exits 2 with a clear error and touches nothing.
            self.assertEqual(proc.returncode, 2, proc.stdout + proc.stderr)
            self.assertIn("not found", proc.stderr)
            self.assertEqual(json.load(open(reg)), {})

    def test_no_build_source_refused(self) -> None:
        # Given: neither --binary nor a download URL (CLAUDE_BINARY_URL unset).
        with tempfile.TemporaryDirectory() as tmp:
            reg = self._registry(tmp, {})
            env = {"CLAUDE_BINARY_URL": ""}
            # When: the recorder is invoked with no source for a build.
            proc = self._run_ci("--registry", reg, env_extra=env)
            # Then: it exits 2 saying what is missing, and writes nothing.
            self.assertEqual(proc.returncode, 2, proc.stdout + proc.stderr)
            self.assertIn("no build to bind", proc.stderr)
            self.assertEqual(json.load(open(reg)), {})

    def test_download_failure_refused(self) -> None:
        # Given: a download URL that fails (a missing file:// target).
        with tempfile.TemporaryDirectory() as tmp:
            reg = self._registry(tmp, {})
            # When: the recorder tries to download and bind the version.
            proc = self._run_ci("--version", "2.1.999",
                                "--download-url", "file:///definitely/missing/xyz",
                                "--registry", reg)
            # Then: a clean refusal (exit 2), no registry write.
            self.assertEqual(proc.returncode, 2, proc.stdout + proc.stderr)
            self.assertIn("download", proc.stderr)
            self.assertEqual(json.load(open(reg)), {})

    def test_key_taken_by_different_size_refused(self) -> None:
        # Given: the registry key is already taken by a DIFFERENT-size build
        # (the false-positive guard).
        with tempfile.TemporaryDirectory() as tmp:
            path = self._synthetic(tmp, {136: 60000, 144: 120000, 152: 60000})
            reg = self._registry(tmp, {"synth": {"size": 9999,
                                                 "sites": [{"offset": 4, "old": 60000, "role": "driver", "target": ls.INT32_MAX}],
                                                 "evidence": {}}})
            stub = self._stub_probe_script(tmp)
            before = open(reg, "rb").read()
            # When: the recorder tries to bind the 256-byte build.
            proc = self._run_ci("--binary", path, "--probe", stub,
                                "--registry", reg)
            # Then: it refuses (exit 1) and leaves the registry untouched.
            self.assertEqual(proc.returncode, 1, proc.stdout + proc.stderr)
            self.assertIn("REFUSED", proc.stdout)
            self.assertEqual(open(reg, "rb").read(), before)

    def test_unmeasurable_build_refused(self) -> None:
        # Given: a binary with no int32 60000/120000 sites in the window
        # (nothing to measure).
        with tempfile.TemporaryDirectory() as tmp:
            path = self._synthetic(tmp, {})
            reg = self._registry(tmp, {})
            stub = self._stub_probe_script(tmp)
            # When: the recorder tries to bind it.
            proc = self._run_ci("--binary", path, "--probe", stub,
                                "--registry", reg)
            # Then: it refuses (exit 1) and records nothing (no-guess).
            self.assertEqual(proc.returncode, 1, proc.stdout + proc.stderr)
            self.assertIn("REFUSED", proc.stdout)
            self.assertEqual(json.load(open(reg)), {})

    def _tarball(self, tmp: str, members: dict, name: str = "build.tar.gz") -> str:
        # Pack {arcname: local-file} into a gzip tarball in tmp.
        path = os.path.join(tmp, name)
        with tarfile.open(path, "w:gz") as tar:
            for arcname, src in members.items():
                tar.add(src, arcname=arcname)
        return path

    def test_download_path_extracts_binary_from_release_tarball(self) -> None:
        # Given: a build shipped as the github release asset shape (a tarball
        # containing a single `claude` member) and an empty registry.
        with tempfile.TemporaryDirectory() as tmp:
            binary = self._synthetic(tmp, {136: 60000, 144: 120000, 152: 60000},
                                     name="claude")
            tgz = self._tarball(tmp, {"claude": binary})
            reg = self._registry(tmp, {})
            stub = self._stub_probe_script(tmp)
            url = "file://" + tgz
            # When: the recorder downloads and binds that version.
            proc = self._run_ci("--version", "2.1.998", "--download-url", url,
                                "--probe", stub, "--registry", reg)
            doc = json.load(open(reg))
            # Then: the tarball's binary is bound, recorded under the version
            # (not the archive name), and the record carries the measured size.
            self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
            entry = doc.get("2.1.998")
            self.assertIsNotNone(entry)
            self.assertEqual(entry["size"], 256)

    def test_download_path_extracts_npm_style_tarball(self) -> None:
        # Given: a build shipped as an npm platform tarball (several members,
        # the binary at package/claude among them).
        with tempfile.TemporaryDirectory() as tmp:
            binary = self._synthetic(tmp, {136: 60000, 144: 120000, 152: 60000},
                                     name="claude")
            pkg_json = os.path.join(tmp, "package.json")
            with open(pkg_json, "w", encoding="utf-8") as f:
                f.write('{"name": "x"}')
            tgz = self._tarball(tmp, {"package/claude": binary,
                                      "package/package.json": pkg_json})
            reg = self._registry(tmp, {})
            stub = self._stub_probe_script(tmp)
            # When: the recorder downloads and binds that version.
            proc = self._run_ci("--version", "2.1.997", "--download-url",
                                "file://" + tgz, "--probe", stub,
                                "--registry", reg)
            doc = json.load(open(reg))
            # Then: the `claude` member (identified by name, not guessed) is
            # bound and recorded.
            self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
            self.assertEqual(doc["2.1.997"]["size"], 256)

    def test_download_path_single_member_archive_uses_the_only_member(self) -> None:
        # Given: a tarball with exactly one regular file, not named `claude`.
        with tempfile.TemporaryDirectory() as tmp:
            binary = self._synthetic(tmp, {136: 60000, 144: 120000, 152: 60000},
                                     name="binfile")
            tgz = self._tarball(tmp, {"binfile": binary})
            reg = self._registry(tmp, {})
            stub = self._stub_probe_script(tmp)
            # When: the recorder downloads and binds that version.
            proc = self._run_ci("--version", "2.1.996", "--download-url",
                                "file://" + tgz, "--probe", stub,
                                "--registry", reg)
            doc = json.load(open(reg))
            # Then: the single member is the binary; bound and recorded.
            self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
            self.assertEqual(doc["2.1.996"]["size"], 256)

    def test_download_path_ambiguous_archive_refused(self) -> None:
        # Given: a tarball with two regular files and no `claude` member
        # (the binary cannot be identified without guessing).
        with tempfile.TemporaryDirectory() as tmp:
            a = self._synthetic(tmp, {136: 60000, 144: 120000, 152: 60000},
                                name="a")
            b = self._synthetic(tmp, {136: 60000, 144: 120000, 152: 60000},
                                name="b")
            tgz = self._tarball(tmp, {"a": a, "b": b})
            reg = self._registry(tmp, {})
            stub = self._stub_probe_script(tmp)
            before = open(reg, "rb").read()
            # When: the recorder downloads and tries to bind that version.
            proc = self._run_ci("--version", "2.1.995", "--download-url",
                                "file://" + tgz, "--probe", stub,
                                "--registry", reg)
            # Then: refused (exit 2) and the registry is untouched.
            self.assertEqual(proc.returncode, 2, proc.stdout + proc.stderr)
            self.assertIn("cannot identify", proc.stderr)
            self.assertEqual(open(reg, "rb").read(), before)

    def test_download_path_corrupt_archive_refused(self) -> None:
        # Given: a file that starts with the gzip magic but is not a readable
        # tarball (truncated/corrupt).
        with tempfile.TemporaryDirectory() as tmp:
            corrupt = os.path.join(tmp, "corrupt.tar.gz")
            with open(corrupt, "wb") as f:
                f.write(b"\x1f\x8b" + b"junk" * 64)
            reg = self._registry(tmp, {})
            stub = self._stub_probe_script(tmp)
            before = open(reg, "rb").read()
            # When: the recorder downloads and tries to bind that version.
            proc = self._run_ci("--version", "2.1.994", "--download-url",
                                "file://" + corrupt, "--probe", stub,
                                "--registry", reg)
            # Then: refused (exit 2) and the registry is untouched.
            self.assertEqual(proc.returncode, 2, proc.stdout + proc.stderr)
            self.assertIn("unreadable", proc.stderr)
            self.assertEqual(open(reg, "rb").read(), before)


_WORKER_TESTS = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                            "worker", "test_release_watch.mjs")


class ReleaseWatchWorkerTests(unittest.TestCase):
    """worker/release-watch.js (the Cloudflare Worker that watches the
    claude-code release feed and dispatches the bind-new-version workflow):
    feed parsing, no-guess URL/asset resolution, the dispatch + KV state
    machine (retry on failure, no-op when up-to-date), and the manual
    routes. The suite is plain node; this runs it as a subprocess."""

    def test_worker_suite_passes(self) -> None:
        node = shutil.which("node")
        if not node:
            self.skipTest("node is not installed")
        # Given: the checked-in worker test suite.
        # When: node runs it.
        # Then: exit 0 and the runner reports zero failures.
        proc = subprocess.run([node, _WORKER_TESTS], capture_output=True,
                              text=True, timeout=120)
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertIn("fail 0", proc.stdout)


_WRAPPER_TEMPLATE = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "claude-wrapper.sh"
)


class _RegistryRoutingBase:
    """Shared layout helpers for the registry routing tests (not a test
    class itself - the test classes below inherit it)."""

    def _fake_home(self, tmp: str, name: str = "home") -> tuple:
        # A claude-native layout: bin link -> versions file, one file per
        # version, one *.bak backup (newer mtime, must never be picked),
        # newest by mtime = 2.1.270.
        home = os.path.join(tmp, name)
        bin_dir = os.path.join(home, ".local", "bin")
        versions = os.path.join(home, ".local", "share", "claude", "versions")
        os.makedirs(bin_dir)
        os.makedirs(versions)

        def binary(n: str, tag: str, mtime: int) -> str:
            path = os.path.join(versions, n)
            with open(path, "wb") as f:
                f.write(f"#!/bin/sh\necho FAKECLAUDE-{tag} $*\n".encode())
            os.chmod(path, 0o755)
            os.utime(path, (mtime, mtime))
            return path

        binary("2.1.269", "269", 1757000000)
        binary("2.1.269.bak", "269bak", 1757000100)
        target = binary("2.1.270", "270", 1757000200)
        os.symlink(target, os.path.join(bin_dir, "claude"))
        return home, bin_dir, versions, target

    def _stub_patcher(self, tmp: str, name: str = "stub_patcher.sh") -> str:
        # Emulates the real patcher's artifact contract: on success it
        # leaves a <binary>.patched file next to the target and never
        # touches the original. It logs its FULL argument line: the binary
        # is the LAST argument, so a --registry <file> prefix is
        # observable in the log.
        path = os.path.join(tmp, name)
        with open(path, "w", encoding="utf-8") as f:
            f.write(
                "#!/bin/bash\n"
                'echo "STUBPATCHER $*" >> "${STUB_LOG:-/dev/null}"\n'
                'BIN="${@: -1}"\n'
                '{ echo "#!/bin/sh"; echo "echo PATCHED-OF-$(basename "$BIN") \\$*"; } > "$BIN.patched"\n'
                'chmod +x "$BIN.patched"\n'
                "exit 0\n"
            )
        os.chmod(path, 0o755)
        return path

    def _registry_doc(self, path: str, version: str, size: int) -> None:
        with open(path, "w", encoding="utf-8") as f:
            json.dump({version: {"size": size,
                                 "sites": [{"offset": 100, "old": 60000,
                                            "target": 425000000}]}}, f)

    def _run(self, *args: object, env_extra: dict = None, timeout: int = 60) -> subprocess.CompletedProcess:
        env = dict(os.environ)
        if env_extra:
            env.update(env_extra)
        return subprocess.run(
            ["bash", *[str(a) for a in args]],
            capture_output=True, text=True, timeout=timeout, env=env,
        )

    def _install(self, home: str, patcher: str) -> subprocess.CompletedProcess:
        return self._run(_INSTALL_SCRIPT, env_extra={"HOME": home, "CLAUDE_PATCHER_SCRIPT": patcher})

    def _wrapper_reg(self, home: str) -> str:
        return os.path.join(home, ".local", "bin", "verified_sites.json")


class WrapperRegistryTests(_RegistryRoutingBase, unittest.TestCase):
    """claude-wrapper.sh registry routing: before the patcher runs on a
    changed binary, the wrapper downloads the latest verified_sites.json
    into the wrapper's own folder (the folder the script lives in; the
    source is CLAUDE_PATCHER_REGISTRY_URL - a URL or a local file path,
    the test/offline hook). The patcher is then invoked with
    --registry <that file> when the file exists next to the wrapper, and
    with its default (checkout) registry when it does not. The download
    runs only on the patching path, is best-effort (a failed download
    never blocks the launch), and is skipped with CLAUDE_WRAPPER_NO_SYNC=1
    or when the wrapper is run from inside the checkout (the file next to
    it is the checkout's own tracked registry)."""

    def test_first_launch_downloads_registry_to_wrapper_folder_and_passes_it(self) -> None:
        # Given: an installed wrapper and a registry the download source
        # serves (CLAUDE_PATCHER_REGISTRY_URL as a local file).
        with tempfile.TemporaryDirectory() as tmp:
            home, bin_dir, versions, target = self._fake_home(tmp)
            stub = self._stub_patcher(tmp)
            log = os.path.join(tmp, "stub.log")
            remote = os.path.join(tmp, "remote_registry.json")
            self._registry_doc(remote, "2.1.270", 200)
            wrapper_reg = self._wrapper_reg(home)
            env = {"HOME": home, "STUB_LOG": log, "CLAUDE_PATCHER_REGISTRY_URL": remote}
            self._install(home, stub)
            # When: the first launch (the never-recorded binary counts as
            # changed - the patcher is about to run).
            boot = self._run(os.path.join(bin_dir, "claude-patched"), "--f", env_extra=env)
            # Then: the latest registry was downloaded INTO THE WRAPPER'S
            # OWN FOLDER, the patcher was invoked with --registry <that
            # file>, and the boot came through the patched artifact.
            self.assertEqual(boot.returncode, 0, boot.stdout + boot.stderr)
            self.assertIn("PATCHED-OF-2.1.270 --f", boot.stdout)
            self.assertTrue(os.path.exists(wrapper_reg))
            self.assertEqual(open(wrapper_reg).read(), open(remote).read())
            self.assertEqual(open(log).read().splitlines(),
                             [f"STUBPATCHER --registry {wrapper_reg} {target}"])
            # When: the download source serves a NEWER registry (a CI
            # record) and the artifact is deleted (a missing artifact
            # forces the re-patch path).
            self._registry_doc(remote, "2.1.270", 201)
            os.remove(target + ".patched")
            boot2 = self._run(os.path.join(bin_dir, "claude-patched"), "--g", env_extra=env)
            # Then: the file next to the wrapper was refreshed to the
            # newer content and the patcher used it again.
            self.assertEqual(boot2.returncode, 0, boot2.stdout + boot2.stderr)
            self.assertIn("PATCHED-OF-2.1.270 --g", boot2.stdout)
            self.assertEqual(open(wrapper_reg).read(), open(remote).read())
            self.assertEqual(open(log).read().splitlines(),
                             [f"STUBPATCHER --registry {wrapper_reg} {target}"] * 2)

    def test_download_failure_without_file_uses_repository_registry(self) -> None:
        # Given: an installed wrapper whose patcher lives in a
        # checkout-shaped folder holding the default registry, and a
        # download source that fails (offline).
        with tempfile.TemporaryDirectory() as tmp:
            home, bin_dir, versions, target = self._fake_home(tmp)
            repo_dir = os.path.join(tmp, "repo")
            os.makedirs(repo_dir)
            stub = self._stub_patcher(repo_dir)
            self._registry_doc(os.path.join(repo_dir, "verified_sites.json"),
                               "2.1.270", 200)
            log = os.path.join(tmp, "stub.log")
            env = {"HOME": home, "STUB_LOG": log,
                   "CLAUDE_PATCHER_REGISTRY_URL": os.path.join(tmp, "no_such_registry.json")}
            self._install(home, stub)
            # When: the first launch.
            boot = self._run(os.path.join(bin_dir, "claude-patched"), "--f", env_extra=env)
            # Then: no file was created next to the wrapper, the patcher
            # ran in repository mode (no --registry - its default
            # registry is the checkout file, with its own download
            # fallback and local auto-bind), and the boot came through
            # the patched artifact.
            self.assertEqual(boot.returncode, 0, boot.stdout + boot.stderr)
            self.assertIn("PATCHED-OF-2.1.270 --f", boot.stdout)
            self.assertFalse(os.path.exists(self._wrapper_reg(home)))
            self.assertIn("repository registry", boot.stdout)
            self.assertEqual(open(log).read().splitlines(), [f"STUBPATCHER {target}"])

    def test_download_failure_with_existing_file_keeps_and_uses_it(self) -> None:
        # Given: a first successful launch (the registry file exists next
        # to the wrapper); then the download source breaks and the
        # artifact is deleted.
        with tempfile.TemporaryDirectory() as tmp:
            home, bin_dir, versions, target = self._fake_home(tmp)
            stub = self._stub_patcher(tmp)
            log = os.path.join(tmp, "stub.log")
            remote = os.path.join(tmp, "remote_registry.json")
            self._registry_doc(remote, "2.1.270", 200)
            wrapper_reg = self._wrapper_reg(home)
            env_ok = {"HOME": home, "STUB_LOG": log,
                      "CLAUDE_PATCHER_REGISTRY_URL": remote}
            self._install(home, stub)
            first = self._run(os.path.join(bin_dir, "claude-patched"), env_extra=env_ok)
            self.assertEqual(first.returncode, 0, first.stdout + first.stderr)
            self.assertTrue(os.path.exists(wrapper_reg))
            v1 = open(wrapper_reg).read()
            os.remove(target + ".patched")
            env_bad = {"HOME": home, "STUB_LOG": log,
                       "CLAUDE_PATCHER_REGISTRY_URL":
                       os.path.join(tmp, "no_such_registry.json")}
            # When: the next launch, with the download failing.
            boot = self._run(os.path.join(bin_dir, "claude-patched"), "--f", env_extra=env_bad)
            # Then: the existing file is KEPT (a failed download must not
            # delete it) and is still passed to the patcher; the boot
            # came through the regenerated artifact.
            self.assertEqual(boot.returncode, 0, boot.stdout + boot.stderr)
            self.assertIn("PATCHED-OF-2.1.270 --f", boot.stdout)
            self.assertEqual(open(wrapper_reg).read(), v1)
            self.assertIn("existing", boot.stdout)
            self.assertEqual(open(log).read().splitlines(),
                             [f"STUBPATCHER --registry {wrapper_reg} {target}"] * 2)

    def test_no_sync_env_var_skips_download_but_still_uses_existing_file(self) -> None:
        # Given: a first launch downloaded the registry (V1); the source
        # then serves V2; the artifact is deleted.
        with tempfile.TemporaryDirectory() as tmp:
            home, bin_dir, versions, target = self._fake_home(tmp)
            stub = self._stub_patcher(tmp)
            log = os.path.join(tmp, "stub.log")
            remote = os.path.join(tmp, "remote_registry.json")
            self._registry_doc(remote, "2.1.270", 200)
            wrapper_reg = self._wrapper_reg(home)
            env = {"HOME": home, "STUB_LOG": log, "CLAUDE_PATCHER_REGISTRY_URL": remote}
            self._install(home, stub)
            first = self._run(os.path.join(bin_dir, "claude-patched"), env_extra=env)
            self.assertEqual(first.returncode, 0, first.stdout + first.stderr)
            v1 = open(wrapper_reg).read()
            self._registry_doc(remote, "2.1.270", 201)
            os.remove(target + ".patched")
            env_nosync = dict(env, CLAUDE_WRAPPER_NO_SYNC="1")
            # When: the next launch with the sync escape hatch set.
            boot = self._run(os.path.join(bin_dir, "claude-patched"), "--f", env_extra=env_nosync)
            # Then: the download was SKIPPED (the file is still V1, not
            # refreshed to V2), but the existing file is still passed to
            # the patcher (the routing is by file existence, not by the
            # download result).
            self.assertEqual(boot.returncode, 0, boot.stdout + boot.stderr)
            self.assertIn("PATCHED-OF-2.1.270 --f", boot.stdout)
            self.assertEqual(open(wrapper_reg).read(), v1)
            self.assertEqual(open(log).read().splitlines(),
                             [f"STUBPATCHER --registry {wrapper_reg} {target}"] * 2)

    def test_no_sync_env_var_without_file_falls_back_to_repository_registry(self) -> None:
        # Given: an installed wrapper, the sync escape hatch set from the
        # start, and a patcher checkout folder holding the default
        # registry.
        with tempfile.TemporaryDirectory() as tmp:
            home, bin_dir, versions, target = self._fake_home(tmp)
            repo_dir = os.path.join(tmp, "repo")
            os.makedirs(repo_dir)
            stub = self._stub_patcher(repo_dir)
            self._registry_doc(os.path.join(repo_dir, "verified_sites.json"),
                               "2.1.270", 200)
            log = os.path.join(tmp, "stub.log")
            remote = os.path.join(tmp, "remote_registry.json")
            self._registry_doc(remote, "2.1.270", 201)
            env = {"HOME": home, "STUB_LOG": log, "CLAUDE_WRAPPER_NO_SYNC": "1",
                   "CLAUDE_PATCHER_REGISTRY_URL": remote}
            self._install(home, stub)
            # When: the first launch.
            boot = self._run(os.path.join(bin_dir, "claude-patched"), "--f", env_extra=env)
            # Then: nothing was downloaded (no file next to the wrapper)
            # and the patcher ran in repository mode (no --registry).
            self.assertEqual(boot.returncode, 0, boot.stdout + boot.stderr)
            self.assertIn("PATCHED-OF-2.1.270 --f", boot.stdout)
            self.assertFalse(os.path.exists(self._wrapper_reg(home)))
            self.assertEqual(open(log).read().splitlines(), [f"STUBPATCHER {target}"])

    def test_unchanged_binary_does_not_attempt_download(self) -> None:
        # Given: a first launch (the registry was downloaded, the binary
        # recorded, the artifact present); then the download source
        # breaks.
        with tempfile.TemporaryDirectory() as tmp:
            home, bin_dir, versions, target = self._fake_home(tmp)
            stub = self._stub_patcher(tmp)
            log = os.path.join(tmp, "stub.log")
            remote = os.path.join(tmp, "remote_registry.json")
            self._registry_doc(remote, "2.1.270", 200)
            env_ok = {"HOME": home, "STUB_LOG": log,
                      "CLAUDE_PATCHER_REGISTRY_URL": remote}
            self._install(home, stub)
            first = self._run(os.path.join(bin_dir, "claude-patched"), env_extra=env_ok)
            self.assertEqual(first.returncode, 0, first.stdout + first.stderr)
            self.assertTrue(os.path.exists(self._wrapper_reg(home)))
            env_bad = {"HOME": home, "STUB_LOG": log,
                       "CLAUDE_PATCHER_REGISTRY_URL":
                       os.path.join(tmp, "no_such_registry.json")}
            # When: the next launch (nothing changed).
            boot = self._run(os.path.join(bin_dir, "claude-patched"), "--f", env_extra=env_bad)
            # Then: the usual zero-cost artifact boot, and NO download
            # was attempted (the sync runs only on the patching path - a
            # failed attempt would have printed a registry message).
            self.assertEqual(boot.returncode, 0, boot.stdout + boot.stderr)
            self.assertIn("PATCHED-OF-2.1.270 --f", boot.stdout)
            self.assertNotIn("new/changed", boot.stdout)
            self.assertNotIn("registry", boot.stdout)
            self.assertEqual(open(log).read().splitlines(),
                             [f"STUBPATCHER --registry {self._wrapper_reg(home)} {target}"])

    def test_unchanged_remote_content_reports_up_to_date(self) -> None:
        # Given: a first launch downloaded the registry; the artifact is
        # deleted; the download source serves the SAME content (the
        # remote is unchanged).
        with tempfile.TemporaryDirectory() as tmp:
            home, bin_dir, versions, target = self._fake_home(tmp)
            stub = self._stub_patcher(tmp)
            log = os.path.join(tmp, "stub.log")
            remote = os.path.join(tmp, "remote_registry.json")
            self._registry_doc(remote, "2.1.270", 200)
            wrapper_reg = self._wrapper_reg(home)
            env = {"HOME": home, "STUB_LOG": log, "CLAUDE_PATCHER_REGISTRY_URL": remote}
            self._install(home, stub)
            first = self._run(os.path.join(bin_dir, "claude-patched"), env_extra=env)
            self.assertEqual(first.returncode, 0, first.stdout + first.stderr)
            self.assertTrue(os.path.exists(wrapper_reg))
            os.remove(target + ".patched")
            # When: the next launch (the re-patch path, remote unchanged).
            boot = self._run(os.path.join(bin_dir, "claude-patched"), "--f", env_extra=env)
            # Then: the file next to the wrapper is in place (replaced
            # atomically with identical content), the patcher used it,
            # and the message reports the registry as up to date.
            self.assertEqual(boot.returncode, 0, boot.stdout + boot.stderr)
            self.assertIn("PATCHED-OF-2.1.270 --f", boot.stdout)
            self.assertIn("up to date", boot.stdout)
            self.assertEqual(open(wrapper_reg).read(), open(remote).read())
            self.assertEqual(open(log).read().splitlines(),
                             [f"STUBPATCHER --registry {wrapper_reg} {target}"] * 2)

    def test_wrapper_run_from_checkout_uses_repository_registry_directly(self) -> None:
        # Given: the wrapper is run from INSIDE the patcher checkout (the
        # file next to it IS the checkout's own tracked registry - the
        # user runs the repo copy of claude-wrapper.sh directly).
        with tempfile.TemporaryDirectory() as tmp:
            home, bin_dir, versions, target = self._fake_home(tmp)
            repo_dir = os.path.join(tmp, "repo")
            os.makedirs(repo_dir)
            stub = self._stub_patcher(repo_dir)
            repo_reg = os.path.join(repo_dir, "verified_sites.json")
            self._registry_doc(repo_reg, "2.1.270", 200)
            v1 = open(repo_reg).read()
            # A repo copy of the wrapper with the stub patcher baked in
            # (install.sh does the same sed for the installed copy).
            repo_wrapper = os.path.join(repo_dir, "claude-wrapper.sh")
            with open(_WRAPPER_TEMPLATE, encoding="utf-8") as f:
                template = f.read()
            with open(repo_wrapper, "w", encoding="utf-8") as f:
                f.write(template.replace('PATCHER="__PATCHER__"', f'PATCHER="{stub}"'))
            os.chmod(repo_wrapper, 0o755)
            # A fresh state file (install.sh's layout, no recorded hash).
            state = os.path.join(home, ".local", "share", "claude",
                                 ".last_known_version")
            with open(state, "w", encoding="utf-8") as f:
                f.write(f"versions_dir={versions}\norigin={target}\n"
                        f"origin_link_target={target}\nbinary=\nversion=\n"
                        "size=\nmtime=\nhash=\n")
            log = os.path.join(tmp, "stub.log")
            remote = os.path.join(tmp, "remote_registry.json")
            self._registry_doc(remote, "2.1.270", 201)  # different content
            env = {"HOME": home, "STUB_LOG": log,
                   "CLAUDE_PATCHER_REGISTRY_URL": remote}
            # When: the repo copy of the wrapper is run.
            boot = self._run(repo_wrapper, "--f", env_extra=env)
            # Then: no download happened (it would replace the tracked
            # file), the patcher ran in repository mode (no --registry -
            # its default registry is exactly that file), and the boot
            # came through the patched artifact.
            self.assertEqual(boot.returncode, 0, boot.stdout + boot.stderr)
            self.assertIn("PATCHED-OF-2.1.270 --f", boot.stdout)
            self.assertEqual(open(repo_reg).read(), v1)
            self.assertEqual(open(log).read().splitlines(), [f"STUBPATCHER {target}"])

    def test_malformed_download_is_rejected(self) -> None:
        # Given: a download source that serves valid JSON that is NOT an
        # object (a truncated/corrupt registry transfer).
        with tempfile.TemporaryDirectory() as tmp:
            home, bin_dir, versions, target = self._fake_home(tmp)
            stub = self._stub_patcher(tmp)
            log = os.path.join(tmp, "stub.log")
            bad = os.path.join(tmp, "bad_registry.json")
            with open(bad, "w", encoding="utf-8") as f:
                f.write("[1, 2, 3]")
            env = {"HOME": home, "STUB_LOG": log, "CLAUDE_PATCHER_REGISTRY_URL": bad}
            self._install(home, stub)
            # When: the first launch.
            boot = self._run(os.path.join(bin_dir, "claude-patched"), "--f", env_extra=env)
            # Then: the corrupt transfer was rejected (no file was written
            # next to the wrapper - a file that is not an object would
            # make the binder refuse), and the patcher ran in repository
            # mode.
            self.assertEqual(boot.returncode, 0, boot.stdout + boot.stderr)
            self.assertIn("PATCHED-OF-2.1.270 --f", boot.stdout)
            self.assertFalse(os.path.exists(self._wrapper_reg(home)))
            self.assertEqual(open(log).read().splitlines(), [f"STUBPATCHER {target}"])


class RegistryDerivedUrlTests(_RegistryRoutingBase, unittest.TestCase):
    """The download source when CLAUDE_PATCHER_REGISTRY_URL is unset: the
    raw URL of the checkout's origin remote default branch, derived from
    the checkout's git config (the remote URL plus the
    refs/remotes/origin/HEAD ref). The branch comes from the FULL ref with
    the refs/remotes/origin/ prefix stripped - git's --short form yields
    "origin/<branch>" and the raw URL 404s. A curl stand-in on the PATH
    makes the derivation testable offline (it logs the URL and serves a
    fixed document); one test also fetches the real repository's registry
    over the network (skipped when offline)."""

    def _git_checkout(self, tmp: str, name: str, origin_url: str,
                      default_branch: str = "develop") -> str:
        # A checkout shaped like a full clone: one commit, an origin remote
        # (the URL is stored, never fetched) and origin/HEAD resolved to
        # the default branch.
        root = os.path.join(tmp, name)
        os.makedirs(root)

        def git(*args: str) -> str:
            proc = subprocess.run(["git", "-C", root, *args],
                                  capture_output=True, text=True)
            self.assertEqual(proc.returncode, 0,
                             "git " + " ".join(args) + ": " + proc.stderr)
            return proc.stdout.strip()

        git("init", "-q", "-b", default_branch)
        git("config", "user.email", "test@example.com")
        git("config", "user.name", "test")
        # The fake checkout must commit without the machine's global GPG
        # signing (pinentry would hang or fail the test).
        git("config", "commit.gpgsign", "false")
        git("config", "tag.gpgsign", "false")
        with open(os.path.join(root, "README.md"), "w", encoding="utf-8") as f:
            f.write("fake checkout\n")
        git("add", "README.md")
        git("commit", "-q", "-m", "init")
        head = git("rev-parse", "HEAD")
        git("remote", "add", "origin", origin_url)
        git("update-ref", f"refs/remotes/origin/{default_branch}", head)
        git("update-ref", "refs/remotes/origin/HEAD",
            f"refs/remotes/origin/{default_branch}")
        return root

    def _fake_curl(self, tmp: str) -> str:
        # A PATH stand-in for curl: logs the full argument line (the URL is
        # what is under test, not the network) and copies FAKE_REGISTRY to
        # the -o target.
        bin_dir = os.path.join(tmp, "fakebin")
        os.makedirs(bin_dir)
        path = os.path.join(bin_dir, "curl")
        with open(path, "w", encoding="utf-8") as f:
            f.write(
                "#!/bin/bash\n"
                'echo "$@" >> "${CURL_LOG:?}"\n'
                'out=""\n'
                'args=("$@")\n'
                'for ((i = 0; i < ${#args[@]}; i++)); do\n'
                '  [ "${args[$i]}" = "-o" ] && out="${args[$i + 1]}"\n'
                "done\n"
                '[ -n "$out" ] && cp "${FAKE_REGISTRY:?}" "$out"\n'
                "exit 0\n"
            )
        os.chmod(path, 0o755)
        return bin_dir

    def _derived_url(self, repo_path: str, branch: str = "develop") -> str:
        return (f"https://raw.githubusercontent.com/{repo_path}/"
                f"{branch}/verified_sites.json")

    def test_wrapper_derives_raw_url_from_checkout_origin_remote(self) -> None:
        # Given: an installed wrapper whose patcher lives in a checkout
        # whose origin remote is a github https URL (stored, never
        # fetched) with origin/HEAD resolved to the default branch - so
        # the download source is the URL derived from the checkout's git
        # config, no test hook - and a curl stand-in on the PATH.
        with tempfile.TemporaryDirectory() as tmp:
            home, bin_dir, versions, target = self._fake_home(tmp)
            root = self._git_checkout(tmp, "checkout",
                                      "https://github.com/fake/fake-repo.git")
            stub = self._stub_patcher(root)
            remote_doc = os.path.join(tmp, "remote_registry.json")
            self._registry_doc(remote_doc, "2.1.270", 200)
            fakebin = self._fake_curl(tmp)
            log = os.path.join(tmp, "stub.log")
            curl_log = os.path.join(tmp, "curl.log")
            env = {"HOME": home, "STUB_LOG": log, "CURL_LOG": curl_log,
                   "FAKE_REGISTRY": remote_doc,
                   "PATH": fakebin + os.pathsep + os.environ["PATH"]}
            self._install(home, stub)
            # When: the first launch (the patching path, no
            # CLAUDE_PATCHER_REGISTRY_URL).
            boot = self._run(os.path.join(bin_dir, "claude-patched"), "--f",
                             env_extra=env)
            # Then: the download used the raw URL of the checkout's
            # default branch WITHOUT the origin/ prefix (the --short form
            # would have 404'd), the registry landed next to the wrapper,
            # and the patcher was passed it.
            self.assertEqual(boot.returncode, 0, boot.stdout + boot.stderr)
            self.assertIn("PATCHED-OF-2.1.270 --f", boot.stdout)
            wrapper_reg = self._wrapper_reg(home)
            self.assertEqual(open(wrapper_reg).read(), open(remote_doc).read())
            expected = self._derived_url("fake/fake-repo")
            lines = open(curl_log).read().splitlines()
            self.assertEqual(len(lines), 1)
            self.assertTrue(lines[0].startswith(
                f"-fsSL --max-time 30 {expected} -o "))
            self.assertNotIn("origin/", lines[0])
            self.assertEqual(open(log).read().splitlines(),
                             [f"STUBPATCHER --registry {wrapper_reg} {target}"])

    def test_patcher_derives_raw_url_from_checkout_origin_remote(self) -> None:
        # Given: a checkout (the patcher's ROOT) with the same git config
        # as above, the patcher and its tools copied into it, a checkout
        # registry that does NOT bind the binary's size, a binary the
        # served registry DOES bind - and a curl stand-in on the PATH.
        with tempfile.TemporaryDirectory() as tmp:
            root = self._git_checkout(tmp, "checkout",
                                      "https://github.com/fake/fake-repo.git")
            shutil.copy(_PATCH_SCRIPT, os.path.join(root, "patch.sh"))
            shutil.copytree(
                os.path.join(os.path.dirname(_PATCH_SCRIPT), "tools"),
                os.path.join(root, "tools"),
                ignore=shutil.ignore_patterns("__pycache__"))
            with open(os.path.join(root, "verified_sites.json"), "w",
                      encoding="utf-8") as f:
                json.dump({"2.1.111": {"size": 2,
                            "sites": [{"offset": 0, "old": 60000,
                                       "role": "driver"}],
                            "evidence": {}}}, f)
            binpath = os.path.join(tmp, "bin")
            with open(binpath, "wb") as f:
                f.write(b"\x00" * 4096)
            os.chmod(binpath, 0o755)
            remote_doc = os.path.join(tmp, "remote_registry.json")
            with open(remote_doc, "w", encoding="utf-8") as f:
                json.dump({"fake": {"size": 4096,
                           "sites": [{"offset": 100, "old": 60000,
                                      "target": 425000000}],
                           "evidence": {}}}, f)
            fakebin = self._fake_curl(tmp)
            curl_log = os.path.join(tmp, "curl.log")
            env = dict(os.environ)
            env.update({"CURL_LOG": curl_log, "FAKE_REGISTRY": remote_doc,
                        "PATH": fakebin + os.pathsep + os.environ["PATH"]})
            # When: the patcher runs from inside the checkout (its remote
            # registry URL is derived from the checkout's git config), no
            # CLAUDE_PATCHER_REGISTRY_URL, auto-bind and verify off.
            proc = subprocess.run(
                ["bash", os.path.join(root, "patch.sh"), binpath,
                 "--no-verify", "--no-auto-bind"],
                capture_output=True, text=True, timeout=120, env=env,
                cwd=root)
            # Then: the local miss was resolved by a download from the raw
            # URL of the checkout's default branch WITHOUT the origin/
            # prefix; the apply was refused afterwards (the zero-filled
            # binary does not hold the recorded bytes, and its pool scan
            # cannot resolve a UNIQUE site) - the download is what is
            # under test.
            self.assertEqual(proc.returncode, 1, proc.stdout + proc.stderr)
            self.assertIn("downloaded", proc.stdout)
            self.assertIn("PHASE 4 REFUSED", proc.stdout)
            expected = self._derived_url("fake/fake-repo")
            lines = open(curl_log).read().splitlines()
            self.assertEqual(len(lines), 1)
            self.assertTrue(lines[0].startswith(
                f"-fsSL --max-time 30 {expected} -o "))
            self.assertNotIn("origin/", lines[0])

    def test_wrapper_downloads_repository_registry_over_the_network(self) -> None:
        # Given: an installed wrapper whose patcher checkout stores THIS
        # repository's https remote as its origin (never fetched) - so
        # the download source is the repository's own raw URL, fetched
        # over the real network (the test skips when offline or when the
        # checkout's origin is not a github https remote).
        repo_root = os.path.dirname(os.path.abspath(__file__))
        proc = subprocess.run(
            ["git", "-C", repo_root, "remote", "get-url", "origin"],
            capture_output=True, text=True)
        real_origin = proc.stdout.strip()
        if (proc.returncode != 0
                or not real_origin.startswith("https://github.com/")):
            self.skipTest("the checkout's origin is not a github https remote")
        repo_path = real_origin.split("https://github.com/", 1)[1]
        repo_path = repo_path[:-4] if repo_path.endswith(".git") else repo_path
        if subprocess.run(
                ["curl", "-fsSI", "--max-time", "20",
                 self._derived_url(repo_path)],
                capture_output=True).returncode != 0:
            self.skipTest("offline - the repository raw URL is not reachable")
        with tempfile.TemporaryDirectory() as tmp:
            home, bin_dir, versions, target = self._fake_home(tmp)
            root = self._git_checkout(tmp, "checkout", real_origin)
            stub = self._stub_patcher(root)
            log = os.path.join(tmp, "stub.log")
            env = {"HOME": home, "STUB_LOG": log}
            self._install(home, stub)
            # When: the first launch (the download source is the
            # repository's raw URL - no test hook).
            boot = self._run(os.path.join(bin_dir, "claude-patched"), "--f",
                             env_extra=env, timeout=120)
            # Then: the latest registry from the repository landed next to
            # the wrapper (a valid document: every entry carries a
            # numeric size), and the patcher was passed it.
            self.assertEqual(boot.returncode, 0, boot.stdout + boot.stderr)
            self.assertIn("PATCHED-OF-2.1.270 --f", boot.stdout)
            self.assertIn("refreshed from the repository", boot.stdout)
            wrapper_reg = self._wrapper_reg(home)
            doc = json.loads(open(wrapper_reg).read())
            self.assertTrue(doc)
            for key, entry in doc.items():
                self.assertIsInstance(entry, dict, key)
                self.assertIsInstance(entry.get("size"), int, key)
            self.assertEqual(open(log).read().splitlines(),
                             [f"STUBPATCHER --registry {wrapper_reg} {target}"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
