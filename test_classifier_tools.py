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
import os
import struct
import subprocess
import tempfile
import unittest
from typing import Dict
from unittest import mock

import classifier_scan as cs
import find_classifier_timeouts as fct
import patch_classifier_timeout as pcp
import verify_classifier_patch as vcp


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


class TestRunSelfTest(unittest.TestCase):
    def test_executable_passes(self) -> None:
        # Given: a stub executable that prints a version and exits 0.
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "stub")
            with open(path, "w") as f:
                f.write('#!/bin/sh\necho "2.1.267 (stub)"\n')
            os.chmod(path, 0o755)
            # When: the self-test runs it.
            ok, detail = pcp.run_self_test(path)
            # Then: PASS with the version in the detail.
            self.assertTrue(ok)
            self.assertIn("2.1.267", detail)

    def test_nonzero_exit_fails(self) -> None:
        # Given: a stub that exits 1.
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "stub")
            with open(path, "w") as f:
                f.write("#!/bin/sh\nexit 1\n")
            os.chmod(path, 0o755)
            # When: the self-test runs it.
            ok, detail = pcp.run_self_test(path)
            # Then: FAIL with the exit code surfaced.
            self.assertFalse(ok)
            self.assertIn("exit=1", detail)

    def test_launch_failure_reported(self) -> None:
        # Given: a path that cannot be launched.
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "stub")
            with open(path, "w") as f:
                f.write("not a script\n")
            os.chmod(path, 0o755)
            # When: launching is forced to raise.
            with mock.patch.object(
                pcp.subprocess, "run", side_effect=OSError("exec format error")
            ):
                ok, detail = pcp.run_self_test(path)
            # Then: reported as a launch failure, not a crash.
            self.assertFalse(ok)
            self.assertIn("failed to launch", detail)


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


if __name__ == "__main__":
    unittest.main(verbosity=2)
