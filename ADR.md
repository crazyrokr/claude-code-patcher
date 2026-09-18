# ADR: Auto-mode classifier timeout tooling for the Claude Code SFE binary

Status: accepted (2026-09-11)
Applies to: `/home/mk/claude-patch/` — `claude` (Bun single-file executable, 217,013,744 bytes)
Supersedes: `claude-code-patch.py`, `claude-code-patch-verify.py` (kept for reference; their verifier's "success" was a false positive)

## Problem

In auto mode, tool permissions are decided by an in-process safety classifier.
Every decision was failing closed after ~70 s with:

```
Got error trying Sonnet 5 as auto mode classifier, using qwen3.8:27b
Auto mode classifier: Sonnet 5 probe demotion errorKind=wall_clock_timeout
Auto mode classifier unavailable, denying with retry guidance (fail closed)
Slow permission decision: 70026ms for Edit (mode=auto, behavior=deny)
```

A prior patch raised the classifier's timeout constants in the binary, and the
prior verifier reported it successful — yet the denial persisted unchanged.

## Findings (measured on this build)

The SFE stores **two independent copies** of the app plus a string pool:

| Region | Offset (decimal MB) | Contents | Executed at runtime? |
|---|---|---|---|
| native | 0 – 85 | Bun/JavaScriptCore ELF code | yes (runtime) |
| string/identifier pool | 91 – 102 | deduplicated identifier table (147,417 entries; see addendum 2026-09-12) | data, not code |
| **live bytecode** | 102 – 177 | compiled Bun bytecode (0x9f opcodes) | **yes — this runs** |
| source (dead) | 177 – 209 | plaintext JS source, retained as fallback (boundary refined from 181; 177–181 is also source) | **no** |
| tail | 209 – 217 | zstd payloads, path pool, SFE file table | — |

Consequences:

1. **The previous patch was a runtime no-op.** The classifier's declaration
   `var TQe=60000,L8=120000,Lrn=60000,Frn=4,$rn=0,Brn=2000,Urn=10000;`
   appears once, in the *source* region @185.045M, and was already patched to
   `99999/999999/99999` plus `Hrn → return 999999999`. The runtime executes
   the compiled bytecode region, which never reads that text.
2. **The live constants are not raw immediates.** The classifier's numbers sit
   in the bytecode's constant table (deduplicated, reordered by first use).
   A raw int32 search for `60000` yields 871 hits app-wide; the ordered run
   `60000→120000→60000→2000→10000` has **zero** matches at any gap. The
   classifier's `TQe` is also *overloaded* with an unrelated bridge function,
   so identifier matching alone cannot isolate the timeout site.
3. **The 70026 ms denial confirms original values are live**
   (≈ `TQe` 60000 + `Urn` 10000 + overhead).
4. **Root cause is the backend, not the timeout.** `wall_clock_timeout` +
   probe demotion mean the model endpoint (`ANTHROPIC_BASE_URL` →
   qwen3.8:27b proxy) is slow or down. `ANTHROPIC_TIMEOUT=1800000` does not
   reach the classifier's internal budget. A larger timeout only lengthens
   each fail-closed wait.

## Decision

Ship three tools with a shared pure engine, and be honest about what a patch
can and cannot do:

| File | Role |
|---|---|
| `classifier_scan.py` | Pure engine: discovery (constant block, `Hrn`, signatures, regions), byte-length-preserving rewrite, all-or-nothing semantics. |
| `find_classifier_timeouts.py` | Read-only: every classifier timeout site with offset + region. |
| `verify_classifier_patch.py` | Verdicts `UNPATCHED` / `SOURCE_PATCHED_LIVE_UNVERIFIED` / `PATCHED_LIVE`; exit 0 only when the executed region is confirmed. Replaces the old verifier that exited 0 on a no-op patch. |
| `live_scan.py` | Pure engine for the reference-anchored **live** path: pool parse, anchor resolution, reference-encoding site sweep, constant-slot binding (UNIQUE/AMBIGUOUS/EMPTY), length-preserving all-or-nothing apply, static verify. See addendum 2026-09-12. |
| `patch_classifier_timeout.py` | Raises TQe/L8/Lrn to the digit-count-preserving maxima (99999/999999/99999) in the source block; any length-changing edit refused unless `--allow-length-change`; `--self-test` executes the staged copy before a swap; `--in-place` is rollback-protected (original saved as `<binary>.orig`, patched copy staged and self-tested first, atomic swap, full restore on failure); a request that resolves to zero edits (values already at target, or a `Hrn` rewrite that cannot be located) is a refusal — nothing is written or copied; `--experimental-live` runs live Phases 1–3 read-only and prints the candidate manifest; `--apply-live` / `--oracle` gate Phase 4 behind UNIQUE resolution; never guesses at live-bytecode sites. |
| `test_classifier_tools.py` | 99 Given-When-Then unittest cases incl. false-positive scenarios (bridge `TQe` overload, non-classifier blocks, length-change refusal, idempotency), the defect regressions (in-place restore on failed self-test, Hrn-not-found refusal, no-op write refusal), and the live-path suite (pool parse accept/reject, anchor resolution, encoding plausibility, UNIQUE/AMBIGUOUS/EMPTY manifest, apply refuse on empty/out-of-range, static-verify failure modes, CLI read-only refusal and Phase 4 refusal on non-UNIQUE). |

**Explicitly not done:** a live-bytecode patcher. It would have to choose
among 26+ ambiguous constant-table sites, cannot be validated without a live
model endpoint, and violates the "no breaking changes" constraint. Failing
closed is the correct behavior here. (The machinery was built and exercised on
this build in 2026-09-12 and refused honestly — see the addendum below.)

## Safe-patch invariants (enforced in code)

- Byte-length preserving by default (same decimal digit count ⇒ no byte
  shifts ⇒ nothing downstream can break).
- All-or-nothing: one refused edit ⇒ zero edits written. A requested `Hrn`
  rewrite that cannot be located is such a refusal, not a skipped edit.
- Unknowns refused: no block found ⇒ no write; Hrn literal longer than body ⇒ no write.
- Self-test gate: `--self-test` runs `<copy> --version`; a failing copy is removed.
- In-place protection: `--in-place` moves the original to `<binary>.orig`
  first (an existing backup is kept, never clobbered), stages the patched
  bytes as `<binary>.new`, self-tests the staged copy, and only then swaps it
  in via atomic rename. A failing or crashed copy triggers a full restore, so
  the original is never lost and never left replaced by a broken binary.
- No no-op writes: a patch request that resolves to zero edits (every value
  already at its target) writes nothing and copies nothing.

## Reliable mitigations (in preference order)

1. Skip the classifier: `claude --permission-mode bypassPermissions`.
2. Allow the specific tool so no classifier decision is needed
   (`permissions.allow: ["Edit(/path/**)"]`).
3. Fix the endpoint — the real defect. `wall_clock_timeout` is a backend
   health signal; check `ANTHROPIC_BASE_URL` reachability and latency.

## Consequences

- The binary can be patched safely (source region) with zero breakage risk,
  but in this build that does not change runtime behavior; the tools state so
  instead of claiming success.
- If a future Bun build executes the source region (or a classifier block
  ever appears inside the live region), `verify_classifier_patch.py` reports
  `PATCHED_LIVE` and exits 0 automatically — no tooling change needed.
- The old scripts remain in place, unmodified, as historical reference.

## Addendum (2026-09-12): reference-anchored live mode (`--experimental-live`)

### Design

`live_scan.py` implements the four phases over a pure `bytes` buffer; the CLI
drives them with three flags:

- **`--experimental-live`** — Phases 1–3 only, read-only: prints the candidate
  manifest (anchors, per-encoding hit counts, candidate sites, candidate
  constant slots, resolution) and stops. Always refuses; writes nothing; exit 0.
- **`--apply-live`** — Phase 4, permitted only when resolution is UNIQUE:
  length-preserving all-or-nothing int32 rewrite to
  `<binary>.patched` (never the original), static re-verify, then the
  `--version` execute gate.
- **`--oracle`** — implies `--apply-live` plus a behavioral oracle: both binaries
  are timed against a local blackholed endpoint; `NO_OP` (wait unchanged)
  removes the patched copy; `UNVERIFIED` never claims success.

Phases: (1) parse the string pool and resolve each classifier-unique anchor to
its entry (ordinal + stored 24-bit hash); (2) sweep the live region for u32
references under a small candidate-encoding set (an encoding is plausible only
with 1..64 hits — zero means wrong encoding, a flood means an unrelated
constant); (3) within each site's ±4096 B neighborhood collect int32 slots
carrying the constraint values {60000, 120000, 2000, 10000}; exactly one
fully-bound site is UNIQUE, otherwise AMBIGUOUS (refuse) or EMPTY (refuse).
Phase 4 re-discovers the slots in the patched bytes: same length, every
differing byte inside a bound slot, each slot reads its new value.

### Pool layout (empirically confirmed on this build)

147,417 entries in 91–102 MB. Entry =
`[len:u8][00 00 80][hash:3 bytes LE][00][chars:len][NUL][zero pad to next header]`;
a header at `off` is valid iff `data[off+1:off+4] == 00 00 80`, `1 ≤ len ≤ 120`,
the next `len` bytes are non-NUL printable, and the byte after is NUL. The
stored 3-byte hash does not match any standard 32-bit hash of the string
(unresolved; not needed — references resolved by ordinal below).

### Findings on the real `claude` binary

- Anchors resolved: `classifierStage` (ordinal 87592, hash24 0xc5abd3),
  `wall_clock_timeout` (ordinal 87612, hash24 0x68684c). `probe demotion` and
  `cannot determine the safety of` are not pool entries in this build.
- Reference encodings in the live region: `hash24: 0`, `hash24_flag80: 0`,
  `offset: 0`, **`ordinal: 7`**, `ordinal+1: 0`. The ordinal u32 is the only
  plausible encoding; 7 candidate sites (3 on `classifierStage`, 4 on
  `wall_clock_timeout`).
- Phase 3: **none** of the 7 sites contains the full 4-value constraint set
  within ±4096 B → resolution AMBIGUOUS → Phase 4 REFUSED (exit 1, nothing
  written, no `<binary>.patched` produced). The 60000/120000/2000/10000
  constants are app-wide ambiguous (250/57/636/537 hits) and the apparent
  172.65 M chain is a cross-function bytecode instruction stream, not a
  constant array.
- The 7 ordinal hits themselves carry no constant neighborhood at all, so even
  the reference sites do not bound a patchable constant slot on this build.

### Consequences

- The no-guess invariant held end-to-end on the real binary: the tool emitted a
  complete, machine-checkable manifest and refused instead of guessing.
  This is a designed honest negative result, not a tooling failure.
- "Explicitly not done: a live-bytecode patcher" stands for this build; the
  machinery is now in place, tested (109/109), and will resolve UNIQUE — and
  apply with verification — if a future build isolates the classifier's
  constants into a single boundable neighborhood.

### Cross-build survey (two subsequent builds), and the final algorithm (2026-09-12)

Two subsequent builds were surveyed with the same tooling and follow-up
probes. The three builds in this ADR are identified by size throughout:
the 217M build (217,013,744 B), the 218M build (218,602,992 B), and the
219M build (219,651,568 B).

| | 217M | 218M | 219M |
|---|---|---|---|
| size | 217,013,744 B | 218,602,992 B | 219,651,568 B |
| pool entries (91–102 M range) | 147,417 | 149,377 | 147,043 |
| `classifierStage` ordinal / hash24 | 87592 / 0xc5abd3 | 88913 / 0xc5abd3 | 86446 / 0xc5abd3 |
| `wall_clock_timeout` ordinal / hash24 | 87612 / 0x68684c | 88933 / 0x68684c | 86468 / 0x68684c |
| plausible reference encodings | ordinal: 7 | ordinal+1: 3 | ordinal: 6, ordinal+1: 1 |

The stored 24-bit hashes are stable across builds; the *reference encoding*
drifts (217M uses bare ordinal, 218M uses ordinal+1, 219M mixes both), which is
exactly why Phase 2 probes a candidate set instead of hard-coding one.

Phase 3 on every build: **no** candidate site contains the full 4-value set
within ±4096 B (nearest anchor-site distances 0.7 MB–16 MB), so all three
resolve AMBIGUOUS and Phase 4 is REFUSED — nothing written, nothing guessed.
The 218M/219M builds are therefore *not* the "future build" the design anticipated.

Probes 3–5 then decoded what the set-test "candidates" actually are. They are
app-wide **settings/limits tables**, not per-function bytecode constant arrays:

- **Family A** (all three builds; 10000-relative layout `2000@-24, 10000@0,
  60000@+48, 120000@+60`, span 84 B): the same value slots byte-identical
  across builds, mixed with durations (200/5000/300000/3600000), small counts,
  the year 2026, INT32_MAX sentinels, and table-relative pointer slots that
  shift with placement (217M `0x81ee..`, 218M `0x82da..`, 219M `0x9026..`).
- **Family B** (218M @ 153,711,608; 219M @ 155,976,188;
  60000-relative `10000@-40, 2000@-24, 60000@0, 120000@+48`, span 88 B):
  value slots byte-identical across builds; index/pointer slots shift.
- The classifier's 5th declared value, the **50000** backoff step, is **never**
  within 4096 B of any of these tables in any build — a real classifier
  constant array would carry it. Ownership of these tables is not statically
  provable, so under the no-guess invariant they are not bindable, and the
  apply gate stays REFUSED on all three builds.

**Final algorithm.** The Phase 1–4 gate is unchanged; a **report-only
set-window diagnostic** was added so the manifest is a complete tripwire for
future builds. `find_set_windows` (SET_WINDOW = 64 B each side of an anchor
occurrence) finds every compact int32 table holding all four constraint
values; candidates are deduped by their slot-offset set, and the aux value
50000 is reported if within 4096 B (None otherwise). The result never
influences status or binding: the 217M build reports 1 table (Family A),
the 218M and 219M builds report 2 each (Families A + B), and every build
still prints AMBIGUOUS →
REFUSED with the diagnostic line. If a future build isolates the classifier's
constants into a single compact table *and* binds it to an anchor site,
Phases 2–3 resolve UNIQUE and Phase 4 applies with the existing
verify + `--version` + optional oracle gates.

Tests grew 99 → 109 GWT cases: the diagnostic (tight-table detection with
center dedupe, scattered/boundary negatives, aux present/absent, range
respect), the 218M/219M false-positive shape (set-window present, no site bound
→ AMBIGUOUS with zero apply candidates), the UNIQUE build also reporting the
diagnostic, the backward-compatible no-`live_range` call form, and CLI output
of the new section.

### Addendum (2026-09-12): extract → patch source → recompile → verify (218M build)

Requested alternative: extract the embedded source, patch it, recompile the
changed sources back into the bundle, and verify the new binary. Each stage,
measured on the 218M build (218,602,992 B; regions: source 179,983,360..213,360,112
= 33.4 MB, 1650 `/$bunfs/root/chunk-*.js` files; bytecode 107,000,000..
179,983,360 ≈ 73 MB; embedded Bun v1.4.1 / 83c373b27):

- **Extract — feasible.** The source region is plain text; any chunk can be
  sliced out (e.g. `classifier_source_slice.txt`, 1.2 MB window at 186,000,000).
- **Patch source — feasible, byte-length preserving.** `tF1_src_patched`
  (JZe=99999, z9=999999, Rin=99999) and `tG_src_jze20k` (JZe=20000); both
  218,602,992 B, verified at offset 186,102,716.
- **Recompile — not available.** No offline path re-embeds Bun 1.4.1 bytecode
  from source, so a source patch can only go live if the runtime parses that
  chunk from source. The verify stage settles that.
- **Verify — source patch has NO runtime effect (decisive A/B/C).**
  Blackhole timing oracle: fake Anthropic endpoint on 127.0.0.1:8791 +
  isolated `CLAUDE_CONFIG_DIR` (base URL → fake endpoint; model
  claude-opus-5; sandbox disabled; no apiKeyHelper/plugins), run as
  `--permission-mode auto -p ... --max-turns 2`. The scripted main turn emits
  `Bash {"command":"sudo -n true"}`: sudo is never sandbox-safe, so the
  acceptEdits fast-path simulation returns `ask` and the classifier must run
  (`echo`-class commands are skipped via that fast path — the reason earlier
  probes saw no classifier traffic). The endpoint blackholes any body
  containing the classifier's system-prompt marker (verified absent from all
  main-conversation bodies) via a 3600 s sleep.

  Measured per binary: exactly **two** classifier attempts (small-model slot,
  then fallback model), each blackholed, each waiting **60.000 s**
  (wall-clock `Din` with small transcript → JZe), then fail-closed deny and
  normal completion (≈121 s total):

  | binary | source JZe | wait per attempt | total |
  |---|---|---|---|
  | 218M (base) | 60000 (original) | 60.0 s × 2 | 121.4 s |
  | tF1_src_patched | 99999 | 60.0 s × 2 | 121.5 s |
  | tG_src_jze20k | 20000 | 60.0 s × 2 | 121.4 s |

  If the runtime parsed this module from source, tG would wait ~20 s and tF1
  ~100 s. Three distinct source values, zero difference: the classifier
  module's constants are bound to the **bytecode** region. This reproduces,
  in a controlled A/B, why the 70026 ms fail-closed persisted after the
  original source-only patch.

**Pipeline verdict.** Extract: yes. Patch source: yes. Recompile: no offline
capability, and now moot — the verify stage shows a source patch of this
module cannot go live in this build at all; only a direct patch of the
bytecode constant slots (the reference-anchored `--apply-live` path, currently
REFUSED/AMBIGUOUS on all three builds) or a future build with isolable tables can
change the live behavior.

**Classifier pipeline (measured, 218M source @ 186,102,716 / 187,230,149 /
190,040,428 / 190,042,545):** `DBo` initial decision → if `ask` and mode auto
→ acceptEdits-mode simulation (skip classifier if it would be allowed) →
`Dut(name,input)` safe allowlist → two-stage classifier (stage 1
"Err on the side of blocking…", stage 2 "Review the classification
process…") → `Din(max(estTokens, mainLoopTokens)) = min(z9, JZe +
ceil((e-50000)/50000)·1e4)` wall-clock per attempt → on `wall_clock_timeout`
fallback-model demotion, then `denying with retry guidance (fail closed)`.
`Dut` allowlist resolved from minified constants: Read, Grep, Glob, LSP,
ToolSearch, MCP resource/registry/connector tools, task tools (TaskCreate/
Get/Update/List/Stop/Output, GetTask, TodoWrite, ConnectGitHub), plan-mode
tools, ShowOnboardingRolePicker, plugin-skill safe tools — **Bash, Write and
Edit are NOT allowlisted** (they reach the classifier when the acceptEdits
simulation says `ask`).

**Source-region liveness refinement (supersedes "source is dead" wording).**
tD (whole source zeroed) broke `mcp list` with
`SyntaxError: Invalid character: '\0'` in `/$bunfs/root/chunk-0ecmdp5e.js` —
some chunks ARE parsed from source at runtime; tE (whole bytecode zeroed)
crashed the app — the main app module graph runs from bytecode. Per-module,
not per-region: the mcp chunk is source-parsed, the classifier chunk is
bytecode-executed. A source patch only matters for chunks that are actually
source-parsed at the runtime path in question.

**Environment notes (probe harness).** Settings-file `env` overrides process
env (a probe with only process env silently talked to the configured remote
LLM host, not the fake endpoint) — isolate with `CLAUDE_CONFIG_DIR` pointing
at a minimal settings file. Each Bash-tool invocation runs in its own
PID/network namespace: fake endpoint and probed binary must share ONE shell
(`python3 fake_endpoint.py 8791 &` then run the binary in the same command).
The binary's own sandbox fails to initialize inside the outer sandbox (EPERM
on the srt-mux socket) and then short-circuits Bash before permission logic —
disable it in the probe config.

Full suite green after the addendum: 109/109 GWT cases (no tooling change;
addendum is record-only).

### Addendum (2026-09-13): oracle-verified site binding (218M build)

Reference-anchored `--apply-live` stays REFUSED on all three builds (no u32
reference encoding binds the classifier strings), and the extract/recompile
stage above proved a source patch of the classifier module cannot go live.
The remaining reliable path is **measurement-verified bytecode binding**:
patch candidate int32 slots in turn, time the blackhole probe, and bind the
slot(s) that move the wait. A bound site is then data (offset + recorded
bytes + recorded probe evidence), not a guess — re-applying refuses unless
the binary's size and the recorded bytes still match, so the no-guess
invariant survives.

**Method.** All 179 int32 `60000` sites in the 218M build's live window
[107,000,000, 179,983,360) are 4-byte aligned (real int32 slots, not
byte-pattern accidents). Bisection via `oracle_binding_step2.py` +
`run_probe.sh` (signal model: 121 s = no driver in subset, 81 s = one wait
moved, 41 s = both waits moved; ~2.5 min per probe, port 8791, one at a
time):

| probe | elapsed | verdict |
|---|---|---|
| baseline (218M) | 121.1 s (60.000 s × 2) | two waits |
| all 179 sites → 20000 | 41.5 s (20.000 s × 2) | driver(s) in set |
| sites 0-89 | 41.4 s | driver in first half |
| sites 0-44 | 41.7 s | driver in first half |
| sites 0-22 | 41.2 s | driver in first half |
| sites 0-11 | 121.5 s | driver past index 11 |
| sites 12-17 | 121.5 s | no single wait either |
| single site @ 114,101,412 | 41.4 s (20.000 s × 2: 04:53:20 → 04:53:40 → 04:54:00) | **the driver** |
| singles @ 114,278,176 / 115,308,688 / 115,309,268 / 115,309,924 | 121.2-121.5 s | no effect (the unrolled triple is a red herring) |

**Result.** One site drives both classifier attempts: int32 `60000` at
offset **114,101,412** in the 218M build — the per-attempt wall-clock base (JZe in
`Din(e) = min(z9, JZe + n·1e4)`), compiled into the live bytecode. It is
isolated: the nearest other 60000 is 176,764 B after it and 642,392 B
before; the `120000` at +1,240 B sits in a different duration table (mixed
20000/25000/300000 neighborhood), and no 50000/10000 within ±2 KB.

**Tooling (Phase 4b).** `live_scan.py` gains `VerifiedSite` / `VerifiedEntry`
and the pure functions `load_verified_sites` (strict JSON parsing; a missing
file is an empty registry, malformed content raises), `match_verified_entry`
(unique size match; two entries claiming one size raise), `verified_sites_match`
(build-drift check over every recorded site) and `apply_verified_sites`
(all-or-nothing, length-preserving, refuses on size mismatch / byte drift /
no-op targets; ops carry `oracle-verified site (<role>)` evidence and pass the
existing `static_verify`). `patch_classifier_timeout.py` `run_live` now
consults the registry at `verified_sites.json` (next to the tool) first:
size + bytes match → `run_live_verified` prints the recorded evidence and
bisect lines, applies the sites (default target: digit-preserving max, i.e.
60000 → 99999; overridable with repeatable `--live-value OLD=NEW`), static-verifies,
writes `<binary>.patched`, and runs the `--version` execute gate (a failing
copy is deleted); `--oracle` optionally re-measures on the blackholed
endpoint. Size mismatch or byte drift prints the drift report and falls back
to the reference-anchored path (unchanged); no registry entry means the
existing Phases 1-4 flow. New flags: `--registry PATH`, `--live-value
OLD=NEW` (repeatable). A malformed registry exits 2.

**Status.** The 218M build is now live-patchable:
`patch_classifier_timeout.py <binary> --apply-live` yields
`<binary>.patched` (60000 → 99999 at the verified site; ~100 s per attempt
instead of 60 s, fail-closed behavior intact). The other two builds can be
bound the same way — each needs the same bisection (≈10-11 probes, ~30 min)
and then gets its own registry entry; the tool needs no further changes.

Full suite green after the addendum: 156/156 GWT cases (47 new: registry
parsing incl. JSON-boolean and non-object-evidence edge cases, size matching,
drift detection, all-or-nothing apply, `--live-value` parsing, the
registry-first CLI including the executable fake-binary self-test gate and
the fallback/drift/no-op paths, and the self-test launch cases).

One integration bug was caught by running the tool end-to-end on the 218M build:
`subprocess.run(["name", ...])` with a bare relative name (no slash) is
PATH-resolved by the kernel (`execvpe`), so the `--version` gate failed with
ENOENT even though `<binary>.patched` sat in the current directory (and, in
`run_behavioral_oracle`, a launch failure would have read as a zero wait and
reported a false NO_OP). Both launchers now resolve their paths to absolute
first; regression tests cover the bare-name launch, the missing-file launch
failure, and the end-to-end relative-path CLI run.

## Addendum (2026-09-13): maximum-value binding — ceiling site and INT32_MAX default (218M build)

### Dead-code finding

The classifier source `chunk-468hdq31.js` (binary offsets 186,011,493 –
186,160,526) defines `var JZe=60000,z9=120000,Rin=60000,Pin=4,Iin=0,Min=2000,
Oin=1e4;` and `function Din(e){let n=Math.max(0,Math.ceil((e-50000)/50000));
return Math.min(z9,JZe+n*1e4)}`, but none of those identifiers is used
anywhere else in that chunk (JZe/z9 each occur only in the definition and in
Din; Din occurs once; `wall_clock_timeout` is absent). The chunk's other 25
60000 literals and 7 120000 literals are unrelated (sandbox timeoutMs,
`wsl?60000:20000`, rpcTimeoutMs, the "m ago" formatter, the
`[15000,30000,60000,120000]` backoff table).

So the live driver @114101412 is **not** that source text: the live bytecode
holds its own copy of the two constants, and the binding is defined by
measurement, never by reading the source (no-guess invariant).

### Ceiling discovery (three blackhole probes)

Probe **max130k** (driver → 130000, ceiling untouched): elapsed 241.9 s with
two 120.000 s waits (11:13:42 → 11:15:42 → 11:17:42). Values above 99999
pass 1:1 only up to a 120000 ceiling; 130000 was clamped to 120000.

50 int32 120000 sites exist in the live window; the one nearest the driver is
@114102652 (+1,240 B), matching the source var-table adjacency
(`JZe=60000,z9=120000` sit next to each other).

Probe **capnear** (driver → 130000, @114102652 → 200000): elapsed 262.4 s
with two 130.000 s waits (11:45:32 → 11:47:42 → 11:49:52). The ceiling site
is @114102652: wait = min(ceiling, base), the compiled
`Din(e) = min(z9, JZe + n·1e4)` at n = 0.

Probe **max300k** (driver → 300000, ceiling → 2147483647): elapsed 601.8 s
with two 300.000 s waits (11:52:12 → 11:57:12 → 12:02:12). Values pass 1:1
above the ceiling, and INT32_MAX in the ceiling slot does not break the
binary (rc=0, run completes, execute gate passes).

| probe | driver | ceiling | wait per attempt | elapsed |
|---|---|---|---|---|
| baseline | 60000 | 120000 | 60.000 s × 2 | 121.1 s |
| (earlier) | 20000 | 120000 | 20.000 s × 2 | 41.4 s |
| max130k | 130000 | 120000 | 120.000 s × 2 | 241.9 s |
| capnear | 130000 | 200000 | 130.000 s × 2 | 262.4 s |
| max300k | 300000 | 2147483647 | 300.000 s × 2 | 601.8 s |

### Algorithm change

- `live_scan.INT32_MAX = 2147483647` — the largest value a 4-byte
  little-endian int32 slot holds.
- `VerifiedSite.target` (optional; strict parsing: positive int, bool /
  zero / negative / strings rejected). `load_verified_sites` reads the
  optional `target` field.
- `run_live_verified` default target: `site.target if set, else INT32_MAX`
  (previously: digit-count-preserving max, 60000 → 99999). The digit-count
  rule only constrained source-text rewrites; a compiled int32 slot accepts
  any int32, and a millisecond timeout has no smaller semantic cap —
  measured 1:1 up to 300000, with the ceiling itself patched in the same
  apply so the clamp no longer bites.
- `--live-value OLD=NEW` unchanged: explicit pairs beat the default
  (escape hatch for smaller maxima, e.g. `--live-value 60000=999999
  120000=999999` for a 1000 s cap).
- The 218M build's registry entry now records **two** sites (base @114101412 and
  ceiling @114102652); the default apply raises both to INT32_MAX.

### Semantics of the maximum

INT32_MAX ms ≈ 24.8 days per classifier attempt: a blackholed
(endpoint-unreachable) classifier now hangs effectively forever instead of
failing closed after 60 s. That is the byte-level maximum requested; pick a
smaller maximum with `--live-value` if that is not wanted.

### Artifact and status

`patch_classifier_timeout.py <binary> --apply-live` now writes
`<binary>.patched` with exactly **8 changed bytes** (4 per site, both slots
→ 2147483647 = little-endian `FF FF FF 7F`); static verify and the
`--version` execute gate pass. The intermediate probe binaries
(`<binary>.bind_max130k`, `.bind_capnear`, `.bind_max300k`) were deleted
after the evidence was recorded. `oracle_cap_probe.py` (experiments/recompile)
builds driver+ceiling probe binaries and runs the blackhole probe.

Tests: 160/160 GWT (up from 156; new: registry `target` parsing including
bool/zero/negative/string rejection, INT32_MAX default application over a
multi-site entry, `target` overriding INT32_MAX; the relative-path
end-to-end test now expects INT32_MAX).

## Addendum (2026-09-13): binding the remaining two builds, the generic pipeline, and the max-wait boundary

### Site binding for the 217M and 219M builds (same oracle method as the 218M build)

| build | size (B) | driver (base 60000) | ceiling (120000) | driver isolation |
|---|---|---|---|---|
| 217M | 217,013,744 | @114,164,748 | @114,166,032 (+1,284 B) | all 169 window 60000 sites → 41.1 s; bisection → single site; 60000→20000 gives two 20.000 s waits |
| 219M | 219,651,568 | @118,042,792 | @118,044,040 (+1,248 B) | all 193 window 60000 sites → 41.2 s; bisection → single site; 60000→20000 gives two 20.000 s waits |

Both ceilings confirmed by the cap probe (driver 130000 + ceiling 200000 →
two 130.000 s waits instead of 130000 clamped at 120000). All three builds
share the same shape: driver and ceiling int32s ~1.2–1.3 KB apart in the
back half of the binary, matching the (dead) source var-table adjacency
`JZe=60000,z9=120000`. Full probe evidence (bisect rounds, ceiling, max
probes with endpoint-log timestamps) is recorded in `verified_sites.json`.

### Generic pipeline (works for any version)

The two experiment scripts are version-agnostic; only the binary path and
the bound site offsets change:

- `experiments/recompile/oracle_binding_step2.py --binary <B> --old 60000
  --indices <i> --new 20000 --label L --timeout S` — enumerates
  4-byte-aligned int32 `--old` sites in `[--win-lo, --win-hi)` (default
  `[size//2, size)` — past the native code and string pool, covering the
  live bytecode), drops sites whose 64-byte neighborhood reads as text
  (`text_density ≤ 0.5`; coincidental int32 patterns inside embedded source
  are not code), rewrites the chosen index subset, and runs the blackhole
  probe on the result. `--indices` accepts comma lists, `a-b` ranges, or
  `all`.
- `experiments/recompile/oracle_cap_probe.py --binary <B> --driver <off>
  --caps <offs|all120k> --driver-new V --cap-new W --label L --timeout S`
  — same site machinery, drives the bound site to `V` above the suspected
  cap while raising the cap candidates to `W`; waits that follow `V`
  identify the ceiling site.

Recipe for a new version: bind the driver (bisect `--indices` halves until
one site moves both waits), bind the ceiling (cap probe at the nearest
120000), probe the max-wait boundary (below), record everything in
`verified_sites.json` with per-site `target`s, then
`patch_classifier_timeout.py <B> --apply-live`.

### Max-wait boundary (the INT32_MAX surprise)

Probe method: 150 s run-timeout on the bound driver (ceiling at INT32_MAX);
rc=124 (killed still waiting) = the value waits; rc=0 in ~1.5–2.5 s = zero
wait, the run completes immediately with the classifier call never blocking
(the blackholed endpoint is never even reached).

217M build driver values (ceiling INT32_MAX):

| value (ms) | result |
|---|---|
| 600,000 / 60,000,000 / 86,400,000 / 300,000,000 / 360,000,000 / 420,000,000 / 425,000,000 | waiting |
| 432,000,000 (= 5 days exactly) / 450,000,000 / 480,000,000 / 500,000,000 / 600,000,000 / 2,147,483,647 | immediate (zero wait) |

218M build driver values: 300,000 → waiting (601.8 s probe); 425,000,000 →
waiting; 2,147,483,647 → waiting. 219M build driver values: 300,000 → waiting
(601.4 s probe); 425,000,000 → waiting; 432,000,000 → waiting;
2,147,483,647 → waiting.

So the wait cap is **build-specific**: the 217M build clamps somewhere in
(425,000,000, 432,000,000) ms — values at or above it produce a *zero*
wait (not a clamped wait), and INT32_MAX on that build is the worst possible
choice — while the 218M/219M builds accept the full INT32_MAX (≈24.8 days).
No int32-overflow mechanism explains the 217M boundary (epoch-ms deadlines
already exceed int32 range; int32-seconds and int32-ms mod-arithmetic
variants are uniform or all-or-nothing, contradicting the partial
boundary); the cap is an unexplained implementation detail of the 217M
wait path, measurement-defined like everything else here.

### Final artifact values and verification

`verified_sites.json` now carries per-site `target`s (the existing
`VerifiedSite.target` mechanism; no code change):

| build | base site → | ceiling site → | wait per attempt | `.patched` probe (150 s timeout) |
|---|---|---|---|---|
| 217M | 425,000,000 (≈4.9 days) | 2,147,483,647 | 4.9 days (measured waiting; above the 217M cap would be 0 s) | rc=124 at 150.4 s — still waiting |
| 218M | 2,147,483,647 (≈24.8 days) | 2,147,483,647 | 24.8 days | rc=124 at 150.5 s — still waiting |
| 219M | 2,147,483,647 (≈24.8 days) | 2,147,483,647 | 24.8 days | rc=124 at 150.4 s — still waiting |

Baseline (unpatched) completes the same probe in ~121–122 s (two 60 s
waits, fail-closed); every patched artifact is still waiting when the
150 s probe timeout kills it — the classifier timeout is really increased,
on all three builds. The 217M build's earlier INT32_MAX artifact (this session's
first `--apply-live`) was re-measured at 2.5 s completion (zero wait) and
replaced at 425,000,000. Each `.patched` is an 8-byte diff (4 bytes per
site) with static verify PASS and the `--version` execute gate PASS;
`--live-value OLD=NEW` remains the escape hatch for smaller caps.

## Addendum (2026-09-13): fully automatic one-liner (`patch.sh` auto-bind) and the 224M build

### Automatic binding (`oracle_bind_auto.py`)

The stepwise scripts above (`oracle_binding_step2.py`, `oracle_cap_probe.py`)
now have a single-entry equivalent:
`experiments/recompile/oracle_bind_auto.py --binary <B>` runs the whole
pipeline in one process, strictly sequential blackhole probes (the fake
endpoint's port is exclusive):

1. **baseline** — the unpatched binary must show the two 60 s waits
   (~121 s, window [100, 140] s) or the binding is refused;
2. **all sites** — every int32 60000 code site in `[size//2, size)` → 20000
   must move both waits (~41 s) or the binding is refused;
3. **bisection** — halve the site set until one site still moves both
   waits; a half that crashes is kept only while the other half measures
   no-effect, any other contradiction refuses;
4. **ceiling** — the nearest int32 120000 sites (default: 5) are tried as
   the wait ceiling (driver 130000 + candidate 200000 → two 130 s waits
   identify it);
5. **boundary** — with the ceiling at INT32_MAX, probe driver values
   (150 s run-timeout: rc=124 = waits, rc=0 in ~2 s = zero wait): if
   INT32_MAX still waits it is the target, otherwise coarse probes plus
   bisection find the largest measured waiting value (the 217M build's
   cap case); the recorded value must still wait on a final probe;
6. **registry** — only then is the entry (key = file name; size-based
   match; per-site `target`s; full probe evidence) written to
   `verified_sites.json`.

Every refusal prints `REFUSED:` with the measured signal and writes
nothing; every temporary `*.bind_*` artifact is removed on exit.
`./patch.sh <binary>` now uses it end-to-end: a build already in the
registry applies directly; an unbound build is bound automatically first
(`--no-auto-bind` refuses it with the manual binding command instead).
`CLASSIFIER_PROBE_SCRIPT` overrides the probe harness (test stubs).
Coverage: `OracleBindAutoTests` (10 cases: uncapped binding, capped
boundary, no-sites refusal, unobservable/contradictory signal refusals,
crashing-subset exclusion, entry preservation, key collision,
already-bound no-op) and `PatchAutoBindTests` (3 end-to-end `patch.sh`
runs against synthetic binaries with a stubbed probe) — suite 183/183.

### The 224M build (223,981,040 B) — bound, patched, verified

Bound by the first real `./patch.sh 2.1.270` run (the fully automatic
path, no manual steps):

| build | size (B) | driver (base 60000) | ceiling (120000) | driver isolation |
|---|---|---|---|---|
| 224M | 223,981,040 | @118,687,664 | @118,688,912 (+1,248 B) | all 182 window 60000 sites → 41.3 s; bisection (10 rounds) → single site; 60000→20000 gives two 20.000 s waits |

The ceiling is the *nearest* 120000 site (first cap probe: 261.4 s = two
130.000 s waits) — same ~1.2–1.3 KB driver/ceiling adjacency and same
source var-table shape as the 217M/218M/219M builds. Max-wait boundary:
INT32_MAX (ceiling at INT32_MAX) still waits at the 150 s probe cap
(rc=124) — **no cap below INT32_MAX observed**, like the 218M/219M builds.

| site | old | target | wait per attempt |
|---|---|---|---|
| @118,687,664 | 60000 | 2,147,483,647 | ≈24.8 days |
| @118,688,912 | 120000 | 2,147,483,647 | clamps at ≈24.8 days |

Verification: baseline 121.0 s (two 60 s waits, fail-closed);
`2.1.270.patched` is an 8-byte diff, static verify PASS, `--version`
execute gate PASS (`2.1.270 (Claude Code)`), and the 150 s verify probe
on the patched artifact is rc=124 at 150.5 s — still waiting. The
original binary is byte-identical after the run (the binder never
modifies its input). `verified_sites.json` now holds 217M/218M/219M/224M,
all four measured by the same oracle, all four artifacts verified waiting.

## Addendum (2026-09-13): symlink resolution and in-place promotion of verified patches

`patch.sh` gained two contract points (tests: 188 cases, all green):

- **Symlink resolution.** A binary path that is a symlink is resolved
  before anything else (`readlink -f`): the oracle binding, the apply, and
  the file rename all use the *real* path and the *target's* file name —
  the registry key, the `.patched`/`.original` names, and the bind
  artifacts are all named after the target, never the link; the symlink
  keeps working and serves the patched binary transparently.
- **In-place promotion on verified success.** When the verify probe
  measures the patched artifact still waiting (rc=124), the original is
  moved to `<name>.original` and the patched binary takes the original's
  name (`.patched` disappears). Backup contract: a pre-existing
  `.original` that *differs* from the current binary is never overwritten
  (the rename is refused, exit 1, the verified `.patched` artifact is kept
  for a manual move); an identical pre-existing `.original` is kept as-is;
  a failed promotion restores the original. `--no-verify` never replaces
  the binary (the patch stays in `.patched` until measured). Re-running
  the patcher on an already-promoted binary is refused by design (the
  recorded site bytes no longer match the promoted content) and the
  refusal names the `.original` backup with the restore command.

Also: `run_probe.sh` keeps its per-label probe state under `$TMPDIR`
(`CLAUDE_PATCHER_PROBE_DIR` overrides the root) instead of a fixed
`/tmp` path — the fixed path ended up read-only under the sandbox once
created, and `$TMPDIR` is writable in both foreground and background
tasks.

## Addendum (2026-09-14): the claude-launch interceptor (`install.sh`)

`install.sh` (repo root, 10 Given-When-Then cases in `InstallWrapperTests`)
installs the launcher that patches a changed claude binary before booting
it:

- **Install.** Records the current `~/.local/bin/claude` link target,
  writes `~/.local/bin/claude-wrapper.sh`, re-points the link at the
  wrapper, and initializes the state file
  `~/.local/share/claude/.last_known_version` with an empty recorded
  hash - so the *first* launch counts as "changed" and patches. A bin
  entry that is a plain file (not a symlink) is refused: the installer
  would have to move the file aside, and the wrapper could not tell the
  file from its own link (an `exec` into itself). Re-running the
  installer over an installed wrapper recovers the real origin from the
  previous state. `--uninstall` restores the recorded link target and
  removes wrapper + state.
- **Wrapper contract.** On every launch: resolve the real binary - the
  newest non-`*.bak` file under `~/.local/share/claude/versions/`
  (one file per version; the native layout keeps *files*, not folders,
  and `*.bak` entries are user backups), falling back to the recorded
  origin; guard: a target that resolves to the wrapper itself aborts
  with a repair hint. Change detection: size+mtime fast check against
  the record; a mismatch is confirmed with sha256 (identical content,
  e.g. a re-download, is re-recorded without patching). On a real
  change the wrapper runs `patch.sh` on the resolved target (never on
  the bin link - that would patch the wrapper - and never `claude` from
  PATH, which would recurse into itself once the link is replaced): a
  successful patch is promoted in place by patch.sh (original ->
  `<name>.original`), a refusal or failure is reported and the current
  binary boots as-is (the wrapper never blocks claude). The current
  content is then recorded, so a failed patch is not retried on every
  launch. `CLAUDE_WRAPPER_NO_PATCH=1` boots without patching *and
  without recording* (a temporary escape, not an acceptance). Finally
  the resolved binary is `exec`ed with all original arguments.
- **Known limitation.** A claude self-update that re-points the bin link
  at a new version overwrites the wrapper link; re-run `install.sh`.

On this machine the wrapper was exercised end-to-end against the fake
layout in the tests; the real install (`~/.local/bin/claude` ->
`versions/2.1.270`, currently the unpatched build recorded in
`verified_sites.json`) is a one-command step the user can trigger at
any time - the first launch then patches the installed binary in place
(registry match, no new binding needed) and boots it. Full suite at this
point: 198/198 (10 of the new cases are the wrapper end-to-end runs).

One-line entry point: `./patch.sh <binary>` runs exactly this sequence —
`patch_classifier_timeout.py <B> --apply-live` (registry-driven, refuses
unbound builds with a pointer to the oracle scripts) followed by the
blackhole verify probe on the `.patched` artifact (rc=124 at the timeout =
VERIFIED, fast clean exit = NOT VERIFIED). Options: `--baseline` (also probe
the unpatched binary), `--no-verify`, `--timeout N`, `--registry PATH`.
Covered by 6 Given-When-Then cases in `test_classifier_tools.py`
(`PatchScriptOneLineTests`, including both verify outcomes via a synthetic
probe binary); full suite 166/166.

## Addendum (2026-09-15): parallel probes and early verification (`--fast-verify`)

The wall time of the pipeline is probe waits, not file I/O (a 217 MB
binary copies and patches in ~0.2 s; every blackhole probe costs its wait
at minimum). Two changes attack that, both measurement-exact.

- **Concurrent probes are safe because each owns its state.**
  `run_probe.sh` now picks a random endpoint port per invocation
  (`10000 + RANDOM % 40000`) in addition to its per-label working
  directory, so independent probes never share the fake endpoint or
  collide on a port. The probe scripts in the repo (and the stubs the
  tests inject) carry no other shared state - append-only logs at most -
  so running several concurrently is a no-op semantically.
- **`oracle_bind_auto.py` runs independent probe sets concurrently**
  (a `run_jobs` helper: `ThreadPoolExecutor`, results collected in job
  order, artifacts prepared sequentially so a refused artifact fails
  before any probe is spent):
  - baseline and all-site probes in one round (was 2 serial rounds);
  - bisection rounds probe BOTH halves concurrently - the decision table
    is unchanged, but both halves are now always measured and logged
    (the old code stopped at the first effective half);
  - the ceiling phase probes ALL nearest cap candidates concurrently and
    still evaluates them in proximity order, breaking at the first
    ceiling (one probe round instead of up to five serial rounds; ~17
    minutes saved on builds with many 120000 sites);
  - the boundary phase probes ALL coarse values concurrently (one round
    instead of up to five, ~10 minutes saved on capped builds), then the
    sequential bisection as before. NEW refusal: if the coarse verdicts
    are non-monotone (some larger value waits while a smaller one
    returns immediately) the pipeline refuses with `BindRefused`
    instead of the old silent skip - strictly safer, no new guessing.
  Boundary bisection stays sequential: each step's bracket depends on
  the previous result, and on capped builds it dominates (~28 steps x up
  to 150 s). Expected wall time: ~12 min for uncapped builds (was
  ~20-60 min), ~50 min for capped builds (was ~2 h).
- **`patch.sh --baseline` runs the baseline probe concurrently with the
  verify probe** (each owns port + dir): 300 s -> ~155 s.
- **Opt-in early verification: `./patch.sh <binary> --fast-verify [N]`.**
  `run_probe.sh` gained an optional 4th argument, a check point in
  seconds. At N seconds, if the run is still alive and the endpoint log
  holds exactly ONE blackholed classifier attempt, the probe prints
  `label early still_waiting=1 elapsed=Ns blackholed=N` and kills the
  run. A single blackholed attempt is only possible while the first
  wait is still running (an unpatched build is already on attempt two
  by ~61.5 s), so the patch verifies there without waiting out the
  150 s cap: common path 155 s -> ~75 s. The trust assumption is the
  same one the 150 s cap already rests on (the blackhole probe is
  trusted evidence that a wait is in progress); N defaults to 70 s with
  a 65 s floor (`CLAUDE_PATCHER_FAST_FLOOR` overrides - the floor
  guarantees the discriminator: 65 s outlives the unpatched ~60 s
  per-attempt wait plus startup). A probe script without 4th-argument
  support emits no early line and the usual cap result decides - the
  flag degrades gracefully instead of failing. `--fast-verify`
  combined with `--no-verify` is a usage error (exit 2).
- **`run_probe.sh` early-check mode keeps the contract exact.** A run
  that finishes before the check point is waited for and reported with
  its true end time (a watcher subshell records the moment the run
  actually ends; `alive()` distinguishes a live process from a zombie
  - `kill -0` cannot: bash reaps background jobs only between its
  commands, so a finished run may still look alive to a plain
  `kill -0` check and would have produced a false early verdict).

Covered by 14 new Given-When-Then cases (212 total, all green):
`RunProbeScriptTests` (4: distinct ports under concurrency; the early
verdict fires exactly once per single blackholed attempt and kills the
run; two attempts stay silent; a run that finished before the check
point is reported at its true end), `PatchScriptParallelTests` (5:
baseline+verify overlap measured via stub probe timestamps; fast-verify
accepts the early evidence and promotes, refuses without it, degrades
to the full cap for probe scripts without support, and rejects check
points below the floor), `OracleBindParallelTests` (5: tracked stub
probes with an active-set sampler prove which probe sets actually run
concurrently - baseline+all, bisection halves, cap candidates, coarse
values; results keep their job order; the non-monotone boundary signal
refuses instead of binding).

## Addendum (2026-09-15, second): no in-place promotion; the claude-patched interceptor link

Two contract changes retire the in-place-rename and link-replacement
designs introduced above:

- **No in-place promotion (patch.sh).** A verified success no longer
  renames anything: the original binary is never moved or modified, and
  the patch stays in the `<name>.patched` artifact next to it (run the
  artifact to use the patched build). Consequences: re-running the
  patcher on the same binary just regenerates the artifact (the original
  never changes, so the recorded bytes keep matching); a refused apply
  (the recorded binding no longer matches the file's bytes) leaves a
  pre-existing `.patched` untouched and says so (it may predate the
  current bytes); `--no-verify` is unchanged (unmeasured artifact). The
  2026-09-13 in-place promotion contract (original -> `<name>.original`,
  foreign-backup refusal, restore hint) is retired; `.original` is no
  longer produced or consulted.
- **claude-patched link (install.sh).** The installer no longer re-points
  the native `~/.local/bin/claude` link: it creates
  `~/.local/bin/claude-patched` -> `claude-wrapper.sh` and leaves `claude`
  exactly as claude's own updater leaves it - a self-update re-points
  `claude` and cannot break the interceptor, so the 2026-09-14 known
  limitation (re-run the installer after every self-update) is gone, and
  the installer's origin-recovery-from-previous-state path is
  unnecessary. Requirements: `claude` may be a symlink or a plain file
  (the installer never touches it, it only reads where it points - the
  old plain-file refusal existed only because the installer used to
  replace the link); a pre-existing `claude-patched` that is a PLAIN FILE
  is refused (no clobbering user files), a pre-existing `claude-patched`
  symlink (a previous install) is replaced. `--uninstall` removes
  `claude-patched` + wrapper + state; there is no link to restore.
- **The wrapper execs the artifact.** Since patch.sh no longer replaces
  the binary, the wrapper boots the patch itself: after a successful
  patcher run it execs `<binary>.patched` when present (falling back to
  the unpatched binary), and `CLAUDE_WRAPPER_NO_PATCH=1` boots the
  unpatched binary even when the artifact exists. Two supporting rules:
  the versions-dir scan skips `*.patched` entries like `*.bak` (an
  artifact is never the target binary - an artifact written by the last
  patch carries a newer mtime than every real binary and would otherwise
  win the `ls -t` newest-file scan); and a FAILED patcher run deletes
  `<target>.patched` before booting the raw binary - a stale artifact
  built from the previous binary's content must never be booted (the
  change-detection record guarantees the wrapper boots an artifact only
  while the recorded content matches what it was built from).
- **Tests.** The stub patcher in `InstallWrapperTests` now emulates the
  real artifact contract (a `<binary>.patched` with a DISTINCT marker,
  so a boot of the artifact is observable); the suite gains the
  scan-filter case (an artifact with the newest mtime in the versions
  dir is never the target), the NO_PATCH-boots-raw-despite-artifact case,
  the plain-file-claude-allowed case, the plain-file-claude-patched-refusal
  case, and the refusal-leaves-stale-artifact-untouched cases; the
  promotion-era cases (identical/foreign `.original`, in-place restore
  hint) are replaced by the regeneration/refusal cases above.

## Addendum (2026-09-15, third): the wrapper lives in the repo; the link is claude-patched

- **claude-wrapper.sh (repo file).** The launcher is no longer generated
  by an install.sh heredoc: the wrapper body lives in
  `claude-wrapper.sh` at the repo root (the patcher path stays a
  `__PATCHER__` placeholder), and the installer copies it to
  `~/.local/bin/claude-wrapper.sh` with the patcher path baked in (the
  installer refuses to run if the repo file is missing). The installed
  contract is byte-identical to before - same state file, same guards,
  same artifact boot - only the wrapper's origin changed.
- **claude-patched (rename).** The interceptor link is renamed
  `~/.local/bin/claude-local` to `~/.local/bin/claude-patched` (the name
  now says what it does: it boots the `.patched` artifact). `--uninstall`
  removes the new name; a home upgraded from the old naming keeps its
  stale `claude-local` link (it still works - same wrapper - but is not
  managed or removed by the installer; remove it manually).

## Addendum (2026-09-16): CI-owned registry recording; jq-first lookup with repo download

Patching and recording are decoupled: the *recording* cost (the 20-60 min
oracle probe) is paid once, on a CI runner, when a new Claude Code build
ships; users' `patch.sh` is a *consumer* that only looks the record up and
applies the patch. Nothing new is guessed anywhere - the recorder is the
same no-guess binder, and the lookup is the same unique-size match.

- **CI records (ci_bind_new_version.py, new, repo root).** Wraps the
  existing `oracle_bind_auto.bind()` (imported, unchanged) behind a CI
  CLI: `--binary PATH` binds a local build directly (the tested, network-
  free path); `--version V --download-url URL` (or `CLAUDE_BINARY_URL`)
  first downloads the build to a workdir file NAMED after the version -
  the registry key is the binary's basename, so the record reads as the
  version. The download is isolated in one swappable `download_version()`
  (the one open detail: how a given version is distributed); a failed
  fetch, a missing binary, or no source at all is a clean exit-2 refusal.
  An already-bound build at the same size is a no-op ("already bound",
  byte-identical registry); a key taken by a different-size build, or a
  build with no measurable sites, is refused with no registry write.
- **The workflow (.github/workflows/bind-new-version.yml).** Manual only
  (`workflow_dispatch`, inputs: version + binary URL), `ubuntu-latest`,
  180 min timeout (the probe wall time plus headroom), `contents: write`;
  checkout → `ci_bind_new_version.py --version … --download-url …` →
  commit + push `verified_sites.json` if and only if it changed. If the
  default branch is push-protected, the fallback is a PR with the record
  (noted in the file).
- **patch.sh lookup is jq-first (registry_lookup, new).** The build is
  matched to the registry by size without reading the binary (`stat -c%s`):
  with `jq` present, a jq program returns the UNIQUE entry whose `size`
  equals the binary's size, and stays empty on no match, several matches
  (the false-positive guard), a malformed registry, or a missing file -
  the exact contract of `live_scan.match_verified_entry`. Without `jq` the
  same lookup falls back to the Python matcher
  (`live_scan.load_verified_sites` + size equality), so the script never
  requires `jq` on the user's machine. (The old `registry_match()` read
  the whole binary through Python just to get its size; that is gone.)
- **Local registry first, then the repo copy.** Resolution order: local
  `verified_sites.json` → (only for the DEFAULT registry, and only on a
  local miss) download `verified_sites.json` from the repository
  (`CLAUDE_PATCHER_REGISTRY_URL` when set - a URL or a local file path -
  else the raw URL derived from the `origin` remote's default branch) →
  apply from whichever file produced the match. A download failure falls
  back to the local file only; the apply is then run with `--registry
  <that file>` so the downloaded record is exactly what is applied and
  re-verified. An explicit `--registry PATH` is honored exactly and never
  downloads. The download is a no-op on the fast path (a build already
  bound locally), so existing use stays fully offline.
- **Auto-bind stays the default.** A build bound nowhere still probes
  locally, as before (`--no-auto-bind` refuses): the repo download just
  lets a CI-recorded build apply *without* the probe.
- **Tests (233 total, all green).** New Given-When-Then classes:
  `RegistryLookupTests` (8: jq unique/no-match/multiple/malformed/missing
  + the Python fallback without jq on the same three cases),
  `RegistryDownloadTests` (3: local-miss + repo-hit applies from the
  downloaded copy with no local probe; a failed download refuses with
  `--no-auto-bind`; an explicit `--registry` never downloads),
  `CiBindTests` (8: bind records an entry keyed by basename with measured
  int32-max targets; re-run is a byte-identical "already bound" no-op; the
  download path records under the version name; missing binary, no build
  source, and a failed download all exit 2 without a write; a key taken by
  a different-size build and a site-less build are refused with no write).

## Addendum (2026-09-16, second): bisection cancel-on-decision (parallelizing the halves made bisection slower)

The 2026-09-15 parallelization of bisection rounds was a regression: a
concurrent round costs max(half A, half B), and the no-effect half
(~121 s) dominated the effective half (~41 s) - 7 bisection rounds went
from ~2.5 min back to ~8.5 min, and every round now logged two
measurements where the old code stopped at the decisive one. The fix is
selective cancellation, not serialization:

- **`oracle_bind_auto.py` cancels the half that is no longer decisive
  (`decided_round`, new).** Both halves still start concurrently, but as
  soon as the first-completed half's verdict decides the round, the other
  half's probe is canceled. Only an 'effective' verdict is decisive (the
  measured model has exactly one effective half); a 'no_effect' or
  crashed verdict is NOT decisive, so that half is still waited out and
  its result stays a measurement. The decision table is the sequential
  one, unchanged; a half canceled before it finished is (None, None) -
  not a measurement - and its bisect log line reads "canceled (not
  measured)" instead of a time. A round now costs the effective half's
  ~41 s, not the no-effect half's ~121 s (7 rounds: ~8.5 min -> ~2.5 min).
- **`probe_via_script` takes an optional cancel event.** The probe runs
  under `Popen` (was `subprocess.run`); a daemon watcher TERMs the script
  when the event is set. A run that finished before the TERM still yields
  its result line (a real measurement, the race is harmless); a run
  killed by it produces no line.
- **`run_probe.sh` handles SIGTERM (cancel contract, new).** The run is
  now always a background job (never a foreground command, so a trapped
  signal fires promptly instead of after the run's whole timeout), and a
  TERM trap stops the run's whole process group and the endpoint, exits
  143, and prints NO result line - a canceled run is not a measurement.
  A run that already finished clears the trap and prints its result line
  as usual. (Before this, a SIGTERM killed the script and orphaned the
  run and its endpoint.) The early-check ($4) path is unchanged.
- **Wall-time correction.** The "~12 min" expected for INT32_MAX-waiting
  builds in the 2026-09-15 addendum was an undercount (it missed the
  ceiling probe's ~261 s); the honest number with cancel-on-decision is
  ~17 min (baseline+all 121 s, 7 bisection rounds x 41 s, single 41 s,
  ceiling 261 s, bmax+final 300 s). Capped builds stay ~50 min (the
  sequential boundary bisection is unchanged by this addendum).

Covered by 5 new Given-When-Then cases (the suite is 234 total, all green
- see the 2026-09-16 third addendum for the test delta):
`RunProbeScriptTests` (+3: a SIGTERM before the run decides exits 143
with no result line and no orphaned run or endpoint, with or without an
early-check point; the binder's cancel event stops the real harness
promptly through `probe_via_script` and leaves no process behind),
`OracleBindParallelTests` (+2: a tracked stub with per-label wall times
proves the no-effect half is canceled, unmeasured, and absent from the
recorded evidence while the round takes the effective half's time; and
that a fast no-effect half is NOT canceled when its verdict does not
decide - both halves stay fully measured).

## Addendum (2026-09-16, third): a missing .patched artifact forces a re-patch

The wrapper's change detection now treats a MISSING <target>.patched
artifact as "changed", even when the recorded content still matches the
binary (the `|| [ ! -f "$TARGET.patched" ]` condition in claude-wrapper.sh):

- **User-deleted artifacts are regenerated.** If the user deletes the
  .patched artifact, the next claude-patched launch re-runs the patcher
  on the unchanged binary and boots the regenerated artifact. Before, the
  recorded content still matched, so the wrapper booted the UNPATCHED
  binary forever - the interceptor silently stopped doing its job.
- **Failing patches are retried.** A patcher that exits non-zero leaves no
  artifact, so every subsequent launch retries it (the old contract was
  "record so the next launch does not retry the failing patch"). This is
  consistent with the wrapper's never-block guarantee: claude always boots
  (raw-binary fallback), but a persistently failing patcher is run on
  EVERY launch - for an unbound build that is a 20-60 min bind attempt
  per launch before the raw boot.
- **Identical-content re-downloads get their own artifact.** A new version
  file with byte-identical content (hash matches the record, new
  name/mtime) is now patched into its own artifact instead of being
  recorded-only and booted raw. The hash fast path (record only, no
  patcher) stays live only while the target's artifact exists.

Tests: the two stale `InstallWrapperTests` cases now encode the new
contract (a failing patch is retried on every launch while claude still
boots raw; the identical-content case exercises the in-place replacement
with the artifact present - the hash fast path - since a new file with
identical content now behaves like a new version, which
`test_new_version_is_detected_and_patched` already covers); a new
`test_removed_artifact_is_regenerated` case covers the motivating case.
Redundant cases removed in the same pass (overlapping tested feature):
`TestRunSelfTest` (3 cases - the success, nonzero-exit, and launch-failure
branches of the SAME `pcp.run_self_test` are covered by
`TestSelfTestLaunch`), `test_apply_live_explicit_missing_registry_falls_back`
(the missing-file refusal is covered by the default-missing case; the
explicit-flag plumbing is proven by the success cases), and
`test_static_verify_accepts_verified_ops` (its static-verify happy path is
embedded in `test_int32_max_target_applies`). Suite: 234 Given-When-Then
cases, all green (235 after the 2026-09-17 addendum below).

## Addendum (2026-09-17): suite speedup (79.7 s -> ~34 s) without contract change

The suite was ~80 s wall, dominated by subprocess-heavy probe tests, not
by logic. Three script-level changes plus test-timing tightening remove
~46 s; every assertion that survived is unchanged (the same branches,
the same refusals, the same cancel semantics).

- **run_probe.sh: the check-point wait is interruptible.** A plain
  foreground `sleep "$CHECK_AT"` defers a trapped SIGTERM until the sleep
  ENDS (bash runs trapped signals only between foreground commands), so a
  cancel arriving while the script waited for the check point was honored
  only at the check point (~10 s later in the test; the binder's
  cancel-on-decision could wait out whole check points for nothing). The
  sleep now runs in the background under `wait` (interruptible, like the
  run wait): a cancel during the wait exits 143 immediately. `test_term_before_the_check_point_cancels_too`
  now pins that (wall < 5 s; it took ~11 s before).
- **run_probe.sh: the check-point sleep is killed on cancel.** It
  inherits the script's stdout; with captured stdout (the binder's
  `probe_via_script`, the tests) an orphaned check-point sleep kept the
  pipe open until it finished, so a CANCELED probe returned to the caller
  only at the check point anyway. cancel_run now kills it (as it already
  did the run and the endpoint).
- **run_probe.sh: endpoint readiness instead of a fixed 1 s grace.** The
  old `sleep 1` after starting the fake endpoint is now a poll of the
  endpoint's "listening" log line (capped at 5 s: a broken endpoint
  cannot stall the probe - the run then just fails to connect, as
  before). Saves ~0.6 s per probe; the probe contract (own port, own
  dir, result line) is unchanged.
- **patch.sh: `CLAUDE_PATCHER_TIMEOUT_FLOOR` (default 15).** The
  `--timeout` floor is now an env var, mirroring the existing
  CLAUDE_PATCHER_FAST_FLOOR test-hook pattern; default behavior is
  unchanged (a cap below 15 s is refused: it cannot observe a wait).
  The verify test that paid the 15 s cap (the single slowest test in the
  suite, 16.1 s) now runs at a 3 s cap (its binary sleeps 30 s, so the
  rc=124 property is identical).
- **Tests: fixed sleeps become condition polls.** The three
  signal/cancel tests burned a fixed `time.sleep(2)` to "let the run
  start"; they now poll the `bin_pid` file the probe binaries already
  write, so the signal lands exactly while the run is inside its wait
  (a stronger precondition, no fixed seconds).
- **Tests: caps/check points shortened where the semantics allow.**
  silent-two-attempts cap 6 s -> 3 s (still past the 2 s check),
  noop check 5 s -> 3 s (the run still finishes before it), the
  PatchScriptParallelTests stub delays 4 s -> 2 s (overlap bound 2.5 ->
  1.5 s; the sequential-vs-parallel wall bound 7.5 -> 3.5 s keeps the
  assertion discriminating), fast-verify check points 2 s -> 1 s (the
  stubs sleep the check point, the floor hook already allows it), the
  degrades stub 3 s -> 2 s. `_tracked_probe` now samples the active set
  at every poll tick, not only at probe start, so the coarse-boundary
  test may emulate each sequential bisection round at 0.1 s instead of
  0.2 s (~27 rounds between the coarse values) while the
  ">=3 concurrent" observation stays robust. New case
  `test_timeout_floor_is_a_test_hook` covers the new env var (accept
  at the lowered floor, refuse below it).

Suite: 235 Given-When-Then cases, all green; wall 79.7 s -> ~34 s
(2.3x), stable across runs. The real binder's 17-50 min wall is the
measured probes themselves (each is a real blackhole run), not test
overhead - it cannot be reduced without changing what is measured.

## Addendum (2026-09-17, second): release-watch worker — feed -> dispatch, and the tarball CI contract

The registry grew only when a human noticed a new build: `patch.sh`
auto-binds an unbound build, but that costs each user the 20-60 min probe
that CI exists to pay once. This closes the gap with a Cloudflare Worker
(`worker/release-watch.js`, plain JS, no build step; `wrangler.toml`) and
the tarball half of the CI contract.

- **The worker (cron every 15 min).** Each tick: read
  `github.com/anthropics/claude-code/releases.atom` (the feed lists
  releases newest first; the first entry's title, v-stripped, must be a
  semver - a feed without a parseable version is NOT dispatched); resolve
  the binary URL from a data template (`BINARY_URL_TEMPLATE`, default: the
  release's `claude-linux-x64.tar.gz` asset under the `v<version>` tag);
  HEAD-check the asset (a 404 is NOT dispatched - the asset may still be
  uploading, and nothing is recorded, so the next tick rechecks from
  scratch); then POST `POST /repos/{GITHUB_REPO}/dispatches` with
  `{ref: BRANCH, workflow: bind-new-version.yml, inputs: {version,
  binary_url}}`. The rest is the runner's (the existing job downloads,
  binds no-guess, commits).
- **The no-guess state machine.** One KV record `{version, binaryUrl,
  dispatched, at}`, written after the dispatch answer: `dispatched: true`
  ends the watch for that version (the workflow is idempotent - a rebind
  is a no-op and the commit step is a no-op, so a duplicate dispatch
  cannot double-record); `dispatched: false` (HTTP error or network error
  from the API) retries the dispatch on the next tick until GitHub
  answers; feed errors, asset-check errors, and no-asset states write
  nothing. A build that the binder later REFUSES is therefore dispatched
  exactly once, and the refusal (not a dispatch failure) is what stops it.
- **Manual routes.** `GET /status` (feed version + state + config),
  `POST /run[?force=1]` (run a tick now; force re-dispatches a recorded
  version, e.g. after a token fix), `POST /reset` (clear state) - the two
  mutating routes honor an optional `SECRET` bearer token; the cron path
  needs none.
- **The tarball CI contract.** The release asset is a tarball, not a
  binary: `claude-linux-x64.tar.gz` holds exactly one member, `claude`
  (verified on 2.1.274: 230,580,536 B, ELF, mode 0755 after extraction).
  `ci_bind_new_version.download_version()` now unpacks a gzip answer
  under a no-guess member rule (`extract_binary`): a regular file named
  `claude` wins (both the github release tarballs and the npm platform
  tarballs carry exactly one - the npm layout `package/claude` also
  works), else exactly one regular file, else refused (ValueError, exit 2,
  registry untouched); extraction goes through `tarfile ...
  filter="data"` (no path escape, no special modes). A non-archive answer
  is the binary itself, as before (raw URLs keep working).
- **Secrets/refs.** `GITHUB_TOKEN` needs the `workflow` scope (dispatches
  endpoint); `BRANCH` (default `develop`, the repo default branch) must
  carry the workflow file.

Suite: 241 Given-When-Then cases green (the worker's 27 node cases run
from the python suite; the tarball download path has five new cases
covering release/npm shapes, the single-member rule, the ambiguous
refusal, and the corrupt-archive refusal). Worker verified end-to-end
against the live feed and the 2.1.274 asset (feed -> `2.1.274` -> asset
HEAD 200).

## Addendum (2026-09-17, third): the six Python tools moved from the repo root to `tools/`

The six root-level Python tools (`classifier_scan.py`,
`find_classifier_timeouts.py`, `verify_classifier_patch.py`,
`patch_classifier_timeout.py`, `live_scan.py`, `ci_bind_new_version.py`)
now live in `tools/`; the entry points (`patch.sh`, `install.sh`,
`claude-wrapper.sh`), `verified_sites.json`, and the test suite stay at
the root, and `experiments/recompile/` is unchanged. Pure layout - no
behavior change; the suite (241 cases, including the end-to-end
`patch.sh` and CI-recorder runs) is green after the move.

- **Path fixes (all repo-root-relative, resolved one level up from
  `tools/`):** `ci_bind_new_version.py` now derives `_ROOT` from its own
  directory and uses it for the `oracle_bind_auto` import path, the
  default `verified_sites.json`, and the default `run_probe.sh`;
  `patch_classifier_timeout.default_registry_path()` points at the repo
  root (one `dirname` up). `patch.sh` invokes
  `tools/patch_classifier_timeout.py` and sets `PYTHONPATH="$ROOT/tools"`
  for its no-jq registry fallback; the workflow calls
  `python3 tools/ci_bind_new_version.py`. Cross-tool imports
  (`classifier_scan`, `live_scan`) need no change - Python puts the
  script's own directory first on `sys.path`, so `tools/` is self-sufficient.
- **Consumer updates:** the test suite inserts `tools/` on `sys.path`
  (and `_CI_SCRIPT` points at `tools/ci_bind_new_version.py`); the
  README file list, the workflow comment, and the CLI hint strings
  (`python3 tools/verify_classifier_patch.py`,
  `python3 tools/patch_classifier_timeout.py`) read the new paths.
  `install.sh` / `claude-wrapper.sh` are untouched (they bake `patch.sh`,
  which carries the new internal path).

## Addendum (2026-09-17, fourth): `experiments/recompile` became `tools/binder`, and the last absolute path is gone

The binding pipeline is no longer an experiment: `oracle_bind_auto` is
the production auto-bind behind `patch.sh` and the CI recorder, so the
`experiments/recompile/` scripts (binder pipeline, probe oracle
`run_probe.sh` + `fake_endpoint.py`, the `classifier_marker.txt`
source slice, `decompress_scan.py`) moved to `tools/binder/` next to
their consumers; `experiments/` is gone (it held nothing else). Pure
layout - no behavior change; the suite (241 cases) is green after the
move.

- **Why no script changes were needed.** Every binder path was already
  `__file__`-relative, and `tools/binder/` sits at the same depth as
  `experiments/recompile/` did (two levels under the root), so
  `oracle_bind_auto.root()` (two `dirname`s up), the step2/cap
  `root()` (three), `fake_endpoint`'s `HERE`, and `decompress_scan`'s
  `OUTDIR` all resolve exactly as before. What moved with the path is
  the *references*: `patch.sh` sets `REC="$ROOT/tools/binder"`;
  `ci_bind_new_version` inserts `tools/binder` on `sys.path` and
  defaults `--probe` to `tools/binder/run_probe.sh`; the test suite's
  `_ORACLE_DIR` and `sys.path` insert point at `tools/binder`.
- **The one absolute path is programmatic now.** `run_probe.sh` had the
  only machine-specific path in the repo (`ROOT=/home/mk/github/
  auto-mode-classifier-patcher`, used solely to find its two sibling
  files); it now resolves `HERE` from its own location
  (`dirname` of `${BASH_SOURCE[0]}`) and copies `fake_endpoint.py` +
  `classifier_marker.txt` from there - no root at all.
- **Registry records untouched.** Existing `verified_sites.json`
  entries keep their recorded `harness` string (it names the path the
  probes ran under at binding time; matching is by size + recorded
  bytes, never by that string). New bindings record
  `tools/binder/run_probe.sh + fake_endpoint.py`.

## Addendum (2026-09-18): the wrapper downloads the registry into its own folder; routing by file existence

The installed wrapper is a COPY of `claude-wrapper.sh` living in
`~/.local/bin/`, outside the checkout - while the checkout's
`verified_sites.json` (patch.sh's default registry) is only as current
as the last `git pull` on that machine. On 2026-09-17 the 2.1.274
binary landed on a machine whose checkout had not yet received the
CI-recorded 2.1.274 binding (the commit reached the checkout hours
later), so the launch fell through to the 20-60 min local oracle bind
instead of applying the CI record. Decision: the wrapper owns a current
registry copy in its own folder and points the patcher at it when
present.

- **The wrapper downloads, not git (explicit decision).** `git pull`
  was rejected: the installed wrapper lives outside the checkout (which
  may be stale, detached, or absent), and pulling the whole branch on a
  patching launch is broader than needed. Instead, before the patcher
  runs on a CHANGED binary (patching path only - an unchanged launch
  never touches the network), the wrapper downloads the latest
  `verified_sites.json` into the wrapper's own folder (the folder the
  script lives in; `~/.local/bin/` for the installed copy). The source
  is `CLAUDE_PATCHER_REGISTRY_URL` (a URL or a local file path - the
  test/offline hook, the same convention patch.sh already uses) else
  the raw URL derived from the patcher checkout's `origin` remote
  (the same derivation as patch.sh's `registry_remote_url`). The
  transfer is validated (non-empty; a JSON object when jq is present)
  and replaced ATOMICALLY (`mv` from a same-folder hidden temp file): a
  failed download or a corrupt transfer leaves any existing file
  untouched. Byte-identical content is reported as "up to date" instead
  of a refresh.
- **Routing is by file existence.** When `verified_sites.json` exists
  next to the wrapper, the patcher is invoked with `--registry <that
  file>` (patch.sh's explicit-registry contract: apply from that file;
  a miss auto-binds INTO it, so a local bind record stays
  machine-local - CI records are the pushed ones). When it does not
  exist (offline with no earlier download), the patcher runs with its
  DEFAULT registry (the checkout's `verified_sites.json`) and its
  unchanged chain: local lookup, its own remote-download fallback,
  local auto-bind. The download never blocks a launch: every failure
  degrades to the local chain (the unpatched binary still boots).
- **A wrapper run from inside the checkout (REPO_MODE).** When the
  wrapper script's folder IS the patcher checkout's folder (the user
  runs the repo copy of `claude-wrapper.sh` directly), the file next
  to it is the checkout's own tracked registry: no download (it would
  replace a tracked file and dirty the working tree) and no
  `--registry` (the patcher's default registry is exactly that file).
- **Escape hatches and cleanup.** `CLAUDE_WRAPPER_NO_SYNC=1` skips the
  download (an existing file is still used by the routing above;
  without one, repository mode). `install.sh --uninstall` now removes
  the downloaded registry from `~/.local/bin/` as well.
- **Worker test fix (pre-existing red, unrelated to the change).**
  `worker/test_release_watch.mjs` still asserted the pre-1cd94f5
  dispatch body (`ref`/`workflow`/`inputs`); the worker sends the
  `repository_dispatch` event `kick-off-patcher` with
  `client_payload {version, binary_url}` (the workflow listens on both
  `workflow_dispatch` and `repository_dispatch`), and the test now
  asserts that body.
- **The raw-URL derivation bug (found while smoke-testing, fixed in BOTH
  scripts).** The first real-network smoke test 404'd: `git symbolic-ref
  --short refs/remotes/origin/HEAD` yields `origin/develop`, not
  `develop`, so the derived URL became
  `…/claude-code-patcher/origin/develop/verified_sites.json`. This bug
  predated the change (it lived in patch.sh's
  `registry_remote_url`, which no test exercised - the suite always used
  the `CLAUDE_PATCHER_REGISTRY_URL` hook), and it is very likely why the
  checkout's remote-download fallback never worked on this machine
  (always 404 -> local bind). Fix in `claude-wrapper.sh registry_url`
  AND `patch.sh registry_remote_url`: read the FULL ref
  (`git symbolic-ref refs/remotes/origin/HEAD`) and strip
  `refs/remotes/origin/` (fallback `develop` when the ref is absent).
- **Tests (253 total, green).** New `WrapperRegistryTests` (9, all
  Given-When-Then): first launch downloads the registry into the
  wrapper folder and invokes the patcher with `--registry <it>` (and a
  re-patch refreshes it to a newer remote copy); failed download with
  no file - repository-mode invocation, no file created; failed
  download with an existing file - the file is kept and still passed;
  `CLAUDE_WRAPPER_NO_SYNC` with a file (download skipped, file still
  passed) and without (repository mode); an unchanged binary never
  attempts a download; unchanged remote content reports "up to date";
  a wrapper run from inside the checkout downloads nothing, passes no
  `--registry`, and leaves the tracked file byte-identical; a corrupt
  (non-object) transfer is rejected with no file written. New
  `RegistryDerivedUrlTests` (3): with a curl stand-in on the PATH (the
  URL is logged, a fixed document is served - offline), the wrapper
  derives `…/<repo>/<default-branch>/verified_sites.json` from the
  checkout's git config (the `--short` form would 404; no `origin/`
  prefix in the logged URL) and passes the downloaded file via
  `--registry`; the same derivation in `patch.sh` (the real script run
  from a fake checkout whose origin is a github https remote, local
  miss, served registry hits, apply then refused by the no-guess gate
  on the zero-filled binary); and one real-network test (skipped when
  offline) in which the wrapper fetches THIS repository's registry over
  the network - the first run fetched a registry NEWER than the local
  checkout (CI had bound 2.1.275 in `f151df0` since the clone),
  exactly the stale-checkout scenario this feature exists for.

## Addendum (2026-09-18, second): two versions at byte-identical size; name+size lookup disambiguates

On 2026-09-18 the 2.1.276 build shipped at exactly the same file size as
2.1.275 (both 232,059,192 B; the two CI records even agree on every site
offset and value - the classifier region did not move between the two
releases). The size-only lookup contract - "the build matches the UNIQUE
registry entry whose recorded size equals the binary's size" - then failed
to resolve 2.1.276 at all:

- `patch.sh`'s `registry_lookup` saw TWO entries at 232,059,192 and produced
  no match, so it concluded the build was unbound and ran the automatic
  oracle bind.
- `oracle_bind_auto.bind()` is keyed by the binary's basename (the native
  layout names its files after the version): it found the existing
  `2.1.276` entry at the same size, printed "already bound ... nothing to
  do", and exited 0.
- The post-bind re-lookup was still ambiguous, so patch.sh died with
  `error: binding reported success but the registry has no matching entry`
  - and the wrapper, finding no `.patched` artifact, re-ran the same
  failing chain on every `claude-patched` launch. The second consumer had
  the same hole: `live_scan.match_verified_entry` (used by
  `patch_classifier_timeout.py --apply-live`) would have raised
  "multiple entries claim size 232059192" even if the shell lookup had
  resolved.

**Decision: the binary's own name disambiguates the size collision; the size
stays in the predicate everywhere.** When NAME (the binary's basename, after
symlink resolution) is a registry key whose recorded size equals the
binary's size, that key is the match - even if other entries claim the same
size. Otherwise the contract is unchanged: the UNIQUE entry at that size.
Rationale: the native claude layout names each file after the version, and
the registry keys its entries by exactly those version names (CI records
them under the version, `ci_bind_new_version.py` names a downloaded build
after `--version`), so name+size identifies the build without a guess - and
the no-guess invariant is preserved twice over: a name never matches
without the size, and `verified_sites_match` / `apply_verified_sites` still
re-check the recorded bytes at every site in the ACTUAL binary before
anything is written (a renamed or drifted build at the same size still
refuses). Where the name is not a registry key (renamed binaries, other
install layouts), the lookup degrades to the old size-only contract, and a
genuinely ambiguous registry still produces no match (never a guess).

**Changed:** `live_scan.match_verified_entry(registry, data, label=None)`
(name+size first, then unique size; a name whose entry has the wrong size
falls through to the size match); `patch_classifier_timeout.py run_live`
passes the binary's basename as the label; `patch.sh registry_lookup FILE
SIZE NAME` (jq fast path and the jq-free Python fallback implement the same
two-stage rule; all three call sites - local, remote, post-bind - pass the
resolved binary's basename). The registry file itself needed no change:
both records were already measurement-correct.

**Tests (266 Python, 27 worker, all green).** 13 new Given-When-Then cases:
`TestVerifiedMatch` (same-size entries disambiguated by name; a named entry
with the wrong size falls back to the size match; a non-key name does not
lift the multiple-size guard); `RegistryLookupTests` (the same three shapes
through BOTH the jq path and the jq-free Python fallback, plus a malformed
named entry falling through to the size match); `PatchAutoBindTests` (the
end-to-end 2.1.276 shape, twice: `--no-auto-bind` apply, and the default
auto-bind-on invocation where the pre-fix run died with "binding reported
success but the registry has no matching entry" - now: no binding run at
all, the collision resolves by name, the patch applies, the registry
untouched); `TestVerifiedCli` (`--apply-live` through the Python tool: the
collision resolves by the binary's own key; a name-resolved entry whose
recorded bytes no longer hold the site falls back to the reference-anchored
path and writes nothing). Verified on the real machine: `./patch.sh
~/.local/share/claude/versions/2.1.276 --registry verified_sites.json`
now applies and VERIFIES (the blackhole probe: the classifier call is
blackholed, the patched binary is still waiting at the 150 s cap, rc=124);
the wrapper's next `claude-patched` launch boots the patched artifact
instead of re-failing the chain.
