# ADR: Auto-mode classifier timeout tooling for the Claude Code SFE binary

Status: accepted (2026-09-11)
Applies to: `/home/mk/claude-patch/` — `claude` (Bun single-file executable, v2.1.267, 217,013,744 bytes)
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
| string/identifier pool | 91 – 102 | deduplicated identifier table (`[chars][00][len][pad][hash]`) | data, not code |
| **live bytecode** | 104 – 177 | compiled Bun bytecode (0x9f opcodes) | **yes — this runs** |
| source (dead) | 181 – 209 | plaintext JS source, retained as fallback | **no** |
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
| `patch_classifier_timeout.py` | Raises TQe/L8/Lrn to the digit-count-preserving maxima (99999/999999/99999) in the source block; any length-changing edit refused unless `--allow-length-change`; `--self-test` executes the patched copy before proposing a swap; never guesses at live-bytecode sites. |
| `test_classifier_tools.py` | 63 Given-When-Then unittest cases incl. false-positive scenarios (bridge `TQe` overload, non-classifier blocks, length-change refusal, idempotency). |

**Explicitly not done:** a live-bytecode patcher. It would have to choose
among 26+ ambiguous constant-table sites, cannot be validated without a live
model endpoint, and violates the "no breaking changes" constraint. Failing
closed is the correct behavior here.

## Safe-patch invariants (enforced in code)

- Byte-length preserving by default (same decimal digit count ⇒ no byte
  shifts ⇒ nothing downstream can break).
- All-or-nothing: one refused edit ⇒ zero edits written.
- Unknowns refused: no block found ⇒ no write; Hrn literal longer than body ⇒ no write.
- Self-test gate: `--self-test` runs `<copy> --version`; a failing copy is removed.

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
