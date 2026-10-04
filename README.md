# auto-mode classifier timeout patcher

Tools to investigate and raise the auto-mode classifier timeouts in a Claude
Code `claude` binary (the `TQe=60000, L8=120000, Lrn=60000, Frn=4, $rn=0,
Brn=2000, Urn=10000` block), with a safe-patch contract: byte-length
preserving, all-or-nothing, no guessing, self-test gated.

- `tools/patch_classifier_timeout.py` — discover, plan, patch (`--dry-run`,
  `--in-place`, `--self-test`), plus the experimental live (bytecode) path:
  `--experimental-live` (read-only candidate manifest), `--apply-live`
  (UNIQUE resolution only), `--oracle` (behavioral no-op check).
- `tools/find_classifier_timeouts.py` — read-only discovery report.
- `tools/verify_classifier_patch.py` — re-scan a patched binary, verdict
  `PATCHED` / `SOURCE_ONLY` / `NOT_APPLIED`.
- `tools/classifier_scan.py` — pure engine for the embedded source region.
- `tools/live_scan.py` — reference-anchored discovery for the executed
  bytecode region (string-pool anchors -> reference sites -> constant-slot
  binding, plus the report-only set-window diagnostic).
- `patch.sh` — the one-line entry point: `./patch.sh <binary>` looks the
  build up in the registry - by the binary's own NAME when it is a registry
  key at the binary's size (two versions may ship byte-identical-sized
  builds, e.g. 2.1.275 and 2.1.276, so size alone cannot disambiguate), else
  by UNIQUE size (jq, falling back to Python when jq is absent - the binary
  is never read for the lookup) - then applies the
  oracle-verified binding and verifies it: the blackhole verify probe
  (the ~150 s end-to-end test, the artifact must still be waiting when the
  probe kills it) - EXCEPT a binding that records the sha256 of the binary
  it was measured on (every entry CI publishes, and an entry a local
  oracle bind just wrote) applies WITHOUT any local probe when the target's
  sha256 matches (the end-to-end test was already paid for these exact
  bytes); a same-size mismatch REFUSES (the recorded binding describes
  other bytes, no patch is applied). Legacy entries without a recorded hash
  (2.1.267-277) keep the full local verify. The local binding cache
  (`~/.local/share/claude/verified_sites.json`, machine state - never in
  the checkout) is checked first; a build not bound locally is looked up
  as the RELEASE named after the binary (`auto-mode-timeout-<name>`, the
  entry CI published for that build; the repository part is derived from
  the checkout's origin remote) - the entry is fetched, validated (a
  single entry object) and upserted into the cache, then applied from it.
  `CLAUDE_PATCHER_REGISTRY_URL` overrides the source (a URL or a local
  file path holding a FULL registry document); `--registry PATH` is
  honored exactly and never downloads. A build bound nowhere is bound
  first, automatically (the 20-60 min oracle probe, `--no-auto-bind`
  refuses it instead); `--baseline`, `--no-verify`, `--timeout N`,
  `--registry PATH` adjust the run; exit 0 only when the patched artifact
  is verified (measured still-waiting, or byte-identical to a measured
  binary). The artifact is STAGED
  (`<name>.patched.tmp.<pid>`) until that verification, and promoted to
  `<name>.patched` only then: a killed or unverified run leaves no
  artifact (stale stages are cleaned, a concurrent run's fresh stage is
  preserved).
- `claude-wrapper.sh` — the launcher: on every launch it resolves the
  real claude binary (newest non-backup file in the versions dir,
  sha256-confirmed change detection; a missing `.patched` artifact counts
  as changed); on a changed binary it runs `sync_verified_site.sh` next
  to itself and reads the status line: a SYNCED cache is passed to
  the patcher as-is; with an UNCHANGED or EXISTING cache it first
  checks whether that cache BINDS the build (the patcher's own
  name+size / unique-size lookup) - bound: patch with the existing file;
  unbound: patching would cost the 20-60 min local bind, so the
  PREVIOUSLY patched binary boots instead (or the raw new binary when no
  earlier artifact exists - claude always boots), the new build is
  recorded, and every next launch retries until CI binds it - then
  seamlessly boots the patched `<binary>.patched` artifact (a refusal
  boots the unpatched binary). `install.sh` copies it to
  `~/.local/bin/claude-wrapper.sh` with the patcher path baked in.
  Before the final exec the wrapper exports
  `CLAUDE_WRAPPER_PATCHED=1` + `CLAUDE_WRAPPER_PATCHED_BUILD=<booted
  build>` ONLY when a `.patched` artifact actually boots (every raw
  boot unsets both - the marker cannot lie).
- `claude-statusline.sh` — the statusline marker (installed next to
  the wrapper): `install.sh` makes it the `statusLine` command in
  `~/.claude/settings.json` (the same merge contract as the hook: never
  clobbered, an unparseable file is refused, the other fields such as
  `refreshInterval` are kept, the merge is idempotent). The user's
  existing statusline command is recorded verbatim in the
  `claude-statusline.orig` sidecar next to the script; the script runs
  it (the same session JSON on stdin, a 5 s guard against a hung
  original) and, only when a PATCHED binary booted, prepends the label
  (default `⚙ (patched)`, `CLAUDE_WRAPPER_PATCHED_LABEL` overrides it)
  to the FIRST line - every remaining line passes through unchanged.
  Unpatched launches print the statusline verbatim; without an
  existing statusline nothing is printed. `--uninstall` restores the
  recorded command verbatim. This is how a patched build marks itself
  in the UI - the banner header cannot be patched (ADR,
  2026-09-19, second addendum).
- `sync_verified_site.sh` — the registry sync (extracted from the
  wrapper): it keeps the local binding cache
  (`~/.local/share/claude/verified_sites.json` - machine state, never in
  the checkout) current. Two source shapes (the first wins):
  `CLAUDE_PATCHER_REGISTRY_URL` - a URL or a local file path holding a
  FULL registry document (the test/offline hook, or a maintainer pin);
  the transfer is validated (non-empty; a JSON object when jq is present)
  and replaces the cache atomically. The default - the GitHub release
  named after the current claude binary (`auto-mode-timeout-<name>` of
  the patcher checkout's own repository, the origin remote URL, github
  https remotes only); the transfer must be a single ENTRY object
  (positive integer size, non-empty sites - the no-guess shape, anything
  else is refused) and is UPSERTED into the cache as `{name: entry}`.
  Every write is atomic (temp file + rename), so a failed or refused
  fetch leaves the existing cache untouched. `CLAUDE_WRAPPER_NO_SYNC=1`
  skips the fetch (an existing cache is still reported). stdout: a
  machine-readable status line (`SYNCED`/`UNCHANGED`/`EXISTING`/`NONE` +
  the file path, the second line the human-readable message).
  `--with-patch`: when a NEW entry was fetched, also run the patcher (its
  path baked in at install) on the current claude binary with
  `--registry <that file>` - DETACHED via `setsid` (SessionEnd hooks are
  killed at their at most 60 s budget, a full apply + verify takes 150 s
  or more - a CI-verified entry with a matching sha256 applies in seconds
  instead - and an unbound build 20-60 min), logged to
  `~/.local/share/claude/.verified_site_sync.log`, one at a time
  (`flock`; a lost race defers to the running one). `install.sh` copies
  it to `~/.local/bin/` next to the wrapper and registers a SessionEnd
  hook (merged into `~/.claude/settings.json`, the user's own settings
  preserved) that runs `sync_verified_site.sh --with-patch` at every
  session end, so a new claude build is patched without waiting for the
  next launch.
- `install.sh` — installs the claude-launch interceptor:
  `~/.local/bin/claude-patched` (a NEW link - the native `claude` link is
  never touched, so a claude self-update cannot break the interceptor)
  launches `~/.local/bin/claude-wrapper.sh`, which on every launch
  detects a changed claude binary (newest non-backup file in the
  versions dir, sha256-confirmed), patches it with the freshest registry
  (see above), and seamlessly boots the patched `<binary>.patched`
  artifact (a refusal boots the unpatched binary). It also installs
  `sync_verified_site.sh` next to the wrapper, registers the
  SessionEnd hook, and installs the `claude-statusline.sh` marker
  (merged into `~/.claude/settings.json`: the user's own settings are
  preserved, an unparseable file is refused and the install rolls
  back). `--uninstall` removes the hook FIRST (the other settings
  stay; the file is deleted when it becomes empty), restores the
  recorded statusline (or removes the key the installer created),
  then removes the link, the wrapper, the sync script, the marker,
  the sidecar, the binding cache, and the state.
- The binding registry — one GitHub RELEASE per binding: the tag
  `auto-mode-timeout-<name>` (the build's version name) carries a single
  asset `verified_site.json` = the entry verbatim. An entry is the
  oracle-verified driver/ceiling site pair for one binary build;
  matching is by name+size when the binary's name is a key at that size
  - two versions may ship byte-identical-sized builds (e.g. 2.1.275 and
  2.1.276) - else by unique size equality, with recorded bytes re-checked
  at every apply. Every entry CI publishes also carries the sha256 of the
  binary it was measured on and the result of the end-to-end test (the
  `ci_e2e` evidence block): a byte-identical local build then applies
  without any local probe. The no-guess contract: an unbound build (no
  release) is refused, never guessed. New builds are published by CI
  (`tools/ci_bind_new_version.py`, see below); the entries of the old
  in-repo `verified_sites.json` were migrated one release each by
  `tools/migrate_registry_to_releases.py` (idempotent: existing releases
  are skipped, every asset round-trip is verified against the entry), and
  the file itself was deleted from the repository. Machines keep the
  entries in the local cache (see `sync_verified_site.sh` above).
- `tools/migrate_registry_to_releases.py` — the one-shot migration of the
  old in-repo registry to one release per entry: every entry of
  `verified_sites.json` becomes the release
  `auto-mode-timeout-<name>` carrying the entry verbatim as its
  `verified_site.json` asset (an existing release is skipped - idempotent
  re-runs; an entry without a positive integer size and non-empty sites
  is refused before any gh call; after the create, every asset is
  downloaded back and compared byte-for-byte).
- `tools/ci_bind_new_version.py` — the CI binder: `--binary PATH` binds an
  existing local build; `--version V --download-url URL` (or
  `CLAUDE_BINARY_URL`) downloads the build first (the file is named after
  the version, which becomes the registry key) and binds it - both through
  the same no-guess `oracle_bind_auto.bind()` against a WORKDIR registry
  (a re-run when the release already exists is a no-op, an unmeasurable
  build is refused without a write). The download URL may also point at a
  tarball (the github release assets ship `claude-<platform>.tar.gz`, the
  npm platform packages their tarball too): the binary is then unpacked
  under a no-guess member rule (a regular file named `claude`, else
  exactly one regular file, else refused).
  A recorded entry is published ONLY if it passes the end-to-end test: the
  entry is applied through the canonical apply path (the same recorded-byte
  re-check and `--version` execute gate the local patcher runs) and the
  artifact is probed at the 150 s cap - `rc=124`, killed still waiting, is
  the pass (the result is stamped into the entry's `ci_e2e` evidence). When
  the test fails the entry is removed and up to 5 other found driver values
  (`--max-candidates`, 0 disables) are each measured against their own
  ceiling and tested the same way before anything is kept; every attempt
  failing emits NOTHING (exit 1 - the release is created only by the
  workflow's publish step, so a failed binding publishes nothing).
  `.github/workflows/bind-new-version.yml` (workflow_dispatch: version +
  binary URL inputs, 240 min) runs it and, only when the binder emitted
  the asset, publishes `auto-mode-timeout-$VERSION` via `gh release
  create`.
- `worker/` — the Cloudflare Worker release watch (`release-watch.js`, plain
  JS, no build step; `wrangler.toml` configures the cron, KV, and vars):
  every 15-minute tick it reads
  `github.com/anthropics/claude-code/releases.atom` (the first entry's
  title, v-stripped, must be a semver - anything else is refused), resolves
  that version's binary URL from the `BINARY_URL_TEMPLATE` data input
  (default: the release's `claude-linux-x64.tar.gz` asset), HEAD-checks the
  asset (a missing asset is NOT dispatched - it may still be uploading),
  and dispatches `bind-new-version.yml` on `BRANCH` with the `version` +
  `binary_url` inputs. State is one KV record `{version, binaryUrl,
  dispatched}` written after the dispatch answer: a failed dispatch retries
  on the next tick, a dispatched version is never touched again (the
  workflow is idempotent), and feed/asset-check errors write nothing.
  Manual routes: `GET /status`, `POST /run[?force=1]`, `POST /reset`
  (protected by an optional `SECRET` bearer token). Deploy from `worker/`:
  `npx wrangler kv namespace create STATE` (paste the id into
  `wrangler.toml`), `npx wrangler secret put GITHUB_TOKEN` (a token with the
  `workflow` scope), `npx wrangler deploy`. Tests:
  `node test_release_watch.mjs` (27 Given-When-Then cases, also run by the
  python suite below).
- `tools/binder/oracle_bind_auto.py` — the automatic binding
  pipeline for a new build: baseline probe, all-sites effect probe, driver
  bisection, ceiling probe, max-wait boundary search, then the registry
  entry. Every step is a measured blackhole probe; any signal that does not
  match the measured model refuses instead of recording.
- `tools/binder/` — the probe oracle (`run_probe.sh` +
  `fake_endpoint.py`: a blackholed endpoint that makes the waits
  time-measurable), the stepwise binding scripts (`oracle_binding_step1/2.py`,
  `oracle_cap_probe.py`), the ADR-cited source slice, and
  `decompress_scan.py` (zstd frame scan, regenerable).
- `test_classifier_tools.py` — the full Given-When-Then suite (349 cases,
  including end-to-end `patch.sh` runs against synthetic binaries and a
  stubbed probe, the cache lookup/release-fetch (the migration script and
  `tools/ci_bind_new_version.py` binders against a fake gh/curl),
  the `install.sh` /
  `claude-wrapper.sh` interceptor end-to-end against a fake claude layout,
  and the `worker/` release-watch suite run under node).

All design decisions, empirical findings, and the cross-build survey
live in the single shared `ADR.md`.
