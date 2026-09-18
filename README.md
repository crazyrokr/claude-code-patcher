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
  oracle-verified binding and runs the blackhole verify probe. The local
  `verified_sites.json` is checked first; a build not bound locally may
  already be bound in the repo copy (recorded by CI) - the default registry
  is then fetched from the repository (`CLAUDE_PATCHER_REGISTRY_URL`
  overrides the source; `--registry PATH` is honored exactly and never
  downloads) and applied from, without a local probe. A build bound nowhere
  is bound first, automatically (the 20-60 min oracle probe, `--no-auto-bind`
  refuses it instead); `--baseline`, `--no-verify`, `--timeout N`,
  `--registry PATH` adjust the run; exit 0 only when the patched artifact
  is measured still-waiting.
- `claude-wrapper.sh` — the launcher: on every launch it resolves the
  real claude binary (newest non-backup file in the versions dir,
  sha256-confirmed change detection); before running `patch.sh` on a
  changed binary it downloads the latest `verified_sites.json` into the
  wrapper's own folder - the patcher is passed `--registry <that file>`
  when the file exists next to the wrapper, or runs with the repository
  checkout's registry (its own download fallback and local auto-bind
  included) when it does not - then seamlessly boots the patched
  `<binary>.patched` artifact (a refusal boots the unpatched binary).
  `install.sh` copies it to `~/.local/bin/claude-wrapper.sh` with the
  patcher path baked in.
- `install.sh` — installs the claude-launch interceptor:
  `~/.local/bin/claude-patched` (a NEW link - the native `claude` link is
  never touched, so a claude self-update cannot break the interceptor)
  launches `~/.local/bin/claude-wrapper.sh`, which on every launch
  detects a changed claude binary (newest non-backup file in the
  versions dir, sha256-confirmed), runs `patch.sh` on it before
  seamlessly booting the patched `<binary>.patched` artifact (a refusal
  boots the unpatched binary). `--uninstall` removes the link, the
  wrapper, the downloaded registry, and the state.
- `verified_sites.json` — the registry of oracle-verified bindings
  (keyed by the build's version name; matching is by name+size when the
  binary's name is a key at that size - two versions may ship
  byte-identical-sized builds - else by unique size equality, with recorded
  bytes re-checked at every apply). The no-guess contract: an unbound build
  is refused, never guessed. New builds are recorded into it by CI
  (`tools/ci_bind_new_version.py`, see below), so a checkout of the current
  branch carries every binding CI has recorded so far.
- `tools/ci_bind_new_version.py` — the CI recorder: `--binary PATH` binds an
  existing local build; `--version V --download-url URL` (or
  `CLAUDE_BINARY_URL`) downloads the build first (the file is named after
  the version, which becomes the registry key) and binds it - both through
  the same no-guess `oracle_bind_auto.bind()` (a re-run on an already-bound
  build is a no-op, an unmeasurable build is refused without a write). The
  download URL may also point at a tarball (the github release assets ship
  `claude-<platform>.tar.gz`, the npm platform packages their tarball too):
  the binary is then unpacked under a no-guess member rule (a regular file
  named `claude`, else exactly one regular file, else refused).
  `.github/workflows/bind-new-version.yml` (workflow_dispatch: version +
  binary URL inputs) runs it and commits the record.
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
- `test_classifier_tools.py` — the full Given-When-Then suite (253 cases,
  including end-to-end `patch.sh` runs against synthetic binaries and a
  stubbed probe, the registry lookup/download and
  `tools/ci_bind_new_version.py` recorders (raw and tarball downloads),
  the `install.sh` /
  `claude-wrapper.sh` interceptor end-to-end against a fake claude layout,
  and the `worker/` release-watch suite run under node).

All design decisions, empirical findings, and the cross-build survey
live in the single shared `ADR.md`.
