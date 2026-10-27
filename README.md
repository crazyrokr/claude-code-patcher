# Claude Code auto-mode classifier timeout patcher

![Python](https://img.shields.io/badge/python-3.10+-blue)
![Shell](https://img.shields.io/badge/shell-bash-informational)
![Worker](https://img.shields.io/badge/worker-cloudflare-informational)
![Tests](https://img.shields.io/badge/tests-385%20python%2B27%20node-informational)
![bind-new-version](https://github.com/crazyrokr/claude-code-patcher/actions/workflows/bind-new-version.yml/badge.svg)

Tools to investigate and raise the auto-mode classifier timeouts in the Claude
Code `claude` binary (the `TQe=60000, L8=120000, Lrn=60000, Frn=4, $rn=0,
Brn=2000, Urn=10000` block), under a safe-patch contract: byte-length
preserving, all-or-nothing, no guessing, self-test gated.

In plain terms: when Claude Code's auto mode waits on the permission
classifier, the wait is capped (60 s per attempt, 120 s ceiling). This
project finds the exact constant sites inside the `claude` binary, rewrites
them (up to `INT32_MAX`), and proves by measurement that the new values are
live — never by pattern-matching alone.

## Quick start

```bash
# One-time install: intercept every claude launch and keep every build patched
./install.sh

# ... or patch a single binary without installing anything
./patch.sh /path/to/claude
```

`patch.sh` exits 0 only when the patched artifact is verified. The artifact
is staged as `<name>.patched.tmp.<pid>` until verification succeeds, then
promoted to `<name>.patched` — a killed or unverified run leaves no artifact
behind.

## What `install.sh` sets up

- `~/.local/bin/claude-patched` — a **new** link that launches
  `claude-wrapper.sh`. The native `claude` link is never touched, so a
  claude self-update cannot break the interceptor (and needs no reinstall).
- **Change detection** — on every launch the wrapper resolves the real
  binary (newest non-backup file in the versions dir, sha256-confirmed);
  a changed build is patched before the session starts.
- **Registry sync** — before patching, `sync_verified_site.sh` refreshes
  the local binding cache from the GitHub release for that build
  (see below). `install.sh` also registers a `SessionEnd` hook that runs
  `sync_verified_site.sh --with-patch` at every session end, so a new build
  is patched while the session is still open (the patcher runs detached
  with `setsid`; the hook budget is 60 s and a full probe takes longer).
- **Self-healing fallback** — if a new build is not yet bound anywhere
  (no release, no local cache entry), patching would cost a 20-60 min
  oracle probe; the wrapper boots the **previously patched** binary
  instead (or the raw binary if there is none — claude always boots),
  records the build, and retries on every next launch until CI binds it.
- **Statusline marker** — `claude-statusline.sh` is installed as the
  `statusLine` command in `~/.claude/settings.json` (merged, never
  clobbered; an unparseable file refuses the install and rolls back). It
  chains your existing statusline (recorded verbatim in the
  `claude-statusline.orig` sidecar, 5 s guard against a hung original) and,
  only when a patched binary actually booted, prepends the label
  (default `⚙ (patched)`, `CLAUDE_WRAPPER_PATCHED_LABEL` overrides it)
  to the first line — the banner header itself cannot be patched (ADR,
  2026-09-19, second addendum).

```bash
./install.sh --uninstall   # removes hook, marker, sidecar, link, wrapper,
                           # sync script, binding cache, state - claude is
                           # never modified
```

## How a build gets bound (the no-guess contract)

Every binary build has to be **measured** before it is patched — never
guessed:

1. **CI pays the probe.** `tools/ci_bind_new_version.py` (run by
   `.github/workflows/bind-new-version.yml`, `workflow_dispatch` with
   version + binary URL inputs) binds a build on a runner through the
   oracle pipeline and publishes one GitHub **release** per binding: tag
   `auto-mode-timeout-<name>`, single asset `verified_site.json` carrying
   the oracle-verified driver/ceiling site pair verbatim. The entry is
   published **only if it passes the end-to-end test** (applied through
   the canonical apply path, probed at the 150 s cap — `rc=124`, killed
   still waiting, is the pass; the result is stamped into the entry's
   `ci_e2e` evidence). A failed binding publishes nothing.
2. **Your machine just applies.** `patch.sh` looks the build up in the
   registry — by the binary's own **name** when it is a registry key at
   the binary's size (two versions may ship byte-identical-sized builds,
   e.g. 2.1.275 and 2.1.276, so size alone cannot disambiguate), else by
   **unique size** — and applies the recorded binding. The local cache
   (`~/.local/share/claude/verified_sites.json`, machine state, never in
   the checkout) is checked first; a missing entry is fetched from the
   release named after the binary and upserted.
3. **The fast path.** Entries carry the sha256 of the binary they were
   measured on: when your build is byte-identical, the patch applies
   **without any local probe** (the end-to-end test was already paid for
   these exact bytes). A same-size sha256 **mismatch refuses** — the
   recorded binding describes other bytes. Legacy entries without a
   recorded hash (2.1.267-277) keep the full local verify.
4. **Unbound builds** (no release, no cache entry) are bound
   automatically by the local oracle probe (20-60 min) — or refused with
   `--no-auto-bind`.

## `patch.sh` options

```text
Usage: ./patch.sh <binary> [options]

  --no-auto-bind   apply only from the registry; refuse unbound builds
  --baseline       also probe the unpatched binary (in parallel with the
                   verify probe; informational)
  --no-verify      apply only, skip the blackhole verification probe
  --timeout N      probe timeout in seconds (default 150)
  --fast-verify [N]
                   verify at an early check point instead of waiting out
                   the full cap (opt-in, default 70 s, floor 65 s)
  --registry PATH  use a different verified_sites registry
  -h, --help       show this help
```

`CLAUDE_PATCHER_REGISTRY_URL` points the registry source at a FULL registry
document (a URL or a local file path — the offline/test hook); `--registry
PATH` is honored exactly and never downloads.

## The registry sync script

```text
Usage: sync_verified_site.sh [--with-patch]
```

Keeps the local binding cache current. Two source shapes (the first wins):
`CLAUDE_PATCHER_REGISTRY_URL` (a full registry document, replaced
atomically), else the default GitHub release named after the current claude
binary (must be a single valid entry object — positive integer size,
non-empty sites — upserted as `{name: entry}`). Every write is atomic
(temp file + rename), so a failed or refused fetch leaves the existing
cache untouched. `CLAUDE_WRAPPER_NO_SYNC=1` skips the fetch. stdout is a
machine-readable status line (`SYNCED`/`UNCHANGED`/`EXISTING`/`NONE` plus
the file path, human-readable message on line two). `--with-patch` runs
the baked-in patcher on the current binary when a NEW entry was fetched
(detached, logged to `~/.local/share/claude/.verified_site_sync.log`,
serialized with `flock`).

## Components

| Component | Role |
|---|---|
| `patch.sh` | One-line entry point: registry lookup → apply verified binding → verify → `<binary>.patched` |
| `install.sh` | Installs the `claude-patched` interceptor (link, wrapper, sync script, SessionEnd hook, statusline marker); `--uninstall` removes everything |
| `claude-wrapper.sh` | The launcher: detects a changed claude build, patches it, seamlessly boots `<binary>.patched` |
| `claude-statusline.sh` | The UI marker: prepends `⚙ (patched)` to line 1 of the statusline on patched boots |
| `sync_verified_site.sh` | Registry sync: keeps the local binding cache current |
| `registry_common.sh` | Shared lookup/apply helpers used by `patch.sh` and the sync script |
| `tools/patch_classifier_timeout.py` | Discover, plan, patch (`--dry-run`, `--in-place`, `--self-test`), plus the experimental live (bytecode) path: `--experimental-live` (read-only manifest), `--apply-live` (unique resolution only), `--oracle` (behavioral no-op check) |
| `tools/find_classifier_timeouts.py` | Read-only discovery report (every timeout site with offset and region) |
| `tools/verify_classifier_patch.py` | Re-scans a patched binary; verdict `PATCHED` / `SOURCE_ONLY` / `NOT_APPLIED` |
| `tools/classifier_scan.py` | Pure engine for the embedded source region |
| `tools/live_scan.py` | Reference-anchored discovery for the executed bytecode region (string-pool anchors → reference sites → constant-slot binding) |
| `tools/ci_bind_new_version.py` | The CI binder: `--binary PATH` or `--version V --download-url URL` (also accepts tarballs), end-to-end gate, release asset |
| `tools/migrate_registry_to_releases.py` | One-shot migration of the old in-repo registry to one release per entry (idempotent, every asset round-trip verified) |
| `tools/release_metadata.py` | Shared release vocabulary: tag/asset/notes shapes + gh/curl accessors |
| `tools/binder/` | The probe oracle (`run_probe.sh` + `fake_endpoint.py`, a blackholed endpoint that makes the waits time-measurable), `oracle_bind_auto.py` (baseline → all-sites → bisection → ceiling → max-wait → registry entry, every step a measured probe), stepwise scripts, `decompress_scan.py` |
| `worker/` | Cloudflare Worker release watch (cron + KV, plain JS, no build step) |
| `test_classifier_tools.py` | The full Given-When-Then suite (385 cases, including end-to-end `patch.sh`/`install.sh`/worker runs) |
| `ADR.md` | The single shared ADR: every design decision, empirical finding, and the cross-build survey |

## Environment variables

| Variable | Where | Effect |
|---|---|---|
| `CLAUDE_PATCHER_REGISTRY_URL` | patch.sh, sync script, install | A FULL registry document (URL or local file path) instead of the per-release default |
| `CLAUDE_PATCHER_SCRIPT` | install.sh | Which patcher to bake into the wrapper |
| `CLAUDE_WRAPPER_STATE` | install.sh / wrapper | State file (default `~/.local/share/claude/.last_known_version`) |
| `CLAUDE_WRAPPER_NO_PATCH=1` | wrapper | Boot the unpatched binary once, without patching or recording |
| `CLAUDE_WRAPPER_NO_SYNC=1` | wrapper / sync script | Skip the registry fetch (an existing cache is still used) |
| `CLAUDE_WRAPPER_PATCHED`, `CLAUDE_WRAPPER_PATCHED_BUILD` | wrapper → any child process | Exported **only** when a `.patched` binary actually boots (every raw boot unsets both — the marker cannot lie) |
| `CLAUDE_WRAPPER_PATCHED_LABEL` | claude-statusline.sh | The marker label (default `⚙ (patched)`) |
| `CLAUDE_PATCHER_GATE_PARALLEL` | tools/binder | Parallelism of the candidate gate probes (default 4) |

## Development

Python 3.10+, standard library only (no third-party dependencies); the
worker is plain JavaScript.

```bash
# Full suite: 385 Given-When-Then cases (~90 s; end-to-end patch.sh and
# install.sh runs against synthetic binaries, cache lookup/release fetch,
# the worker suite run under node)
python -m pytest test_classifier_tools.py -q

# Worker suite: 27 Given-When-Then cases (plain node, no dependencies)
cd worker && node test_release_watch.mjs

# Lint / format (config in pyproject.toml)
python -m ruff check .
python -m ruff format .
```

### Deploying the release-watch worker

```bash
cd worker
npx wrangler kv namespace create STATE   # paste the id into wrangler.toml
npx wrangler secret put GITHUB_TOKEN     # a token with the `workflow` scope
npx wrangler deploy
```

Every 15-minute tick the worker reads
`github.com/anthropics/claude-code/releases.atom` (the first entry's
title, v-stripped, must be a semver), HEAD-checks the version's binary
asset, and dispatches `bind-new-version.yml` with `version` + `binary_url`
inputs. State is one KV record `{version, binaryUrl, dispatched}`: a
failed dispatch retries on the next tick, a dispatched version is never
touched again (the workflow is idempotent). Manual routes: `GET /status`,
`POST /run[?force=1]`, `POST /reset` (protected by an optional `SECRET`
bearer token).

## License

TODO: the repository does not contain a LICENSE file yet.
