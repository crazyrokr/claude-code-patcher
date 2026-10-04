#!/bin/bash
# sync_verified_site.sh - keep the local binding cache current.
#
# The cache: ~/.local/share/claude/verified_sites.json, the machine-local
# registry document (build name -> the entry's size/sites/evidence, same
# shape as the in-repo file used to be). The cache is NEVER in the
# repository checkout: the source of a new entry is the GitHub release
# named after the binary on this machine (auto-mode-timeout-<name>, the
# asset verified_site.json = the entry verbatim) - CI publishes exactly
# that release when a build passes its end-to-end test, and a build with
# no release is an unbound build (the patcher binds it locally, the
# wrapper boots the previous patched binary).
#
# Two source shapes (the first wins):
#   1. CLAUDE_PATCHER_REGISTRY_URL - a URL or a local file path holding a
#      FULL registry document (the test/offline hook; also how a maintainer
#      can pin a specific document). The transfer is validated (non-empty,
#      a JSON object when jq is present) and the cache is replaced
#      atomically.
#   2. The default: the release asset for the current claude binary's name,
#      fetched from the patcher checkout's own repository (the origin
#      remote; github https remotes only). The transfer must be a single
#      entry object (positive integer size, non-empty sites - the no-guess
#      shape, anything else is refused) and is UPSERTED into the cache as
#      {name: entry} - the merge is atomic (temp file + rename), so a
#      failed or refused fetch leaves the existing cache untouched.
#
# install.sh copies this script next to the installed wrapper (the PATCHER
# path is baked in, the same way the wrapper gets it) and registers a
# Claude Code SessionEnd hook (in ~/.claude/settings.json) that runs
# `sync_verified_site.sh --with-patch`: at every session end the cache is
# refreshed, and when a NEW entry was fetched the patcher runs on the
# current claude binary with --registry <that file> - DETACHED (its own
# session: SessionEnd hooks share a 1.5 s budget, raised to at most 60 s
# by the configured timeout - a full apply + verify probe takes 150 s or
# more and would be killed mid-run if it ran in the foreground). The
# patcher's output goes to ~/.local/share/claude/.verified_site_sync.log.
#
# A wrapper run of this script (bare, no flag) is SYNC ONLY: the wrapper
# reads the status line and invokes the patcher itself, so the patcher
# runs exactly once per launch.
#
# stdout protocol (the first line is machine-readable, the wrapper parses
# it; the second line is the human-readable message):
#   SYNCED <path>    a new entry was fetched (or a new document was
#                   downloaded) and the cache was updated
#   UNCHANGED <path> the cache is up to date (the entry it already holds
#                    is byte-identical, the document unchanged) or the
#                    sync was skipped (CLAUDE_WRAPPER_NO_SYNC=1)
#   EXISTING <path>  the fetch failed (no release for this build, network
#                    down, or an invalid transfer); the existing cache is
#                    kept and still usable
#   NONE             no registry is available (fetch failed and no cache)
#
# Exit: 0 whenever the sync completed (success or graceful degradation -
# a failed fetch never fails a session end); 2 on usage errors.
#
# Env: CLAUDE_PATCHER_REGISTRY_URL (a full-document source; a URL or a
# local file path), CLAUDE_WRAPPER_NO_SYNC=1 (skip the fetch; an existing
# cache is still reported), CLAUDE_WRAPPER_STATE (the wrapper state file,
# used to resolve the current binary in --with-patch mode), SYNC_NO_DETACH=1
# (test hook: run the --with-patch patcher in the foreground instead of
# detached).
set -u
PATCHER="__PATCHER__"
WITH_PATCH=0

usage() {
  cat <<'EOF'
Usage: sync_verified_site.sh [--with-patch]

Keeps the local binding cache (~/.local/share/claude/verified_sites.json)
current: the default source is the GitHub release named after the current
claude binary (auto-mode-timeout-<name>); CLAUDE_PATCHER_REGISTRY_URL
points at a full registry document instead (URL or local file).
--with-patch: when a NEW entry was fetched, also run the baked-in patcher
on the current claude binary with --registry <that file> (detached,
logged to ~/.local/share/claude/.verified_site_sync.log).
EOF
}

for arg in "$@"; do
  case "$arg" in
    --with-patch) WITH_PATCH=1 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "error: unknown option $arg" >&2; usage >&2; exit 2 ;;
  esac
done

SCRIPT_DIR=""
{ SCRIPT_DIR="$(cd "$(dirname -- "$0")" && pwd -P)"; } 2>/dev/null || SCRIPT_DIR=""

REPO_DIR=""
if [ -n "${PATCHER:-}" ] && [ "$PATCHER" != "__PATCHER__" ] && [ -f "$PATCHER" ]; then
  { REPO_DIR="$(cd "$(dirname -- "$PATCHER")" && pwd -P)"; } 2>/dev/null || REPO_DIR=""
fi

# The cache (the machine-local registry document; never in the checkout).
CACHE_DIR="$HOME/.local/share/claude"
REG="$CACHE_DIR/verified_sites.json"

# The repository part of the release URL (the checkout's own origin remote;
# github https remotes only, the .git suffix stripped). Empty when the
# checkout is not a github https remote.
repo_part() {
  local remote
  [ -n "$REPO_DIR" ] || return 1
  remote="$(git -C "$REPO_DIR" remote get-url origin 2>/dev/null || true)"
  case "$remote" in
    https://github.com/*|http://github.com/*) : ;;
    *) return 1 ;;
  esac
  printf '%s' "${remote#*://github.com/}" | sed 's/\.git$//'
}

# The release asset URL for a build name (no auth, no API): the one entry
# of the registry, published by CI as its own release.
release_url() {
  local name repo
  name="$(basename "$1")"
  repo="$(repo_part 2>/dev/null || true)"
  [ -n "$repo" ] || return 1
  printf 'https://github.com/%s/releases/download/auto-mode-timeout-%s/%s' "$repo" "$name" "verified_site.json"
}

# The current claude binary's name (the newest non-backup file in the
# versions dir, the wrapper's own resolution; the state file's recorded
# binary and the native claude link are the fallbacks). Prints the name,
# returns 1 when no binary can be found.
current_binary_name() {
  local bin
  bin="$(resolve_current_binary 2>/dev/null || true)"
  [ -n "$bin" ] || return 1
  basename "$bin"
}

# Document source (CLAUDE_PATCHER_REGISTRY_URL): download into a same-folder
# temp file (validated; mv is the atomic replace). Returns 1 on a failed
# download or an invalid transfer.
download_doc() {
  local url out
  url="${CLAUDE_PATCHER_REGISTRY_URL:-}"
  [ -n "$url" ] || return 1
  mkdir -p "$CACHE_DIR" 2>/dev/null || return 1
  out="$(mktemp "$CACHE_DIR/.verified_sites.json.XXXXXX" 2>/dev/null)" || return 1
  case "$url" in
    /*|./*) cp "$url" "$out" 2>/dev/null || { rm -f "$out"; return 1; } ;;
    *)      curl -fsSL --max-time 30 "$url" -o "$out" 2>/dev/null || { rm -f "$out"; return 1; } ;;
  esac
  [ -s "$out" ] || { rm -f "$out"; return 1; }
  if command -v jq >/dev/null 2>&1; then
    jq -e 'type == "object"' "$out" >/dev/null 2>&1 || { rm -f "$out"; return 1; }
  fi
  mv -f "$out" "$REG" 2>/dev/null || { rm -f "$out"; return 1; }
  return 0
}

# Release source (the default): fetch the entry for the current binary's
# name from its release, validate it (a single entry object - positive
# integer size, non-empty sites: the no-guess shape; anything else is
# refused), and upsert it into the cache as {name: entry}. Atomic: the
# merged document is written to a temp file and renamed; a failed or
# refused fetch leaves the existing cache untouched. Returns 1 when there
# is no release for this build (an unbound build) or the transfer is
# invalid.
fetch_release_entry() {
  local name url out existing merged
  name="$(current_binary_name 2>/dev/null || true)"
  [ -n "$name" ] || return 1
  url="$(release_url "$name" 2>/dev/null || true)"
  [ -n "$url" ] || return 1
  mkdir -p "$CACHE_DIR" 2>/dev/null || return 1
  out="$(mktemp "$CACHE_DIR/.verified_sites.json.XXXXXX" 2>/dev/null)" || return 1
  curl -fsSL --max-time 30 "$url" -o "$out" 2>/dev/null || { rm -f "$out"; return 1; }
  [ -s "$out" ] || { rm -f "$out"; return 1; }
  # The no-guess shape check: the transfer must be the entry object itself.
  if command -v jq >/dev/null 2>&1; then
    jq -e 'type == "object" and (.size | type == "number") and (.size > 0)
           and (.sites | type == "array") and (.sites | length > 0)' \
      "$out" >/dev/null 2>&1 || { rm -f "$out"; return 1; }
  else
    # Without jq the shape cannot be validated: refuse (a wrong-shaped
    # transfer must never enter the cache).
    command -v python3 >/dev/null 2>&1 || { rm -f "$out"; return 1; }
  fi
  if [ -f "$REG" ]; then
    existing="$(cat "$REG" 2>/dev/null || true)"
  else
    existing=""
  fi
  if command -v jq >/dev/null 2>&1; then
    if [ -n "$existing" ] && printf '%s' "$existing" | jq -e 'type == "object"' >/dev/null 2>&1; then
      merged="$(jq -n --arg n "$name" \
        --argjson old "$(printf '%s' "$existing" | jq -c '.')" \
        --slurpfile new "$out" '($old // {}) + {($n): $new[0]}')" || { rm -f "$out"; return 1; }
    else
      merged="$(jq -n --arg n "$name" --slurpfile new "$out" '{($n): $new[0]}')" || { rm -f "$out"; return 1; }
    fi
  else
    # python3 fallback (the same merge the jq path does).
    if [ -n "$existing" ] && printf '%s' "$existing" | python3 -c 'import json,sys; d=json.load(sys.stdin); sys.exit(0 if isinstance(d, dict) else 1)' 2>/dev/null; then
      merged="$(python3 - "$REG" "$out" "$name" <<'PY'
import json, sys
with open(sys.argv[1], encoding="utf-8") as f:
    old = json.load(f)
with open(sys.argv[2], encoding="utf-8") as f:
    new = json.load(f)
doc = {**old, sys.argv[3]: new}
print(json.dumps(doc, indent=2))
PY
)" || { rm -f "$out"; return 1; }
    else
      merged="$(python3 - "$out" "$name" <<'PY'
import json, sys
with open(sys.argv[1], encoding="utf-8") as f:
    new = json.load(f)
print(json.dumps({sys.argv[2]: new}, indent=2))
PY
)" || { rm -f "$out"; return 1; }
    fi
  fi
  [ -n "$merged" ] || { rm -f "$out"; return 1; }
  # The merge result must itself be a JSON object (it always is, but the
  # check keeps a broken tool from poisoning the cache).
  if command -v jq >/dev/null 2>&1; then
    printf '%s' "$merged" | jq -e 'type == "object"' >/dev/null 2>&1 || { rm -f "$out"; return 1; }
  fi
  local tmp
  tmp="$(mktemp "$CACHE_DIR/.verified_sites.json.XXXXXX" 2>/dev/null)" || { rm -f "$out"; return 1; }
  printf '%s\n' "$merged" > "$tmp"
  if [ -f "$REG" ] && cmp -s "$tmp" "$REG"; then
    # The cache already holds exactly this entry.
    rm -f "$tmp" "$out"
    return 2
  fi
  mv -f "$tmp" "$REG" 2>/dev/null || { rm -f "$tmp" "$out"; return 1; }
  rm -f "$out"
  return 0
}

# The sync itself. Sets STATUS and REG_PATH (empty for NONE) and prints the
# two stdout lines.
sync_registry() {
  local old new
  if [ -n "${CLAUDE_WRAPPER_NO_SYNC:-}" ]; then
    # Escape: no fetch. An existing cache is still reported (and still
    # usable by the caller); the message says the sync was skipped.
    if [ -f "$REG" ]; then
      STATUS="UNCHANGED"; REG_PATH="$REG"
      echo "UNCHANGED $REG"
      echo "registry: fetch skipped (CLAUDE_WRAPPER_NO_SYNC=1) - using the existing verified_sites.json cache"
    else
      STATUS="NONE"; REG_PATH=""
      echo "NONE"
      echo "registry: fetch skipped (CLAUDE_WRAPPER_NO_SYNC=1) - no verified_sites.json cache"
    fi
    return 0
  fi
  if [ -f "$REG" ]; then
    old="$(sha256sum "$REG" 2>/dev/null | cut -d' ' -f1)"
  else
    old=""
  fi
  # A temp file orphaned by a KILLED run (the hook budget can kill the
  # script mid-download; the names are unique per run, so only leftovers
  # are garbage) is removed before the next fetch.
  mkdir -p "$CACHE_DIR" 2>/dev/null || true
  rm -f "$CACHE_DIR/.verified_sites.json."* 2>/dev/null || true
  if [ -n "${CLAUDE_PATCHER_REGISTRY_URL:-}" ]; then
    # A full registry document (the test/offline hook, or a maintainer
    # pin): download and atomically replace the cache.
    if download_doc; then
      new="$(sha256sum "$REG" 2>/dev/null | cut -d' ' -f1)"
      if [ -n "$old" ] && [ "$old" = "$new" ]; then
        STATUS="UNCHANGED"; REG_PATH="$REG"
        echo "UNCHANGED $REG"
        echo "registry: the document at CLAUDE_PATCHER_REGISTRY_URL is up to date"
        return 0
      fi
      STATUS="SYNCED"; REG_PATH="$REG"
      echo "SYNCED $REG"
      echo "registry: the cache was refreshed from CLAUDE_PATCHER_REGISTRY_URL"
      return 0
    fi
    if [ -f "$REG" ]; then
      STATUS="EXISTING"; REG_PATH="$REG"
      echo "EXISTING $REG"
      echo "registry: the document download failed - using the existing verified_sites.json cache"
      return 0
    fi
    STATUS="NONE"; REG_PATH=""
    echo "NONE"
    echo "registry: the document download failed - the patcher will bind locally if the build is unbound"
    return 0
  fi
  # The default source: the release named after the current binary (0 = a
  # new entry was upserted; 2 = the release exists and the cache already
  # holds exactly this entry; 1 = no release / fetch failed).
  fetch_release_entry
  rc=$?
  if [ "$rc" -eq 0 ]; then
    new="$(sha256sum "$REG" 2>/dev/null | cut -d' ' -f1)"
    STATUS="SYNCED"; REG_PATH="$REG"
    echo "SYNCED $REG"
    echo "registry: the entry for $(current_binary_name 2>/dev/null || echo 'this build') was fetched from its release"
    return 0
  fi
  if [ "$rc" -eq 2 ] && [ -f "$REG" ]; then
    STATUS="UNCHANGED"; REG_PATH="$REG"
    echo "UNCHANGED $REG"
    echo "registry: the cache is up to date for $(current_binary_name 2>/dev/null || echo 'this build')"
    return 0
  fi
  if [ -f "$REG" ]; then
    STATUS="EXISTING"; REG_PATH="$REG"
    echo "EXISTING $REG"
    echo "registry: no release for this build (or the fetch failed) - using the existing verified_sites.json cache"
    return 0
  fi
  STATUS="NONE"; REG_PATH=""
  echo "NONE"
  echo "registry: no release for this build and no cache - the patcher will bind locally (and the wrapper will boot the previous patched binary)"
  return 0
}

# The current claude binary (the newest non-backup file in the versions
# dir, the wrapper's own resolution; the state file's recorded binary and
# the native claude link are the fallbacks). Prints the path, returns 1
# when no binary can be found.
resolve_current_binary() {
  local state vd origin n link
  state="${CLAUDE_WRAPPER_STATE:-$HOME/.local/share/claude/.last_known_version}"
  vd=""
  origin=""
  if [ -f "$state" ]; then
    while IFS="=" read -r k v; do
      case "$k" in
        versions_dir) vd="$v" ;;
        binary) origin="$v" ;;
      esac
    done < "$state"
  fi
  [ -n "$vd" ] || vd="$HOME/.local/share/claude/versions"
  if [ -d "$vd" ]; then
    for n in $(ls -t "$vd" 2>/dev/null); do
      case "$n" in *.bak*|*.patched|*.tmp.*) continue ;; esac
      if [ -f "$vd/$n" ]; then printf '%s' "$vd/$n"; return 0; fi
    done
  fi
  if [ -n "$origin" ] && [ -f "$origin" ]; then
    printf '%s' "$origin"
    return 0
  fi
  link="$(readlink -f "$HOME/.local/bin/claude" 2>/dev/null || true)"
  if [ -n "$link" ] && [ -f "$link" ] && [ "$(basename "$link")" != "claude-wrapper.sh" ]; then
    printf '%s' "$link"
    return 0
  fi
  return 1
}

sync_registry
if [ -z "$STATUS" ]; then
  echo "error: the sync produced no status" >&2
  exit 2
fi

# --with-patch (the SessionEnd hook contract): when a NEW entry was
# fetched, run the patcher on the current claude binary with
# --registry <that file>. Detached: SessionEnd hooks are killed at their
# (at most 60 s) budget, and a full apply + verify probe takes 150 s or
# more (an unbound build 20-60 min); the detached run survives the budget
# and the artifact is promoted only after it VERIFIES (the patcher stages
# it until then). SYNC_NO_DETACH=1 keeps the run in the foreground (the
# test hook).
if [ "$WITH_PATCH" -eq 1 ] && [ "$STATUS" = "SYNCED" ]; then
  BIN="$(resolve_current_binary || true)"
  if [ -z "$BIN" ]; then
    echo "note: no claude binary found - the patch was skipped (the registry is current)"
  elif [ -z "${PATCHER:-}" ] || [ "$PATCHER" = "__PATCHER__" ] || [ ! -f "$PATCHER" ]; then
    echo "note: the patcher is not available (re-run install.sh to bake it in) - the patch was skipped"
  else
    LOCK_DIR="$HOME/.local/share/claude"
    LOG="$LOCK_DIR/.verified_site_sync.log"
    mkdir -p "$LOCK_DIR" 2>/dev/null || { LOCK_DIR="/tmp"; LOG="$LOCK_DIR/.verified_site_sync.log"; }
    PATCH_RAN=0
    if [ -z "${SYNC_NO_DETACH:-}" ] && command -v setsid >/dev/null 2>&1; then
      # One patcher at a time (two claude sessions can end at the same
      # moment): the lock is held for the whole detached run (the child
      # inherits the fd), and a lost race defers to the running one.
      if command -v flock >/dev/null 2>&1; then
        if exec 9>"$LOCK_DIR/.verified_site_sync.lock" 2>/dev/null; then
          if ! flock -n 9 2>/dev/null; then
            echo "note: a registry sync is already in progress - its patcher will patch the current binary"
          else
            setsid bash "$PATCHER" --registry "$REG_PATH" "$BIN" >> "$LOG" 2>&1 < /dev/null &
            PATCH_RAN=1
          fi
        fi
      else
        setsid bash "$PATCHER" --registry "$REG_PATH" "$BIN" >> "$LOG" 2>&1 < /dev/null &
        PATCH_RAN=1
      fi
      if [ "$PATCH_RAN" -eq 1 ]; then
        echo "note: new entry fetched - the patcher is running in the background on $(basename "$BIN") (log: $LOG)"
      fi
    else
      bash "$PATCHER" --registry "$REG_PATH" "$BIN" >> "$LOG" 2>&1
      echo "note: new entry fetched - the patcher ran on $(basename "$BIN") (log: $LOG)"
    fi
  fi
fi

exit 0
