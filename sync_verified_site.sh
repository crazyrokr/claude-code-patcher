#!/bin/bash
# sync_verified_site.sh - keep the registry next to this script current.
#
# The registry routing that used to live inline in claude-wrapper.sh: the
# latest verified_sites.json is downloaded into the folder THIS script
# lives in (the installed copy is ~/.local/bin/, next to the wrapper; the
# source is CLAUDE_PATCHER_REGISTRY_URL - a URL or a local file path -
# else the raw URL of the patcher checkout's origin remote default
# branch). The transfer is validated (non-empty; a JSON object when jq is
# present) and replaced atomically (a failed download or an invalid
# transfer leaves the existing file untouched).
#
# install.sh copies this script next to the installed wrapper (the PATCHER
# path is baked in, the same way the wrapper gets it) and registers a
# Claude Code SessionEnd hook (in ~/.claude/settings.json) that runs
# `sync_verified_site.sh --with-patch`: at every session end the registry
# is refreshed, and when a NEW version was downloaded the patcher runs on
# the current claude binary with --registry <that file> - DETACHED (its
# own session: SessionEnd hooks share a 1.5 s budget, raised to at most
# 60 s by the configured timeout - a full apply + verify probe takes
# 150 s or more and would be killed mid-run if it ran in the foreground).
# The patcher's output goes to ~/.local/share/claude/.verified_site_sync.log.
#
# A wrapper run of this script (bare, no flag) is SYNC ONLY: the wrapper
# reads the status line and invokes the patcher itself, so the patcher
# runs exactly once per launch.
#
# stdout protocol (the first line is machine-readable, the wrapper parses
# it; the second line is the human-readable message):
#   SYNCED <path>    a new version of the registry was downloaded
#   UNCHANGED <path> the existing registry is up to date (or the sync was
#                    skipped - CLAUDE_WRAPPER_NO_SYNC=1, or REPO_MODE -
#                    the script's folder is the patcher checkout and the
#                    file next to it is the checkout's own tracked
#                    registry, never downloaded over)
#   EXISTING <path>  the download failed; the existing registry is kept
#                    and still usable
#   NONE             no registry is available (download failed or no
#                    source; no file next to the script)
#
# Exit: 0 whenever the sync completed (success or graceful degradation -
# a failed download never fails a session end); 2 on usage errors.
#
# Env: CLAUDE_PATCHER_REGISTRY_URL (the download source; a URL or a local
# file path), CLAUDE_WRAPPER_NO_SYNC=1 (skip the download; an existing
# file is still reported), CLAUDE_WRAPPER_STATE (the wrapper state file,
# used to resolve the current binary in --with-patch mode), SYNC_NO_DETACH=1
# (test hook: run the --with-patch patcher in the foreground instead of
# detached).
set -u
PATCHER="__PATCHER__"
WITH_PATCH=0

usage() {
  cat <<'EOF'
Usage: sync_verified_site.sh [--with-patch]

Downloads the latest verified_sites.json into the folder this script
lives in. --with-patch: when a NEW version was downloaded, also run the
baked-in patcher on the current claude binary with --registry <that
file> (detached, logged to
~/.local/share/claude/.verified_site_sync.log).
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
REG=""
[ -n "$SCRIPT_DIR" ] && REG="$SCRIPT_DIR/verified_sites.json"

REPO_DIR=""
if [ -n "${PATCHER:-}" ] && [ "$PATCHER" != "__PATCHER__" ] && [ -f "$PATCHER" ]; then
  { REPO_DIR="$(cd "$(dirname -- "$PATCHER")" && pwd -P)"; } 2>/dev/null || REPO_DIR=""
fi

# A script run from inside the checkout (the script's folder IS the
# patcher checkout's folder, e.g. the repo copy of this script): the file
# next to it is the checkout's own tracked registry - no download (it
# would replace a tracked file and dirty the working tree).
REPO_MODE=0
if [ -n "$SCRIPT_DIR" ] && [ -n "$REPO_DIR" ]; then
  s="$(readlink -f "$SCRIPT_DIR" 2>/dev/null || true)"
  r="$(readlink -f "$REPO_DIR" 2>/dev/null || true)"
  if [ -n "$s" ] && [ "$s" = "$r" ]; then
    REPO_MODE=1
  fi
fi

# The source of the registry download: CLAUDE_PATCHER_REGISTRY_URL (a URL,
# or a local file path - the test/offline hook, same convention as
# patch.sh), else the raw URL of the checkout's origin remote default
# branch (empty when the checkout is not a github https remote).
registry_url() {
  if [ -n "${CLAUDE_PATCHER_REGISTRY_URL:-}" ]; then
    printf '%s' "${CLAUDE_PATCHER_REGISTRY_URL}"
    return 0
  fi
  local remote branch scheme repo
  [ -n "$REPO_DIR" ] || return 1
  remote="$(git -C "$REPO_DIR" remote get-url origin 2>/dev/null || true)"
  case "$remote" in
    https://github.com/*|http://github.com/*) : ;;
    *) return 1 ;;
  esac
  scheme="https"
  case "$remote" in http://*) scheme="http" ;; esac
  repo="${remote#*://github.com/}"
  repo="${repo%.git}"
  # NOTE: no --short here - it yields "origin/develop", not "develop"
  # (the raw URL would 404). Strip the remote prefix from the full ref.
  branch="$(git -C "$REPO_DIR" symbolic-ref --quiet refs/remotes/origin/HEAD 2>/dev/null || true)"
  branch="${branch#refs/remotes/origin/}"
  [ -n "$branch" ] || branch="develop"
  printf '%s://raw.githubusercontent.com/%s/%s/verified_sites.json' "$scheme" "$repo" "$branch"
}

# Download into a same-folder temp file (validated; mv is the atomic
# replace). Returns 1 on a failed download or an invalid transfer.
download_to() {
  local url out
  url="$(registry_url 2>/dev/null || true)"
  [ -n "$url" ] || return 1
  [ -n "$SCRIPT_DIR" ] || return 1
  out="$(mktemp "$SCRIPT_DIR/.verified_sites.json.XXXXXX" 2>/dev/null)" || return 1
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

# The sync itself. Sets STATUS and REG_PATH (empty for NONE) and prints the
# two stdout lines.
sync_registry() {
  local old new
  if [ -n "${CLAUDE_WRAPPER_NO_SYNC:-}" ]; then
    # Escape: no download. An existing file is still reported (and still
    # usable by the caller); the message says the sync was skipped.
    if [ -f "$REG" ]; then
      STATUS="UNCHANGED"; REG_PATH="$REG"
      echo "UNCHANGED $REG"
      echo "registry: download skipped (CLAUDE_WRAPPER_NO_SYNC=1) - using the existing verified_sites.json next to this script"
    else
      STATUS="NONE"; REG_PATH=""
      echo "NONE"
      echo "registry: download skipped (CLAUDE_WRAPPER_NO_SYNC=1) - no registry file next to this script"
    fi
    return 0
  fi
  if [ "$REPO_MODE" -eq 1 ]; then
    # The file next to the script is the checkout's tracked registry.
    if [ -f "$REG" ]; then
      STATUS="UNCHANGED"; REG_PATH="$REG"
      echo "UNCHANGED $REG"
      echo "registry: run from inside the checkout - the tracked verified_sites.json is used as-is (no download)"
    else
      STATUS="NONE"; REG_PATH=""
      echo "NONE"
      echo "registry: run from inside the checkout - no tracked verified_sites.json found"
    fi
    return 0
  fi
  if [ -f "$REG" ]; then
    old="$(sha256sum "$REG" 2>/dev/null | cut -d' ' -f1)"
  else
    old=""
  fi
  # A download temp file orphaned by a KILLED run (the hook budget can
  # kill the script mid-download; the names are unique per run, so only
  # leftovers are garbage) is removed before the next download.
  rm -f "$SCRIPT_DIR/.verified_sites.json."* 2>/dev/null || true
  if download_to; then
    new="$(sha256sum "$REG" 2>/dev/null | cut -d' ' -f1)"
    if [ -n "$old" ] && [ "$old" = "$new" ]; then
      STATUS="UNCHANGED"; REG_PATH="$REG"
      echo "UNCHANGED $REG"
      echo "registry: verified_sites.json next to this script is up to date"
      return 0
    fi
    STATUS="SYNCED"; REG_PATH="$REG"
    echo "SYNCED $REG"
    echo "registry: verified_sites.json next to this script refreshed from the repository"
    return 0
  fi
  if [ -f "$REG" ]; then
    STATUS="EXISTING"; REG_PATH="$REG"
    echo "EXISTING $REG"
    echo "registry: download failed - using the existing verified_sites.json next to this script"
    return 0
  fi
  STATUS="NONE"; REG_PATH=""
  echo "NONE"
  echo "registry: download failed - the patcher will use the repository registry (and bind locally if the build is unbound there)"
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

# --with-patch (the SessionEnd hook contract): when a NEW version of the
# registry was downloaded, run the patcher on the current claude binary
# with --registry <that file>. Detached: SessionEnd hooks are killed at
# their (at most 60 s) budget, and a full apply + verify probe takes
# 150 s or more (an unbound build 20-60 min); the detached run survives
# the budget and the artifact is promoted only after it VERIFIES (the
# patcher stages it until then). SYNC_NO_DETACH=1 keeps the run in the
# foreground (the test hook).
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
        echo "note: new registry downloaded - the patcher is running in the background on $(basename "$BIN") (log: $LOG)"
      fi
    else
      bash "$PATCHER" --registry "$REG_PATH" "$BIN" >> "$LOG" 2>&1
      echo "note: new registry downloaded - the patcher ran on $(basename "$BIN") (log: $LOG)"
    fi
  fi
fi

exit 0
