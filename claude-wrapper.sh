#!/bin/bash
# claude-wrapper.sh - the launcher template; install.sh copies it to
# ~/.local/bin/claude-wrapper.sh with the PATCHER path baked in (re-run
# install.sh to reinstall, install.sh --uninstall to remove).
#
# Intercepts claude-patched launches: if the real claude binary changed
# since the last launch, run the patcher on it first (a refusal just boots
# the unpatched binary - the wrapper never blocks claude), then exec the
# patched artifact (<binary>.patched) when it exists, falling back to the
# unpatched binary, seamlessly with all original arguments. The native
# claude link is never touched.
#
# Registry routing (on the patching path, before the patcher runs): the
# wrapper downloads the latest verified_sites.json into ITS OWN folder
# (the folder the script lives in; the source is CLAUDE_PATCHER_REGISTRY_URL
# - a URL or a local file path - else the raw URL of the patcher checkout's
# origin remote). When the file exists next to the wrapper the patcher is
# invoked with --registry <that file>; when it does not exist (e.g. an
# offline machine with no earlier download) the patcher runs with its
# default registry (the checkout's verified_sites.json, with its own
# remote-download fallback and local auto-bind). CLAUDE_WRAPPER_NO_SYNC=1
# skips the download (an existing file is still used). A wrapper run from
# inside the checkout (the file next to it is the checkout's own tracked
# registry) downloads nothing and passes no --registry.
set -u
PATCHER="__PATCHER__"
STATE_FILE="${CLAUDE_WRAPPER_STATE:-$HOME/.local/share/claude/.last_known_version}"

versions_dir=""; origin=""; link_target=""; rec_size=""; rec_mtime=""; rec_hash=""
if [ -f "$STATE_FILE" ]; then
  while IFS="=" read -r k v; do
    case "$k" in
      versions_dir) versions_dir="$v" ;;
      origin) origin="$v" ;;
      origin_link_target) link_target="$v" ;;
      size) rec_size="$v" ;;
      mtime) rec_mtime="$v" ;;
      hash) rec_hash="$v" ;;
    esac
  done < "$STATE_FILE"
fi

# The real binary: newest non-backup file in the versions dir (one file per
# version; *.bak entries are user backups and *.patched entries are this
# patcher's artifacts - neither is the active binary), falling back to the
# origin recorded at install time.
TARGET=""
if [ -n "$versions_dir" ] && [ -d "$versions_dir" ]; then
  for n in $(ls -t "$versions_dir" 2>/dev/null); do
    case "$n" in *.bak*|*.patched) continue ;; esac
    if [ -f "$versions_dir/$n" ]; then TARGET="$versions_dir/$n"; break; fi
  done
fi
[ -n "$TARGET" ] || TARGET="$origin"
if [ -z "$TARGET" ] || [ ! -f "$TARGET" ]; then
  echo "[claude-wrapper] no claude binary found (looked in versions dir ${versions_dir:-<none>} and origin ${origin:-<none>})" >&2
  exit 1
fi
if [ "$(basename "$(readlink -f "$TARGET" 2>/dev/null || true)")" = "claude-wrapper.sh" ]; then
  echo "[claude-wrapper] the resolved target is the wrapper itself - the installation is broken; re-run install.sh" >&2
  exit 1
fi

write_state() {
  {
    echo "versions_dir=$versions_dir"
    echo "origin=$origin"
    if [ -n "$link_target" ]; then
      echo "origin_link_target=$link_target"
    fi
    echo "binary=$1"
    echo "version=$(basename "$1")"
    echo "size=$(stat -c %s "$1")"
    echo "mtime=$(stat -c %Y "$1")"
    echo "hash=$2"
  } > "$STATE_FILE"
}

# --- registry routing (the file next to the wrapper) -----------------------
# WRAPPER_DIR: the folder the wrapper script lives in (the installed copy
# is ~/.local/bin/). REG: the registry file next to the wrapper (a
# downloaded copy of the repository's verified_sites.json).
WRAPPER_DIR=""
{ WRAPPER_DIR="$(cd "$(dirname -- "$0")" && pwd -P)"; } 2>/dev/null || WRAPPER_DIR=""
REG=""
[ -n "$WRAPPER_DIR" ] && REG="$WRAPPER_DIR/verified_sites.json"

REPO_DIR=""
{ REPO_DIR="$(cd "$(dirname -- "$PATCHER")" && pwd -P)"; } 2>/dev/null || REPO_DIR=""

# A wrapper run from inside the checkout (same folder as the patcher): the
# file next to it is the checkout's own tracked registry - no download (it
# would replace a tracked file) and no --registry (the patcher's default
# registry is exactly that file).
REPO_MODE=0
if [ -n "$WRAPPER_DIR" ] && [ -n "$REPO_DIR" ]; then
  w="$(readlink -f "$WRAPPER_DIR" 2>/dev/null || true)"
  r="$(readlink -f "$REPO_DIR" 2>/dev/null || true)"
  if [ -n "$w" ] && [ "$w" = "$r" ]; then
    REPO_MODE=1
  fi
fi

# The source of the registry download: CLAUDE_PATCHER_REGISTRY_URL (a URL,
# or a local file path - the test/offline hook, same convention as patch.sh),
# else the raw URL of the checkout's origin remote default branch (empty
# when the checkout is not a github https remote).
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

# Download the latest registry into the wrapper's own folder (an atomic
# replace: a failed download or an invalid transfer leaves the existing
# file untouched). Prints what happened; returns 1 on a failed download.
download_registry() {
  local url out
  url="$(registry_url)" || return 1
  [ -n "$url" ] && [ -n "$REG" ] || return 1
  out="$(mktemp "$WRAPPER_DIR/.verified_sites.json.XXXXXX" 2>/dev/null)" || return 1
  case "$url" in
    /*|./*) cp "$url" "$out" 2>/dev/null || { rm -f "$out"; return 1; } ;;
    *)      curl -fsSL --max-time 30 "$url" -o "$out" 2>/dev/null || { rm -f "$out"; return 1; } ;;
  esac
  [ -s "$out" ] || { rm -f "$out"; return 1; }
  if command -v jq >/dev/null 2>&1; then
    jq -e 'type == "object"' "$out" >/dev/null 2>&1 || { rm -f "$out"; return 1; }
  fi
  if [ -f "$REG" ]; then
    old="$(sha256sum "$REG" 2>/dev/null | cut -d' ' -f1)"
    new="$(sha256sum "$out" | cut -d' ' -f1)"
    if [ -n "$old" ] && [ "$old" = "$new" ]; then
      rm -f "$out"
      echo "[claude-wrapper] registry: verified_sites.json next to the wrapper is up to date"
      return 0
    fi
  fi
  mv -f "$out" "$REG" 2>/dev/null || { rm -f "$out"; return 1; }
  echo "[claude-wrapper] registry: verified_sites.json next to the wrapper refreshed from the repository"
  return 0
}

# Best-effort registry sync before the patcher runs (the patching path
# only): download the latest registry next to the wrapper; when the
# download fails, the existing file (if any) is still used, and without
# one the patcher falls back to its default (checkout) registry.
# CLAUDE_WRAPPER_NO_SYNC=1 skips the download; a wrapper run from inside
# the checkout (REPO_MODE) skips it too.
sync_registry() {
  if [ -n "${CLAUDE_WRAPPER_NO_SYNC:-}" ] || [ "$REPO_MODE" -eq 1 ]; then
    return 0
  fi
  if download_registry; then
    :
  elif [ -f "$REG" ]; then
    echo "[claude-wrapper] registry: download failed - using the existing verified_sites.json next to the wrapper"
  else
    echo "[claude-wrapper] registry: download failed - the patcher will use the repository registry (and bind locally if the build is unbound there)"
  fi
}

size=$(stat -c %s "$TARGET")
mtime=$(stat -c %Y "$TARGET")
CHANGED=0
# A missing .patched artifact counts as changed: a user-deleted artifact is
# regenerated on the next launch, and a patcher that never produced one is
# retried until it does (claude itself always boots - the raw binary is the
# fallback).
if [ -z "$rec_hash" ] || [ ! -f "$TARGET.patched" ]; then
  CHANGED=1
elif [ "$size" != "$rec_size" ] || [ "$mtime" != "$rec_mtime" ]; then
  hash="$(sha256sum "$TARGET" | cut -d' ' -f1)"
  if [ "$hash" = "$rec_hash" ]; then
    write_state "$TARGET" "$hash"   # same content (re-download): record only
  else
    CHANGED=1
  fi
fi

if [ "$CHANGED" -eq 1 ]; then
  if [ -n "${CLAUDE_WRAPPER_NO_PATCH:-}" ]; then
    echo "[claude-wrapper] changed claude binary $(basename "$TARGET") - patch skipped (CLAUDE_WRAPPER_NO_PATCH set; not recorded, the next normal launch patches it)"
  else
    sync_registry
    PATCH_ARGS=()
    if [ "$REPO_MODE" -eq 0 ] && [ -f "$REG" ]; then
      PATCH_ARGS=(--registry "$REG")
    fi
    echo "[claude-wrapper] new/changed claude binary detected: $(basename "$TARGET")"
    echo "[claude-wrapper] running the patcher first (binding a brand-new build can take 20-60 min)..."
    if bash "$PATCHER" ${PATCH_ARGS[@]+"${PATCH_ARGS[@]}"} "$TARGET"; then
      :
    else
      # A failed patcher run must not leave a .patched artifact built from
      # the PREVIOUS binary's content: it would be booted on the next
      # launch (the record now matches the current content).
      rm -f "$TARGET.patched"
      echo "[claude-wrapper] patcher exited non-zero - booting the current binary as-is (re-run the patcher on $TARGET to fix)"
    fi
  fi
  if [ -z "${CLAUDE_WRAPPER_NO_PATCH:-}" ]; then
    size=$(stat -c %s "$TARGET")
    mtime=$(stat -c %Y "$TARGET")
    hash="$(sha256sum "$TARGET" | cut -d' ' -f1)"
    write_state "$TARGET" "$hash"
  fi
fi

# Exec the patched artifact when the patcher produced one (and patching is
# not skipped); otherwise the unpatched binary.
EXEC="$TARGET"
if [ -z "${CLAUDE_WRAPPER_NO_PATCH:-}" ] && [ -f "$TARGET.patched" ]; then
  EXEC="$TARGET.patched"
fi
exec "$EXEC" "$@"
