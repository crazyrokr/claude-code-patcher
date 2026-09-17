#!/bin/bash
# install.sh - install the claude-launch interceptor.
#
# What gets installed:
#   ~/.local/bin/claude-patched -> ~/.local/bin/claude-wrapper.sh - the
#     launcher that intercepts claude launches WITHOUT touching the
#     native `claude` link (which stays exactly as claude's own updater
#     leaves it: a self-update re-points `claude` at the new version and
#     cannot break claude-patched). On every claude-patched start the
#     wrapper resolves the real claude binary (the newest non-backup file
#     under ~/.local/share/claude/versions/, falling back to the origin
#     recorded at install time), and if that binary changed since the last
#     launch - size+mtime fast check, sha256 to confirm - it runs the
#     patcher on it first (automatic oracle bind; the verified patch lands
#     in the <binary>.patched artifact next to the unmodified original; a
#     refusal just boots the unpatched binary), then execs the patched
#     artifact (<binary>.patched) when it exists - falling back to the
#     unpatched binary - with all original arguments. The wrapper always
#     execs the resolved target - never `claude` from PATH. The installed
#     wrapper is a copy of claude-wrapper.sh from this directory (the
#     patcher path is baked in at install time).
#
#   State: ~/.local/share/claude/.last_known_version (key=value; the
#     recorded binary identity is what "changed since last time" means).
#     An empty recorded hash (fresh install) counts as "changed", so the
#     first launch patches.
#
# Usage:
#   ./install.sh               install claude-patched (wrapper + the new link)
#   ./install.sh --uninstall   remove claude-patched, the wrapper, and the
#                              state file (claude was never modified)
#
# Requirements: ~/.local/bin/claude must exist - a symlink (the native
# claude layout links it to ~/.local/share/claude/versions/<ver>) or a
# plain file; the installer never touches it, it only reads where it
# points. A pre-existing claude-patched that is a PLAIN FILE is refused
# (the installer does not clobber user files - remove or rename it
# first); a pre-existing claude-patched symlink (a previous install) is
# replaced.
#
# Env overrides:
#   CLAUDE_PATCHER_SCRIPT  patcher to bake in (default: patch.sh next to install.sh)
#   CLAUDE_WRAPPER_STATE   state file (default: ~/.local/share/claude/.last_known_version)
#   CLAUDE_WRAPPER_NO_PATCH=1 at claude-patched runtime: boot the unpatched
#     binary without patching - even when a patched artifact exists - and
#     without recording the new binary (the next normal launch patches).
#
# Note: a claude self-update re-points the native `claude` link at the
# new version; claude-patched (and the wrapper it names) are left alone,
# so no reinstall is needed.
set -u

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PATCHER="${CLAUDE_PATCHER_SCRIPT:-$ROOT/patch.sh}"
WRAPPER_SRC="$ROOT/claude-wrapper.sh"
UNINSTALL=0
[ "${1:-}" = "--uninstall" ] && UNINSTALL=1

HOME_BIN="$HOME/.local/bin"
BIN_LINK="$HOME_BIN/claude"
LOCAL_LINK="$HOME_BIN/claude-patched"
WRAPPER="$HOME_BIN/claude-wrapper.sh"
STATE_FILE="${CLAUDE_WRAPPER_STATE:-$HOME/.local/share/claude/.last_known_version}"
VERSIONS_DIR_DEFAULT="$HOME/.local/share/claude/versions"

state_get() {
  grep "^$1=" "$STATE_FILE" 2>/dev/null | head -n1 | cut -d= -f2-
}

if [ "$UNINSTALL" -eq 1 ]; then
  [ -f "$STATE_FILE" ] || { echo "no installation found (no state file $STATE_FILE)" >&2; exit 1; }
  rm -f "$LOCAL_LINK"
  rm -f "$WRAPPER" "$STATE_FILE"
  echo "removed $LOCAL_LINK, the wrapper, and the state file."
  echo "claude was never modified; nothing else to restore."
  exit 0
fi

[ -d "$HOME_BIN" ] || { echo "error: $HOME_BIN does not exist; install claude first" >&2; exit 2; }
[ -e "$BIN_LINK" ] || { echo "error: $BIN_LINK does not exist; install claude first" >&2; exit 2; }
[ -L "$BIN_LINK" ] || [ -f "$BIN_LINK" ] || {
  echo "error: $BIN_LINK is not a readable file or symlink" >&2
  exit 2
}
if [ -e "$LOCAL_LINK" ] && [ ! -L "$LOCAL_LINK" ]; then
  echo "error: $LOCAL_LINK exists and is a plain file - the installer does not"
  echo "clobber user files. Remove or rename it, then re-run this script." >&2
  exit 2
fi
[ -f "$PATCHER" ] || { echo "error: patcher $PATCHER not found" >&2; exit 2; }
[ -f "$WRAPPER_SRC" ] || { echo "error: wrapper source $WRAPPER_SRC not found" >&2; exit 2; }

ORIGIN="$(readlink -f "$BIN_LINK" 2>/dev/null || true)"
[ -n "$ORIGIN" ] || { echo "error: cannot resolve the real claude binary behind $BIN_LINK" >&2; exit 2; }
CURRENT_TARGET="$(readlink "$BIN_LINK" 2>/dev/null || true)"

# claude native layout: the versions dir holds one binary file per version
# (*.bak entries are user backups, never the active binary; *.patched
# entries are this patcher's artifacts, never the active binary either).
# Other layouts track the origin file directly (versions_dir stays empty).
VERSIONS_DIR=""
case "$ORIGIN" in
  "$VERSIONS_DIR_DEFAULT"/*) VERSIONS_DIR="$VERSIONS_DIR_DEFAULT" ;;
esac

mkdir -p "$(dirname "$STATE_FILE")"

# The wrapper (PATCHER baked in at install time).
cp "$WRAPPER_SRC" "$WRAPPER"
sed -i "s|^PATCHER=.*|PATCHER=\"$PATCHER\"|" "$WRAPPER"
chmod +x "$WRAPPER"

# Initialize the state: no recorded hash yet, so the first launch patches.
{
  echo "versions_dir=$VERSIONS_DIR"
  echo "origin=$ORIGIN"
  echo "origin_link_target=$CURRENT_TARGET"
  echo "binary="
  echo "version="
  echo "size="
  echo "mtime="
  echo "hash="
} > "$STATE_FILE"

ln -sf "$WRAPPER" "$LOCAL_LINK"

echo "installed: $LOCAL_LINK now launches via $WRAPPER (the native"
echo "$BIN_LINK link is untouched: $(readlink "$BIN_LINK" 2>/dev/null || echo '<plain file>'))"
echo "  real binary tracked: $ORIGIN (versions dir: ${VERSIONS_DIR:-none})"
echo "  patcher baked in: $PATCHER"
echo "  state: $STATE_FILE (no hash recorded - the FIRST claude-patched launch"
echo "  runs the patcher; on a brand-new build that first bind can take 20-60 min)."
echo "  skip once with CLAUDE_WRAPPER_NO_PATCH=1, remove with: $0 --uninstall"
