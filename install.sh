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
#     patcher path is baked in at install time). Before patching, the
#     wrapper runs sync_verified_site.sh (also installed next to the
#     wrapper, patcher path baked in): it downloads the latest
#     verified_sites.json into its own folder; the patcher is passed
#     --registry <that file> when it exists, and runs against the
#     checkout's registry (with its own download fallback and local
#     auto-bind) when it does not. A NEW claude binary that is not yet
#     bound in the current registry boots the PREVIOUSLY patched binary
#     instead (retried on every launch; once CI binds the build, the
#     patch lands).
#
#   SessionEnd hook (~/.claude/settings.json, the file is MERGED, never
#     clobbered; an unparseable file is refused): at every Claude Code
#     session end the installed sync script runs with --with-patch - it
#     refreshes the registry, and when a NEW version was downloaded the
#     patcher runs on the current claude binary with --registry <that
#     file>, detached (the hook budget is at most 60 s; the patch is
#     logged to ~/.local/share/claude/.verified_site_sync.log and the
#     artifact is promoted only after it verifies).
#
#   Statusline marker (~/.local/bin/claude-statusline.sh + the
#     claude-statusline.orig sidecar next to it): the statusLine command
#     in ~/.claude/settings.json is swapped to the marker script (the
#     same merge contract as the hook - never clobbered, an unparseable
#     file is refused, the other fields such as refreshInterval are
#     kept, the merge is idempotent). The user's existing statusline
#     command is recorded verbatim in the sidecar; the script runs it
#     (the same session JSON on stdin, a 5 s guard against a hung
#     original) and prepends the label (default "⚙ (patched)",
#     CLAUDE_WRAPPER_PATCHED_LABEL overrides it) to the FIRST line only
#     when the wrapper booted a PATCHED binary (it exports
#     CLAUDE_WRAPPER_PATCHED=1 for that boot and unsets it for every
#     raw boot - the marker cannot lie). Unpatched launches print the
#     statusline verbatim; without an original statusline nothing is
#     printed (the label alone when patched). Uninstall restores the
#     recorded command verbatim (or removes the key the installer
#     created, and the file when it becomes empty).
#
#   State: ~/.local/share/claude/.last_known_version (key=value; the
#     recorded binary identity is what "changed since last time" means).
#     An empty recorded hash (fresh install) counts as "changed", so the
#     first launch patches.
#
# Usage:
#   ./install.sh               install claude-patched (wrapper + the new
#                              link + the sync script + the SessionEnd
#                              hook + the statusline marker)
#   ./install.sh --uninstall   remove claude-patched, the wrapper, the
#                              sync script, the marker, the hook, the
#                              recorded statusline, and the state file
#                              (claude was never modified)
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
#   CLAUDE_WRAPPER_NO_SYNC=1 at claude-patched runtime: skip the registry
#     download the wrapper performs before patching (an existing
#     verified_sites.json next to the wrapper is still used; without one
#     the patcher falls back to the repository registry).
#   CLAUDE_PATCHER_REGISTRY_URL: source of that registry download (a URL,
#     or a local file path); default is the raw URL of the patcher
#     checkout's origin remote.
#
# Note: a claude self-update re-points the native `claude` link at the
# new version; claude-patched (and the wrapper it names) are left alone,
# so no reinstall is needed.
set -u

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PATCHER="${CLAUDE_PATCHER_SCRIPT:-$ROOT/patch.sh}"
WRAPPER_SRC="$ROOT/claude-wrapper.sh"
SYNC_SRC="$ROOT/sync_verified_site.sh"
UNINSTALL=0
[ "${1:-}" = "--uninstall" ] && UNINSTALL=1

HOME_BIN="$HOME/.local/bin"
BIN_LINK="$HOME_BIN/claude"
LOCAL_LINK="$HOME_BIN/claude-patched"
WRAPPER="$HOME_BIN/claude-wrapper.sh"
SYNC="$HOME_BIN/sync_verified_site.sh"
SETTINGS="$HOME/.claude/settings.json"
STATE_FILE="${CLAUDE_WRAPPER_STATE:-$HOME/.local/share/claude/.last_known_version}"
VERSIONS_DIR_DEFAULT="$HOME/.local/share/claude/versions"
HOOK_COMMAND="$SYNC --with-patch"
STATUSLINE_SRC="$ROOT/claude-statusline.sh"
STATUSLINE="$HOME_BIN/claude-statusline.sh"
STATUSLINE_ORIG="$HOME_BIN/claude-statusline.orig"
STATUSLINE_COMMAND="bash $HOME_BIN/claude-statusline.sh"

state_get() {
  grep "^$1=" "$STATE_FILE" 2>/dev/null | head -n1 | cut -d= -f2-
}

# The SessionEnd hook in ~/.claude/settings.json (mode, command, file):
# MERGES the one hook group into the user's settings - the file is never
# clobbered (an unparseable file is refused), the write is atomic, and a
# re-install replaces the existing entry instead of duplicating it.
hook_settings() {
  python3 - "$1" "$2" "$3" <<'PYEOF'
import json, os, sys

mode, command, path = sys.argv[1], sys.argv[2], sys.argv[3]
doc = {}
if os.path.exists(path):
    try:
        with open(path, encoding="utf-8") as f:
            doc = json.load(f)
    except (ValueError, OSError) as exc:
        print(f"error: cannot parse {path} ({exc}); refusing to modify it",
              file=sys.stderr)
        sys.exit(2)
if not isinstance(doc, dict):
    print(f"error: {path} does not hold a JSON object; refusing to modify it",
          file=sys.stderr)
    sys.exit(2)

entry = {"type": "command", "command": command, "timeout": 60}
hooks = doc.get("hooks")
if mode == "add":
    if not isinstance(hooks, dict):
        hooks = {}
        doc["hooks"] = hooks
    groups = hooks.get("SessionEnd")
    if not isinstance(groups, list):
        groups = []
        hooks["SessionEnd"] = groups
    replaced = False
    for group in groups:
        handlers = group.get("hooks") if isinstance(group, dict) else None
        if not isinstance(handlers, list):
            continue
        for i, handler in enumerate(handlers):
            if isinstance(handler, dict) and handler.get("command") == command:
                handlers[i] = entry
                replaced = True
                break
        if replaced:
            break
    if not replaced:
        groups.append({"hooks": [entry]})
else:
    if isinstance(hooks, dict):
        groups = hooks.get("SessionEnd")
        if isinstance(groups, list):
            kept_groups = []
            for group in groups:
                handlers = group.get("hooks") if isinstance(group, dict) else None
                if not isinstance(handlers, list):
                    kept_groups.append(group)
                    continue
                kept = [h for h in handlers
                        if not (isinstance(h, dict) and h.get("command") == command)]
                if kept:
                    group["hooks"] = kept
                    kept_groups.append(group)
            if kept_groups:
                hooks["SessionEnd"] = kept_groups
            else:
                del hooks["SessionEnd"]
            if not hooks:
                del doc["hooks"]
    if not doc:
        if os.path.exists(path):
            os.remove(path)
            print(f"removed the SessionEnd hook ({path} held no other settings)")
        sys.exit(0)

tmp = path + ".tmp-{}".format(os.getpid())
with open(tmp, "w", encoding="utf-8") as f:
    json.dump(doc, f, indent=2)
    f.write("\n")
os.replace(tmp, path)
PYEOF
}

# The statusline marker in ~/.claude/settings.json (mode, file, sidecar,
# the marker command): the SAME merge contract as the hook - the file is
# never clobbered (an unparseable file is refused), the write is atomic,
# the merge is idempotent. add: the user's existing statusline command is
# recorded verbatim in the sidecar next to the marker script (the script
# chains it: runs it with the same session JSON on stdin) and the
# statusLine command is swapped to the marker script - the other fields
# (type, refreshInterval, ...) are kept; without a usable statusline one
# is created and a stale sidecar is dropped. remove: the recorded
# command is restored verbatim (the sidecar deleted), or the statusLine
# key is removed when the installer created it (the file deleted when it
# becomes empty); a statusline that is no longer ours (the user swapped
# it out) is left as found, the dead sidecar is dropped.
statusline_settings() {
  python3 - "$1" "$2" "$3" "$4" <<'PYEOF'
import json, os, sys

mode, path, orig, ours = sys.argv[1:5]
doc = {}
if os.path.exists(path):
    try:
        with open(path, encoding="utf-8") as f:
            doc = json.load(f)
    except (ValueError, OSError) as exc:
        print(f"error: cannot parse {path} ({exc}); refusing to modify it",
              file=sys.stderr)
        sys.exit(2)
if not isinstance(doc, dict):
    print(f"error: {path} does not hold a JSON object; refusing to modify it",
          file=sys.stderr)
    sys.exit(2)

sl = doc.get("statusLine")
if mode == "add":
    if isinstance(sl, dict) and sl.get("command") == ours:
        sys.exit(0)  # already ours (re-install): the sidecar stays
    if isinstance(sl, dict) and isinstance(sl.get("command"), str) \
            and sl["command"]:
        with open(orig, "w", encoding="utf-8") as f:
            f.write(sl["command"])
        sl.setdefault("type", "command")
        sl["command"] = ours
    else:
        doc["statusLine"] = {"type": "command", "command": ours}
        if os.path.exists(orig):
            os.remove(orig)
else:
    if isinstance(sl, dict) and sl.get("command") == ours:
        if os.path.exists(orig):
            with open(orig, encoding="utf-8") as f:
                original = f.read().rstrip("\n")
            os.remove(orig)
            if original:
                sl["command"] = original
            else:
                del doc["statusLine"]
        else:
            del doc["statusLine"]
    else:
        if os.path.exists(orig):
            os.remove(orig)
        sys.exit(0)  # not ours: the settings are left as found
    if not doc:
        if os.path.exists(path):
            os.remove(path)
            print(f"restored the statusline ({path} held no other settings)")
        sys.exit(0)

tmp = path + ".tmp-{}".format(os.getpid())
with open(tmp, "w", encoding="utf-8") as f:
    json.dump(doc, f, indent=2)
    f.write("\n")
os.replace(tmp, path)
PYEOF
}

if [ "$UNINSTALL" -eq 1 ]; then
  [ -f "$STATE_FILE" ] || { echo "no installation found (no state file $STATE_FILE)" >&2; exit 1; }
  # The hook is removed BEFORE anything else: a file the installer cannot
  # parse is refused, and the uninstall stops with the machine as found.
  if [ -f "$SETTINGS" ]; then
    if ! hook_settings remove "$HOOK_COMMAND" "$SETTINGS"; then
      echo "error: could not remove the SessionEnd hook from $SETTINGS - nothing was removed" >&2
      exit 1
    fi
  fi
  # The user's statusline is restored from the sidecar BEFORE the
  # sidecar (and the marker script) are deleted.
  if [ -f "$SETTINGS" ]; then
    if ! statusline_settings remove "$SETTINGS" "$STATUSLINE_ORIG" "$STATUSLINE_COMMAND"; then
      echo "error: could not restore the statusline in $SETTINGS (the SessionEnd hook was already removed; fix the file and re-run --uninstall)" >&2
      exit 1
    fi
  fi
  rm -f "$LOCAL_LINK"
  rm -f "$WRAPPER" "$SYNC" "$STATUSLINE" "$STATUSLINE_ORIG" "$HOME_BIN/verified_sites.json" "$STATE_FILE"
  echo "removed $LOCAL_LINK, the wrapper, the sync script, the statusline"
  echo "marker, the downloaded registry, the SessionEnd hook, and the state file."
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
[ -f "$SYNC_SRC" ] || { echo "error: sync script source $SYNC_SRC not found" >&2; exit 2; }
[ -f "$STATUSLINE_SRC" ] || { echo "error: statusline script source $STATUSLINE_SRC not found" >&2; exit 2; }

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

# The wrapper and the sync script (PATCHER baked in at install time; the
# sync script's folder is the registry download destination - the same
# folder as the wrapper, so the file lands next to both).
cp "$WRAPPER_SRC" "$WRAPPER"
sed -i "s|^PATCHER=.*|PATCHER=\"$PATCHER\"|" "$WRAPPER"
chmod +x "$WRAPPER"
cp "$SYNC_SRC" "$SYNC"
sed -i "s|^PATCHER=.*|PATCHER=\"$PATCHER\"|" "$SYNC"
chmod +x "$SYNC"
# The statusline marker script (self-locating - nothing baked in): it
# runs the user's existing statusline (recorded in the .orig sidecar
# next to it) and prepends the label when a PATCHED binary boots.
cp "$STATUSLINE_SRC" "$STATUSLINE"
chmod +x "$STATUSLINE"

# The SessionEnd hook (merges into the user's settings.json).
mkdir -p "$HOME/.claude"
if ! hook_settings add "$HOOK_COMMAND" "$SETTINGS"; then
  echo "error: could not add the SessionEnd hook to $SETTINGS - the rest of the install was removed" >&2
  rm -f "$WRAPPER" "$SYNC" "$STATUSLINE" "$STATUSLINE_ORIG" "$LOCAL_LINK"
  exit 2
fi

# The statusline marker (the same merge contract: the user's existing
# statusline is recorded in the sidecar next to the script and restored
# verbatim on uninstall; without one, the key is created, no sidecar).
if ! statusline_settings add "$SETTINGS" "$STATUSLINE_ORIG" "$STATUSLINE_COMMAND"; then
  echo "error: could not merge the statusline marker into $SETTINGS - the rest of the install was removed" >&2
  rm -f "$WRAPPER" "$SYNC" "$STATUSLINE" "$STATUSLINE_ORIG" "$LOCAL_LINK"
  exit 2
fi

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
echo "  registry: before patching, $SYNC downloads the latest"
echo "  verified_sites.json into $HOME_BIN (the patcher uses it when present,"
echo "  the checkout's registry when not; CLAUDE_WRAPPER_NO_SYNC=1 skips it)."
echo "  hook: at every Claude Code session end, $SYNC --with-patch"
echo "  refreshes the registry and - when a new version was downloaded -"
echo "  patches the current binary detached (log: $HOME/.local/share/claude/.verified_site_sync.log);"
echo "  registered in $SETTINGS as the SessionEnd hook (merged, never clobbered)."
echo "  statusline: $STATUSLINE is now the statusLine command in $SETTINGS;"
echo "  when a PATCHED binary boots it prepends the label (default"
echo "  '⚙ (patched)', CLAUDE_WRAPPER_PATCHED_LABEL overrides it) to your existing"
echo "  statusline (recorded in $STATUSLINE_ORIG, restored on uninstall);"
echo "  unpatched boots print it verbatim."
echo "  state: $STATE_FILE (no hash recorded - the FIRST claude-patched launch"
echo "  runs the patcher; on a brand-new build that first bind can take 20-60 min)."
echo "  skip once with CLAUDE_WRAPPER_NO_PATCH=1, remove with: $0 --uninstall"
