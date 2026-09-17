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
    echo "[claude-wrapper] new/changed claude binary detected: $(basename "$TARGET")"
    echo "[claude-wrapper] running the patcher first (binding a brand-new build can take 20-60 min)..."
    if bash "$PATCHER" "$TARGET"; then
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
