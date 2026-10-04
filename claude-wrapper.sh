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
# wrapper runs sync_verified_site.sh from ITS OWN folder (the script keeps
# the local cache ~/.local/share/claude/verified_sites.json current; the
# default source is the GitHub release named after the binary -
# auto-mode-timeout-<name>, the one entry CI publishes for a bound build -
# else CLAUDE_PATCHER_REGISTRY_URL, a full-document URL or local file) and
# reads its status line (SYNCED/UNCHANGED/EXISTING/NONE + the file path).
# The cache path is passed via --registry. A SYNCED cache is passed as-is
# (a newly fetched release entry may carry the binding for a brand-new
# build). With an UNCHANGED or EXISTING cache the wrapper first checks
# whether that cache Binds the target build (the same name+size /
# unique-size lookup the patcher uses, jq, never a guess) - bound: patch
# with the existing file (a missing artifact on a bound build is the
# regenerate contract); unbound (no release for this build yet): patching
# would cost the 20-60 min local bind, so the PREVIOUSLY patched binary
# boots instead (or the raw target when no earlier artifact exists), the
# target is recorded, and every next launch retries the sync (the
# SessionEnd hook keeps the cache fresh; once CI publishes the release,
# the patch lands). CLAUDE_WRAPPER_NO_SYNC=1 skips the fetch (an existing
# cache is still used).
#
# Statusline marker: before the final exec the wrapper exports
# CLAUDE_WRAPPER_PATCHED=1 + CLAUDE_WRAPPER_PATCHED_BUILD=<booted build>
# ONLY when a .patched artifact boots (including a skip boot of the
# previous patched binary); every raw boot unsets both (the marker
# cannot lie). The installed claude-statusline.sh (install.sh) reads it
# and prepends the label to the statusline.
set -u
PATCHER="__PATCHER__"
STATE_FILE="${CLAUDE_WRAPPER_STATE:-$HOME/.local/share/claude/.last_known_version}"

versions_dir=""; origin=""; link_target=""; rec_binary=""; rec_size=""; rec_mtime=""; rec_hash=""
if [ -f "$STATE_FILE" ]; then
  while IFS="=" read -r k v; do
    case "$k" in
      versions_dir) versions_dir="$v" ;;
      origin) origin="$v" ;;
      origin_link_target) link_target="$v" ;;
      binary) rec_binary="$v" ;;
      size) rec_size="$v" ;;
      mtime) rec_mtime="$v" ;;
      hash) rec_hash="$v" ;;
    esac
  done < "$STATE_FILE"
fi

# The real binary: newest non-backup file in the versions dir (one file per
# version; *.bak entries are user backups, *.patched entries are this
# patcher's artifacts, and *.tmp.* entries are the patcher's unmeasured
# STAGED files - none of them is the active binary), falling back to the
# origin recorded at install time.
TARGET=""
if [ -n "$versions_dir" ] && [ -d "$versions_dir" ]; then
  for n in $(ls -t "$versions_dir" 2>/dev/null); do
    case "$n" in *.bak*|*.patched|*.tmp.*) continue ;; esac
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

# --- registry routing (sync_verified_site.sh next to the wrapper) ----------
# WRAPPER_DIR: the folder the wrapper script lives in (the installed copy
# is ~/.local/bin/). SYNC: the sync script next to the wrapper (installed
# by install.sh); its stdout carries the status line (STATUS REG_PATH) and
# the human-readable registry message, which the wrapper relays.
WRAPPER_DIR=""
{ WRAPPER_DIR="$(cd "$(dirname -- "$0")" && pwd -P)"; } 2>/dev/null || WRAPPER_DIR=""
SYNC=""
[ -n "$WRAPPER_DIR" ] && SYNC="$WRAPPER_DIR/sync_verified_site.sh"

# Does this registry bind the build? The SAME no-guess predicate the
# patcher's lookup uses (patch.sh registry_lookup): the binary's own NAME
# when it is a registry key at the binary's SIZE (two versions may ship
# byte-identical-sized builds), else the UNIQUE entry at that size. The
# size comes from stat; the binary is never read. jq-only (the fast path
# the patcher prefers); without jq the lookup is UNKNOWN - the caller
# then patches as before and lets the patcher decide (it carries the
# jq-free Python fallback and its own remote-download chain).
registry_binds() {
  local reg_file="$1" size="$2" name="$3" hit
  command -v jq >/dev/null 2>&1 || return 0
  hit="$(jq -r --argjson size "$size" --arg name "$name" '
      if (type == "object") then
        if ($name | length) > 0
           and has($name)
           and ((.[$name] | type) == "object")
           and (((.[$name].size | type) == "number") and (.[$name].size > 0))
           and (.[$name].size == $size)
        then $name
        else
          [ to_entries[]
            | select((.value | type) == "object")
            | select(((.value.size | type) == "number") and (.value.size > 0))
            | select(.value.size == $size) ] as $m
          | if ($m | length) == 1 then $m[0].key else empty end
        end
      else empty end
    ' "$reg_file" 2>/dev/null || true)"
  [ -n "$hit" ]
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

SKIP_BOOT=""
if [ "$CHANGED" -eq 1 ]; then
  if [ -n "${CLAUDE_WRAPPER_NO_PATCH:-}" ]; then
    echo "[claude-wrapper] changed claude binary $(basename "$TARGET") - patch skipped (CLAUDE_WRAPPER_NO_PATCH set; not recorded, the next normal launch patches it)"
  else
    # Best-effort registry sync (sync_verified_site.sh next to the
    # wrapper; its status line and messages are relayed).
    SYNC_STATUS=""
    SYNC_REG=""
    if [ -f "$SYNC" ]; then
      sync_rc=0
      sync_out="$(bash "$SYNC")" || sync_rc=$?
      if [ -n "$sync_out" ]; then
        printf '%s\n' "$sync_out"
        read -r SYNC_STATUS SYNC_REG <<< "$(printf '%s' "$sync_out" | head -n1)"
      else
        echo "[claude-wrapper] registry sync produced no status (exit $sync_rc) - the patcher uses its default registry"
      fi
    else
      echo "[claude-wrapper] sync script missing next to the wrapper (re-run install.sh) - the patcher uses its default registry"
    fi

    PATCH_ARGS=()
    case "$SYNC_STATUS" in
      SYNCED|UNCHANGED|EXISTING)
        if [ -n "$SYNC_REG" ] && [ -f "$SYNC_REG" ]; then
          PATCH_ARGS=(--registry "$SYNC_REG")
        fi
        ;;
    esac

    # A target the current registry does NOT bind (a brand-new build CI
    # has not recorded yet): patching it would cost the 20-60 min local
    # bind, so the PREVIOUSLY patched binary boots instead (or the raw
    # target when no earlier artifact exists). The target is recorded;
    # the missing-artifact condition keeps every next launch on this
    # path, re-syncing each time (the SessionEnd hook keeps the registry
    # fresh; once CI binds the build, a SYNCED refresh patches it - or
    # the lookup below does, when the current registry already carries
    # the binding). A target that IS bound is never skipped: a missing
    # artifact on a bound build is the regenerate contract, a failed
    # patch is retried.
    if [ -n "$SYNC_REG" ] && [ -f "$SYNC_REG" ] \
       && [ "$SYNC_STATUS" != "SYNCED" ] \
       && ! registry_binds "$SYNC_REG" "$size" "$(basename "$TARGET")"; then
      # The previous patched binary: the newest binary in the versions
      # dir OTHER THAN the target that has a .patched artifact (the
      # recorded binary may already be the new one, recorded on the
      # previous launch); the recorded binary's artifact (a different
      # file) is the fallback for non-native layouts.
      PREV_BOOT=""
      if [ -n "$versions_dir" ] && [ -d "$versions_dir" ]; then
        base="$(basename "$TARGET")"
        for n in $(ls -t "$versions_dir" 2>/dev/null); do
          case "$n" in *.bak*|*.patched|*.tmp*) continue ;; esac
          [ "$n" = "$base" ] && continue
          if [ -f "$versions_dir/$n" ] && [ -f "$versions_dir/$n.patched" ]; then
            PREV_BOOT="$versions_dir/$n.patched"
            break
          fi
        done
      fi
      if [ -z "$PREV_BOOT" ] && [ -n "$rec_binary" ] && [ "$rec_binary" != "$TARGET" ] \
         && [ -f "$rec_binary.patched" ]; then
        PREV_BOOT="$rec_binary.patched"
      fi
      if [ -n "$PREV_BOOT" ]; then
        SKIP_BOOT="$PREV_BOOT"
        echo "[claude-wrapper] build $(basename "$TARGET") is not bound in the current registry - booting the previous patched binary $(basename "$SKIP_BOOT") (retried on every launch until a binding appears)"
      else
        SKIP_BOOT="$TARGET"
        echo "[claude-wrapper] build $(basename "$TARGET") is not bound in the current registry and no earlier patched artifact exists - booting it unpatched (retried on every launch until a binding appears)"
      fi
    fi

    if [ -n "$SKIP_BOOT" ]; then
      # Record the current (new) binary: the missing-artifact condition
      # keeps every next launch on this retry path.
      size=$(stat -c %s "$TARGET")
      mtime=$(stat -c %Y "$TARGET")
      hash="$(sha256sum "$TARGET" | cut -d' ' -f1)"
      write_state "$TARGET" "$hash"
    else
      echo "[claude-wrapper] new/changed claude binary detected: $(basename "$TARGET")"
      echo "[claude-wrapper] running the patcher first (binding a brand-new build can take 20-60 min)..."
      if bash "$PATCHER" ${PATCH_ARGS[@]+"${PATCH_ARGS[@]}"} "$TARGET"; then
        :
      else
        # A failed patcher run must not leave a .patched artifact built
        # from the PREVIOUS binary's content: it would be booted on the
        # next launch (the record now matches the current content).
        rm -f "$TARGET.patched"
        echo "[claude-wrapper] patcher exited non-zero - booting the current binary as-is (re-run the patcher on $TARGET to fix)"
      fi
      size=$(stat -c %s "$TARGET")
      mtime=$(stat -c %Y "$TARGET")
      hash="$(sha256sum "$TARGET" | cut -d' ' -f1)"
      write_state "$TARGET" "$hash"
    fi
  fi
fi

# Exec the skip target when the patch was skipped (the previous patched
# binary, or the raw new one), the patched artifact when the patcher
# produced one (and patching is not skipped); otherwise the unpatched
# binary.
EXEC="$TARGET"
if [ -n "$SKIP_BOOT" ]; then
  EXEC="$SKIP_BOOT"
elif [ -z "${CLAUDE_WRAPPER_NO_PATCH:-}" ] && [ -f "$TARGET.patched" ]; then
  EXEC="$TARGET.patched"
fi

# Statusline marker (read by the installed claude-statusline.sh): set
# ONLY when a PATCHED artifact is what actually boots - the marker must
# never lie (a raw boot, including a CLAUDE_WRAPPER_NO_PATCH override
# and a skip boot of the new unpatched build, carries no marker even
# if the user pre-set the variable).
case "$EXEC" in
  *.patched)
    CLAUDE_WRAPPER_PATCHED=1
    CLAUDE_WRAPPER_PATCHED_BUILD="$(basename "$EXEC" .patched)"
    export CLAUDE_WRAPPER_PATCHED CLAUDE_WRAPPER_PATCHED_BUILD
    ;;
  *)
    unset CLAUDE_WRAPPER_PATCHED CLAUDE_WRAPPER_PATCHED_BUILD
    ;;
esac
exec "$EXEC" "$@"
