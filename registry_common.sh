# registry_common.sh - the registry helpers shared by patch.sh,
# sync_verified_site.sh, and the installed claude-wrapper.sh (install.sh
# copies this file next to the installed wrapper and sync script).
#
# Sourced, never executed: the callers set REGISTRY_TOOLS_DIR (this
# checkout's tools/ directory - the lookup's jq-free Python fallback
# imports live_scan from it; empty where the checkout has none, the
# installed wrapper) and source this file from their own directory.
#
# Every helper degrades to "no match / refused" instead of guessing: a
# missing jq, a missing tools directory, a missing github origin, or an
# unparseable transfer never produces a registry entry or a cache write.

# The jq lookup predicate (the no-guess contract): when NAME is a registry
# key whose recorded size equals SIZE, that key is the match - two
# different versions may ship byte-identical-sized binaries (2.1.275 and
# 2.1.276 both record 232,059,192 B), so size alone cannot disambiguate
# them; the name is the native layout's version, which is exactly how the
# registry keys its entries, and the size stays part of the predicate
# either way. Otherwise the build matches the UNIQUE registry entry whose
# recorded size equals SIZE. No match, several matches, or a malformed
# registry -> no output (never a guess). registry_lookup_jq FILE SIZE [NAME]
registry_lookup_jq() {
  jq -r --argjson size "$2" --arg name "${3:-}" '
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
  ' "$1" 2>/dev/null || true
}

# registry_lookup FILE SIZE [NAME]: the jq fast path (the size comes from
# the caller's stat - the binary is never read), falling back to the Python
# matcher without jq (same contract; it imports live_scan from
# REGISTRY_TOOLS_DIR - an empty directory there means no fallback and no
# match, the installed wrapper's case). Prints the matched key, or nothing.
registry_lookup() {
  local reg_file="$1" size="$2" name="${3:-}"
  if command -v jq >/dev/null 2>&1; then
    registry_lookup_jq "$reg_file" "$size" "$name"
  else
    PYTHONPATH="${REGISTRY_TOOLS_DIR:-}" python3 -c '
import sys
import live_scan as ls
try:
    registry = ls.load_verified_sites(sys.argv[1])
except ValueError:
    sys.exit(0)
size = int(sys.argv[2])
name = sys.argv[3] if len(sys.argv) > 3 else ""
if name and name in registry and registry[name].size == size:
    sys.stdout.write(name)
else:
    matches = [e for e in registry.values() if e.size == size]
    if len(matches) == 1:
        sys.stdout.write(matches[0].label)
' "$reg_file" "$size" "$name" 2>/dev/null || true
  fi
}

# registry_release_url REPO_DIR NAME: the release-asset URL for a build
# name (no auth, no API) - the single entry CI publishes as the release
# auto-mode-timeout-<name> of the repository at REPO_DIR (the origin
# remote; github https remotes only, the .git suffix stripped). Returns 1
# when the repository cannot be derived.
registry_release_url() {
  local remote repo
  remote="$(git -C "$1" remote get-url origin 2>/dev/null || true)"
  case "$remote" in
    https://github.com/*|http://github.com/*) : ;;
    *) return 1 ;;
  esac
  repo="${remote#*://github.com/}"
  repo="${repo%.git}"
  printf 'https://github.com/%s/releases/download/auto-mode-timeout-%s/%s' "$repo" "$2" "verified_site.json"
}

# registry_validate_entry FILE: the no-guess shape check for a transfer -
# it must be a single entry object (positive integer size, non-empty
# sites); anything else (a full document, a list, a truncated file) is
# refused. Requires python3 (a machine without it cannot validate, so the
# transfer is refused, never accepted).
registry_validate_entry() {
  python3 - "$1" <<'PY' 2>/dev/null
import json, sys
try:
    with open(sys.argv[1], encoding="utf-8") as f:
        d = json.load(f)
except ValueError:
    sys.exit(1)
ok = (isinstance(d, dict)
      and isinstance(d.get("size"), int)
      and not isinstance(d.get("size"), bool)
      and d.get("size", 0) > 0
      and isinstance(d.get("sites"), list)
      and len(d.get("sites")) > 0)
sys.exit(0 if ok else 1)
PY
}

# registry_merge_entry CACHE ENTRY_FILE NAME: {existing cache, NAME:
# entry}, printed as the cache's JSON (a missing or unreadable cache is
# {} - the merge is the caller's atomic-replace half).
registry_merge_entry() {
  python3 - "$1" "$2" "$3" <<'PY' 2>/dev/null
import json, sys
try:
    with open(sys.argv[1], encoding="utf-8") as f:
        old = json.load(f)
    if not isinstance(old, dict):
        old = {}
except (OSError, ValueError):
    old = {}
with open(sys.argv[2], encoding="utf-8") as f:
    new = json.load(f)
print(json.dumps({**old, sys.argv[3]: new}, indent=2))
PY
}

# registry_download_doc URL OUT: fetch a registry document (a URL, or a
# local file path - the CLAUDE_PATCHER_REGISTRY_URL hook) into OUT. The
# transfer must be non-empty and, when jq is present, a JSON object; a
# failed or invalid transfer removes OUT and returns 1.
registry_download_doc() {
  local url="$1" out="$2"
  case "$url" in
    /*|./*) cp "$url" "$out" 2>/dev/null || { rm -f "$out"; return 1; } ;;
    *)      curl -fsSL --max-time 30 "$url" -o "$out" 2>/dev/null || { rm -f "$out"; return 1; } ;;
  esac
  [ -s "$out" ] || { rm -f "$out"; return 1; }
  if command -v jq >/dev/null 2>&1; then
    jq -e 'type == "object"' "$out" >/dev/null 2>&1 || { rm -f "$out"; return 1; }
  fi
  return 0
}

# newest_non_backup DIR [EXCLUDE]: the newest non-backup file in DIR (one
# file per version; *.bak entries are user backups, *.patched entries are
# the patcher's artifacts, and *.tmp.* entries are the patcher's
# unmeasured staged files - none of them is the active binary). Prints
# the name, returns 1 when the directory holds none (EXCLUDE, when set,
# is skipped).
newest_non_backup() {
  local dir="$1" exclude="${2:-}" n
  for n in $(ls -t "$dir" 2>/dev/null); do
    case "$n" in *.bak*|*.patched|*.tmp.*) continue ;; esac
    if [ -n "$exclude" ] && [ "$n" = "$exclude" ]; then
      continue
    fi
    if [ -f "$dir/$n" ]; then
      printf '%s' "$n"
      return 0
    fi
  done
  return 1
}

# newest_patched DIR [EXCLUDE]: like newest_non_backup, but the file must
# also carry its .patched artifact (the "previous patched binary" scan).
newest_patched() {
  local dir="$1" exclude="${2:-}" n
  for n in $(ls -t "$dir" 2>/dev/null); do
    case "$n" in *.bak*|*.patched|*.tmp.*) continue ;; esac
    if [ -n "$exclude" ] && [ "$n" = "$exclude" ]; then
      continue
    fi
    if [ -f "$dir/$n" ] && [ -f "$dir/$n.patched" ]; then
      printf '%s' "$n"
      return 0
    fi
  done
  return 1
}
