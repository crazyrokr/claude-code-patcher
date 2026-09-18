#!/usr/bin/env bash
# One-line patch for a Claude Code SFE binary: apply the oracle-verified
# classifier timeout patch and verify the wait really increased.
#
# Usage:
#   ./patch.sh <binary>                    bind (if needed) + apply + verify
#   ./patch.sh <binary> --no-auto-bind     apply only from the registry; refuse unbound builds
#   ./patch.sh <binary> --baseline         also probe the unpatched binary
#                                          (in parallel with the verify probe)
#   ./patch.sh <binary> --no-verify        apply only, skip the probe
#   ./patch.sh <binary> --timeout 150      probe timeout in seconds
#   ./patch.sh <binary> --fast-verify [N]  verify at an early check point (opt-in)
#   ./patch.sh <binary> --registry PATH    a different verified_sites registry
#
# Registry lookup: the build is matched to the registry entry whose recorded
# size equals the binary's size - first by the binary's own NAME when it is a
# registry key at that size (two different versions may ship
# byte-identical-sized binaries, 2.1.275 and 2.1.276 do, so size alone cannot
# disambiguate; the name is the native layout's version, the registry key of
# each build), else by UNIQUE size - no match, several matches, or a malformed
# registry is a refusal, never a guess. The lookup is jq-based (the size comes
# from stat, the binary is never read); without jq it falls back to the Python
# matcher. A build not bound in the LOCAL registry may already be
# bound in the repo copy (recorded by CI): for the default registry only, a
# local miss fetches verified_sites.json from the repository
# (CLAUDE_PATCHER_REGISTRY_URL, or the origin remote's default branch) and
# applies from that without a local probe. An explicit --registry is used
# exactly as given (no download).
#
# A build with no binding anywhere is bound first, automatically (the default;
# --no-auto-bind refuses instead): the oracle pipeline (oracle_bind_auto.py)
# measures the wait driver, the ceiling, and the max-wait boundary with
# blackhole probes, records the binding in the registry, and only then is the
# patch applied. Nothing is guessed: every site and target is
# measurement-defined, and a signal that does not match the measured model
# refuses instead of patching.
#
# Verify runs the blackhole probe on the .patched artifact: rc=124 (killed at
# the timeout, still waiting) means the wait is really extended; a fast clean
# exit means the wait collapsed and the artifact is marked NOT VERIFIED.
# With --fast-verify [N] the probe additionally checks the endpoint log at N
# seconds (default 70, floor 65 - an unpatched build is already on classifier
# attempt two by then): exactly one blackholed attempt means the first wait
# is still running and the patch verifies there; without that line the
# usual cap result decides (a probe script without early-check support
# degrades to the full cap automatically). With --baseline, the baseline
# probe runs in parallel with the verify probe (each owns its endpoint
# port and working directory).
#
# Symlinks: a binary path that is a symlink is resolved first; binding,
# patching, and the .patched artifact all use the real path and the
# target's name (the symlink keeps working).
#
# No in-place replacement: the original binary is never renamed or
# modified; the patch always stays in the <name>.patched artifact next to
# it (run that file to use the patched build). A pre-existing .patched is
# rewritten from the current binary's bytes by every successful apply; a
# refused apply leaves a pre-existing .patched untouched and says so (it
# may predate the current bytes). --no-verify leaves the unmeasured
# .patched. Re-running the patcher on the same binary just regenerates the
# artifact (the original never changes, so the recorded bytes keep
# matching).
#
# CLASSIFIER_PROBE_SCRIPT: optional path to a probe script with the
# run_probe.sh contract (used instead of tools/binder/run_probe.sh;
# for tests).
#
# Exit codes: 0 = patched and verified; 1 = apply refused or verify failed;
# 2 = bad usage.
set -u

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REC="$ROOT/tools/binder"
RUN_PROBE="${CLASSIFIER_PROBE_SCRIPT:-$REC/run_probe.sh}"

usage() {
  cat <<'EOF'
Usage: ./patch.sh <binary> [options]

Options:
  --no-auto-bind   apply only from the registry; refuse unbound builds
  --baseline       also probe the unpatched binary (in parallel with the
                   verify probe; informational)
  --no-verify      apply only, skip the blackhole verification probe
  --timeout N      probe timeout in seconds (default 150)
  --fast-verify [N]
                   verify at an early check point instead of waiting out the
                   full cap (opt-in, default 70 s, floor 65 s): at N seconds
                   the probe checks the endpoint log - exactly one blackholed
                   classifier attempt means the first wait is still running
                   (an unpatched build is already on attempt two by then) and
                   the patch is verified there. A probe script without early-
                   check support degrades to the full cap automatically.
  --registry PATH  use a different verified_sites registry
  -h, --help       show this help

Behavior:
  * A symlink is resolved first: binding, patching, and the .patched
    artifact use the real path and the target's name (the link keeps
    working).
  * The original binary is never renamed or modified: the patch stays in
    <name>.patched next to it (a verified success, or an unmeasured one
    with --no-verify). A refused apply leaves a stale .patched untouched
    and says so; re-running on the same binary just regenerates it.
  * The build is matched to the registry: by its own NAME when the name is a
    registry key at the binary's size (two versions may ship
    byte-identical-sized builds), else by UNIQUE size (jq, falling back to
    Python). A build not in the local registry may be bound in the repo copy
    (recorded by CI): the default registry is then fetched from the repository
    and applied from, with no local probe. --registry PATH is used exactly
    (no download).
EOF
}

BIN=""
VERIFY=1
BASELINE=0
AUTO_BIND=1
FAST_VERIFY=0
FAST_CHECK=""
REG_PATH=""
PROBE_TIMEOUT=150

while [ $# -gt 0 ]; do
  case "$1" in
    --no-verify) VERIFY=0 ;;
    --baseline) BASELINE=1 ;;
    --no-auto-bind) AUTO_BIND=0 ;;
    --fast-verify)
      FAST_VERIFY=1
      if [ $# -gt 1 ]; then
        case "$2" in
          ''|*[!0-9]*) : ;;
          *) shift; FAST_CHECK="$1" ;;
        esac
      fi
      ;;
    --timeout)
      shift
      [ $# -gt 0 ] || { echo "error: --timeout needs a value" >&2; exit 2; }
      case "$1" in
        ''|*[!0-9]*) echo "error: --timeout expects a positive integer" >&2; exit 2 ;;
      esac
      # CLAUDE_PATCHER_TIMEOUT_FLOOR (default 15 s): a shorter cap cannot
      # observe a wait. A test hook, like CLAUDE_PATCHER_FAST_FLOOR.
      [ "$1" -ge "${CLAUDE_PATCHER_TIMEOUT_FLOOR:-15}" ] || {
        echo "error: --timeout below the ${CLAUDE_PATCHER_TIMEOUT_FLOOR:-15} s floor cannot observe a wait" >&2; exit 2; }
      PROBE_TIMEOUT="$1"
      ;;
    --registry)
      shift
      [ $# -gt 0 ] || { echo "error: --registry needs a path" >&2; exit 2; }
      REG_PATH="$1"
      ;;
    -h|--help) usage; exit 0 ;;
    -*) echo "error: unknown option $1" >&2; usage >&2; exit 2 ;;
    *)
      [ -z "$BIN" ] || { echo "error: exactly one binary argument" >&2; exit 2; }
      BIN="$1"
      ;;
  esac
  shift
done

if [ -z "$BIN" ]; then
  echo "error: missing <binary> argument" >&2
  usage >&2
  exit 2
fi
case "$BIN" in
  /*) : ;;
  *) BIN="$PWD/$BIN" ;;
esac
[ -f "$BIN" ] || { echo "error: binary $BIN not found" >&2; exit 2; }
if [ -L "$BIN" ]; then
  REAL="$(readlink -f "$BIN" 2>/dev/null || true)"
  if [ -z "$REAL" ] || [ ! -f "$REAL" ]; then
    echo "error: $BIN does not resolve to a readable file" >&2
    exit 2
  fi
  echo "symlink: $BIN -> $REAL (working on the real path and name)"
  BIN="$REAL"
fi
if [ "$FAST_VERIFY" -eq 1 ]; then
  if [ "$VERIFY" -eq 0 ]; then
    echo "error: --fast-verify requires verification (--no-verify is not allowed)" >&2
    exit 2
  fi
  if [ -z "$FAST_CHECK" ]; then
    FAST_CHECK=70
  fi
  if [ "$FAST_CHECK" -lt "${CLAUDE_PATCHER_FAST_FLOOR:-65}" ]; then
    echo "error: --fast-verify check point ${FAST_CHECK}s is below the" \
      "${CLAUDE_PATCHER_FAST_FLOOR:-65}s floor (it must outlast the" \
      "unpatched ~60 s per-attempt wait plus startup)" >&2
    exit 2
  fi
fi

REG_FILE="${REG_PATH:-$ROOT/verified_sites.json}"
# A user-supplied --registry is used as-is (no download); only the default
# registry (the committed verified_sites.json) is looked up against the repo
# copy, since that is the file CI keeps recording new builds into.
USE_DEFAULT_REGISTRY=1
[ -n "$REG_PATH" ] && USE_DEFAULT_REGISTRY=0

# Registry lookup (the no-guess contract). registry_lookup FILE SIZE [NAME]:
# when NAME (the binary's own name) is a registry key whose recorded size
# equals SIZE, that key is the match - two different versions may ship
# byte-identical-sized binaries (2.1.275 and 2.1.276 both record
# 232,059,192 B), so size alone cannot disambiguate them; the name is the
# native layout's version, which is exactly how the registry keys its
# entries, and the size stays part of the predicate either way. Otherwise
# the build matches the UNIQUE registry entry whose recorded size equals the
# binary's size. No match, several matches, or a malformed registry -> no
# output (the caller then binds automatically or refuses, never guesses).
# The fast path is jq - the size comes from stat, the binary is never read;
# without jq it falls back to the Python matcher (same contract).
registry_lookup() {
  local reg_file="$1" size="$2" name="${3:-}"
  if command -v jq >/dev/null 2>&1; then
    jq -r --argjson size "$size" --arg name "$name" '
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
    ' "$reg_file" 2>/dev/null || true
  else
    PYTHONPATH="$ROOT/tools" python3 -c '
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

# The raw URL of the registry on the repo default branch, derived from the
# origin remote (empty when it is not a github https remote).
registry_remote_url() {
  local remote repo branch scheme
  remote="$(git remote get-url origin 2>/dev/null || true)"
  case "$remote" in
    https://github.com/*|http://github.com/*) : ;;
    *) return 0 ;;
  esac
  scheme="https"
  case "$remote" in http://*) scheme="http" ;; esac
  repo="${remote#*://github.com/}"
  repo="${repo%.git}"
  # NOTE: no --short here - it yields "origin/develop", not "develop"
  # (the raw URL would 404). Strip the remote prefix from the full ref.
  branch="$(git symbolic-ref --quiet refs/remotes/origin/HEAD 2>/dev/null || true)"
  branch="${branch#refs/remotes/origin/}"
  [ -n "$branch" ] || branch="develop"
  printf '%s://raw.githubusercontent.com/%s/%s/verified_sites.json' "$scheme" "$repo" "$branch"
}

# Fetch the registry from the remote. The source is CLAUDE_PATCHER_REGISTRY_URL
# (a URL, or a local file path - the test/offline hook) when set, else the URL
# derived above. Prints the fetched file path on success, returns 1 otherwise
# (the caller then continues with the local file only).
download_remote_registry() {
  local url out
  if [ -n "${CLAUDE_PATCHER_REGISTRY_URL:-}" ]; then
    url="$CLAUDE_PATCHER_REGISTRY_URL"
  else
    url="$(registry_remote_url)"
  fi
  [ -n "$url" ] || return 1
  out="$(mktemp)" || return 1
  case "$url" in
    /*|./*) cp "$url" "$out" 2>/dev/null || { rm -f "$out"; return 1; } ;;
    *)      curl -fsSL --max-time 30 "$url" -o "$out" 2>/dev/null || { rm -f "$out"; return 1; } ;;
  esac
  [ -s "$out" ] || { rm -f "$out"; return 1; }
  if command -v jq >/dev/null 2>&1; then
    jq -e 'type == "object"' "$out" >/dev/null 2>&1 || { rm -f "$out"; return 1; }
  fi
  printf '%s' "$out"
}

SIZE="$(stat -c%s "$BIN" 2>/dev/null)"
[ -n "$SIZE" ] || { echo "error: cannot determine the size of $BIN" >&2; exit 2; }
# The binary's own name (after symlink resolution): the native claude layout
# names its files after the version, which is the registry key of each build -
# the size-collision disambiguator for lookups below.
BASE="$(basename "$BIN")"

# Local registry first. A build not bound locally may already be bound in the
# repo copy (recorded by CI): fetch that only for the default registry and only
# on a local miss, so the fast path stays offline and an explicit --registry is
# honored exactly.
MATCH="$(registry_lookup "$REG_FILE" "$SIZE" "$BASE")"
SRC="$REG_FILE"
REMOTE_REG=""
# The downloaded registry (if any) is a temp file: remove it on exit.
trap 'rm -f "$REMOTE_REG" 2>/dev/null || true' EXIT
if [ -z "$MATCH" ] && [ "$USE_DEFAULT_REGISTRY" -eq 1 ]; then
  if REMOTE_REG="$(download_remote_registry)"; then
    RMT="$(registry_lookup "$REMOTE_REG" "$SIZE" "$BASE")"
    if [ -n "$RMT" ]; then
      echo "registry: $RMT is bound in the repo copy (downloaded) - applying without a local probe"
      MATCH="$RMT"
      SRC="$REMOTE_REG"
    fi
  fi
fi

BPROBE_ARGS=()
[ -n "${CLASSIFIER_PROBE_SCRIPT:-}" ] && BPROBE_ARGS=(--probe "$CLASSIFIER_PROBE_SCRIPT")

if [ -z "$MATCH" ] && [ "$AUTO_BIND" -eq 1 ]; then
  echo
  echo "== no oracle-verified binding for this build =="
  echo "binding now (blackhole probes, measured - never guessed; ~20-60 min, longer if the build caps waits below the int32 max):"
  python3 "$REC/oracle_bind_auto.py" --binary "$BIN" --registry "$REG_FILE" ${BPROBE_ARGS[@]+"${BPROBE_ARGS[@]}"}
  RC=$?
  if [ $RC -eq 2 ]; then
    echo
    echo "error: the registry $REG_FILE is not readable; nothing was done."
    exit 2
  elif [ $RC -ne 0 ]; then
    echo
    echo "binding refused: no registry entry was recorded; nothing was patched."
    exit 1
  fi
  MATCH="$(registry_lookup "$REG_FILE" "$SIZE" "$BASE")"
  SRC="$REG_FILE"
  [ -n "$MATCH" ] || { echo "error: binding reported success but the registry has no matching entry" >&2; exit 1; }
  echo "registry: $MATCH is now bound (size-based match)"
fi

if [ -z "$MATCH" ]; then
  echo
  echo "apply refused: this build has no oracle-verified binding in the registry."
  echo "bind it first (no-guess invariant): re-run without --no-auto-bind for the"
  echo "automatic oracle binding, or bind manually starting with:"
  echo "  python3 $REC/oracle_bind_auto.py --binary $BIN --registry $REG_FILE"
  exit 1
fi

PATCHED="$BIN.patched"
echo "== apply: $BIN =="
if python3 "$ROOT/tools/patch_classifier_timeout.py" --registry "$SRC" "$BIN" --apply-live; then
  :
else
  echo
  echo "apply refused: the recorded binding no longer matches this build's bytes."
  if [ -f "$PATCHED" ]; then
    echo "note: a pre-existing $PATCHED is from an earlier run; this run did"
    echo "not update it, and it may not match the current binary's bytes."
  fi
  exit 1
fi
[ -f "$PATCHED" ] || { echo "error: apply finished but $PATCHED was not written" >&2; exit 1; }

if [ "$VERIFY" -eq 1 ]; then
  BASE_OUT=""
  BASE_PID=""
  if [ "$BASELINE" -eq 1 ]; then
    echo
    echo "== baseline probe (unpatched, timeout ${PROBE_TIMEOUT}s) =="
    # The baseline and the verify probe are independent measurements (each
    # owns its endpoint port and working dir): run them concurrently.
    BASE_OUT="$(mktemp)"
    bash "$RUN_PROBE" "$BIN" "base" "$PROBE_TIMEOUT" > "$BASE_OUT" 2>&1 &
    BASE_PID=$!
  fi
  echo
  echo "== verify probe ($PATCHED, timeout ${PROBE_TIMEOUT}s) =="
  if [ "$FAST_VERIFY" -eq 1 ]; then
    OUT="$(bash "$RUN_PROBE" "$PATCHED" "verify" "$PROBE_TIMEOUT" "$FAST_CHECK" 2>&1)"
  else
    OUT="$(bash "$RUN_PROBE" "$PATCHED" "verify" "$PROBE_TIMEOUT" 2>&1)"
  fi
  if [ -n "$BASE_PID" ]; then
    wait "$BASE_PID" 2>/dev/null
    printf '%s\n' "$(cat "$BASE_OUT")"
    rm -f "$BASE_OUT"
  fi
  [ -n "$OUT" ] && printf '%s\n' "$OUT"
  EARLY=""
  if [ "$FAST_VERIFY" -eq 1 ]; then
    EARLY="$(printf '%s\n' "$OUT" | grep -E ' early still_waiting=1 elapsed=[0-9.]+s blackholed=1' | head -1 || true)"
  fi
  LINE="$(printf '%s\n' "$OUT" | grep -E ' rc=[0-9]+ elapsed=[0-9]+(\.[0-9]+)?s' | head -1 || true)"
  if [ -z "$LINE" ] && [ -z "$EARLY" ]; then
    echo
    echo "NOT VERIFIED: the probe produced no result line."
    exit 1
  fi
  RC="$(printf '%s' "$LINE" | sed -E 's/.* rc=([0-9]+).*/\1/')"
  EL="$(printf '%s' "$LINE" | sed -E 's/.* elapsed=([0-9]+(\.[0-9]+)?)s.*/\1/')"
  if [ -n "$EARLY" ] || [ "$RC" = "124" ]; then
    if [ -n "$EARLY" ]; then
      echo
      echo "VERIFIED: $(basename "$PATCHED") is still inside its first classifier wait"
      echo "at the ${FAST_CHECK}s early check (one blackholed attempt in the"
      echo "endpoint log - the wait is really extended; no need to wait out"
      echo "the ${PROBE_TIMEOUT}s cap)."
    else
      echo
      echo "VERIFIED: $(basename "$PATCHED") is still waiting at ${PROBE_TIMEOUT}s"
      echo "(killed by the probe timeout) - the classifier wait is really extended."
    fi
    echo "artifact: $PATCHED holds the verified patch; the original $BIN is"
    echo "untouched. Run $(basename "$PATCHED") to use the patched build."
    echo "re-running this script on $BIN just regenerates $PATCHED (the"
    echo "original is never modified)."
    exit 0
  fi
  echo
  echo "NOT VERIFIED: the patched run ended on its own (rc=$RC, ${EL}s): the wait is"
  echo "shorter than the ${PROBE_TIMEOUT}s probe cap, or zero. Check the registry"
  echo "target for this version (max_driver_boundary in verified_sites.json)."
  exit 1
fi

echo
echo "applied: $PATCHED holds the patch (verification skipped with"
echo "--no-verify - the artifact is not measured). $BIN is unchanged."
