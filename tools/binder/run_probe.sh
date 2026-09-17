#!/bin/bash
# Blackhole timing probe: $1 = binary path, $2 = label, $3 = run timeout in
# seconds (default 300; raise it for probes whose waits exceed ~2.5 min),
# $4 = optional early status check point in seconds (see below).
# Own working directory per probe and own endpoint port per invocation, so
# concurrent probes never share state or collide on the fake endpoint.
#
# Early status check ($4): at that many seconds, if the run is still alive
# and the endpoint log holds exactly ONE blackholed classifier attempt, the
# run is still inside its first per-attempt wait (an unpatched build is
# already on attempt two by then) - the probe prints
# " label early still_waiting=1 elapsed=<S>s blackholed=<N>" and kills the
# run instead of waiting out the timeout. Two or more attempts (or an
# already-finished run) produce no early line; the run ends the usual way
# and the result line carries rc/elapsed as before.
#
# Cancel: SIGTERM to the script at any point (the binder cancels the
# bisection half that is no longer decisive as soon as the other half's
# verdict decides the round): the trap stops the run (its whole process
# group) and the endpoint and exits 143 WITHOUT a result line - a canceled
# run is not a measurement. A run that already finished prints its result
# line as usual. The run is always a background job and the check-point
# wait is interruptible, so the trap fires promptly (a foreground command
# would defer a trapped signal until the command ends).
set -u
TIMEOUT="${3:-300}"
CHECK_AT="${4:-}"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# Probe state lives under $TMPDIR (writable in foreground and background
# tasks alike); CLAUDE_PATCHER_PROBE_DIR overrides the root.
PROBE_ROOT="${CLAUDE_PATCHER_PROBE_DIR:-${TMPDIR:-/tmp}}"
mkdir -p "$PROBE_ROOT"
DIR="$PROBE_ROOT/claude-patcher-probe-$2"
mkdir -p "$DIR"
cp "$HERE/fake_endpoint.py" "$HERE/classifier_marker.txt" "$DIR/"
cd "$DIR"
rm -f fake_endpoint.log fake_endpoint.state all_bodies.jsonl unknown-*.json
PORT=$(( 10000 + RANDOM % 40000 ))
BLACKHOLE=1 python3 fake_endpoint.py "$PORT" >/dev/null 2>&1 &
EP=$!
# cancel_run: SIGTERM handling (see header). The run is backgrounded, so a
# trapped signal interrupts the wait below and the trap runs immediately.
RUN=""
WATCHER=""
CHECK_SLEEP=""
cancel_run() {
  CHILD="$(pgrep -P "$RUN" 2>/dev/null | head -1 || true)"
  [ -n "$CHILD" ] && kill -TERM -- "-$CHILD" 2>/dev/null
  kill -TERM "$RUN" 2>/dev/null
  wait "$RUN" 2>/dev/null
  [ -n "$WATCHER" ] && wait "$WATCHER" 2>/dev/null
  # The check-point sleep (when set) inherits the script's stdout: kill it,
  # or a captured stdout pipe stays open until the sleep ends.
  [ -n "$CHECK_SLEEP" ] && kill "$CHECK_SLEEP" 2>/dev/null
  kill "$EP" 2>/dev/null
  wait "$EP" 2>/dev/null
  exit 143
}
trap cancel_run TERM
# The endpoint is ready once it logs its listening line (usually well
# under 1 s). The poll is capped at 5 s so a broken endpoint cannot stall
# the probe: the run then just fails to connect, as before.
i=0
until grep -q "listening on" fake_endpoint.log 2>/dev/null; do
  i=$(( i + 1 ))
  [ "$i" -ge 50 ] && break
  sleep 0.1
done
mkdir -p "$DIR/probecfg"
printf '{"env":{"ANTHROPIC_BASE_URL":"http://127.0.0.1:%s"},"model":"claude-opus-5","sandbox":{"enabled":false}}' "$PORT" > "$DIR/probecfg/settings.json"
# alive: 0 only while the process exists and is not a zombie (kill -0 alone
# cannot tell a zombie from a running process: bash reaps background jobs
# only between its commands, so a finished run may still look alive).
alive() {
  S="$(ps -o state= -p "$1" 2>/dev/null | tr -d ' ' || true)"
  [ -n "$S" ] && [ "$S" != "Z" ]
}
START=$(date +%s.%N)
if [ -n "$CHECK_AT" ]; then
  # The early check needs the run in the background; a run that finishes
  # before the check point is simply waited for (the result is unchanged).
  # A lightweight watcher records the moment the run actually ends (the
  # wait below could only notice it at the check point at the latest), so
  # the reported elapsed stays true even for an early-finished run.
  END_MARK="$DIR/run_end"
  rm -f "$END_MARK"
  env CLAUDE_CONFIG_DIR="$DIR/probecfg" ANTHROPIC_API_KEY=fake \
      timeout "$TIMEOUT" "$1" -p "Run the probe command now." --permission-mode auto --max-turns 2 \
      </dev/null > "$DIR/probe.out" 2>&1 &
  RUN=$!
  ( while alive "$RUN"; do sleep 0.2; done; date +%s.%N > "$END_MARK" ) &
  WATCHER=$!
  # Interruptible check-point wait: a plain foreground `sleep "$CHECK_AT"`
  # would defer a cancel (SIGTERM) until the check point itself; wait() on
  # a background sleep returns as soon as the signal's trap runs.
  sleep "$CHECK_AT" &
  CHECK_SLEEP=$!
  wait "$CHECK_SLEEP" 2>/dev/null
  if alive "$RUN"; then
    N="$(grep -c BLACKHOLED fake_endpoint.log 2>/dev/null || true)"
    if [ "${N:-0}" = "1" ]; then
      NOW=$(date +%s.%N)
      CHECKED_AT=$(awk -v a="$START" -v b="$NOW" 'BEGIN{printf "%.1f", b-a}')
      echo "$2 early still_waiting=1 elapsed=${CHECKED_AT}s blackholed=$N"
      # timeout runs the binary in its own process group: TERM the group
      # (the binary and everything it spawned), then the timeout itself.
      CHILD="$(pgrep -P "$RUN" 2>/dev/null | head -1 || true)"
      [ -n "$CHILD" ] && kill -TERM -- "-$CHILD" 2>/dev/null
      kill -TERM "$RUN" 2>/dev/null
    fi
  fi
  wait "$RUN" 2>/dev/null
  RC=$?
  wait "$WATCHER" 2>/dev/null
  if [ -f "$END_MARK" ]; then
    END="$(cat "$END_MARK")"
  else
    END=$(date +%s.%N)
  fi
else
  env CLAUDE_CONFIG_DIR="$DIR/probecfg" ANTHROPIC_API_KEY=fake \
      timeout "$TIMEOUT" "$1" -p "Run the probe command now." --permission-mode auto --max-turns 2 \
      </dev/null > "$DIR/probe.out" 2>&1 &
  RUN=$!
  wait "$RUN" 2>/dev/null
  RC=$?
  END=$(date +%s.%N)
fi
# The run is done: a late SIGTERM must not skip the result line.
trap - TERM
kill "$EP" 2>/dev/null
wait "$EP" 2>/dev/null
ELAPSED=$(awk -v a="$START" -v b="$END" 'BEGIN{printf "%.1f", b-a}')
echo "$2 rc=$RC elapsed=${ELAPSED}s"
echo "  endpoint log:"
sed 's/^/    /' "$DIR/fake_endpoint.log" 2>/dev/null | head -8
