#!/bin/bash
# claude-statusline.sh - the statusline marker; install.sh copies it to
# ~/.local/bin/ and makes it the statusLine command in
# ~/.claude/settings.json (the file is MERGED, never clobbered; the
# user's existing statusline command is recorded in the
# claude-statusline.orig file next to this script and restored verbatim
# by install.sh --uninstall).
#
# What it does: it runs the user's existing statusline command (the
# command recorded in claude-statusline.orig next to this script, the
# SAME session JSON claude passes on stdin) and prints its output. When
# the claude-patched wrapper booted a PATCHED binary (it exports
# CLAUDE_WRAPPER_PATCHED=1 for that boot and unsets it for every raw
# boot, so the marker cannot lie), the label (default "⚙ (patched)",
# CLAUDE_WRAPPER_PATCHED_LABEL overrides it) is prepended to the FIRST
# line of the output - every remaining line passes through verbatim.
# Unpatched launches print the original output verbatim; without an
# original statusline nothing is printed (the marker line alone when
# patched).
#
# The original command is guarded by a timeout: a hung statusline must
# never block the UI - it degrades to the label alone (patched launch)
# or to nothing.
set -u

SELF_DIR=""
{ SELF_DIR="$(cd "$(dirname -- "$0")" && pwd -P)"; } 2>/dev/null || SELF_DIR=""
ORIG="${SELF_DIR}/claude-statusline.orig"
LABEL="${CLAUDE_WRAPPER_PATCHED_LABEL:-⚙ (patched)}"
PATCHED="${CLAUDE_WRAPPER_PATCHED:-}"

orig=""
if [ -n "$SELF_DIR" ] && [ -f "$ORIG" ]; then
  # The recorded command runs in a subshell with the same stdin (the
  # session JSON). A non-zero exit or a hang degrades to the label
  # alone, never to an error line.
  orig="$(timeout 5 sh -c "$(cat "$ORIG")" 2>/dev/null || true)"
fi

if [ -n "$PATCHED" ]; then
  first="$(printf '%s\n' "$orig" | head -n1)"
  rest="$(printf '%s\n' "$orig" | tail -n +2)"
  if [ -n "$first" ]; then
    printf '%s  %s\n' "$LABEL" "$first"
  else
    printf '%s\n' "$LABEL"
  fi
  if [ -n "$rest" ]; then
    printf '%s\n' "$rest"
  fi
else
  if [ -n "$orig" ]; then
    printf '%s\n' "$orig"
  fi
fi
exit 0
