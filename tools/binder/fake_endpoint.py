"""Fake Anthropic endpoint for classifier liveness probes.

Routing rules (order matters):
- session-title call (system mentions naming a coding session) -> short text
- main conversation (system carries one of the main markers), no
  tool_result yet -> scripted tool_use(Bash "sudo -n true") so auto mode
  must classify: sudo is never sandbox-safe, so the acceptEdits fast-path
  simulation returns ask and the classifier has to run
- main conversation with a tool_result -> end_turn text
- anything else -> full body captured to unknown-N.json, harmless end_turn

Main marker (a disjunction, both checked in the system text):
- "interactive agent that h" - the flag-off persona line ("You are an
  interactive agent that helps users with software engineering tasks.",
  and the Output-Style variant). The growthbook flag tengu_ochre_wren
  (remote, env override CLAUDE_CODE_INTRO_FRAME; run_probe.sh pins it
  false) rewrites the persona line to "You are an agent working with the
  user toward their goals ..." when ON - wording the first marker does
  not match. It flipped ON remotely on 2026-10-09 (no binary change: the
  same bytes measured 121 s on 2026-10-07 and ~1 s on 2026-10-09), which
  is why the disjunction exists.
- "built on Anthropic's Claude Agent SDK" - the SDK intro line that opens
  the main prompt in both wording regimes. Classifier requests carry
  neither marker (their system prompt is the "security monitor" one), so
  the disjunction cannot misroute them even though they embed the probe
  prompt text in their messages.

Classifier blackholing is enabled by setting BLACKHOLE=1 and passing a
marker file; the marker must come from a captured classifier request so we
never misfire on the main conversation.
"""

import http.server
import json
import os
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
LOG = os.path.join(HERE, "fake_endpoint.log")
STATE = os.path.join(HERE, "fake_endpoint.state")
MARKER_FILE = os.path.join(HERE, "classifier_marker.txt")

TOOL_USE_PAYLOAD = {
    "id": "msg_fake",
    "type": "message",
    "role": "assistant",
    "model": "fake",
    "content": [
        {
            "type": "tool_use",
            "id": "toolu_fake_1",
            "name": "Bash",
            "input": {"command": "sudo -n true", "description": "probe"},
        }
    ],
    "stop_reason": "tool_use",
    "usage": {"input_tokens": 10, "output_tokens": 5},
}

DONE_PAYLOAD = {
    "id": "msg_fake2",
    "type": "message",
    "role": "assistant",
    "model": "fake",
    "content": [{"type": "text", "text": "Probe finished."}],
    "stop_reason": "end_turn",
    "usage": {"input_tokens": 10, "output_tokens": 5},
}

TEXT_PAYLOAD = {
    "id": "msg_fake3",
    "type": "message",
    "role": "assistant",
    "model": "fake",
    "content": [{"type": "text", "text": "ok."}],
    "stop_reason": "end_turn",
    "usage": {"input_tokens": 10, "output_tokens": 5},
}


def log(line: str) -> None:
    with open(LOG, "a", encoding="utf-8") as fh:
        fh.write(time.strftime("%H:%M:%S") + " " + line.rstrip("\n") + "\n")


def load_count() -> int:
    try:
        with open(STATE, "r", encoding="utf-8") as fh:
            return int(fh.read().strip() or 0)
    except (OSError, ValueError):
        return 0


def save_count(n: int) -> None:
    with open(STATE, "w", encoding="utf-8") as fh:
        fh.write(str(n))


def marker() -> bytes:
    if os.environ.get("BLACKHOLE") != "1":
        return b""
    try:
        with open(MARKER_FILE, "rb") as fh:
            m = fh.read()
            return m if len(m) >= 8 else b""
    except OSError:
        return b""


class Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        pass

    def _send_json(self, doc: dict) -> None:
        data = json.dumps(doc).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length)
        try:
            doc = json.loads(body)
        except Exception:
            doc = {}
        model = doc.get("model", "?")
        messages = doc.get("messages", [])
        has_tool_result = any(
            isinstance(m, dict)
            and isinstance(m.get("content"), list)
            and any(isinstance(c, dict) and c.get("type") == "tool_result" for c in m["content"])
            for m in messages
        )
        sys_text = json.dumps(doc.get("system", ""))
        is_title = "naming a coding session" in sys_text
        # Main marker: the flag-off persona line or the SDK intro line
        # (the flag-on persona line carries neither, see the module
        # docstring); classifier requests carry neither.
        is_main = ("interactive agent that h" in sys_text) or \
                  ("built on Anthropic's Claude Agent SDK" in sys_text)
        log(f"REQ model={model} msgs={len(messages)} tool_result={has_tool_result} title={is_title} main={is_main}")
        with open(os.path.join(HERE, "all_bodies.jsonl"), "a", encoding="utf-8") as fh:
            fh.write(json.dumps(doc) + "\n")

        marker_bytes = marker()
        if marker_bytes and marker_bytes in body:
            log("  -> BLACKHOLED (classifier marker matched)")
            time.sleep(3600)
            return

        if is_title:
            self._send_json(TEXT_PAYLOAD)
            return
        if is_main and not has_tool_result:
            log("  -> scripted tool_use(Bash)")
            self._send_json(TOOL_USE_PAYLOAD)
            return
        if is_main:
            log("  -> scripted end_turn (tool_result seen)")
            self._send_json(DONE_PAYLOAD)
            return

        # unknown request: capture fully, answer harmlessly
        n = load_count()
        path = os.path.join(HERE, f"unknown-{n}.json")
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(doc, fh, indent=1)
        log(f"  -> UNKNOWN captured to {os.path.basename(path)}; end_turn")
        save_count(n + 1)
        self._send_json(TEXT_PAYLOAD)


def main() -> None:
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8791
    server = http.server.ThreadingHTTPServer(("127.0.0.1", port), Handler)
    log(f"fake endpoint listening on 127.0.0.1:{port} pid={os.getpid()} BLACKHOLE={os.environ.get('BLACKHOLE', '0')}")
    server.serve_forever()


if __name__ == "__main__":
    main()
