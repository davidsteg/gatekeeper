"""Scripted OpenAI-compatible model for the live adapter test. No credentials.

It decides from the conversation it is sent, never from hidden state:

* a turn whose input carries `[gatekeeper-continuation …]` (the resumed
  turn): call the Gatekeeper read tool, then write a Kanban comment on the
  bound task (progress), then answer;
* a turn whose input contains `START <board> <task>`: bind the task, then call
  the failing Gatekeeper tool on every further step (the loop exhausts);
* anything else (a plain user message, Hermes's own summary/titling calls):
  answer with text.

Every request is appended to requests.jsonl for evidence.
"""

from __future__ import annotations

import json
import os
import re
import sys
import time
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

LOG = os.path.join(os.path.dirname(os.path.abspath(__file__)), "out", "requests.jsonl")


def _text(content) -> str:
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        return " ".join(p.get("text", "") for p in content if isinstance(p, dict))
    return ""


def _tool(tools, suffix):
    for t in tools or []:
        name = (t.get("function") or {}).get("name", "")
        if name == suffix or name.endswith("__" + suffix):
            return name
    return None


def decide(body: dict) -> dict:
    messages = body.get("messages") or []
    tools = body.get("tools") or []
    last_user_idx = max((i for i, m in enumerate(messages) if m.get("role") == "user"), default=-1)
    user = _text(messages[last_user_idx].get("content")) if last_user_idx >= 0 else ""
    steps = sum(1 for m in messages[last_user_idx + 1:] if m.get("role") == "assistant" and m.get("tool_calls"))

    names = {(t.get("function") or {}).get("name", "") for t in tools}

    def call(name, args):
        # Deferred tools (MCP, plugin) go through Hermes's documented
        # tool_call bridge; hooks still see the real tool name.
        if name not in names and "tool_call" in names:
            name, args = "tool_call", {"calls": [{"name": name, "arguments": args}]}
        return {"role": "assistant", "content": None, "tool_calls": [{
            "id": "call_" + uuid.uuid4().hex[:12], "type": "function",
            "function": {"name": name, "arguments": json.dumps(args)}}]}

    def say(text):
        return {"role": "assistant", "content": text}

    if not tools:
        return say("Summary: the Gatekeeper tool kept failing; stopping here.")
    if "[gatekeeper-continuation" in user:
        if "superseded" in user.lower() and "do not act" in user.lower():
            return say("superseded")
        m = re.search(r"Continue task (\S+)", user)
        task = m.group(1) if m else ""
        if steps == 0:
            return call("mcp__gatekeeper__demo_read", {})
        if steps == 1:
            return call("kanban_comment", {"task_id": task, "body": "Recovered: stack checked."})
        return say("Recovered: checked the stack state and recorded progress on the task.")
    m = re.search(r"START (\S+) (\S+)", user)
    if m:
        if steps == 0:
            return call("gatekeeper_recovery_bind_task",
                        {"board_id": m.group(1), "task_id": m.group(2), "objective": "Check the stack"})
        return call("mcp__gatekeeper__demo_fail", {"target": "nas"})
    return say(f"Noted: {user[:80]}")


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *_):
        pass

    def _send(self, code, payload):
        data = json.dumps(payload).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        if self.path.rstrip("/").endswith("/models"):
            return self._send(200, {"object": "list", "data": [{"id": "fake-model", "object": "model"}]})
        self._send(404, {"error": "not found"})

    def do_POST(self):
        body = json.loads(self.rfile.read(int(self.headers.get("Content-Length") or 0)) or b"{}")
        msg = decide(body)
        os.makedirs(os.path.dirname(LOG), exist_ok=True)
        if body.get("tools") and not os.path.exists(LOG + ".tools"):
            with open(LOG + ".tools", "w", encoding="utf-8") as f:
                json.dump(sorted((t.get("function") or {}).get("name", "") for t in body.get("tools") or []), f)
        with open(LOG, "a", encoding="utf-8") as f:
            f.write(json.dumps({"ts": time.time(), "n_messages": len(body.get("messages") or []),
                                "n_tools": len(body.get("tools") or []), "reply": msg}) + "\n")
        if body.get("stream"):
            # Minimal SSE: one chunk carrying the whole message, then [DONE].
            delta = {"role": "assistant"}
            if msg.get("tool_calls"):
                delta["tool_calls"] = [{**tc, "index": i} for i, tc in enumerate(msg["tool_calls"])]
            else:
                delta["content"] = msg["content"]
            chunk = {"id": "chatcmpl-fake", "object": "chat.completion.chunk", "created": int(time.time()),
                     "model": "fake-model", "choices": [{"index": 0, "delta": delta,
                     "finish_reason": "tool_calls" if msg.get("tool_calls") else "stop"}]}
            data = f"data: {json.dumps(chunk)}\n\ndata: [DONE]\n\n".encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
            return
        self._send(200, {"id": "chatcmpl-fake", "object": "chat.completion", "created": int(time.time()),
                         "model": "fake-model",
                         "choices": [{"index": 0, "message": msg,
                                      "finish_reason": "tool_calls" if msg.get("tool_calls") else "stop"}],
                         "usage": {"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2}})


if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 18770
    ThreadingHTTPServer(("0.0.0.0", port), Handler).serve_forever()
