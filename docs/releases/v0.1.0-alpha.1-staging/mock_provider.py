"""Minimal OpenAI-compatible provider for the staging rehearsal. Stdlib only.

Echoes the last user message back as the assistant reply and keeps the request
bodies it received in memory, so the probe can check what actually left the
gateway. Synthetic data only.
"""

import json
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

SEEN: list[dict] = []


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def _send(self, status: int, payload: object) -> None:
        data = json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self) -> None:  # noqa: N802
        if self.path == "/_requests":
            self._send(200, SEEN)
        else:
            self._send(404, {"error": "not found"})

    def do_POST(self) -> None:  # noqa: N802
        length = int(self.headers.get("Content-Length", "0"))
        raw = self.rfile.read(length)
        if self.path == "/_reset":
            SEEN.clear()
            self._send(200, {"ok": True})
            return
        if not self.path.endswith("/chat/completions"):
            self._send(404, {"error": "not found"})
            return
        body = json.loads(raw)
        SEEN.append(body)
        last = ""
        for message in body.get("messages", []):
            if message.get("role") == "user":
                last = str(message.get("content", ""))
        self._send(
            200,
            {
                "id": "chatcmpl-rehearsal",
                "object": "chat.completion",
                "created": int(time.time()),
                "model": body.get("model", "mock"),
                "choices": [
                    {
                        "index": 0,
                        "message": {"role": "assistant", "content": f"ECHO: {last}"},
                        "finish_reason": "stop",
                    }
                ],
                "usage": {"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2},
            },
        )

    def log_message(self, *_: object) -> None:
        return


if __name__ == "__main__":
    ThreadingHTTPServer(("0.0.0.0", 9000), Handler).serve_forever()
