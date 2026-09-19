"""Hermetic mock host for gateway chat proxy tests.

Binds ``http://127.0.0.1:<port>/v1/chat/completions``. No WireGuard, no AGX.
Does not log or retain the prompt body.
"""

from __future__ import annotations

import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Thread
from typing import Any


MOCK_COMPLETION = {
    "id": "cmpl-synthetic-gateway",
    "object": "chat.completion",
    "model": "llama-3.1-8b-q4",
    "choices": [
        {
            "index": 0,
            "message": {"role": "assistant", "content": "synthetic-gateway-ok"},
            "finish_reason": "stop",
        }
    ],
}


class MockHost:
    def __init__(self) -> None:
        self.hits = 0
        self.last_path = ""
        self.last_content_length = 0
        self._server: ThreadingHTTPServer | None = None
        self._thread: Thread | None = None

    @property
    def client_address(self) -> str:
        return "127.0.0.1/32"

    @property
    def port(self) -> int:
        if self._server is None:
            raise RuntimeError("mock host is not started")
        return int(self._server.server_address[1])

    def start(self) -> MockHost:
        owner = self

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self) -> None:
                length = int(self.headers.get("Content-Length") or 0)
                # Read and discard. Do not store or log the prompt body.
                if length:
                    self.rfile.read(length)
                owner.hits += 1
                owner.last_path = self.path
                owner.last_content_length = length
                payload = json.dumps(MOCK_COMPLETION).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)

            def log_message(self, format: str, *args: Any) -> None:
                del format, args

        self._server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self._thread = Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()
        return self

    def stop(self) -> None:
        if self._server is not None:
            self._server.shutdown()
            self._server.server_close()
        if self._thread is not None:
            self._thread.join(timeout=2)
        self._server = None
        self._thread = None
