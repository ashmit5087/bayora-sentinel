"""Tiny HTTP stub used as the gauntlet's stand-in for the model and for a decoy
cloud-metadata endpoint.

It exists so probes have a real network target to reach (or fail to reach). It
holds no data and does no inference.

    python -m sentinel.stubs.http_stub --name model --port 8080
"""
from __future__ import annotations

import argparse
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


def make_handler(name: str):
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args) -> None:  # keep container logs quiet
            pass

        def _send(self, obj: dict) -> None:
            data = json.dumps(obj).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def do_GET(self) -> None:
            self._send({"stub": name, "path": self.path})

        def do_POST(self) -> None:
            length = int(self.headers.get("Content-Length") or 0)
            if length:
                self.rfile.read(length)
            # Shaped like llama.cpp's /completion so the gateway's llama backend works against it.
            self._send({"content": f"[{name}-stub] ok", "timings": {"prompt_n": 1, "cache_n": 0}})

    return Handler


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--name", required=True)
    ap.add_argument("--port", type=int, required=True)
    args = ap.parse_args()
    ThreadingHTTPServer(("0.0.0.0", args.port), make_handler(args.name)).serve_forever()


if __name__ == "__main__":
    main()
