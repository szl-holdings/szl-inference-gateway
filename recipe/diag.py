"""Diagnostic fallback server for the SZL Inference Gateway recipe.

Parked on the inference port while llama-server is down, so health probes
through the tunnel get an honest JSON diagnosis instead of a dead port.
"""
from __future__ import annotations

import http.server
import json
import os
import subprocess


def tail(path: str, n: int = 6000) -> str:
    try:
        size = os.path.getsize(path)
        with open(path, "rb") as handle:
            handle.seek(max(0, size - n))
            return handle.read().decode("utf-8", "replace")
    except Exception as exc:
        return "ERR " + repr(exc)


class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        try:
            with open("/root/llama.pid") as handle:
                pid = handle.read().strip()
            alive = bool(pid) and subprocess.run(
                ["kill", "-0", pid], capture_output=True
            ).returncode == 0
        except Exception:
            alive = False
        body = json.dumps(
            {
                "diag": "v7-fallback",
                "llama_alive": alive,
                "model_sz": os.path.getsize("/root/bonsai.gguf")
                if os.path.exists("/root/bonsai.gguf")
                else -1,
                "lane_log": tail("/tmp/lane.log"),
                "llama_log": tail("/tmp/llama_server.log"),
                "install_log": tail("/tmp/llama_install.log"),
                "cudart_log": tail("/tmp/cudart_install.log"),
                "cf_log": tail("/tmp/cloudflared.log", 1500),
            }
        ).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args) -> None:
        pass


def main() -> None:
    try:
        http.server.ThreadingHTTPServer(("127.0.0.1", 11434), Handler).serve_forever()
    except OSError:
        pass


if __name__ == "__main__":
    main()
