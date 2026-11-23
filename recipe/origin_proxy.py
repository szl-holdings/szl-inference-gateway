"""Loopback origin proxy that enforces PAYMENT-CONTEXT before paid inference."""

from __future__ import annotations

import argparse
import http.client
import json
import os
import sys
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from szl_inference_gateway.origin_gate import ReplayCache, authorize_payment_context  # noqa: E402

MESSAGE_LIMIT = 1_048_576
RESOURCE_PATH = "/v1/chat/completions"


def _json(status: int, body: dict) -> tuple[int, bytes, str]:
    payload = json.dumps(body, separators=(",", ":")).encode("utf-8")
    return status, payload, "application/json"


class OriginHandler(BaseHTTPRequestHandler):
    server_version = "szl-origin-gate/1"
    protocol_version = "HTTP/1.1"

    def _send(self, status: int, payload: bytes, content_type: str) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(payload)

    def _deny(self, reason: str, status: int = 403) -> None:
        code, payload, kind = _json(status, {"admission": {"state": "HOLD", "reason": reason}})
        self._send(code, payload, kind)

    def _backend(self, method: str, path: str, body: bytes | None = None) -> None:
        conn = http.client.HTTPConnection("127.0.0.1", self.server.backend_port, timeout=10)
        try:
            headers = {"Connection": "close"}
            if body is not None:
                headers["Content-Type"] = self.headers.get("Content-Type", "application/json")
                headers["Content-Length"] = str(len(body))
            conn.request(method, path, body=body, headers=headers)
            response = conn.getresponse()
            payload = response.read(MESSAGE_LIMIT + 1)
            if len(payload) > MESSAGE_LIMIT:
                self._deny("BACKEND_RESPONSE_TOO_LARGE", 502)
                return
            content_type = response.getheader("Content-Type", "application/json")
            self._send(response.status, payload, content_type)
        except (OSError, TimeoutError):
            self._deny("BACKEND_UNAVAILABLE", 503)
        finally:
            conn.close()

    def do_GET(self) -> None:
        if self.path not in ("/health", "/v1/models"):
            self._deny("ROUTE_NOT_EXPOSED", 404)
            return
        self._backend("GET", self.path)

    def do_POST(self) -> None:
        if self.path != RESOURCE_PATH:
            self._deny("ROUTE_NOT_EXPOSED", 404)
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            self._deny("REQUEST_LENGTH_INVALID", 400)
            return
        if length < 0 or length > MESSAGE_LIMIT:
            self._deny("REQUEST_BODY_TOO_LARGE", 413)
            return
        body = self.rfile.read(length)
        if len(body) != length:
            self._deny("REQUEST_BODY_TRUNCATED", 400)
            return
        gate = authorize_payment_context(
            self.headers,
            method="POST",
            path=self.path,
            now_unix=int(time.time()),
            jwks_bytes=self.server.jwks_bytes,
            expected_jwks_sha256=self.server.jwks_sha256,
            replay_cache=self.server.replay_cache,
        )
        if gate["inference_forward_authorized"] is not True:
            self._deny(gate["reason"] or "PAYMENT_CONTEXT_DENIED")
            return
        self._backend("POST", self.path, body)

    def log_message(self, *_args) -> None:
        if os.environ.get("ORIGIN_GATE_VERBOSE") == "1":
            super().log_message(*_args)


class OriginServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, address, handler, *, backend_port: int, jwks_bytes: bytes, jwks_sha256: str):
        super().__init__(address, handler)
        self.backend_port = backend_port
        self.jwks_bytes = jwks_bytes
        self.jwks_sha256 = jwks_sha256
        self.replay_cache = ReplayCache()


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--listen-host", default=os.environ.get("ORIGIN_GATE_HOST", "127.0.0.1"))
    parser.add_argument("--listen-port", type=int, default=int(os.environ.get("ORIGIN_GATE_PORT", "11434")))
    parser.add_argument("--backend-port", type=int, default=int(os.environ.get("ORIGIN_BACKEND_PORT", "11435")))
    args = parser.parse_args()
    jwks_file = os.environ.get("PAYMENT_CONTEXT_JWKS_FILE", "")
    jwks_sha256 = os.environ.get("PAYMENT_CONTEXT_JWKS_SHA256", "")
    if not jwks_file or not jwks_sha256:
        raise SystemExit("PAYMENT_CONTEXT_GATE_CONFIG_REQUIRED")
    try:
        jwks = Path(jwks_file).read_bytes()
    except OSError as exc:
        raise SystemExit("PAYMENT_CONTEXT_JWKS_UNAVAILABLE") from exc
    server = OriginServer(
        (args.listen_host, args.listen_port),
        OriginHandler,
        backend_port=args.backend_port,
        jwks_bytes=jwks,
        jwks_sha256=jwks_sha256,
    )
    print(json.dumps({"origin_gate": "ready", "listen_port": args.listen_port, "backend_port": args.backend_port}), flush=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
