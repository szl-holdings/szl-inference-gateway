"""SSRF regressions for the loopback origin proxy.

The proxy may dial only the backend named by the deploy recipe. Request
targets and redirect locations are untrusted and must not be concatenated
into that origin.
"""

from __future__ import annotations

import base64
import hashlib
import json
import socket
import sys
import threading
import time
from pathlib import Path

import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "recipe"))
sys.path.insert(0, str(ROOT / "src"))

from szl_inference_gateway.origin_allowlist import (  # noqa: E402
    OriginConfigError,
    OriginRejected,
    assess_redirect,
    build_pinned_url,
    load_pinned_origin,
    rejection_for_request_target,
    vetted_literal_path,
)
import origin_proxy  # noqa: E402

RECIPE = ROOT / "recipe" / "entrypoint.sh"
RESOURCE = "https://inference.a-11-oy.com/v1/chat/completions"


def _minimal_recipe(host: str = "127.0.0.1", port: str = "11435", extra: str = "") -> str:
    return f"ORIGIN_BACKEND_PORT={port}\nllama-server --host {host} --port \"$ORIGIN_BACKEND_PORT\"\n{extra}"


def _pin():
    return load_pinned_origin(11435, env_port=None, entrypoint=RECIPE)


def test_real_recipe_allowlist_is_only_the_loopback_backend() -> None:
    text = RECIPE.read_text(encoding="utf-8")
    assert "ORIGIN_BACKEND_PORT=11435\n" in text
    assert "--host 127.0.0.1" in text
    pin = _pin()
    assert (pin.scheme, pin.host, pin.port) == ("http", "127.0.0.1", 11435)
    assert pin.origin == "http://127.0.0.1:11435"
    assert "a-11-oy.com" not in pin.origin
    assert pin.origin == build_pinned_url(pin, "GET", "/health").rsplit("/", 1)[0]


def test_unset_or_unknown_port_fails_closed(tmp_path: Path) -> None:
    recipe = tmp_path / "entrypoint.sh"
    recipe.write_text(_minimal_recipe(), encoding="utf-8")
    with pytest.raises(OriginConfigError) as missing:
        load_pinned_origin(None, env_port=None, entrypoint=recipe)
    assert missing.value.reason == "ORIGIN_BACKEND_UNCONFIGURED"
    with pytest.raises(OriginConfigError) as unknown:
        load_pinned_origin(8080, env_port=None, entrypoint=recipe)
    assert unknown.value.reason == "ORIGIN_BACKEND_PORT_NOT_ALLOWED"
    with pytest.raises(OriginConfigError) as conflict:
        load_pinned_origin(11435, env_port="11436", entrypoint=recipe)
    assert conflict.value.reason == "ORIGIN_BACKEND_PORT_NOT_ALLOWED"
    with pytest.raises(OriginConfigError) as invalid:
        load_pinned_origin(None, env_port="11435 ", entrypoint=recipe)
    assert invalid.value.reason == "ORIGIN_BACKEND_PORT_INVALID"
    with pytest.raises(OriginConfigError) as flagged:
        load_pinned_origin(True, env_port=None, entrypoint=recipe)  # type: ignore[arg-type]
    assert flagged.value.reason == "ORIGIN_BACKEND_PORT_INVALID"
    assert load_pinned_origin(None, env_port="11435", entrypoint=recipe).port == 11435


def test_recipe_without_a_single_loopback_http_origin_fails_closed(tmp_path: Path) -> None:
    cases = {
        "ORIGIN_DEPLOY_RECIPE_UNAVAILABLE": None,
        "ORIGIN_BACKEND_UNCONFIGURED": "llama-server --host 127.0.0.1\n",
        "ORIGIN_BACKEND_PORT_NOT_ALLOWED": _minimal_recipe(port="11435") + "ORIGIN_BACKEND_PORT=80\n",
        "ORIGIN_BACKEND_PORT_INVALID": _minimal_recipe(port="011435"),
        "ORIGIN_BACKEND_HOST_NOT_ALLOWED": _minimal_recipe(host="0.0.0.0"),
        "ORIGIN_BACKEND_HOST_NOT_ALLOWED_PILOT": _minimal_recipe(host="router-control.a-11-oy.com"),
        "ORIGIN_BACKEND_HOST_NOT_ALLOWED_SPACE": _minimal_recipe(host="szl-router-control.hf.space"),
        "ORIGIN_SCHEME_UNPINNED": _minimal_recipe(extra="llama-server --ssl\n"),
    }
    missing = tmp_path / "missing.sh"
    with pytest.raises(OriginConfigError) as unavailable:
        load_pinned_origin(11435, env_port=None, entrypoint=missing)
    assert unavailable.value.reason == "ORIGIN_DEPLOY_RECIPE_UNAVAILABLE"
    for name, text in cases.items():
        if text is None:
            continue
        path = tmp_path / f"{name}.sh"
        path.write_text(text, encoding="utf-8")
        with pytest.raises(OriginConfigError) as exc:
            load_pinned_origin(11435, env_port=None, entrypoint=path)
        assert exc.value.reason == name.split("_PILOT")[0].split("_SPACE")[0]


@pytest.mark.parametrize(
    ("method", "target"),
    [
        ("GET", "/health"),
        ("GET", "/v1/models"),
        ("POST", "/v1/chat/completions"),
    ],
)
def test_vetted_paths_are_literals(method: str, target: str) -> None:
    assert vetted_literal_path(method, target) == target
    pin = _pin()
    url = build_pinned_url(pin, method, target)
    assert url == f"http://127.0.0.1:11435{target}"
    assert rejection_for_request_target(method, target, pin=pin) is None


@pytest.mark.parametrize(
    ("target", "reason"),
    [
        ("http://8.8.8.8:11435/health", "HOST_NOT_ALLOWLISTED"),
        ("http://inference.a-11-oy.com:11435/health", "HOST_NOT_ALLOWLISTED"),
        ("https://127.0.0.1:11435/health", "SCHEME_REJECTED"),
        ("file:///etc/passwd", "SCHEME_REJECTED"),
        ("gopher://127.0.0.1:11435/health", "SCHEME_REJECTED"),
        ("//169.254.169.254/latest/meta-data", "SCHEME_REJECTED"),
        ("http://127.0.0.1:443/health", "PORT_REJECTED"),
        ("http://127.0.0.1:80/health", "PORT_REJECTED"),
        ("http://127.0.0.1/health", "PORT_REJECTED"),
        ("http://user:pass@127.0.0.1:11435/health", "USERINFO_REJECTED"),
        ("http://user@127.0.0.1:11435/health", "USERINFO_REJECTED"),
        ("/health/../admin", "PATH_REJECTED"),
        ("/v1/../../etc/passwd", "PATH_REJECTED"),
        ("/%2e%2e/health", "PATH_REJECTED"),
        ("/health%00", "PATH_REJECTED"),
        ("http://127.0.0.1:11435/health/../../etc/passwd", "PATH_REJECTED"),
        ("http://127.0.0.1:11435/%2e%2e/health", "PATH_REJECTED"),
        ("http://127.0.0.1:11435/health?next=http://169.254.169.254/", "PATH_REJECTED"),
        ("http://127.0.0.1:11435/health", "TARGET_REJECTED"),
    ],
)
def test_attacker_controlled_request_targets_are_rejected(target: str, reason: str) -> None:
    pin = _pin()
    assert rejection_for_request_target("GET", target, pin=pin) == reason
    with pytest.raises(OriginRejected) as exc:
        build_pinned_url(pin, "GET", target)
    assert exc.value.reason == "PATH_REJECTED"


@pytest.mark.parametrize(
    "location",
    [
        "http://169.254.169.254/latest/meta-data",
        "http://169.254.169.254:11435/latest/meta-data",
        "http://169.254.1.1:11435/",
        "http://[::ffff:169.254.169.254]:11435/",
        "http://127.0.0.1:11435/health",
        "http://127.0.0.2:11435/",
        "http://localhost:11435/health",
        "http://localhost./health",
        "http://[::1]:11435/",
        "http://[::1]/",
        "http://[::ffff:127.0.0.1]:11435/health",
        "http://10.1.2.3:11435/",
        "http://172.16.5.5:11435/",
        "http://172.31.255.255:11435/health",
        "http://192.168.0.10:11435/",
        "http://0.0.0.0:11435/",
    ],
)
def test_redirects_to_internal_and_metadata_addresses_are_rejected(location: str) -> None:
    pin = _pin()
    assert assess_redirect(location, pin=pin) == "BLOCKED_ADDRESS"


def test_dns_rebinding_is_rejected_without_using_it_as_an_origin() -> None:
    pin = _pin()
    flipped = iter((["8.8.8.8"], ["169.254.169.254"]))

    def rebind(_host: str) -> list[str]:
        return next(flipped)

    assert assess_redirect(
        "http://rebind.example:11435/health", pin=pin, resolve=rebind
    ) == "DNS_REBIND"

    to_rfc1918 = iter((["8.8.8.8"], ["10.0.0.5"]))
    assert assess_redirect(
        "http://rebind.example:11435/health",
        pin=pin,
        resolve=lambda _host: next(to_rfc1918),
    ) == "DNS_REBIND"

    to_v6 = iter((["8.8.8.8"], ["::1"]))
    assert assess_redirect(
        "http://rebind.example:11435/health",
        pin=pin,
        resolve=lambda _host: next(to_v6),
    ) == "DNS_REBIND"

    assert assess_redirect(
        "http://metadata.example:11435/latest",
        pin=pin,
        resolve=lambda _host: ["169.254.169.254"],
    ) == "BLOCKED_ADDRESS"
    assert assess_redirect(
        "http://example.com:11435/health",
        pin=pin,
        resolve=lambda _host: ["8.8.8.8", "8.8.8.8"],
    ) == "HOST_NOT_ALLOWLISTED"


def test_hostname_redirects_do_not_query_dns_by_default(monkeypatch: pytest.MonkeyPatch) -> None:
    def fail_dns(*_args, **_kwargs):
        raise AssertionError("DNS lookup")

    monkeypatch.setattr(socket, "getaddrinfo", fail_dns)
    pin = _pin()
    assert assess_redirect("http://rebind.example:11435/health", pin=pin) == "HOST_NOT_ALLOWLISTED"


class _Backend(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def _record(self, body: bytes | None = None) -> None:
        self.server.seen.append(
            {
                "method": self.command,
                "path": self.path,
                "host": self.headers.get("Host"),
                "body": body,
            }
        )

    def _respond(self) -> None:
        location = self.server.location
        if location is not None:
            raw = b""
            self.send_response(302)
            self.send_header("Location", location)
            self.send_header("Content-Length", "0")
            self.send_header("Connection", "close")
            self.end_headers()
            return
        raw = self.server.body
        self.send_response(self.server.status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(raw)

    def do_GET(self) -> None:
        self._record()
        self._respond()

    def do_POST(self) -> None:
        length = int(self.headers.get("Content-Length", "0") or "0")
        self._record(self.rfile.read(length))
        self._respond()

    def log_message(self, *_args) -> None:
        return


class _ReuseServer(ThreadingHTTPServer):
    allow_reuse_address = True
    daemon_threads = True


def _b64(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def _payment() -> tuple[str, bytes, str]:
    private = Ed25519PrivateKey.generate()
    public = private.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    jwks = json.dumps(
        {
            "keys": [
                {
                    "kty": "OKP",
                    "crv": "Ed25519",
                    "use": "sig",
                    "alg": "EdDSA",
                    "kid": "test-key-1",
                    "x": _b64(public),
                }
            ]
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode()
    now = int(time.time())
    token = jwt.encode(
        {
            "iat": now - 10,
            "nbf": now - 10,
            "exp": now + 100,
            "aud": RESOURCE,
            "scheme": "exact",
            "amount": "20000",
        },
        private,
        algorithm="EdDSA",
        headers={"kid": "test-key-1"},
    )
    return token, jwks, hashlib.sha256(jwks).hexdigest()


@pytest.fixture()
def proxy_pair(monkeypatch: pytest.MonkeyPatch):
    backend = _ReuseServer(("127.0.0.1", 11435), _Backend)
    backend.seen = []
    backend.location = None
    backend.status = 200
    backend.body = b'{"status":"ok"}'
    token, jwks, digest = _payment()
    proxy = origin_proxy.OriginServer(
        ("127.0.0.1", 0),
        origin_proxy.OriginHandler,
        backend_port=11435,
        jwks_bytes=jwks,
        jwks_sha256=digest,
    )
    dials: list[tuple[str, int]] = []
    original = origin_proxy.http.client.HTTPConnection

    def wrapped(host, port=None, timeout=socket._GLOBAL_DEFAULT_TIMEOUT, source_address=None, blocksize=8192):
        dials.append((str(host), port))
        if (str(host), port) != ("127.0.0.1", 11435):
            raise AssertionError(f"refusing dial to {host}:{port}")
        return original(host, port, timeout=timeout, source_address=source_address, blocksize=blocksize)

    monkeypatch.setattr(origin_proxy.http.client, "HTTPConnection", wrapped)
    threads = [
        threading.Thread(target=backend.serve_forever, daemon=True),
        threading.Thread(target=proxy.serve_forever, daemon=True),
    ]
    for thread in threads:
        thread.start()
    try:
        yield proxy, backend, dials, token, original
    finally:
        proxy.shutdown()
        backend.shutdown()
        proxy.server_close()
        backend.server_close()


def _ask(client, port: int, method: str, target: str, body: bytes | None = None, headers: dict | None = None):
    conn = client("127.0.0.1", port, timeout=3)
    try:
        conn.request(method, target, body=body, headers=headers or {"Connection": "close"})
        response = conn.getresponse()
        return response.status, response.read()
    finally:
        conn.close()


def test_legitimate_pinned_origin_serves_health_and_models(proxy_pair) -> None:
    proxy, backend, dials, _token, client = proxy_pair
    port = proxy.server_address[1]
    status, body = _ask(client, port, "GET", "/health")
    assert status == 200
    assert body == b'{"status":"ok"}'
    backend.body = b'{"data":[]}'
    status, body = _ask(client, port, "GET", "/v1/models")
    assert status == 200
    assert body == b'{"data":[]}'
    assert [item["path"] for item in backend.seen] == ["/health", "/v1/models"]
    assert {item["host"] for item in backend.seen} == {"127.0.0.1:11435"}
    assert dials == [("127.0.0.1", 11435), ("127.0.0.1", 11435)]


def test_payment_context_still_gates_paid_route(proxy_pair) -> None:
    proxy, backend, dials, token, client = proxy_pair
    port = proxy.server_address[1]
    status, body = _ask(
        client,
        port,
        "POST",
        "/v1/chat/completions",
        body=b'{"model":"x"}',
        headers={"Content-Type": "application/json", "Connection": "close"},
    )
    assert status == 403
    assert b"PAYMENT_CONTEXT_MISSING_OR_INVALID" in body
    assert backend.seen == []
    assert dials == []
    status, body = _ask(
        client,
        port,
        "POST",
        "/v1/chat/completions",
        body=b'{"model":"x"}',
        headers={
            "Content-Type": "application/json",
            "Payment-Context": token,
            "Connection": "close",
        },
    )
    assert status == 200
    assert backend.seen == [
        {
            "method": "POST",
            "path": "/v1/chat/completions",
            "host": "127.0.0.1:11435",
            "body": b'{"model":"x"}',
        }
    ]
    assert dials == [("127.0.0.1", 11435)]


@pytest.mark.parametrize(
    "target",
    [
        "http://169.254.169.254/latest/meta-data",
        "http://user:pass@127.0.0.1:11435/health",
        "https://127.0.0.1:11435/health",
        "http://127.0.0.1:443/health",
        "http://8.8.8.8:11435/health",
        "http://10.1.2.3/latest",
        "http://[::1]/",
        "/health/../../etc/passwd",
        "/%2e%2e/health",
        "/health?x=1",
        "http://127.0.0.1:11435/health",
    ],
)
def test_forged_request_targets_are_not_dialed(proxy_pair, target: str) -> None:
    proxy, backend, dials, _token, client = proxy_pair
    status, body = _ask(client, proxy.server_address[1], "GET", target)
    assert status == 404
    assert b"ROUTE_NOT_EXPOSED" in body
    assert backend.seen == []
    assert dials == []


@pytest.mark.parametrize(
    "location",
    [
        "http://169.254.169.254/latest/meta-data",
        "http://127.0.0.1:11435/admin",
        "http://localhost/health",
        "http://10.2.3.4/",
        "http://192.168.1.9/health",
        "http://[::1]/latest",
        "http://rebind.example/health",
    ],
)
def test_backend_redirect_is_not_followed(proxy_pair, location: str) -> None:
    proxy, backend, dials, _token, client = proxy_pair
    backend.location = location
    status, body = _ask(client, proxy.server_address[1], "GET", "/health")
    assert status == 502
    assert b"BACKEND_REDIRECT_REJECTED" in body
    assert location.encode() not in body
    assert len(backend.seen) == 1
    assert backend.seen[0]["path"] == "/health"
    assert dials == [("127.0.0.1", 11435)]
