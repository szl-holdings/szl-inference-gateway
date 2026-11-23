"""Focused origin-gate tests using disposable in-memory Ed25519 keys."""

from __future__ import annotations

import base64
import hashlib
import json

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from szl_inference_gateway.origin_gate import ReplayCache, authorize_payment_context

NOW = 1_800_000_000
RESOURCE = "https://inference.a-11-oy.com/v1/chat/completions"
PATH = "/v1/chat/completions"


def _b64(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def _evidence() -> tuple[str, bytes, str]:
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
    claims = {
        "iat": NOW - 10,
        "nbf": NOW - 10,
        "exp": NOW + 100,
        "aud": RESOURCE,
        "scheme": "exact",
        "amount": "20000",
    }
    token = jwt.encode(
        claims,
        private,
        algorithm="EdDSA",
        headers={"kid": "test-key-1"},
    )
    return token, jwks, hashlib.sha256(jwks).hexdigest()


def test_valid_context_is_authorized_once() -> None:
    token, jwks, pin = _evidence()
    cache = ReplayCache()
    headers = {"payment-context": token}
    first = authorize_payment_context(
        headers,
        method="POST",
        path=PATH,
        now_unix=NOW,
        jwks_bytes=jwks,
        expected_jwks_sha256=pin,
        replay_cache=cache,
    )
    second = authorize_payment_context(
        headers,
        method="POST",
        path=PATH,
        now_unix=NOW,
        jwks_bytes=jwks,
        expected_jwks_sha256=pin,
        replay_cache=cache,
    )
    assert first["state"] == "PAYMENT_CONTEXT_AUTHORIZED"
    assert first["inference_forward_authorized"] is True
    assert second["reason"] == "PAYMENT_CONTEXT_REPLAY"
    assert second["inference_forward_authorized"] is False


def test_missing_context_and_unapproved_route_are_held() -> None:
    _, jwks, pin = _evidence()
    cache = ReplayCache()
    missing = authorize_payment_context(
        {},
        method="POST",
        path=PATH,
        now_unix=NOW,
        jwks_bytes=jwks,
        expected_jwks_sha256=pin,
        replay_cache=cache,
    )
    wrong_route = authorize_payment_context(
        {"PAYMENT-CONTEXT": "not-used"},
        method="POST",
        path=PATH + "?alternate=1",
        now_unix=NOW,
        jwks_bytes=jwks,
        expected_jwks_sha256=pin,
        replay_cache=cache,
    )
    assert missing["reason"] == "PAYMENT_CONTEXT_MISSING_OR_INVALID"
    assert wrong_route["reason"] == "COMPUTE_ROUTE_NOT_APPROVED"
    assert missing["inference_forward_authorized"] is False
    assert wrong_route["inference_forward_authorized"] is False


def test_pin_mismatch_is_held() -> None:
    token, jwks, _ = _evidence()
    result = authorize_payment_context(
        {"Payment-Context": token},
        method="POST",
        path=PATH,
        now_unix=NOW,
        jwks_bytes=jwks,
        expected_jwks_sha256="0" * 64,
        replay_cache=ReplayCache(),
    )
    assert result["reason"] == "JWKS_PIN_MISMATCH"
    assert result["inference_forward_authorized"] is False
