"""Offline negative Ed25519 x402 origin JWT tests. Synthetic ephemeral keys only."""

from __future__ import annotations

import base64
import hashlib
import json

import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from szl_inference_gateway import payment_context_shadow as shadow

NOW = 1_800_000_000
AUD = "https://inference.a-11-oy.com/v1/chat/completions"


def _b64(payload: bytes) -> str:
    return base64.urlsafe_b64encode(payload).decode().rstrip("=")


@pytest.fixture
def evidence():
    # Generate *new disposable synthetic test keys* in memory; never use an owner key.
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
    pin = hashlib.sha256(jwks).hexdigest()
    claims = {
        "iat": NOW - 10,
        "nbf": NOW - 10,
        "exp": NOW + 100,
        "aud": AUD,
        "scheme": "exact",
        "amount": "20000",
    }

    def build(claim_overrides=None, *, key=None, headers=None):
        d = dict(claims)
        d.update(claim_overrides or {})
        return jwt.encode(
            d,
            key or private,
            algorithm="EdDSA",
            headers={"kid": "test-key-1", **(headers or {})},
        )

    def check(
        token=None,
        *,
        key_bytes=None,
        hash_pin=None,
        method="POST",
        resource=AUD,
        clock=NOW,
    ):
        return shadow.shadow_verify(
            build() if token is None else token,
            jwks if key_bytes is None else key_bytes,
            pin if hash_pin is None else hash_pin,
            method=method,
            resource=resource,
            now_unix=clock,
        )

    return private, jwks, pin, claims, build, check


def test_signature_valid_is_shadow_not_authorized(evidence):
    _, _, _, _, _, check = evidence
    r = check()
    assert r["state"] == "CRYPTO_CLAIMS_MATCH_SHADOW_ONLY"
    assert r["inference_forward_authorized"] is False
    assert r["replay_prevention_verified"] is False
    assert r["origin_runtime_protected"] is False
    assert r["payment_settlement_verified"] is False
    assert r["production_authorized"] is False


@pytest.mark.parametrize(
    "bad_url,method",
    [
        (AUD, "GET"),
        (AUD, "PATCH"),
        (AUD + "/redirect", "POST"),
        (AUD + "?tenant=other", "POST"),
        ("http://inference.a-11-oy.com/v1/chat/completions", "POST"),
        ("https://inference.a-11-oy.com/completion", "POST"),
        ("https://inference.a-11-oy.com/", "POST"),
    ],
)
def test_uncovered_compute_and_method_never_admitted(evidence, bad_url, method):
    *_, check = evidence
    r = check(resource=bad_url, method=method)
    assert r["state"] == "HOLD"
    assert r["reason"] == "COMPUTE_ROUTE_NOT_APPROVED"
    assert not r["inference_forward_authorized"]


def test_replaying_identical_signed_token_never_authorizes_backend(evidence):
    *_, build, check = evidence
    token = build()
    first, second = check(token), check(token)
    assert first == second
    assert first["state"] == "CRYPTO_CLAIMS_MATCH_SHADOW_ONLY"
    assert first["replay_prevention_verified"] is False
    assert first["inference_forward_authorized"] is False


def test_missing_header_rejected(evidence):
    _, jwks, pin, _, _, _ = evidence
    r = shadow.shadow_verify(None, jwks, pin, method="POST", resource=AUD, now_unix=NOW)
    assert r["state"] == "HOLD"
    assert r["reason"] == "PAYMENT_CONTEXT_MISSING_OR_INVALID"


@pytest.mark.parametrize(
    "overrides",
    [
        {"aud": "https://evil.invalid/v1/chat/completions"},
        {"aud": [AUD, "https://evil.invalid/v1/chat/completions"]},
        {"scheme": "upto"},
        {"amount": "20001"},
        {"amount": 20000},
        {"amount": "020000"},
        {"nbf": NOW + 1},
        {"exp": NOW},
        {"iat": NOW + 1},
        {"exp": NOW + 301},
        {"exp": None},
        {"iat": True},
    ],
)
def test_bad_audience_amount_scheme_time_held(evidence, overrides):
    *_, build, check = evidence
    outcome = check(build(overrides))
    assert outcome["state"] == "HOLD"
    assert outcome["production_authorized"] is False


def test_explicit_second_route_must_match_signed_audience(evidence):
    *_, build, check = evidence
    alt = "https://inference.a-11-oy.com/v1/completions"
    assert (
        check(build({"aud": alt}), resource=alt)["state"]
        == "CRYPTO_CLAIMS_MATCH_SHADOW_ONLY"
    )
    assert check(build({"aud": alt}), resource=AUD)["state"] == "HOLD"


def test_malformed_algorithm_and_unknown_key_rejected(evidence):
    *_, build, check = evidence
    unsigned_alg = jwt.encode(
        {"aud": AUD},
        "synthetic-attacker-key-not-real-32bytes",
        algorithm="HS256",
        headers={"kid": "test-key-1"},
    )
    assert check(unsigned_alg)["state"] == "HOLD"
    for headers in (
        {"kid": "unreviewed-key"},
        {"jku": "https://evil.invalid/keys"},
        {"typ": "JWE"},
    ):
        assert check(build(headers=headers))["state"] == "HOLD"


def test_signature_tamper_rejected(evidence):
    *_, build, check = evidence
    original = build()
    a, b, c = original.split(".")
    signature = bytearray(base64.urlsafe_b64decode(c + "=" * (-len(c) % 4)))
    signature[0] ^= 1
    assert check(a + "." + b + "." + _b64(signature))["state"] == "HOLD"


def test_wrong_pubkey_and_pin_mismatch_held(evidence):
    _, _, _, _, build, check = evidence
    different = (
        Ed25519PrivateKey.generate()
        .public_key()
        .public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    )
    wrong = json.dumps(
        {
            "keys": [
                {
                    "kty": "OKP",
                    "crv": "Ed25519",
                    "x": _b64(different),
                    "use": "sig",
                    "alg": "EdDSA",
                    "kid": "test-key-1",
                }
            ]
        },
        separators=(",", ":"),
    ).encode()
    assert (
        check(build(), key_bytes=wrong, hash_pin=hashlib.sha256(wrong).hexdigest())[
            "state"
        ]
        == "HOLD"
    )
    assert check(build(), hash_pin="0" * 64)["reason"] == "JWKS_PIN_MISMATCH"


def test_duplicate_jwk_keys_and_wrong_jwk_algorithm_hold(evidence):
    _, jwks, _, _, build, check = evidence
    doc = json.loads(jwks)
    doc["keys"].append(dict(doc["keys"][0]))
    invalid = json.dumps(doc).encode()
    assert (
        check(build(), key_bytes=invalid, hash_pin=hashlib.sha256(invalid).hexdigest())[
            "reason"
        ]
        == "JWKS_INVALID"
    )
    doc["keys"][1]["kid"] = "test-key-2"
    doc["keys"][1]["alg"] = "HS256"
    invalid2 = json.dumps(doc).encode()
    assert (
        check(
            build(), key_bytes=invalid2, hash_pin=hashlib.sha256(invalid2).hexdigest()
        )["reason"]
        == "JWKS_INVALID"
    )


def test_jwt_duplicate_claims_fail_even_when_signed(evidence):
    private, jwks, pin, claims, _, _ = evidence
    payload = json.dumps(claims, separators=(",", ":")).replace(
        '"amount":"20000"', '"amount":"1","amount":"20000"'
    )
    header = '{"typ":"JWT","alg":"EdDSA","kid":"test-key-1"}'
    a, b = _b64(header.encode()), _b64(payload.encode())
    token = a + "." + b + "." + _b64(private.sign((a + "." + b).encode()))
    r = shadow.shadow_verify(
        token, jwks, pin, method="POST", resource=AUD, now_unix=NOW
    )
    assert r["state"] == "HOLD"
    assert r["reason"] == "AMBIGUOUS_JSON"


def test_jwt_duplicate_header_fails_even_when_signed(evidence):
    private, jwks, pin, claims, _, _ = evidence
    header = '{"typ":"JWT","alg":"none","alg":"EdDSA","kid":"test-key-1"}'
    a, b = _b64(header.encode()), _b64(json.dumps(claims).encode())
    token = a + "." + b + "." + _b64(private.sign((a + "." + b).encode()))
    r = shadow.shadow_verify(
        token, jwks, pin, method="POST", resource=AUD, now_unix=NOW
    )
    assert r["reason"] == "AMBIGUOUS_JSON"


@pytest.mark.parametrize("clock", [None, True, -1, "1800000000"])
def test_clock_invalid(evidence, clock):
    *_, check = evidence
    assert check(clock=clock)["reason"] == "CLOCK_UNAVAILABLE"


def test_no_handler_exists_to_forward_gpu_inference():
    assert not hasattr(shadow, "forward")
    assert not hasattr(shadow, "serve")
    assert not hasattr(shadow, "deploy")
