"""Offline Ed25519 PAYMENT-CONTEXT verifier; NEVER enables inference or payment.

Cloudflare's Monetization Gateway provides a signed JWT to the origin after
payment authorization. This module can validate recorded synthetic claims
against a caller-supplied, independently hash-pinned JWKS using PyJWT. It
DOES NOT authenticate where a JWKS pin came from, provide replay protection,
protect all origin ports, forward requests, or establish a settlement.
No network, wallet, signing-key, GPU or deployment code exists here.

Docs: https://developers.cloudflare.com/monetization-gateway/configuration/payment-validation/
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import re
from typing import Any

SCHEMA = "szl.payment-context-shadow/v1"
MAX_JWT_BYTES = 4096
MAX_JWKS_BYTES = 8192
MAX_HEADER_BYTES = 512
MAX_PAYLOAD_BYTES = 2048
MAX_KEYS = 8
MAX_LIFETIME_SECONDS = 300
AUDIENCE_HOST = "https://inference.a-11-oy.com"
PAID_URLS = frozenset(
    {
        AUDIENCE_HOST + "/v1/chat/completions",
        AUDIENCE_HOST + "/v1/completions",
    }
)
EXACT_AMOUNT_ATOMIC = "20000"
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_B64 = re.compile(r"^[A-Za-z0-9_-]+$")
_KID = re.compile(r"^[A-Za-z0-9_.-]{1,80}$")


class EvidenceHold(ValueError):
    """Fixed denial reason. Never include header contents or public keys."""


def _hold(reason: str) -> None:
    raise EvidenceHold(reason)


def _unique_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for name, value in pairs:
        if name in result:
            _hold("AMBIGUOUS_JSON")
        result[name] = value
    return result


def _nonfinite(_: str) -> None:
    _hold("INVALID_JSON")


def _strict_json(raw: bytes) -> Any:
    try:
        return json.loads(
            raw.decode("utf-8", "strict"),
            object_pairs_hook=_unique_pairs,
            parse_constant=_nonfinite,
        )
    except (UnicodeError, ValueError, RecursionError) as exc:
        if isinstance(exc, EvidenceHold):
            raise
        _hold("INVALID_JSON")


def _decode_segment(segment: str, maximum: int) -> bytes:
    if (
        not isinstance(segment, str)
        or len(segment) > maximum * 2
        or not _B64.fullmatch(segment)
    ):
        _hold("INVALID_JWT_ENCODING")
    try:
        raw = base64.urlsafe_b64decode(segment + "=" * (-len(segment) % 4))
    except (ValueError, base64.binascii.Error):
        _hold("INVALID_JWT_ENCODING")
    if (
        len(raw) > maximum
        or base64.urlsafe_b64encode(raw).decode().rstrip("=") != segment
    ):
        _hold("INVALID_JWT_ENCODING")
    return raw


def _pinned_keys(jwks_bytes: bytes, digest: str) -> dict[str, dict[str, Any]]:
    if type(jwks_bytes) is not bytes or not (1 <= len(jwks_bytes) <= MAX_JWKS_BYTES):
        _hold("JWKS_UNAVAILABLE")
    if type(digest) is not str or not _SHA256.fullmatch(digest):
        _hold("JWKS_PIN_INVALID")
    if not hmac.compare_digest(hashlib.sha256(jwks_bytes).hexdigest(), digest):
        _hold("JWKS_PIN_MISMATCH")
    obj = _strict_json(jwks_bytes)
    if type(obj) is not dict or set(obj) != {"keys"}:
        _hold("JWKS_INVALID")
    entries = obj["keys"]
    if type(entries) is not list or not 1 <= len(entries) <= MAX_KEYS:
        _hold("JWKS_INVALID")
    keys = {}
    for item in entries:
        if type(item) is not dict or set(item) != {
            "kty",
            "crv",
            "x",
            "use",
            "alg",
            "kid",
        }:
            _hold("JWKS_INVALID")
        kid = item["kid"]
        if type(kid) is not str or not _KID.fullmatch(kid) or kid in keys:
            _hold("JWKS_INVALID")
        if (item["kty"], item["crv"], item["use"], item["alg"]) != (
            "OKP",
            "Ed25519",
            "sig",
            "EdDSA",
        ):
            _hold("JWKS_INVALID")
        pub = _decode_segment(item["x"], 32)
        if len(pub) != 32:
            _hold("JWKS_INVALID")
        keys[kid] = item
    return keys


def _check_context(
    token: str | None,
    jwks_bytes: bytes | None,
    expected_jwks_sha256: str | None,
    *,
    method: str,
    resource: str,
    now_unix: int,
) -> None:
    """Validate claims to a *source-only observation*. Never authorizes forwarding."""
    if method != "POST" or resource not in PAID_URLS:
        _hold("COMPUTE_ROUTE_NOT_APPROVED")
    if type(now_unix) is not int or not 0 < now_unix < 2**53:
        _hold("CLOCK_UNAVAILABLE")
    if (
        type(token) is not str
        or not 20 <= len(token) <= MAX_JWT_BYTES
        or any(c.isspace() for c in token)
    ):
        _hold("PAYMENT_CONTEXT_MISSING_OR_INVALID")
    segments = token.split(".")
    if len(segments) != 3:
        _hold("INVALID_JWT_ENCODING")
    head_bytes = _decode_segment(segments[0], MAX_HEADER_BYTES)
    payload_bytes = _decode_segment(segments[1], MAX_PAYLOAD_BYTES)
    signature = _decode_segment(segments[2], 64)
    if len(signature) != 64:
        _hold("INVALID_JWT_ENCODING")
    header = _strict_json(head_bytes)
    claims = _strict_json(payload_bytes)
    if type(header) is not dict or set(header) != {"alg", "typ", "kid"}:
        _hold("UNSUPPORTED_JWT_HEADER")
    if header["alg"] != "EdDSA" or header["typ"] != "JWT":
        _hold("UNSUPPORTED_JWT_HEADER")
    if type(header["kid"]) is not str or not _KID.fullmatch(header["kid"]):
        _hold("UNSUPPORTED_JWT_HEADER")
    if type(claims) is not dict:
        _hold("CLAIMS_INVALID")
    # The reviewed public JWKS is supplied by a separate owner-controlled pin.
    keys = _pinned_keys(jwks_bytes, expected_jwks_sha256)
    key = keys.get(header["kid"])
    if key is None:
        _hold("SIGNING_KEY_UNKNOWN")
    try:
        import jwt  # optional PyJWT + cryptography dependency

        pubkey = jwt.PyJWK.from_dict(key).key
        decoded = jwt.decode(
            token,
            pubkey,
            algorithms=["EdDSA"],
            audience=resource,
            options={
                "verify_exp": False,
                "verify_nbf": False,
                "verify_iat": False,
                "verify_aud": True,
                "require": ["aud", "scheme", "amount", "exp", "nbf", "iat"],
            },
        )
    except ImportError:
        _hold("JWT_VERIFIER_UNAVAILABLE")
    except Exception:  # noqa: BLE001 - all unexpected verifier failures must deny
        _hold("SIGNATURE_OR_AUDIENCE_INVALID")
    if type(decoded) is not dict or decoded != claims:
        _hold("CLAIMS_INVALID")
    if type(decoded.get("aud")) is not str or decoded["aud"] != resource:
        _hold("AUDIENCE_INVALID")
    if type(decoded.get("scheme")) is not str or decoded["scheme"] != "exact":
        _hold("PAYMENT_SCHEME_INVALID")
    if (
        type(decoded.get("amount")) is not str
        or decoded["amount"] != EXACT_AMOUNT_ATOMIC
    ):
        _hold("PAYMENT_AMOUNT_INVALID")
    for name in ("iat", "nbf", "exp"):
        if type(decoded.get(name)) is not int:
            _hold("TIME_CLAIM_INVALID")
    issued, notbefore, expires = (decoded[k] for k in ("iat", "nbf", "exp"))
    if (
        issued > now_unix
        or notbefore > now_unix
        or expires <= now_unix
        or not (0 < expires - issued <= MAX_LIFETIME_SECONDS)
        or notbefore > expires
    ):
        _hold("TIME_CLAIM_INVALID")
    # This only establishes cryptographic consistency of a frozen synthetic
    # observation with caller-provided keys. Network origin trust/replay, exact
    # deployed route set, policy authority, and monetary settlement remain HOLD.


def shadow_verify(
    token: str | None,
    jwks_bytes: bytes | None,
    expected_jwks_sha256: str | None,
    *,
    method: str,
    resource: str,
    now_unix: int,
) -> dict[str, Any]:
    """Return safe fixed labels, never decoded payment content or token material."""
    try:
        _check_context(
            token,
            jwks_bytes,
            expected_jwks_sha256,
            method=method,
            resource=resource,
            now_unix=now_unix,
        )
    except EvidenceHold as exc:
        classification, reason = "HOLD", str(exc)
    else:
        classification, reason = (
            "CRYPTO_CLAIMS_MATCH_SHADOW_ONLY",
            "REPLAY_AND_ORIGIN_AUTH_UNVERIFIED",
        )
    return {
        "schema": SCHEMA,
        "state": classification,
        "reason": reason,
        "training_authorized": False,
        "inference_forward_authorized": False,
        "origin_runtime_protected": False,
        "replay_prevention_verified": False,
        "payment_settlement_verified": False,
        "production_authorized": False,
        "source_only_shadow": True,
    }
