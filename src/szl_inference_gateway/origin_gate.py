"""Fail-closed per-request PAYMENT-CONTEXT authorization.

This module is the narrow origin admission gate. It verifies the signed
Cloudflare PAYMENT-CONTEXT JWT against an operator-supplied hash-pinned JWKS,
checks the exact paid route, and consumes each token once in a bounded replay
cache. It never fetches keys or forwards requests.
"""

from __future__ import annotations

import hashlib
import threading
import time
from collections.abc import Mapping
from typing import Any

from .payment_context_shadow import MAX_LIFETIME_SECONDS, _check_context

_RESOURCE_BY_PATH = {
    "/v1/chat/completions": "https://inference.a-11-oy.com/v1/chat/completions",
}


class ReplayCache:
    """Bounded, process-local one-time token cache."""

    def __init__(self, *, max_entries: int = 10_000) -> None:
        if type(max_entries) is not int or not 1 <= max_entries <= 100_000:
            raise ValueError("REPLAY_CACHE_SIZE_INVALID")
        self._max_entries = max_entries
        self._entries: dict[str, int] = {}
        self._lock = threading.Lock()

    def consume(self, token: str, *, now_unix: int) -> None:
        """Reserve a token once until its maximum lifetime ends."""
        digest = hashlib.sha256(token.encode("utf-8")).hexdigest()
        with self._lock:
            expired = [key for key, expires in self._entries.items() if expires <= now_unix]
            for key in expired:
                del self._entries[key]
            if digest in self._entries:
                raise ValueError("PAYMENT_CONTEXT_REPLAY")
            if len(self._entries) >= self._max_entries:
                raise ValueError("PAYMENT_CONTEXT_REPLAY_CACHE_FULL")
            self._entries[digest] = now_unix + MAX_LIFETIME_SECONDS


def _header(headers: Mapping[str, Any], name: str) -> Any:
    wanted = name.lower()
    for key, value in headers.items():
        if isinstance(key, str) and key.lower() == wanted:
            return value
    return None


def authorize_payment_context(
    headers: Mapping[str, Any],
    *,
    method: str,
    path: str,
    now_unix: int | None = None,
    jwks_bytes: bytes | None,
    expected_jwks_sha256: str | None,
    replay_cache: ReplayCache,
) -> dict[str, Any]:
    """Return a fixed authorization decision for one origin request."""
    now = int(time.time()) if now_unix is None else now_unix
    resource = _RESOURCE_BY_PATH.get(path)
    token = _header(headers, "PAYMENT-CONTEXT")
    try:
        _check_context(
            token,
            jwks_bytes,
            expected_jwks_sha256,
            method=method,
            resource=resource,
            now_unix=now,
        )
        replay_cache.consume(token, now_unix=now)
    except Exception as exc:  # noqa: BLE001 - all gate failures deny
        reason = str(exc) if str(exc) in {
            "COMPUTE_ROUTE_NOT_APPROVED", "CLOCK_UNAVAILABLE",
            "PAYMENT_CONTEXT_MISSING_OR_INVALID", "INVALID_JWT_ENCODING",
            "UNSUPPORTED_JWT_HEADER", "CLAIMS_INVALID", "JWKS_UNAVAILABLE",
            "JWKS_PIN_INVALID", "JWKS_PIN_MISMATCH", "JWKS_INVALID",
            "SIGNING_KEY_UNKNOWN", "JWT_VERIFIER_UNAVAILABLE",
            "SIGNATURE_OR_AUDIENCE_INVALID", "AUDIENCE_INVALID",
            "PAYMENT_SCHEME_INVALID", "PAYMENT_AMOUNT_INVALID",
            "TIME_CLAIM_INVALID", "PAYMENT_CONTEXT_REPLAY",
            "PAYMENT_CONTEXT_REPLAY_CACHE_FULL",
        } else "PAYMENT_CONTEXT_DENIED"
        return {
            "state": "HOLD",
            "reason": reason,
            "inference_forward_authorized": False,
            "production_authorized": False,
            "replay_prevention_verified": False,
        }
    return {
        "state": "PAYMENT_CONTEXT_AUTHORIZED",
        "reason": "SIGNED_CONTEXT_AND_REPLAY_CHECKS_PASSED",
        "inference_forward_authorized": True,
        "production_authorized": True,
        "replay_prevention_verified": True,
    }
