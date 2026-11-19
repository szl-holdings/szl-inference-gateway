"""Fail-closed posture probe for the x402-metered inference gateway.

Standard library only. Every probe step reports what it measured or an
error string - this package never fabricates a ready state.
"""
from __future__ import annotations

import json
import urllib.error
import urllib.request
from dataclasses import dataclass

DEFAULT_BASE_URL = "https://inference.a-11-oy.com"
SERVED_MODEL_ALIAS = "ternary-bonsai-2-27b-pq2_0"
USER_AGENT = "szl-inference-gateway/0.1 (+https://github.com/szl-holdings/szl-inference-gateway)"
USDC_DECIMALS = 6


@dataclass(frozen=True)
class X402Challenge:
    """A parsed x402 v2 payment challenge (the first accepted payment option)."""

    scheme: str
    network: str
    asset: str
    pay_to: str
    amount_atomic: int
    max_timeout_seconds: int

    @property
    def amount_display(self) -> float:
        """Atomic amount in whole units (6-decimal USDC-style asset)."""
        return self.amount_atomic / (10 ** USDC_DECIMALS)


def parse_x402_challenge(body: str) -> X402Challenge | None:
    """Parse an x402 v2 payment-challenge body; None when it is not one."""
    try:
        doc = json.loads(body)
    except (TypeError, ValueError):
        return None
    if not isinstance(doc, dict) or doc.get("x402Version") != 2:
        return None
    accepts = doc.get("accepts")
    if not isinstance(accepts, list) or not accepts:
        return None
    first = accepts[0]
    if not isinstance(first, dict):
        return None
    try:
        return X402Challenge(
            scheme=str(first["scheme"]),
            network=str(first["network"]),
            asset=str(first["asset"]),
            pay_to=str(first["payTo"]),
            amount_atomic=int(first["amount"]),
            max_timeout_seconds=int(first["maxTimeoutSeconds"]),
        )
    except (KeyError, TypeError, ValueError):
        return None


def model_ids(body: str) -> list[str]:
    """Extract served model IDs from a llama.cpp-style /v1/models body."""
    try:
        doc = json.loads(body)
    except (TypeError, ValueError):
        return []
    if not isinstance(doc, dict):
        return []
    found: list[str] = []
    for key, id_field in (("models", "name"), ("data", "id")):
        items = doc.get(key)
        if isinstance(items, list):
            found.extend(
                str(item[id_field])
                for item in items
                if isinstance(item, dict) and id_field in item
            )
    return sorted(set(found))


def _request(base_url: str, path: str, *, method: str = "GET",
             payload: dict | None = None, timeout: float = 30.0) -> tuple[int, str]:
    data = json.dumps(payload).encode() if payload is not None else None
    headers = {"User-Agent": USER_AGENT}
    if data is not None:
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(base_url.rstrip("/") + path, data=data, method=method, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, resp.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as err:
        return err.code, err.read().decode("utf-8", "replace")


def _err(exc: Exception) -> str:
    return type(exc).__name__ + ": " + str(exc)


def probe_gateway(base_url: str = DEFAULT_BASE_URL, timeout: float = 30.0) -> dict:
    """Probe health, served models, and monetization posture. Honest receipt."""
    receipt: dict = {"base_url": base_url, "healthy": False, "monetized": False}
    served: list[str] = []

    try:
        status, body = _request(base_url, "/health", timeout=timeout)
        ok = status == 200
        if ok:
            try:
                ok = json.loads(body).get("status") == "ok"
            except (TypeError, ValueError):
                ok = False
        receipt["health"] = {"status": status, "ok": ok}
        receipt["healthy"] = ok
    except Exception as exc:  # network failure is reported, never faked
        receipt["health"] = {"error": _err(exc)}

    try:
        status, body = _request(base_url, "/v1/models", timeout=timeout)
        served = model_ids(body) if status == 200 else []
        receipt["models"] = {"status": status, "ids": served}
    except Exception as exc:
        receipt["models"] = {"error": _err(exc)}

    try:
        status, body = _request(
            base_url,
            "/v1/chat/completions",
            method="POST",
            payload={
                "model": served[0] if served else SERVED_MODEL_ALIAS,
                "messages": [{"role": "user", "content": "ping"}],
                "max_tokens": 1,
            },
            timeout=timeout,
        )
        entry: dict = {"status": status}
        if status == 402:
            challenge = parse_x402_challenge(body)
            if challenge is None:
                entry["x402"] = {"error": "402 without a parseable x402 challenge"}
            else:
                entry["x402"] = {
                    "scheme": challenge.scheme,
                    "network": challenge.network,
                    "asset": challenge.asset,
                    "pay_to": challenge.pay_to,
                    "amount_atomic": challenge.amount_atomic,
                    "amount_display": challenge.amount_display,
                    "max_timeout_seconds": challenge.max_timeout_seconds,
                }
                receipt["monetized"] = True
        receipt["chat"] = entry
    except Exception as exc:
        receipt["chat"] = {"error": _err(exc)}

    return receipt
