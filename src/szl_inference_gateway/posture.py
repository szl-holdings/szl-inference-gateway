"""Fail-closed, offline x402 v2 *posture* admission for SZL's gateway.

The result is never a payment settlement, authenticated signature, verified
model inference, source-bound deployment, SLA, or permission to deploy.
This module makes no network calls and never opens a payment wallet.
"""
from __future__ import annotations

import base64
import binascii
import json
import re
from typing import Any

SCHEMA = "szl.inference-gateway.x402-posture/v1"
BASE = "https://inference.a-11-oy.com"
RESOURCE = BASE + "/v1/chat/completions"
MODEL = "ternary-bonsai-2-27b-pq2_0"
BASE_NETWORK = "eip155:8453"
USDC_BASE = "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913"
RECEIVER = "0x7b133ef996852c223379d6d1245430300970291A"
AMOUNT_ATOMIC = "20000"
MAX_HEADER_BYTES = 8192
MAX_DECODED_BYTES = 6144
_ADDRESS = re.compile(r"0x[0-9a-fA-F]{40}\Z")
_AMOUNT = re.compile(r"[1-9][0-9]{0,24}\Z")


class DuplicatePaymentField(ValueError):
    """Ambiguous x402 JSON is not valid protocol-posture evidence."""


def _reject_duplicate_payment_fields(pairs):
    obj = {}
    for key, value in pairs:
        if key in obj:
            raise DuplicatePaymentField("DUPLICATE_PAYMENT_JSON_KEY")
        obj[key] = value
    return obj


def strict_payment_json_loads(body):
    """Parse x402 JSON with duplicate rejection at every object depth."""
    return json.loads(
        body,
        object_pairs_hook=_reject_duplicate_payment_fields,
        parse_constant=lambda _: (_ for _ in ()).throw(ValueError("NONFINITE_PAYMENT_JSON")),
    )


def decode_payment_required_header(value: Any) -> dict[str, Any] | None:
    """Decode x402 v2 HTTP PAYMENT-REQUIRED; reject malformed/unbounded headers."""
    if type(value) is not str or not 4 <= len(value) <= MAX_HEADER_BYTES:
        return None
    try:
        blob = base64.b64decode(value, validate=True)
        if len(blob) > MAX_DECODED_BYTES:
            return None
        doc = strict_payment_json_loads(blob.decode("utf-8", "strict"))
    except (ValueError, UnicodeError, binascii.Error, TypeError, RecursionError):
        return None
    return doc if type(doc) is dict else None


def _valid_terms(doc: Any) -> bool:
    if type(doc) is not dict or type(doc.get("x402Version")) is not int or doc["x402Version"] != 2:
        return False
    resource = doc.get("resource")
    if type(resource) is not dict or resource.get("url") != RESOURCE:
        return False
    accepts = doc.get("accepts")
    if type(accepts) is not list or len(accepts) != 1:
        return False
    for item in accepts:
        if type(item) is not dict:
            return False
        fields = ("scheme", "network", "amount", "asset", "payTo", "maxTimeoutSeconds")
        if not all(field in item for field in fields):
            return False
        if any(type(item[f]) is not str for f in fields[:-1]):
            return False
        if not _AMOUNT.fullmatch(item["amount"]):
            return False
        if not _ADDRESS.fullmatch(item["asset"]) or not _ADDRESS.fullmatch(item["payTo"]):
            return False
        if type(item["maxTimeoutSeconds"]) is not int or not 1 <= item["maxTimeoutSeconds"] <= 3600:
            return False
    return any(
        item["scheme"] == "exact"
        and item["network"] == BASE_NETWORK
        and item["amount"] == AMOUNT_ATOMIC
        and item["asset"].lower() == USDC_BASE.lower()
        and item["payTo"].lower() == RECEIVER.lower()
        and item["maxTimeoutSeconds"] == 3600
        for item in accepts
    )


def evaluate_posture(receipt: Any) -> dict[str, Any]:
    """Evaluate one untrusted public probe report against a pinned policy.

    An acceptable report is *only* protocol-posture evidence; zero permission
    is granted even when all checks match. Callers must separately prove source,
    payment settlement, model accuracy, service auth, tenant and SLOs.
    """
    reasons: list[str] = []
    if type(receipt) is not dict:
        reasons.append("RECEIPT_MALFORMED")
        receipt = {}
    if receipt.get("base_url") != BASE:
        reasons.append("GATEWAY_HOST_UNPINNED")
    health = receipt.get("health")
    if not (type(health) is dict and type(health.get("status")) is int
            and health["status"] == 200 and health.get("ok") is True
            and receipt.get("healthy") is True):
        reasons.append("HEALTH_NOT_VERIFIED")
    models = receipt.get("models")
    if not (type(models) is dict and type(models.get("status")) is int
            and models["status"] == 200 and type(models.get("ids")) is list
            and len(models["ids"]) <= 128 and all(type(v) is str for v in models["ids"])
            and MODEL in models["ids"]):
        reasons.append("PINNED_MODEL_NOT_VERIFIED")
    chat = receipt.get("chat")
    if not (type(chat) is dict and type(chat.get("status")) is int and chat["status"] == 402):
        reasons.append("PAYMENT_CHALLENGE_NOT_402")
    header_doc = decode_payment_required_header(chat.get("payment_required_header") if type(chat) is dict else None)
    if header_doc is None:
        reasons.append("CANONICAL_X402_V2_HEADER_UNAVAILABLE")
    elif not _valid_terms(header_doc):
        reasons.append("X402_POLICY_MISMATCH")
    # Body may legitimately be empty; only refuse an *explicit conflicting*
    # PaymentRequired document. The canonical transport contract is the header.
    if type(chat) is dict and "payment_required_body" in chat:
        body = chat["payment_required_body"]
        if type(body) is not str or len(body) > MAX_DECODED_BYTES:
            reasons.append("PAYMENT_BODY_UNSUPPORTED")
        else:
            try:
                body_doc = strict_payment_json_loads(body)
            except DuplicatePaymentField:
                # Ordinary HTML/text 402 bodies may be unparseable, but an
                # explicit contradictory JSON object is not benign evidence.
                reasons.append("PAYMENT_BODY_AMBIGUOUS_JSON")
                body_doc = None
            except (ValueError, TypeError, RecursionError):
                body_doc = None
            if type(body_doc) is dict and "x402Version" in body_doc:
                if not _valid_terms(body_doc) or (header_doc is not None and
                        (body_doc.get("resource") != header_doc.get("resource") or
                         body_doc.get("accepts") != header_doc.get("accepts"))):
                    reasons.append("PAYMENT_HEADER_BODY_CONFLICT")
    return {
        "schema": SCHEMA,
        "state": "POSTURE_MATCH_NOT_SETTLEMENT" if not reasons else "HOLD",
        "reasons": reasons,
        "production_authorized": False,
        "payment_settlement_verified": False,
        "model_inference_verified": False,
        "source_revision_verified": False,
        "receipt_signed": False,
        "caller_authentication_verified": False,
        "evidence_class": "UNSIGNED_NETWORK_POSTURE_ONLY",
    }
