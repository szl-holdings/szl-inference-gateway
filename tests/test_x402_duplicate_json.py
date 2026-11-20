"""Adversarial x402 JSON ambiguity: no signed or settled claims are made."""

import base64
import json

import pytest

from szl_inference_gateway.gateway import parse_x402_challenge
from szl_inference_gateway.posture import (
    AMOUNT_ATOMIC,
    BASE,
    BASE_NETWORK,
    MODEL,
    RECEIVER,
    RESOURCE,
    USDC_BASE,
    decode_payment_required_header,
    evaluate_posture,
)


def valid_doc():
    return {
        "x402Version": 2,
        "resource": {"url": RESOURCE},
        "accepts": [
            {
                "scheme": "exact",
                "network": BASE_NETWORK,
                "amount": AMOUNT_ATOMIC,
                "asset": USDC_BASE,
                "payTo": RECEIVER,
                "maxTimeoutSeconds": 3600,
            },
        ],
    }


def fixture():
    document = valid_doc()
    return {
        "base_url": BASE,
        "healthy": True,
        "health": {"status": 200, "ok": True},
        "models": {"status": 200, "ids": [MODEL]},
        "chat": {
            "status": 402,
            "payment_required_header": base64.b64encode(
                json.dumps(document).encode()
            ).decode(),
            "payment_required_body": json.dumps(document),
        },
    }


def add_duplicate(source, key, invalid):
    needle = json.dumps(key) + ": " + json.dumps(source[key])
    assert needle in json.dumps(source)
    original = json.dumps(source)
    duplicate = json.dumps(key) + ": " + json.dumps(invalid) + ", " + needle
    return original.replace(needle, duplicate, 1)


@pytest.mark.parametrize(
    "key,invalid",
    [
        ("x402Version", 1),
        ("accepts", []),
    ],
)
def test_ambiguous_header_root_must_hold(key, invalid):
    receipt = fixture()
    raw = add_duplicate(valid_doc(), key, invalid)
    receipt["chat"]["payment_required_header"] = base64.b64encode(raw.encode()).decode()
    assert (
        decode_payment_required_header(receipt["chat"]["payment_required_header"])
        is None
    )
    outcome = evaluate_posture(receipt)
    assert outcome["state"] == "HOLD"
    assert not outcome["payment_settlement_verified"]


def test_ambiguous_header_nested_payment_amount_must_hold():
    receipt = fixture()
    document = valid_doc()
    raw = json.dumps(document).replace(
        '"amount": "20000"', '"amount": "1", "amount": "20000"', 1
    )
    receipt["chat"]["payment_required_header"] = base64.b64encode(raw.encode()).decode()
    assert (
        decode_payment_required_header(receipt["chat"]["payment_required_header"])
        is None
    )
    assert evaluate_posture(receipt)["state"] == "HOLD"


def test_ambiguous_body_with_valid_header_must_hold():
    receipt = fixture()
    raw = json.dumps(valid_doc()).replace(
        '"amount": "20000"', '"amount": "1", "amount": "20000"', 1
    )
    receipt["chat"]["payment_required_body"] = raw
    outcome = evaluate_posture(receipt)
    assert outcome["state"] == "HOLD"
    assert not outcome["production_authorized"]


def test_gateway_parser_does_not_present_ambiguous_body_as_challenge():
    raw = json.dumps(valid_doc()).replace(
        '"amount": "20000"', '"amount": "1", "amount": "20000"', 1
    )
    assert parse_x402_challenge(raw) is None


def test_ordinary_valid_posture_stays_unsigned_not_settled():
    result = evaluate_posture(fixture())
    assert result["state"] == "POSTURE_MATCH_NOT_SETTLEMENT"
    assert result["payment_settlement_verified"] is False
    assert result["production_authorized"] is False
