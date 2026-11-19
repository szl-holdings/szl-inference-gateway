"""Offline tests: pure parsing against the recorded production challenge shape."""
import json

from szl_inference_gateway import X402Challenge, model_ids, parse_x402_challenge

# The exact challenge shape the production gateway returned at cutover
# (2026-11-15, inference.a-11-oy.com): USDC on Base, 20000 atomic = $0.02.
PRODUCTION_CHALLENGE = json.dumps(
    {
        "x402Version": 2,
        "error": "PAYMENT-SIGNATURE header is required",
        "resource": {"url": "https://inference.a-11-oy.com/v1/chat/completions"},
        "accepts": [
            {
                "scheme": "exact",
                "network": "eip155:8453",
                "amount": "20000",
                "asset": "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
                "payTo": "0x7b133ef996852c223379d6d1245430300970291A",
                "maxTimeoutSeconds": 3600,
                "extra": {"name": "USD Coin", "version": "2"},
            }
        ],
    }
)


def test_parse_production_challenge():
    challenge = parse_x402_challenge(PRODUCTION_CHALLENGE)
    assert isinstance(challenge, X402Challenge)
    assert challenge.scheme == "exact"
    assert challenge.network == "eip155:8453"
    assert challenge.amount_atomic == 20000
    assert challenge.amount_display == 0.02
    assert challenge.pay_to == "0x7b133ef996852c223379d6d1245430300970291A"
    assert challenge.max_timeout_seconds == 3600


def test_parse_rejects_non_challenges():
    assert parse_x402_challenge(json.dumps({"status": "ok"})) is None
    assert parse_x402_challenge("not json at all") is None
    assert parse_x402_challenge(json.dumps({"x402Version": 2, "accepts": []})) is None
    assert parse_x402_challenge(json.dumps({"x402Version": 2, "accepts": [{"scheme": "exact"}]})) is None


def test_model_ids_llama_cpp_shape():
    body = json.dumps(
        {
            "models": [{"name": "ternary-bonsai-2-27b-pq2_0"}],
            "data": [{"id": "ternary-bonsai-2-27b-pq2_0"}],
        }
    )
    assert model_ids(body) == ["ternary-bonsai-2-27b-pq2_0"]
    assert model_ids("garbage") == []
    assert model_ids(json.dumps({"models": "not-a-list"})) == []
