"""Offline, deterministic contract checks for the x402 HTTP v2 gate."""
import base64
import copy
import json

from szl_inference_gateway.posture import (
    AMOUNT_ATOMIC, BASE, BASE_NETWORK, MODEL, RECEIVER, RESOURCE,
    USDC_BASE, decode_payment_required_header, evaluate_posture,
)


def valid_doc():
    return {
        "x402Version": 2, "resource": {"url": RESOURCE},
        "accepts": [{"scheme": "exact", "network": BASE_NETWORK,
                     "amount": AMOUNT_ATOMIC, "asset": USDC_BASE,
                     "payTo": RECEIVER, "maxTimeoutSeconds": 3600}],
    }


def encode(value):
    return base64.b64encode(json.dumps(value, sort_keys=True).encode()).decode("ascii")


def fixture():
    doc = valid_doc()
    return {"base_url": BASE, "healthy": True, "health": {"status": 200, "ok": True},
            "models": {"status": 200, "ids": [MODEL]},
            "chat": {"status": 402, "payment_required_header": encode(doc),
                     "payment_required_body": json.dumps(doc)}}


def test_fully_matched_is_not_settlement_or_deployment():
    rec = evaluate_posture(fixture())
    assert rec["state"] == "POSTURE_MATCH_NOT_SETTLEMENT"
    for k in ("production_authorized", "payment_settlement_verified", "receipt_signed",
              "source_revision_verified", "model_inference_verified"):
        assert rec[k] is False


def test_header_only_body_absent_is_allowed():
    x = fixture(); del x["chat"]["payment_required_body"]
    assert evaluate_posture(x)["state"] == "POSTURE_MATCH_NOT_SETTLEMENT"


def test_health_alone_is_held():
    x = fixture(); del x["models"]; del x["chat"]
    assert "PINNED_MODEL_NOT_VERIFIED" in evaluate_posture(x)["reasons"]
    assert evaluate_posture(x)["state"] == "HOLD"


def test_http_200_chat_refused():
    x = fixture(); x["chat"]["status"] = 200
    assert "PAYMENT_CHALLENGE_NOT_402" in evaluate_posture(x)["reasons"]


def test_body_only_402_refused():
    x = fixture(); del x["chat"]["payment_required_header"]
    assert "CANONICAL_X402_V2_HEADER_UNAVAILABLE" in evaluate_posture(x)["reasons"]


def test_wrong_chain_and_wrong_recipient():
    for key, value in (("network", "eip155:84532"), ("payTo", "0x" + "a"*40)):
        x = fixture(); doc = valid_doc(); doc["accepts"][0][key] = value
        x["chat"]["payment_required_header"] = encode(doc)
        x["chat"]["payment_required_body"] = json.dumps(doc)
        assert "X402_POLICY_MISMATCH" in evaluate_posture(x)["reasons"]


def test_missing_resource_and_wrong_url():
    for url in ("http://example.com/challenge", BASE + "/unrelated"):
        x=fixture();doc=valid_doc();doc["resource"]["url"]=url
        x["chat"]["payment_required_header"] = encode(doc)
        x["chat"]["payment_required_body"] = json.dumps(doc)
        assert evaluate_posture(x)["state"] == "HOLD"


def test_amount_negative_decimal_boolean_excess():
    for amount in ("-1", "0", "20000.0", 20000, False, "999999999999999999999999999"):
        x=fixture();doc=valid_doc();doc["accepts"][0]["amount"]=amount
        x["chat"]["payment_required_header"]=encode(doc)
        x["chat"]["payment_required_body"]=json.dumps(doc)
        assert evaluate_posture(x)["state"] == "HOLD"


def test_timeout_boolean_and_zero_rejected():
    for val in (True,0,3601,"3600"):
        x=fixture();doc=valid_doc();doc["accepts"][0]["maxTimeoutSeconds"]=val
        x["chat"]["payment_required_header"]=encode(doc)
        x["chat"]["payment_required_body"]=json.dumps(doc)
        assert evaluate_posture(x)["state"] == "HOLD"


def test_mismatched_body_held():
    x=fixture();doc=valid_doc();doc["accepts"][0]["amount"]="10000"
    x["chat"]["payment_required_body"]=json.dumps(doc)
    assert "PAYMENT_HEADER_BODY_CONFLICT" in evaluate_posture(x)["reasons"]


def test_header_parser_untrusted_types():
    for raw in (None, False, "!", "A"*10000, b"notstr", encode([1,2]), encode({"foo":"bar"})[:-1]):
        r=decode_payment_required_header(raw)
        assert r is None or (type(r) is dict and not r.get("accepts"))


def test_model_bool_status_rejected():
    x=fixture();x["health"]["status"]=True
    assert evaluate_posture(x)["state"] == "HOLD"
    x=fixture();x["models"]["status"]=True
    assert evaluate_posture(x)["state"] == "HOLD"


def test_wrong_base_refused():
    x=fixture();x["base_url"]="http://127.0.0.1:8000"
    assert "GATEWAY_HOST_UNPINNED" in evaluate_posture(x)["reasons"]


def test_malformed_envelope_rejected():
    for x in ([],None,"yes",42):
        assert evaluate_posture(x)["state"] == "HOLD"


def test_randomized_mutation_never_authorizes():
    import random
    rng=random.Random(20261119)
    for _ in range(512):
        x=fixture()
        which=rng.randrange(8)
        if which == 0: x["models"]["ids"]=[]
        elif which == 1: x["health"]["ok"]=False
        elif which == 2: x["chat"]["payment_required_header"]="%%%"
        elif which == 3: x["chat"]["status"]=rng.choice([200,401,403,404,500])
        elif which == 4: x["base_url"]=BASE+"/bad"
        else:
            d=valid_doc();d["accepts"][0][rng.choice(["amount","network","asset"])]=rng.choice(["0","eip155:84532","0x"+"0"*40])
            x["chat"]["payment_required_header"]=encode(d)
        assert evaluate_posture(x)["state"]=="HOLD"
