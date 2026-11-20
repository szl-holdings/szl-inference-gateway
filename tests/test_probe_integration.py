"""Offline mocked network/CLI: no real POST requests, payment or inference."""
import json

from szl_inference_gateway import gateway
from szl_inference_gateway import __main__ as cli
from test_posture import encode, valid_doc


def mock_request(base_url, path, **kwargs):
    if path == "/health":
        return 200, '{"status":"ok"}'
    if path == "/v1/models":
        return 200, json.dumps({"data": [{"id": gateway.SERVED_MODEL_ALIAS}]})
    if path == "/v1/chat/completions":
        assert kwargs["method"] == "POST"
        assert kwargs["include_headers"] is True
        assert kwargs["payload"]["max_tokens"] == 1
        doc = valid_doc()
        return 402, json.dumps(doc), {"payment-required": encode(doc)}
    raise AssertionError(path)


def test_mocked_full_posture(monkeypatch):
    monkeypatch.setattr(gateway, "_request", mock_request)
    r = gateway.probe_gateway(allow_unsigned_post=True, acknowledge_inference_risk=True)
    assert r["healthy"] is True
    assert r["admission"]["state"] == "POSTURE_MATCH_NOT_SETTLEMENT"
    assert r["admission"]["payment_settlement_verified"] is False
    assert r["monetized"] is True


def test_mocked_bad_model_holds(monkeypatch):
    def bad_model(base_url, path, **kwargs):
        if path == "/v1/models":
            return 200, '{"data":[{"id":"unrelated-model"}]}'
        return mock_request(base_url, path, **kwargs)
    monkeypatch.setattr(gateway, "_request", bad_model)
    r = gateway.probe_gateway(allow_unsigned_post=True, acknowledge_inference_risk=True)
    assert r["healthy"] is True
    assert r["admission"]["state"] == "HOLD"
    assert not r["monetized"]


def test_mocked_body_only_holds(monkeypatch):
    def body_only(base_url, path, **kwargs):
        if path == "/v1/chat/completions":
            x = mock_request(base_url, path, **kwargs)
            return x[0], x[1], {}
        return mock_request(base_url, path, **kwargs)
    monkeypatch.setattr(gateway, "_request", body_only)
    r = gateway.probe_gateway(allow_unsigned_post=True, acknowledge_inference_risk=True)
    assert r["admission"]["state"] == "HOLD"
    assert "CANONICAL_X402_V2_HEADER_UNAVAILABLE" in r["admission"]["reasons"]


def test_mocked_health_only_holds(monkeypatch):
    def bad(base_url, path, **kwargs):
        if path == "/v1/models":
            raise TimeoutError("MODELS_TIMEOUT")
        if path == "/v1/chat/completions":
            raise TimeoutError("CHAT_TIMEOUT")
        return mock_request(base_url, path, **kwargs)
    monkeypatch.setattr(gateway, "_request", bad)
    r = gateway.probe_gateway(allow_unsigned_post=True, acknowledge_inference_risk=True)
    assert r["healthy"] is True
    assert r["admission"]["state"] == "HOLD"


def test_cli_refuses_bare_health(monkeypatch, capsys):
    monkeypatch.setattr(cli, "probe_gateway", lambda *a, **kw: {"healthy": True, "admission": {"state":"HOLD"}})
    assert cli.main([]) == 1


def test_cli_accepts_only_limited_posture(monkeypatch, capsys):
    monkeypatch.setattr(cli, "probe_gateway", lambda *a, **kw: {"healthy": True, "admission": {"state":"POSTURE_MATCH_NOT_SETTLEMENT"}})
    assert cli.main(['--allow-unsigned-post', '--acknowledge-inference-risk']) == 0


def test_transport_captures_canonical_http_402_header(monkeypatch):
    import io
    import urllib.error
    import urllib.request
    doc = valid_doc()
    encoded = encode(doc)
    def fake_urlopen(request, timeout):
        raise urllib.error.HTTPError(
            request.full_url, 402, "Payment Required",
            {"PAYMENT-REQUIRED": encoded}, io.BytesIO(json.dumps(doc).encode()),
        )
    monkeypatch.setattr(gateway, "_urlopen_no_redirect", fake_urlopen)
    status, body, headers = gateway._request(gateway.DEFAULT_BASE_URL, "/v1/chat/completions",
                                              method="POST", payload={"test": True}, include_headers=True)
    assert status == 402
    assert json.loads(body) == doc
    assert headers["payment-required"] == encoded


def test_transport_rejects_oversize_http_body(monkeypatch):
    import io
    import urllib.request
    class FakeResponse:
        status = 200
        headers = {}
        def __enter__(self): return self
        def __exit__(self, *args): return False
        def read(self, limit): return b"a" * (limit + 1)
    monkeypatch.setattr(gateway, "_urlopen_no_redirect", lambda *a, **kw: FakeResponse())
    import pytest
    with pytest.raises(ValueError, match="PROBE_RESPONSE_BYTE_BUDGET"):
        gateway._request(gateway.DEFAULT_BASE_URL, "/health")
