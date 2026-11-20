"""Offline fail-closed audit safety: no unapproved generation or paid GPU calls."""
import json
import pytest
from szl_inference_gateway import gateway
from szl_inference_gateway import __main__ as cli


def _get_only(requests):
    def request(base, path, **kwargs):
        requests.append((base, path, kwargs.get("method", "GET")))
        if path == "/health":
            return 200, '{"status":"ok"}'
        if path == "/v1/models":
            return 200, json.dumps({"data": [{"id": gateway.SERVED_MODEL_ALIAS}]})
        raise AssertionError("UNEXPECTED_NETWORK_REQUEST")
    return request


def test_default_is_get_only_even_when_healthy(monkeypatch):
    requests = []
    monkeypatch.setattr(gateway, "_request", _get_only(requests))
    receipt = gateway.probe_gateway()
    assert [q[1:] for q in requests] == [
        ("/health", "GET"), ("/v1/models", "GET")
    ]
    assert receipt["healthy"] is True
    assert receipt["post_check_enabled"] is False
    assert receipt["post_attempted"] is False
    assert receipt["chat"] == {"state": "NOT_PROBED_READ_ONLY", "request_sent": False}
    assert receipt["admission"]["state"] == "HOLD"
    assert receipt["monetized"] is False
    assert receipt["admission"]["payment_settlement_verified"] is False


@pytest.mark.parametrize("allow,ack", [(True, False), (False, True), (1, True), ("false", False)])
def test_incomplete_or_nonboolean_post_scope_refused_before_network(monkeypatch, allow, ack):
    def impossible(*args, **kw):
        raise AssertionError("NETWORK_MUST_NOT_RUN")
    monkeypatch.setattr(gateway, "_request", impossible)
    with pytest.raises(ValueError):
        gateway.probe_gateway(allow_unsigned_post=allow, acknowledge_inference_risk=ack)


@pytest.mark.parametrize("base", [
    "http://inference.a-11-oy.com",
    "https://evil.example",
    "https://inference.a-11-oy.com/",
    "https://inference.a-11-oy.com:443",
    "https://user@inference.a-11-oy.com",
    "https://inference.a-11-oy.com.example",
    "https://inference.a-11-oy.com/other",
])
def test_explicit_post_never_targets_alternate_origin(monkeypatch, base):
    monkeypatch.setattr(gateway, "_request", lambda *a, **kw: (_ for _ in ()).throw(AssertionError("NETWORK")))
    with pytest.raises(ValueError, match="POST_ORIGIN_NOT_EXACT_CANONICAL_HTTPS"):
        gateway.probe_gateway(base, allow_unsigned_post=True, acknowledge_inference_risk=True)


@pytest.mark.parametrize("timeout", [0, -1, 31, float("inf"), float("nan"), "60", True])
def test_invalid_or_unbounded_timeout_rejected_before_network(monkeypatch, timeout):
    monkeypatch.setattr(gateway, "_request", lambda *a, **kw: (_ for _ in ()).throw(AssertionError("NETWORK")))
    with pytest.raises(ValueError, match="PROBE_TIMEOUT_OUT_OF_RANGE"):
        gateway.probe_gateway(timeout=timeout)


def test_explicit_post_makes_one_bounded_request_but_200_is_hold(monkeypatch):
    calls = []
    def fake(base, path, **kw):
        calls.append((base, path, kw))
        if path == "/health": return 200, '{"status":"ok"}'
        if path == "/v1/models":
            return 200, json.dumps({"data": [{"id": gateway.SERVED_MODEL_ALIAS}]})
        if path == "/v1/chat/completions":
            assert kw["method"] == "POST"
            assert kw["payload"]["max_tokens"] == 1
            assert kw["timeout"] == 4.5
            return 200, '{"choices":[]}', {}
        raise AssertionError("UNEXPECTED_ROUTE")
    monkeypatch.setattr(gateway, "_request", fake)
    receipt = gateway.probe_gateway(timeout=4.5, allow_unsigned_post=True, acknowledge_inference_risk=True)
    assert len(calls) == 3
    assert len([c for c in calls if c[2].get("method") == "POST"]) == 1
    assert receipt["post_attempted"] is True
    assert receipt["admission"]["state"] == "HOLD"
    assert receipt["monetized"] is False


@pytest.mark.parametrize("health_ok,model_alias", [
    (False, gateway.SERVED_MODEL_ALIAS),
    (True, "unrelated-model"),
    (False, "unrelated-model"),
])
def test_even_explicit_post_is_withheld_when_preflight_unqualified(monkeypatch, health_ok, model_alias):
    paths = []
    def fake(base, path, **kw):
        paths.append(path)
        if path == "/health":
            return 200, '{"status":"ok"}' if health_ok else '{"status":"down"}'
        if path == "/v1/models":
            return 200, json.dumps({"data": [{"id": model_alias}]})
        raise AssertionError("POST_MUST_NOT_BE_SENT")
    monkeypatch.setattr(gateway, "_request", fake)
    receipt = gateway.probe_gateway(allow_unsigned_post=True, acknowledge_inference_risk=True)
    assert paths == ["/health", "/v1/models"]
    assert receipt["post_attempted"] is False
    assert receipt["chat"]["state"] == "NOT_PROBED_UNQUALIFIED_PREFLIGHT"
    assert receipt["admission"]["state"] == "HOLD"


def test_two_served_models_cannot_redirect_opted_in_probe_to_wrong_model(monkeypatch):
    paths = []
    def fake(base, path, **kw):
        paths.append(path)
        if path == "/health":
            return 200, '{"status":"ok"}'
        if path == "/v1/models":
            return 200, json.dumps({"data": [
                {"id": "unrelated-model"}, {"id": gateway.SERVED_MODEL_ALIAS}
            ]})
        raise AssertionError("UNREVIEWED_MODEL_POST_FORBIDDEN")
    monkeypatch.setattr(gateway, "_request", fake)
    receipt = gateway.probe_gateway(
        allow_unsigned_post=True, acknowledge_inference_risk=True
    )
    assert paths == ["/health", "/v1/models"]
    assert receipt["post_attempted"] is False
    assert receipt["chat"]["state"] == "NOT_PROBED_UNQUALIFIED_PREFLIGHT"
    assert receipt["admission"]["state"] == "HOLD"


def test_redirect_handler_returns_no_followup_request():
    handler = gateway._NoRedirect()
    assert handler.redirect_request(None, None, 302, "Found", {}, "https://evil.example") is None


def test_transport_constructs_no_redirect_opener(monkeypatch):
    observed = []
    class FakeResponse:
        status = 302
        headers = {"Location": "https://evil.example"}
        def read(self, cap): return b""
        def __enter__(self): return self
        def __exit__(self, *args): return False
    class FakeOpener:
        def open(self, request, timeout):
            observed.append((request.full_url, timeout))
            return FakeResponse()
    def fake_build(*handlers):
        assert len(handlers) == 1
        assert isinstance(handlers[0], gateway._NoRedirect)
        return FakeOpener()
    monkeypatch.setattr(gateway.urllib.request, "build_opener", fake_build)
    status, body = gateway._request(gateway.DEFAULT_BASE_URL, "/health", timeout=2.0)
    assert status == 302
    assert len(observed) == 1


def test_cli_default_is_hold_and_never_posts(monkeypatch, capsys):
    calls = []
    monkeypatch.setattr(gateway, "_request", _get_only(calls))
    assert cli.main([]) == 1
    out = json.loads(capsys.readouterr().out)
    assert out["post_attempted"] is False
    assert len(calls) == 2
    assert out["admission"]["state"] == "HOLD"


def test_cli_cannot_exit_green_from_forged_receipt_without_opt_in(monkeypatch, capsys):
    monkeypatch.setattr(cli, "probe_gateway", lambda *a, **kw: {
        "healthy": True, "admission": {"state": "POSTURE_MATCH_NOT_SETTLEMENT"},
    })
    assert cli.main([]) == 1
    assert cli.main(["--allow-unsigned-post"]) == 1
    assert cli.main(["--allow-unsigned-post", "--acknowledge-inference-risk"]) == 0


def test_cli_one_flag_is_invalid_before_get_or_post(monkeypatch, capsys):
    monkeypatch.setattr(gateway, "_request", lambda *a, **kw: (_ for _ in ()).throw(AssertionError("NETWORK")))
    assert cli.main(["--allow-unsigned-post"]) == 2
    out = json.loads(capsys.readouterr().out)
    assert out["post_attempted"] is False
    assert out["admission"]["state"] == "HOLD"
