"""Live-validator dispatch tests (no network)."""

from src import secret_validator as sv


class FakeResponse:
    def __init__(self, status_code=200, payload=None, headers=None):
        self.status_code = status_code
        self._payload = payload or {}
        self.headers = headers or {}

    def json(self):
        return self._payload


def test_new_validators_are_dispatched(monkeypatch):
    calls = []

    def fake_request(method, url, **kwargs):
        calls.append(url)
        if "cloudflare" in url:
            return FakeResponse(payload={"success": True, "result": {"status": "active"}})
        if "openrouter" in url:
            return FakeResponse(payload={"data": {"label": "test", "usage": 1}})
        if "replicate" in url:
            return FakeResponse(payload={"username": "octocat", "type": "user"})
        return FakeResponse(payload={"data": []})

    monkeypatch.setattr(sv, "_safe_request", fake_request)

    assert sv.validate_secret("cloudflare_api_token", "x")["valid"] is True
    assert sv.validate_secret("groq_api_key", "x")["valid"] is True
    assert sv.validate_secret("openrouter_api_key", "x")["valid"] is True
    assert sv.validate_secret("replicate_api_token", "x")["valid"] is True
    assert sv.validate_secret("cohere_api_key", "x")["valid"] is True
    assert len(calls) == 5


def test_safe_mode_skips_validation(monkeypatch):
    monkeypatch.setattr(
        sv, "_safe_request",
        lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("network")),
    )
    result = sv.validate_secret("github_token", "x", safe_mode=True)
    assert result["valid"] is None
    assert "safe mode" in result["reason"]


def test_allowlisted_hosts_only():
    assert "api.cloudflare.com" in sv._ALLOWED_HOSTS
    assert "api.groq.com" in sv._ALLOWED_HOSTS
    assert "openrouter.ai" in sv._ALLOWED_HOSTS
    assert "api.replicate.com" in sv._ALLOWED_HOSTS
    assert "api.cohere.com" in sv._ALLOWED_HOSTS
