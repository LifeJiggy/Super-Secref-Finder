"""Webhook notification tests (no network)."""

import json

from src.notify import send_notification

FINDINGS = [
    {"type": "github_token", "value": "ghp_" + "a" * 36, "severity": "critical", "url": "https://x.test/.env"},
    {"type": "email_address", "value": "person@example.test", "severity": "low", "url": "https://x.test/"},
]


class Response:
    status_code = 204
    text = ""


def test_slack_webhook_redacts_and_filters(monkeypatch):
    calls = []

    def fake_post(url, json=None, timeout=None):
        calls.append((url, json, timeout))
        return Response()

    monkeypatch.setattr("src.notify.requests.post", fake_post)
    ok, detail = send_notification(
        "https://hooks.test/abc",
        FINDINGS,
        meta={"target": "x.test"},
        fmt="slack",
        min_severity="high",
    )
    assert ok
    assert detail == "HTTP 204"
    payload = calls[0][1]
    serialized = json.dumps(payload)
    assert "ghp_" not in serialized
    assert "person@example.test" not in serialized
    assert "Super Secref Finder" in payload["text"]


def test_generic_webhook_shape(monkeypatch):
    calls = []
    monkeypatch.setattr(
        "src.notify.requests.post",
        lambda url, json=None, timeout=None: calls.append(json) or Response(),
    )
    ok, _ = send_notification(
        "https://hooks.test/abc",
        FINDINGS,
        fmt="generic",
        min_severity="low",
    )
    assert ok
    assert calls[0]["total"] == 2
    assert calls[0]["by_severity"]["critical"] == 1
