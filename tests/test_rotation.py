"""Rotation guidance and output coverage."""

import json

from src.config import ScanConfig
from src.output import save_csv, save_json, save_sarif
from src.rotation import GENERIC_ROTATION_URL, rotation_guidance
from src.scanner import scan_text
from src.patterns import get_rules


def test_rotation_guidance_known_and_generic():
    assert "github.com/settings/tokens" in rotation_guidance("github_token", "token")
    assert rotation_guidance("private_key_header", "credential") == GENERIC_ROTATION_URL
    assert rotation_guidance("console_log", "code-risk") == ""
    assert rotation_guidance("custom_rule", "custom") == ""


def test_scanner_adds_rotation_url():
    cfg = ScanConfig(confidence_threshold=0.0, max_per_rule=1)
    token = "ghp_" + "a" * 36
    findings = scan_text(
        f'GITHUB_TOKEN = "{token}"',
        "https://example.test/app.js",
        get_rules(include_types=["github_token"]),
        cfg,
    )
    assert findings
    assert "github.com/settings/tokens" in findings[0]["rotation_url"]


def test_rotation_is_exported(tmp_path):
    findings = [{
        "type": "github_token",
        "value": "ghp_" + "a" * 36,
        "url": "https://example.test/app.js",
        "severity": "critical",
        "category": "token",
        "confidence": 0.95,
        "line": 1,
        "rotation_url": "https://github.com/settings/tokens",
    }]
    save_json(findings, str(tmp_path / "out.json"))
    data = json.loads((tmp_path / "out.json").read_text(encoding="utf-8"))
    assert data["findings"][0]["rotation_url"] == "https://github.com/settings/tokens"

    save_csv(findings, str(tmp_path / "out.csv"))
    assert "rotation_url" in (tmp_path / "out.csv").read_text(encoding="utf-8").splitlines()[0]

    save_sarif(findings, str(tmp_path / "out.sarif"))
    sarif = json.loads((tmp_path / "out.sarif").read_text(encoding="utf-8"))
    assert sarif["runs"][0]["results"][0]["properties"]["rotationUrl"] == (
        "https://github.com/settings/tokens"
    )
