"""Output format tests."""

import json
import re
import xml.etree.ElementTree as ET

from src.output import (
    save_csv,
    save_findings,
    save_html,
    save_json,
    save_jsonl,
    save_junit,
    save_markdown,
    save_sarif,
)

FINDINGS = [
    {
        "type": "github_token",
        "value": "ghp_" + "a" * 36,
        "url": "https://target.test/app.js",
        "severity": "critical",
        "category": "token",
        "confidence": 0.96,
        "validated": True,
        "line": 3,
        "column": 12,
        "description": "GitHub token",
        "context": 'token = "ghp_' + "a" * 36 + '"',
    },
    {
        "type": "console_log",
        "value": "console.log('x')",
        "url": "https://target.test/app.js",
        "severity": "info",
        "category": "code-risk",
        "confidence": 0.5,
        "validated": None,
        "line": 9,
        "column": 1,
        "description": "Console logging",
    },
]


def test_json(tmp_path):
    path = tmp_path / "out.json"
    save_json(FINDINGS, str(path), meta={"target": "https://target.test"})
    data = json.loads(path.read_text(encoding="utf-8"))
    assert data["summary"]["total"] == 2
    assert data["summary"]["by_severity"]["critical"] == 1
    assert data["findings"][0]["severity"] == "critical"
    assert data["meta"]["target"] == "https://target.test"


def test_json_redacts(tmp_path):
    path = tmp_path / "out.json"
    save_json(FINDINGS, str(path), redact=True)
    data = json.loads(path.read_text(encoding="utf-8"))
    value = data["findings"][0]["value"]
    assert value != FINDINGS[0]["value"]
    assert "*" in value
    assert "a" * 20 not in value


def test_jsonl(tmp_path):
    path = tmp_path / "out.jsonl"
    save_jsonl(FINDINGS, str(path))
    lines = path.read_text(encoding="utf-8").strip().splitlines()
    assert len(lines) == 2
    assert json.loads(lines[0])["severity"] in {"critical", "info"}


def test_csv(tmp_path):
    path = tmp_path / "out.csv"
    save_csv(FINDINGS, str(path))
    header = path.read_text(encoding="utf-8").splitlines()[0]
    assert "severity" in header
    assert "category" in header
    assert "confidence" in header


def test_markdown(tmp_path):
    path = tmp_path / "out.md"
    save_markdown(FINDINGS, str(path), meta={"target": "https://target.test"})
    content = path.read_text(encoding="utf-8")
    assert "Severity summary" in content
    assert "github_token" in content
    assert "CRITICAL" in content


def test_html(tmp_path):
    path = tmp_path / "out.html"
    save_html(FINDINGS, str(path), show_context=True)
    content = path.read_text(encoding="utf-8")
    assert "Super Secref Finder" in content
    assert "github_token" in content
    assert "data-filter" in content
    assert "CRITICAL" in content.upper()


def test_sarif(tmp_path):
    path = tmp_path / "out.sarif"
    save_sarif(FINDINGS, str(path))
    data = json.loads(path.read_text(encoding="utf-8"))
    assert data["version"] == "2.1.0"
    run = data["runs"][0]
    assert run["results"]
    rule = next(r for r in run["tool"]["driver"]["rules"] if r["id"] == "github_token")
    assert rule["properties"]["security-severity"] == "9.5"
    assert run["results"][0]["level"] in {"error", "warning", "note"}


def test_junit(tmp_path):
    path = tmp_path / "out.xml"
    save_junit(FINDINGS, str(path), redact=True)
    tree = ET.parse(path)
    suite = tree.getroot().find("testsuite")
    assert suite is not None
    assert suite.attrib["tests"] == "2"
    assert suite.attrib["failures"] == "2"
    assert len(suite.findall("testcase")) == 2
    assert "a" * 20 not in path.read_text(encoding="utf-8")


def test_save_findings_multiple_formats(tmp_path):
    paths = save_findings(
        FINDINGS,
        str(tmp_path),
        ["json", "html", "sarif", "junit", "json"],
        meta={"target": "t"},
    )
    assert len(paths) == 4
    assert all(p for p in paths)
    assert len(re.findall(r"findings_\d{8}_\d{6}\.json", str(paths[0]))) == 1
