"""CLI and end-to-end local scan tests."""

import json
import shutil
import subprocess

import pytest

from src.cli import parse_args
from src.__main__ import main


def test_parse_path_mode():
    args = parse_args(["--path", "src"])
    assert args.path == ["src"]
    assert args.url is None


def test_parse_url_mode():
    args = parse_args(["https://example.com", "--fail-on", "high"])
    assert args.url == "https://example.com"
    assert args.fail_on == "high"


def test_url_and_path_conflict():
    with pytest.raises(SystemExit):
        parse_args(["https://example.com", "--path", "src"])


def test_requires_target():
    with pytest.raises(SystemExit):
        parse_args([])


def test_list_rules(capsys):
    assert main(["--list-rules"]) == 0
    output = capsys.readouterr().out
    assert "aws_access_key_id" in output
    assert "Total:" in output


def test_local_scan_and_fail_on(tmp_path, capsys):
    target = tmp_path / "target"
    target.mkdir()
    (target / ".env").write_text(
        "AWS_ACCESS_KEY_ID=AKIA1234567890ABCDEF\n"
        f"GITHUB_TOKEN=ghp_{'a' * 36}\n",
        encoding="utf-8",
    )
    out_dir = tmp_path / "reports"

    code = main([
        "--path", str(target),
        "-o", str(out_dir),
        "--format", "json", "sarif",
        "--fail-on", "high",
        "-q",
    ])

    assert code == 1
    reports = list(out_dir.glob("findings_*.json"))
    assert reports
    data = json.loads(reports[0].read_text(encoding="utf-8"))
    assert data["summary"]["total"] >= 2
    assert data["summary"]["by_severity"]["critical"] >= 2


def test_update_baseline_and_diff(tmp_path):
    target = tmp_path / "target"
    target.mkdir()
    secret_file = target / ".env"
    secret_file.write_text(
        "AWS_ACCESS_KEY_ID=AKIA1234567890ABCDEF\n",
        encoding="utf-8",
    )
    baseline = tmp_path / "baseline.json"

    assert main([
        "--path", str(target),
        "-o", str(tmp_path / "report1"),
        "--format", "json",
        "--update-baseline", str(baseline),
        "-q",
    ]) == 0
    assert baseline.exists()
    assert "AKIA1234567890ABCDEF" not in baseline.read_text(encoding="utf-8")

    assert main([
        "--path", str(target),
        "-o", str(tmp_path / "report2"),
        "--format", "json",
        "--baseline", str(baseline),
        "-q",
    ]) == 0
    report = next((tmp_path / "report2").glob("findings_*.json"))
    data = json.loads(report.read_text(encoding="utf-8"))
    assert data["summary"]["total"] == 0

    secret_file.write_text(
        "AWS_ACCESS_KEY_ID=AKIA1234567890ABCDEF\n"
        f"GITHUB_TOKEN=ghp_{'b' * 36}\n",
        encoding="utf-8",
    )
    assert main([
        "--path", str(target),
        "-o", str(tmp_path / "report3"),
        "--format", "json",
        "--baseline", str(baseline),
        "-q",
    ]) == 0
    report = next((tmp_path / "report3").glob("findings_*.json"))
    data = json.loads(report.read_text(encoding="utf-8"))
    assert data["summary"]["total"] == 1
    assert data["findings"][0]["type"] == "github_token"


def test_clean_local_scan_returns_zero(tmp_path):
    target = tmp_path / "clean"
    target.mkdir()
    (target / "app.py").write_text("print('hello world')\n", encoding="utf-8")
    out_dir = tmp_path / "reports"

    code = main([
        "--path", str(target),
        "-o", str(out_dir),
        "--format", "json",
        "--fail-on", "high",
        "-q",
    ])
    assert code == 0


def test_github_scan_uses_downloader_and_relabels(tmp_path, monkeypatch):
    checkout = tmp_path / "checkout"
    checkout.mkdir()
    (checkout / ".env").write_text(
        "AWS_ACCESS_KEY_ID=AKIA1234567890ABCDEF\n",
        encoding="utf-8",
    )
    monkeypatch.setattr("src.scanner.download_repo", lambda *a, **k: str(checkout))
    monkeypatch.setattr("src.scanner._cleanup_checkout", lambda path: None)

    out_dir = tmp_path / "reports"
    code = main([
        "--github", "acme/widgets",
        "-o", str(out_dir),
        "--format", "json",
        "-q",
    ])
    assert code == 0
    report = next(out_dir.glob("findings_*.json"))
    data = json.loads(report.read_text(encoding="utf-8"))
    assert data["summary"]["total"] >= 1
    assert data["findings"][0]["url"].startswith("github://acme/widgets/")


@pytest.mark.skipif(shutil.which("git") is None, reason="git not installed")
def test_staged_scan(tmp_path, monkeypatch):
    repo = tmp_path / "repo"
    repo.mkdir()
    subprocess.run(["git", "init"], cwd=repo, check=True, capture_output=True)
    subprocess.run(
        ["git", "config", "user.email", "test@example.com"],
        cwd=repo, check=True, capture_output=True,
    )
    subprocess.run(
        ["git", "config", "user.name", "Test"],
        cwd=repo, check=True, capture_output=True,
    )
    (repo / "app.env").write_text(
        "GITHUB_TOKEN=ghp_" + "a" * 36 + "\n",
        encoding="utf-8",
    )
    subprocess.run(["git", "add", "app.env"], cwd=repo, check=True, capture_output=True)
    monkeypatch.chdir(repo)

    out_dir = tmp_path / "reports"
    code = main([
        "--staged",
        "-o", str(out_dir),
        "--format", "json",
        "-q",
    ])
    assert code == 0
    report = next(out_dir.glob("findings_*.json"))
    data = json.loads(report.read_text(encoding="utf-8"))
    assert data["summary"]["total"] >= 1
    assert data["findings"][0]["source"] == "staged"


def test_workflow_audit_cli(tmp_path):
    workflows = tmp_path / ".github" / "workflows"
    workflows.mkdir(parents=True)
    (workflows / "ci.yml").write_text(
        "on: pull_request_target\n"
        "permissions: write-all\n"
        "jobs:\n"
        "  build:\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        "      - uses: actions/checkout@v4\n"
        "        with:\n"
        "          ref: ${{ github.event.pull_request.head.sha }}\n"
        "      - run: echo \"${{ github.event.issue.title }}\"\n",
        encoding="utf-8",
    )
    out_dir = tmp_path / "reports"
    code = main([
        "--path", str(tmp_path),
        "--audit-github-actions",
        "-o", str(out_dir),
        "--format", "json",
        "--fail-on", "high",
        "-q",
    ])
    assert code == 1
    report = next(out_dir.glob("findings_*.json"))
    data = json.loads(report.read_text(encoding="utf-8"))
    types = {finding["type"] for finding in data["findings"]}
    assert "gha_untrusted_checkout" in types
    assert "gha_script_injection" in types
    assert "gha_write_all_permissions" in types


def test_junit_cli_output(tmp_path):
    target = tmp_path / "target"
    target.mkdir()
    (target / ".env").write_text(
        "GITHUB_TOKEN=ghp_" + "b" * 36 + "\n",
        encoding="utf-8",
    )
    out_dir = tmp_path / "reports"
    assert main([
        "--path", str(target),
        "-o", str(out_dir),
        "--format", "junit",
        "-q",
    ]) == 0
    assert list(out_dir.glob("findings_*.junit")) or list(out_dir.glob("findings_*.xml"))
