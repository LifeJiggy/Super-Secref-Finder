"""Scanner engine tests — signal, noise, dedupe, allowlist, exit codes."""

from src.allowlist import (
    Allowlist,
    fingerprint,
    load_ignore_file,
    write_ignore_file,
)
from src.config import ScanConfig
from src.patterns import get_rules
from src.scanner import compute_exit_code, dedupe_findings, scan_text

RULES = get_rules()
CFG = ScanConfig()


def _types(findings):
    return {finding["type"] for finding in findings}


def test_detects_real_secret_formats():
    text = "\n".join([
        "AWS_ACCESS_KEY_ID=AKIA1234567890ABCDEF",
        f"GITHUB_TOKEN=ghp_{'b' * 36}",
        f"OPENAI_API_KEY=sk-proj-{'c' * 40}",
        "MONGO=mongodb://admin:s3cr3tP4ss@db.internal.net:27017/app",
        "-----BEGIN RSA PRIVATE KEY-----",
        'password = "hunter2hunter2"',
    ])
    findings = scan_text(text, "https://target.test/app.js", RULES, CFG)
    types = _types(findings)
    assert "aws_access_key_id" in types
    assert "github_token" in types
    assert "openai_api_key" in types
    assert "database_uri_with_credentials" in types
    assert "private_key_header" in types


def test_default_scan_is_high_signal():
    noise = "\n".join([
        '<script async src="https://cdn.example.com/app.js"></script>',
        "b.p = e + '../../'",
        '<a href="/assets/990f7d1b-3a16-4748-aafc-e0638c6219e2/report.pdf">',
        "new Error('chunk failed')",
        "console.log('debug')",
        "document.getElementById('root').innerHTML = value",
        "d41d8cd98f00b204e9800998ecf8427e",
    ])
    assert scan_text(noise, "https://target.test/", RULES, CFG) == []


def test_noise_rules_are_opt_in():
    cfg = ScanConfig(include_noise=True)
    rules = get_rules(include_noise=True)
    findings = scan_text("console.log('x'); b.p = '../../';", "https://t.test/", rules, cfg)
    types = _types(findings)
    assert "console_log" in types
    assert types & {"path_traversal", "lfi_vector"}


def test_placeholder_values_are_rejected():
    text = 'api_key = "your_api_key_here"\nkey = "AKIAIOSFODNN7EXAMPLE"'
    assert scan_text(text, "https://t.test/", RULES, CFG) == []


def test_allowlist_value_and_rule(tmp_path):
    ignore = tmp_path / ".secrefignore"
    ignore.write_text(
        f"value: ^ghp_{'b' * 36}$\nrule: ^aws_access_key_id$\n",
        encoding="utf-8",
    )
    allowlist = load_ignore_file(str(ignore))
    text = "\n".join([
        "AWS_ACCESS_KEY_ID=AKIA1234567890ABCDEF",
        f"g = 'ghp_{'b' * 36}'",
        f"o = 'sk-proj-{'c' * 40}'",
    ])
    findings = scan_text(text, "https://t.test/", RULES, CFG, allowlist)
    types = _types(findings)
    assert "aws_access_key_id" not in types
    assert "github_token" not in types
    assert "openai_api_key" in types


def test_inline_ignore():
    text = f'token = "ghp_{"d" * 36}"  # secref:ignore'
    assert scan_text(text, "https://t.test/", RULES, CFG) == []


def test_inline_suppression_compatibility():
    token = f'ghp_{"d" * 36}'
    for marker in (
        "secref:ignore",
        "secref:disable-line",
        "gitleaks:allow",
        "trufflehog:ignore",
        "secretlint-disable-line",
        "pragma: allowlist secret",
        "nosec",
    ):
        text = f'token = "{token}"  # {marker}'
        assert scan_text(text, "https://t.test/", RULES, CFG) == [], marker


def test_inline_next_line_suppression():
    token = f'ghp_{"d" * 36}'
    for marker in ("secref:disable-next-line", "secretlint-disable-next-line"):
        text = f"# {marker}\ntoken = \"{token}\""
        assert scan_text(text, "https://t.test/", RULES, CFG) == [], marker


def test_per_rule_cap():
    keys = "\n".join(
        f"K{i}=AKIA{str(i) * 4}{'ABCDEFGHIJKL'}"
        for i in range(1, 8)
    )
    cfg = ScanConfig(max_per_rule=2)
    findings = scan_text(keys, "https://t.test/", RULES, cfg)
    assert len([f for f in findings if f["type"] == "aws_access_key_id"]) == 2


def test_dedupe_keeps_highest_severity():
    findings = [
        {"type": "generic_secret_assignment", "value": "abc", "url": "u", "severity": "medium", "confidence": 0.9},
        {"type": "github_token", "value": "abc", "url": "u", "severity": "critical", "confidence": 0.8},
    ]
    deduped = dedupe_findings(findings)
    assert len(deduped) == 1
    assert deduped[0]["type"] == "github_token"


def test_dedupe_prefers_specific_rule_at_same_severity():
    findings = [
        {
            "type": "generic_secret_assignment", "value": "abc", "url": "u",
            "severity": "high", "confidence": 0.99,
        },
        {
            "type": "semgrep_internal_token", "value": "abc", "url": "u",
            "severity": "high", "confidence": 0.8,
        },
    ]
    deduped = dedupe_findings(findings)
    assert len(deduped) == 1
    assert deduped[0]["type"] == "semgrep_internal_token"


def test_exit_codes():
    critical = [{"type": "x", "value": "v", "severity": "critical", "confidence": 0.9}]
    medium = [{"type": "x", "value": "v", "severity": "medium", "confidence": 0.9}]
    assert compute_exit_code(critical, "high") == 1
    assert compute_exit_code(medium, "high") == 0
    assert compute_exit_code(critical, "never") == 0


def test_findings_have_metadata():
    text = "AKIA1234567890ABCDEF"
    finding = scan_text(text, "https://t.test/", RULES, CFG)[0]
    for key in ("severity", "category", "confidence", "line", "column", "description"):
        assert key in finding
    assert finding["line"] == 1
    assert finding["column"] == 1


def test_write_ignore_uses_hashed_fingerprints(tmp_path):
    finding = {
        "type": "github_token",
        "value": "ghp_" + "e" * 36,
        "severity": "critical",
        "url": "https://t.test/.env?token=leak",
    }
    path = tmp_path / ".secrefignore"
    count = write_ignore_file(str(path), [finding])
    assert count == 1
    content = path.read_text(encoding="utf-8")
    assert "ghp_" not in content
    assert "token=leak" not in content
    assert fingerprint("github_token", finding["value"]) in content

    allowlist = load_ignore_file(str(path))
    assert allowlist.is_ignored("github_token", finding["value"], finding["url"])
    assert not allowlist.is_ignored("github_token", "different", finding["url"])


def test_write_ignore_can_include_values(tmp_path):
    finding = {
        "type": "github_token",
        "value": "ghp_" + "f" * 36,
        "severity": "critical",
        "url": "file:///tmp/.env",
    }
    path = tmp_path / ".secrefignore"
    write_ignore_file(str(path), [finding], include_values=True)
    content = path.read_text(encoding="utf-8")
    assert "value: ^ghp_" in content


def test_entropy_scan_integration():
    from src.scanner import _analyze

    cfg = ScanConfig(entropy_scan=True, entropy_min_length=20, entropy_scan_threshold=3.5)
    text = 'const k = "Zx9Qw8Er7Ty6Ui5Op4As3Df2Gh1Jk0Lm";'
    findings = _analyze(cfg, "https://t.test/app.js", text, RULES, Allowlist())
    assert any(f["type"] == "high_entropy_string" for f in findings)
