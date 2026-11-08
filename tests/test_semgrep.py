"""Semgrep-compatible YAML rule import tests."""

from src.config import ScanConfig
from src.patterns import get_rules
from src.scanner import scan_text
from src.semgrep import load_semgrep_rules

CONFIG = """
rules:
  - id: example_access_token
    languages: [python]
    message: Hardcoded example access token
    severity: ERROR
    patterns:
      - pattern-regex: 'token\\s*=\\s*"((?:ex|alt)_[A-Za-z0-9]{12})"'
      - pattern-not-regex: 'example'
    paths:
      include:
        - "app/**"
      exclude:
        - "app/tests/**"
    metadata:
      category: token
      tags: [example, token]
      entropy_min: 2.0

  - id: example_either_token
    message: Either-format token
    severity: WARNING
    pattern-either:
      - pattern-regex: 'either_[A-Za-z0-9]{10}'
      - pattern-regex: 'other_[A-Za-z0-9]{10}'

  - id: unsupported_ast_rule
    pattern: foo(...)
    message: AST-only rule

  - id: invalid_regex_rule
    pattern-regex: '(?P<broken'
    message: Broken regex
"""


def _write_config(tmp_path):
    path = tmp_path / "semgrep.yml"
    path.write_text(CONFIG.strip() + "\n", encoding="utf-8")
    return path


def test_load_semgrep_rules(tmp_path):
    rules = load_semgrep_rules(str(_write_config(tmp_path)))
    by_id = {rule.id: rule for rule in rules}

    assert set(by_id) == {"example_access_token", "example_either_token"}
    access = by_id["example_access_token"]
    assert access.category == "token"
    assert access.severity == "high"
    assert access.secret_group == 1
    assert access.path_include == ("app/**",)
    assert access.path_exclude == ("app/tests/**",)
    assert access.negative_pattern == "example"
    assert "semgrep" in access.tags

    either = by_id["example_either_token"]
    assert either.severity == "medium"
    assert "either_" in either.pattern
    assert "other_" in either.pattern


def test_semgrep_rules_merge_with_builtins(tmp_path):
    rules = get_rules(semgrep_files=[str(_write_config(tmp_path))])
    ids = {rule.id for rule in rules}
    assert "example_access_token" in ids
    assert "github_token" in ids
    assert "unsupported_ast_rule" not in ids
    assert "invalid_regex_rule" not in ids


def test_semgrep_path_filters_and_negative_pattern(tmp_path):
    rules = [rule for rule in load_semgrep_rules(str(_write_config(tmp_path))) if rule.id == "example_access_token"]
    cfg = ScanConfig()

    included = scan_text(
        'token = "ex_abcdefghijkl"',
        "https://t.test/app/config.py",
        rules,
        cfg,
    )
    assert [finding["type"] for finding in included] == ["example_access_token"]

    assert scan_text(
        'token = "ex_abcdefghijkl"',
        "https://t.test/app/tests/config.py",
        rules,
        cfg,
    ) == []
    assert scan_text(
        'token = "ex_abcdefghijkl"',
        "https://t.test/lib/config.py",
        rules,
        cfg,
    ) == []

    # pattern-not-regex excludes values containing "example".
    assert scan_text(
        'token = "ex_exampleabcde"',
        "https://t.test/app/config.py",
        rules,
        cfg,
    ) == []


def test_semgrep_either_rule_matches(tmp_path):
    rules = [rule for rule in load_semgrep_rules(str(_write_config(tmp_path))) if rule.id == "example_either_token"]
    findings = scan_text(
        "a = either_abcdefghij\nb = other_abcdefghij",
        "https://t.test/app/config.py",
        rules,
        ScanConfig(),
    )
    assert len(findings) == 2
