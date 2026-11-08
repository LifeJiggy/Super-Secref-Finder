"""Rule registry tests."""

import textwrap

from src.patterns import get_all_patterns, get_rules, load_custom_rules
from src.rules import BUILTIN_RULES, all_rule_ids, validate_rule_metadata


def test_metadata_is_valid():
    assert validate_rule_metadata() == []


def test_rule_ids_are_unique():
    ids = [rule.id for rule in BUILTIN_RULES]
    assert len(ids) == len(set(ids))


def test_default_rules_exclude_noise_and_pii():
    rules = get_rules()
    ids = {rule.id for rule in rules}
    assert "console_log" not in ids
    assert "inline_script" not in ids
    assert "email_address" not in ids
    assert "api_endpoint" not in ids
    assert "aws_access_key_id" in ids


def test_include_endpoints():
    ids = {rule.id for rule in get_rules(include_endpoints=True)}
    assert "api_endpoint" in ids
    assert "graphql_endpoint" in ids


def test_include_noise_and_pii():
    ids = {rule.id for rule in get_rules(include_noise=True, include_pii=True)}
    assert "console_log" in ids
    assert "email_address" in ids
    assert "path_traversal" in ids


def test_severity_filter():
    ids = {rule.id for rule in get_rules(min_severity="critical")}
    assert "aws_access_key_id" in ids
    assert "generic_secret_assignment" not in ids


def test_include_and_exclude_types():
    ids = {rule.id for rule in get_rules(include_types=["aws_access_key_id", "github_token"])}
    assert ids == {"aws_access_key_id", "github_token"}

    ids = {rule.id for rule in get_rules(exclude_types=["aws_access_key_id"])}
    assert "aws_access_key_id" not in ids


def test_compiled_once():
    rules = get_rules()
    assert all(rule.compiled is not None for rule in rules)


def test_capture_group_value():
    rule = all_rule_ids()["api_key"].compile()
    text = 'api_key = "abcdefghijklmnopqrstuvwxyz123456"'
    match = next(rule.compiled.finditer(text))
    assert rule.value_of(match) == "abcdefghijklmnopqrstuvwxyz123456"


def test_custom_rule_loading(tmp_path):
    path = tmp_path / "rules.yaml"
    path.write_text(textwrap.dedent("""
        patterns:
          internal_token:
            regex: "INTERNAL_[A-Z0-9]{12,}"
            description: "Internal token"
            severity: high
            category: token
          simple_pattern: "SIMPLE-[0-9]{6}"
    """), encoding="utf-8")

    rules = load_custom_rules(str(path))
    ids = {rule.id for rule in rules}
    assert ids == {"internal_token", "simple_pattern"}
    internal = next(rule for rule in rules if rule.id == "internal_token")
    assert internal.severity == "high"
    assert internal.category == "token"

    merged = get_all_patterns([str(path)])
    assert "internal_token" in merged


def test_no_patterns_are_duplicated_in_legacy_view():
    patterns = get_all_patterns()
    assert len(patterns) == len(set(patterns))
