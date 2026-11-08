"""Gitleaks TOML rule import tests."""

from src.gitleaks import load_gitleaks_rules
from src.patterns import get_rules

CONFIG = """
title = "test pack"

[[rules]]
id = "example_api_key"
description = "Example API token"
regex = '''example_[A-Za-z0-9]{20}'''
tags = ["token", "high"]

[[rules]]
id = "example_cloud_key"
description = "Example cloud credential"
regex = '''cloud_[A-Za-z0-9]{16}'''
tags = ["aws", "critical"]

[[rules]]
id = "broken_rule"
regex = '''(?P<broken'''
"""


def test_load_gitleaks_rules(tmp_path):
    path = tmp_path / "gitleaks.toml"
    path.write_text(CONFIG.strip() + "\n", encoding="utf-8")
    rules = load_gitleaks_rules(str(path))
    by_id = {rule.id: rule for rule in rules}

    assert set(by_id) == {"example_api_key", "example_cloud_key"}
    assert by_id["example_api_key"].category == "token"
    assert by_id["example_api_key"].severity == "high"
    assert by_id["example_cloud_key"].category == "cloud"
    assert by_id["example_cloud_key"].severity == "critical"
    assert "gitleaks" in by_id["example_api_key"].tags


def test_gitleaks_rules_are_merged_with_builtins(tmp_path):
    path = tmp_path / "gitleaks.toml"
    path.write_text(CONFIG.strip() + "\n", encoding="utf-8")
    rules = get_rules(gitleaks_files=[str(path)])
    ids = {rule.id for rule in rules}
    assert "example_api_key" in ids
    assert "github_token" in ids
    assert "broken_rule" not in ids
