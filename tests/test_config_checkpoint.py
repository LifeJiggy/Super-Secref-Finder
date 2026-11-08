"""Configuration, checkpoint, baseline, and entropy tests."""

from src.checkpoint import (
    diff_findings,
    fingerprint,
    load_checkpoint,
    load_differential_baseline,
    save_checkpoint,
    save_differential_baseline,
)
from src.config import ScanConfig
from src.entropy import entropy_label, is_likely_secret, shannon_entropy


def test_config_normalize_and_validate():
    cfg = ScanConfig(paths=["."], threads=500, delay=-4, output_format=["JSON", "nope"])
    cfg.normalize()
    assert cfg.threads == 100
    assert cfg.delay == 0
    assert cfg.output_format == ["json", "nope"]
    assert cfg.is_local
    assert cfg.target == "."
    assert cfg.validate() == []


def test_config_conflict_is_reported():
    cfg = ScanConfig(url="https://x.test", paths=["."])
    assert any("choose one target" in problem for problem in cfg.validate())


def test_checkpoint_roundtrip(tmp_path):
    path = tmp_path / "state.json"
    findings = [{"type": "aws_access_key_id", "value": "AKIA1234567890ABCDEF", "context": "secret context"}]
    assert save_checkpoint(str(path), {"https://x.test"}, findings, 3)
    data = load_checkpoint(str(path))
    assert data["scanned_count"] == 3
    assert data["visited_urls"] == ["https://x.test"]
    assert "context" not in data["findings"][0]
    assert data["version"] >= 1


def test_baseline_stores_fingerprints_not_secrets(tmp_path):
    path = tmp_path / "baseline.json"
    findings = [{"type": "github_token", "value": "ghp_" + "a" * 36}]
    assert save_differential_baseline(findings, str(path))

    raw = path.read_text(encoding="utf-8")
    assert "ghp_" not in raw
    assert fingerprint("github_token", "ghp_" + "a" * 36) in raw

    baseline = load_differential_baseline(str(path))
    assert diff_findings(findings, baseline) == []
    assert diff_findings([{"type": "github_token", "value": "new"}], baseline)


def test_legacy_baseline_is_supported(tmp_path):
    import json

    path = tmp_path / "legacy.json"
    findings = [{"type": "github_token", "value": "ghp_" + "a" * 36}]
    path.write_text(json.dumps(findings), encoding="utf-8")
    baseline = load_differential_baseline(str(path))
    assert diff_findings(findings, baseline) == []


def test_entropy_helpers():
    assert shannon_entropy("") == 0
    assert shannon_entropy("aaaaaaaa") < shannon_entropy("aB3dE9fG")
    assert entropy_label("aB3dE9fG2hJ4kL6mN8pQ") in {"HIGH", "VERY_HIGH"}
    assert is_likely_secret("aB3dE9fG2hJ4kL6mN8pQ")
    assert not is_likely_secret("password")
    assert not is_likely_secret("aaaaaaaaaaaaaaaaaaaa")
