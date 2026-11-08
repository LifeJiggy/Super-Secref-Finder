"""Whole-file entropy scan tests."""

from src.config import ScanConfig
from src.entropy_scan import find_entropy_findings

TOKEN = "Zx9Qw8Er7Ty6Ui5Op4As3Df2Gh1Jk0Lm"


def test_entropy_scan_is_opt_in():
    assert find_entropy_findings(TOKEN, "https://t.test/", ScanConfig()) == []


def test_entropy_scan_detects_random_token():
    cfg = ScanConfig(entropy_scan=True, entropy_min_length=20, entropy_scan_threshold=3.5)
    findings = find_entropy_findings(f'const token = "{TOKEN}";', "https://t.test/app.js", cfg)
    assert any(f["type"] == "high_entropy_string" for f in findings)
    assert findings[0]["category"] == "secret"


def test_entropy_scan_ignores_hash_context_and_urls():
    cfg = ScanConfig(entropy_scan=True, entropy_min_length=20, entropy_scan_threshold=3.5)
    text = (
        f'sha256 = "{TOKEN}"\n'
        f'url = "https://example.test/{TOKEN}"\n'
    )
    assert find_entropy_findings(text, "https://t.test/", cfg) == []
