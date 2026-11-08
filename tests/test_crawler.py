"""Crawler tests (network-free)."""

from src.config import ScanConfig
from src.crawler import (
    build_target_list,
    extract_all_links,
    extract_js_links,
    extract_secrets_from_text,
    is_excluded,
    is_in_scope,
)


def test_extract_js_links():
    html = """
    <script src="/static/app.js"></script>
    <script src="https://cdn.example.com/vendor.js?v=1"></script>
    <a href="/about">About</a>
    """
    links = extract_js_links(html, "https://example.com/")
    assert "https://example.com/static/app.js" in links
    assert "https://cdn.example.com/vendor.js?v=1" in links


def test_extract_all_links_filters_binary_assets():
    html = '<a href="/about">a</a><img src="/logo.png"><script src="/app.js"></script>'
    links = extract_all_links(html, "https://example.com/")
    assert "https://example.com/about" in links
    assert "https://example.com/app.js" in links
    assert not any(link.endswith(".png") for link in links)


def test_scope_and_exclusion():
    cfg = ScanConfig(scope_regex=r"example\.com")
    assert is_in_scope("https://example.com/a", cfg)
    assert not is_in_scope("https://other.com/a", cfg)

    cfg = ScanConfig(exclude_patterns=[r"\.pdf$"])
    assert is_excluded("https://example.com/a.pdf", cfg)
    assert not is_excluded("https://example.com/a.js", cfg)


def test_build_target_list_caches_fetched_pages():
    pages = {
        "https://example.com/": (
            '<html><script src="/app.js"></script><a href="/about">About</a></html>',
            "https://example.com/",
        ),
        "https://example.com/about": ("<html>about</html>", "https://example.com/about"),
    }
    calls = []

    def fake_fetch(url, method="GET"):
        calls.append((url, method))
        return pages.get(url, (None, None, None))

    cfg = ScanConfig(url="https://example.com/", depth=1, delay=0)
    result = build_target_list(cfg, fake_fetch)

    assert set(result.targets) == {
        "https://example.com/",
        "https://example.com/app.js",
        "https://example.com/about",
    }
    # Discovery fetches the seed exactly once and uses GET.
    assert calls == [("https://example.com/", "GET")]
    assert "https://example.com/" in result.prefetched


def test_build_target_list_same_host_only_by_default():
    pages = {
        "https://example.com/": (
            '<a href="https://other.com/page">External</a><script src="https://cdn.other.com/x.js"></script>',
            "https://example.com/",
        ),
    }

    def fake_fetch(url, method="GET"):
        return pages.get(url, (None, None, None))

    cfg = ScanConfig(url="https://example.com/", depth=1, delay=0)
    result = build_target_list(cfg, fake_fetch)
    assert result.targets == ["https://example.com/"]

    cfg = ScanConfig(url="https://example.com/", depth=1, delay=0, allow_external=True)
    result = build_target_list(cfg, fake_fetch)
    assert "https://other.com/page" in result.targets


def test_legacy_extract_secrets_helper():
    patterns = {"aws_access_key_id": r"\b(?:AKIA)[0-9A-Z]{16}\b"}
    findings = extract_secrets_from_text(
        "key=AKIA1234567890ABCDEF",
        "https://t.test/",
        patterns,
        lambda *args: True,
    )
    assert findings
    assert findings[0]["type"] == "aws_access_key_id"
    assert findings[0]["severity"] == "critical"
