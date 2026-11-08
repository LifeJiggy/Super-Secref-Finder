"""Source-map and chunk discovery tests."""

from src.config import ScanConfig
from src.crawler import build_target_list
from src.sourcemaps import extract_bundler_chunks, extract_source_map_urls


def test_extract_source_map_urls():
    text = (
        "//# sourceMappingURL=app.js.map\n"
        "/*# sourceMappingURL=/static/other.css.map */\n"
        "//# sourceMappingURL=data:application/json;base64,AAAA\n"
    )
    urls = extract_source_map_urls(text, "https://example.com/assets/app.js")
    assert "https://example.com/assets/app.js.map" in urls
    assert "https://example.com/static/other.css.map" in urls
    assert not any(url.startswith("data:") for url in urls)


def test_extract_bundler_chunks():
    text = 'const a = "/static/chunk-vendor.js"; const b = "./chunk-main.mjs";'
    chunks = extract_bundler_chunks(text, "https://example.com/assets/app.js")
    assert "https://example.com/static/chunk-vendor.js" in chunks
    assert "https://example.com/assets/chunk-main.mjs" in chunks


def test_crawler_discovers_maps_and_chunks_at_depth_limit():
    pages = {
        "https://example.com/": (
            '<html><script src="/static/app.js"></script></html>',
            "https://example.com/",
        ),
        "https://example.com/static/app.js": (
            '//# sourceMappingURL=app.js.map\n'
            'const chunk = "/static/chunk-vendor.js";\n',
            "https://example.com/static/app.js",
        ),
    }
    calls = []

    def fake_fetch(url, method="GET"):
        calls.append(url)
        return pages.get(url, (None, None, None))

    cfg = ScanConfig(
        url="https://example.com/",
        depth=1,
        delay=0,
        source_maps=True,
    )
    result = build_target_list(cfg, fake_fetch)
    assert "https://example.com/static/app.js" in result.targets
    assert "https://example.com/static/app.js.map" in result.targets
    assert "https://example.com/static/chunk-vendor.js" in result.targets
    assert calls == [
        "https://example.com/",
        "https://example.com/static/app.js",
    ]
