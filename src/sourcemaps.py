"""Source-map and JavaScript chunk discovery.

Modern bundles routinely ship ``sourceMappingURL`` comments or split chunks
that are not linked from the HTML.  These helpers turn those references into
normal crawl targets so the existing rule engine can scan them.
"""

from __future__ import annotations

import re
from typing import List, Set
from urllib.parse import urljoin, urlparse

_SOURCE_MAP_RE = re.compile(
    r"(?://[#@]\s*sourceMappingURL=([^\s'\"<>]+)"
    r"|/\*[#@]\s*sourceMappingURL=([^*]+?)\s*\*/)",
    re.IGNORECASE,
)

# Quoted JS paths commonly found in webpack/Vite/Rollup manifests and runtime
# chunks.  They are only added when ``--source-maps`` is enabled.
_CHUNK_RE = re.compile(
    r"""["']((?:https?:)?//[^"'\s<>]+?\.(?:m?js|cjs)(?:\?[^"'\s<>]*)?|"""
    r"""(?:/|\.{1,2}/)[^"'\s<>]+?\.(?:m?js|cjs)(?:\?[^"'\s<>]*)?)["']""",
    re.IGNORECASE,
)

_SKIP_PREFIXES = ("data:", "blob:", "javascript:", "#")


def _normalize(candidate: str, base_url: str) -> str:
    candidate = candidate.strip().strip("'\"")
    if not candidate or candidate.lower().startswith(_SKIP_PREFIXES):
        return ""
    absolute = urljoin(base_url, candidate)
    parsed = urlparse(absolute)
    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        return ""
    return absolute


def extract_source_map_urls(text: str, base_url: str) -> List[str]:
    """Return absolute source-map URLs referenced by JS/CSS content."""
    urls: Set[str] = set()
    if not text:
        return []
    for match in _SOURCE_MAP_RE.finditer(text):
        raw = match.group(1) or match.group(2) or ""
        normalized = _normalize(raw, base_url)
        if normalized:
            urls.add(normalized)
    return sorted(urls)


def extract_bundler_chunks(text: str, base_url: str) -> List[str]:
    """Return absolute JavaScript chunk URLs from quoted bundle references."""
    urls: Set[str] = set()
    if not text:
        return []
    for match in _CHUNK_RE.finditer(text):
        normalized = _normalize(match.group(1), base_url)
        if normalized:
            urls.add(normalized)
    return sorted(urls)


__all__ = ["extract_bundler_chunks", "extract_source_map_urls"]
