"""URL crawling with scope, depth, exclusion, robots.txt, and a fetch cache.

v8 never fetches the same page twice: pages fetched during discovery are
returned in :class:`CrawlResult.prefetched` and reused by the scanner.
"""

from __future__ import annotations

import logging
import re
from collections import deque
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple
from urllib.parse import urldefrag, urljoin, urlparse
from urllib.robotparser import RobotFileParser

from .config import ScanConfig
from .rules import Rule, all_rule_ids
from .validators import confidence_for, validate_rule

logger = logging.getLogger("secref.crawler")

# A deliberately broad but cheap set of link patterns. We only keep URLs that
# parse as HTTP(S) and generally point at text resources.
_LINK_PATTERNS = [
    re.compile(r'<script[^>]+src\s*=\s*["\']?([^"\'>\s]+)', re.IGNORECASE),
    re.compile(r'<link[^>]+href\s*=\s*["\']?([^"\'>\s]+)', re.IGNORECASE),
    re.compile(r'<a[^>]+href\s*=\s*["\']?([^"\'>\s]+)', re.IGNORECASE),
    re.compile(r'<img[^>]+src\s*=\s*["\']?([^"\'>\s]+)', re.IGNORECASE),
    re.compile(r'<source[^>]+src\s*=\s*["\']?([^"\'>\s]+)', re.IGNORECASE),
    re.compile(r'["\']((?:https?:)?//[^"\'\s<>]+)["\']', re.IGNORECASE),
    re.compile(r'["\']((?:/|\./|\.\./)[^"\'\s<>]+\.(?:js|mjs|json|html?|xml|map)(?:\?[^"\']*)?)["\']', re.IGNORECASE),
]

_JS_PATTERNS = [
    re.compile(r'<script[^>]+src\s*=\s*["\']?([^"\'>\s]+\.(?:m?js)(?:\?[^"\'>\s]*)?)', re.IGNORECASE),
    re.compile(r'["\']((?:https?:)?//[^"\'\s<>]+\.(?:m?js)(?:\?[^"\'\s<>]*)?)["\']', re.IGNORECASE),
]

_TEXTUAL_PATH_EXT = (
    ".js", ".mjs", ".cjs", ".json", ".jsonl", ".html", ".htm", ".xhtml",
    ".xml", ".txt", ".map", ".css", ".yaml", ".yml", ".csv",
)

_SKIP_SCHEMES = ("mailto:", "tel:", "javascript:", "data:", "blob:", "about:")


@dataclass
class CrawlResult:
    """Output of :func:`build_target_list`."""

    targets: List[str] = field(default_factory=list)
    prefetched: Dict[str, Tuple[str, str]] = field(default_factory=dict)


def validate_url(url: str) -> bool:
    """Validate a URL uses HTTP(S) and has a host."""
    try:
        parsed = urlparse(url)
        return parsed.scheme in ("http", "https") and bool(parsed.netloc)
    except Exception:
        return False


def _normalize(url: str) -> str:
    """Strip fragments and normalize whitespace/entities."""
    url = url.strip().strip("'\"")
    if not url or url.startswith(_SKIP_SCHEMES):
        return ""
    url, _ = urldefrag(url)
    return url.rstrip()


def _host(url: str) -> str:
    return urlparse(url).netloc.lower()


def is_in_scope(url: str, cfg: ScanConfig, allowed_hosts: Optional[Set[str]] = None) -> bool:
    """Check scope: explicit regex wins, otherwise same-host by default."""
    if not validate_url(url):
        return False
    if cfg.scope_regex:
        try:
            return bool(re.search(cfg.scope_regex, url))
        except re.error:
            return True
    if cfg.allow_external:
        return True
    if allowed_hosts:
        return _host(url) in allowed_hosts
    return True


def is_excluded(url: str, cfg: ScanConfig) -> bool:
    """Check if a URL matches any exclusion pattern."""
    for pattern in cfg.exclude_patterns:
        try:
            if re.search(pattern, url, re.IGNORECASE):
                return True
        except re.error:
            continue
    return False


def _same_host_js(url: str, allowed_hosts: Set[str]) -> bool:
    return not allowed_hosts or _host(url) in allowed_hosts


def _link_allowed(url: str, cfg: ScanConfig, allowed_hosts: Set[str]) -> bool:
    """Host/scope gate for discovered links."""
    if cfg.allow_external or cfg.scope_regex:
        return True
    return _same_host_js(url, allowed_hosts)


def extract_js_links(text: str, base_url: str) -> List[str]:
    """Extract JavaScript file links from HTML content."""
    links: Set[str] = set()
    for pattern in _JS_PATTERNS:
        for match in pattern.finditer(text):
            candidate = _normalize(urljoin(base_url, match.group(1)))
            if validate_url(candidate):
                links.add(candidate)
    # Also keep any script src that does not end in .js (bundler endpoints,
    # ``/assets/app`` etc.) if the tag is clearly a script.
    for match in _LINK_PATTERNS[0].finditer(text):
        candidate = _normalize(urljoin(base_url, match.group(1)))
        if validate_url(candidate) and urlparse(candidate).path:
            links.add(candidate)
    return sorted(links)


def extract_all_links(text: str, base_url: str) -> List[str]:
    """Extract likely crawlable URLs from page content."""
    links: Set[str] = set()
    for pattern in _LINK_PATTERNS:
        for match in pattern.finditer(text):
            candidate = _normalize(urljoin(base_url, match.group(1)))
            if not validate_url(candidate):
                continue
            path = urlparse(candidate).path.lower()
            if path and not path.endswith(_TEXTUAL_PATH_EXT):
                # Still allow extension-less HTML routes (SPA links, /api/...).
                if "." in path.rsplit("/", 1)[-1]:
                    continue
            links.add(candidate)
    return sorted(links)


class RobotsPolicy:
    """Small robots.txt cache using the standard library parser."""

    def __init__(self, cfg: ScanConfig, fetch_fn):
        self.cfg = cfg
        self.fetch_fn = fetch_fn
        self._parsers: Dict[str, RobotFileParser] = {}
        self._allow_all: Set[str] = set()

    def allowed(self, url: str) -> bool:
        if not self.cfg.respect_robots:
            return True
        parsed = urlparse(url)
        origin = f"{parsed.scheme}://{parsed.netloc}"
        if origin in self._allow_all:
            return True
        parser = self._parsers.get(origin)
        if parser is None:
            parser = RobotFileParser()
            robots_url = origin + "/robots.txt"
            try:
                text, _ = _fetch_page(self.fetch_fn, robots_url, "GET")
                if text:
                    parser.parse(text.splitlines())
                else:
                    self._allow_all.add(origin)
                    return True
            except Exception:
                self._allow_all.add(origin)
                return True
            self._parsers[origin] = parser
        try:
            return parser.can_fetch(self.cfg.user_agent or "*", url)
        except Exception:
            return True


def _fetch_page(fetch_fn, url: str, method: Optional[str] = None):
    """Call ``fetch_fn`` and normalize 2- or 3-tuple results."""
    if method and _accepts_method(fetch_fn):
        result = fetch_fn(url, method)
    else:
        result = fetch_fn(url)

    if isinstance(result, tuple):
        text = result[0] if result else None
        final_url = result[1] if len(result) > 1 and result[1] else url
        return text, final_url
    return result, url


def build_target_list(cfg: ScanConfig, fetch_fn) -> CrawlResult:
    """Build the full URL target list, caching any pages fetched for discovery.

    Seeds: ``cfg.js_files`` (direct), plus ``cfg.url`` when present. Discovery
    is always a GET, even when the scan itself is configured for POST.
    """
    result = CrawlResult()
    visited: Set[str] = set()
    queue: deque = deque()
    robots = RobotsPolicy(cfg, fetch_fn)

    allowed_hosts: Set[str] = set()
    if cfg.url:
        allowed_hosts.add(_host(cfg.url))
    for js_url in cfg.js_files:
        allowed_hosts.add(_host(js_url))

    # Direct JS files are always targets (and are never crawled for links).
    direct_js: Set[str] = set()
    for js_url in cfg.js_files:
        normalized = _normalize(js_url)
        if validate_url(normalized) and normalized not in visited:
            visited.add(normalized)
            direct_js.add(normalized)
            queue.append((normalized, cfg.depth))

    if cfg.url:
        normalized = _normalize(cfg.url)
        if validate_url(normalized) and normalized not in visited:
            visited.add(normalized)
            queue.append((normalized, 0))

    while queue:
        url, depth = queue.popleft()

        if not is_in_scope(url, cfg, allowed_hosts):
            logger.debug(f"Out of scope: {url}")
            continue
        if is_excluded(url, cfg):
            logger.debug(f"Excluded: {url}")
            continue
        if not robots.allowed(url):
            logger.debug(f"Blocked by robots.txt: {url}")
            continue
        if len(result.targets) >= cfg.max_urls:
            logger.info(f"Reached max URL limit ({cfg.max_urls})")
            break

        result.targets.append(url)

        # Direct JS files are leaves: never fetch during discovery.
        if url in direct_js:
            continue
        if depth >= cfg.depth:
            continue

        text, final_url = _fetch_page(fetch_fn, url, "GET")
        if not text:
            continue
        effective_url = final_url or url
        result.prefetched[url] = (text, effective_url)
        if effective_url != url:
            result.prefetched[effective_url] = (text, effective_url)

        # JavaScript is always worth adding, even if it is beyond depth.
        for js_url in extract_js_links(text, effective_url):
            if js_url in visited:
                continue
            if not _link_allowed(js_url, cfg, allowed_hosts):
                continue
            visited.add(js_url)
            if len(result.targets) + len(queue) >= cfg.max_urls:
                break
            queue.append((js_url, depth + 1))

        # Crawl ordinary links up to the configured depth.
        for link in extract_all_links(text, effective_url):
            if link in visited:
                continue
            if not _link_allowed(link, cfg, allowed_hosts):
                continue
            visited.add(link)
            queue.append((link, depth + 1))

    return result


def _accepts_method(fetch_fn) -> bool:
    """Return True when ``fetch_fn`` accepts a ``method`` keyword."""
    try:
        import inspect

        signature = inspect.signature(fetch_fn)
        params = signature.parameters
        return "method" in params or any(p.kind == p.VAR_KEYWORD for p in params.values())
    except (TypeError, ValueError):  # pragma: no cover - callables without signatures
        return False


def extract_secrets_from_text(
    text: str,
    url: str,
    patterns: Dict[str, str],
    validators_fn,
    confidence_threshold: float = 0.6,
    entropy_threshold: float = 3.5,
) -> List[dict]:
    """Legacy helper: run ``patterns`` against ``text`` and return findings.

    New code should call :func:`src.scanner.scan_text`, which also applies
    allowlists, severity and per-rule caps.
    """
    registry = all_rule_ids()
    findings: List[dict] = []
    seen: Set[str] = set()

    for name, pattern in patterns.items():
        rule = registry.get(name)
        if rule is None:
            rule = Rule(id=name, pattern=pattern, severity="medium", category="custom")
        try:
            rule.compile()
        except re.error:
            continue
        assert rule.compiled is not None
        for match in rule.compiled.finditer(text):
            value = rule.value_of(match)
            if not validators_fn(name, value, text, match, entropy_threshold):
                continue
            dedup_key = f"{name}:{value}"
            if dedup_key in seen:
                continue
            seen.add(dedup_key)
            start, end = rule.value_span(match)
            confidence = confidence_for(rule, value, text, match)
            if confidence < confidence_threshold:
                continue
            findings.append({
                "type": name,
                "value": value,
                "url": url,
                "confidence": confidence,
                "severity": rule.severity,
                "category": rule.category,
                "description": rule.description,
                "start": start,
                "end": end,
                "line": text.count("\n", 0, start) + 1,
            })

    return findings
