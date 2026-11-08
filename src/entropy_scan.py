"""Opt-in whole-file entropy scanning for generic high-entropy tokens."""

from __future__ import annotations

import re
from typing import List, Optional

from .allowlist import Allowlist, has_inline_ignore
from .config import ScanConfig
from .entropy import is_likely_secret, shannon_entropy
from .validators import extract_context

_TOKEN_RE = re.compile(r"[A-Za-z0-9+/_\-=.]{20,200}")
_HASH_CONTEXT_RE = re.compile(
    r"(?i)\b(?:sha[-_]?(?:1|224|256|384|512)|md5|hash|checksum|integrity|etag|digest)\b"
)
_COMMON_SUFFIXES = {
    ".js", ".mjs", ".cjs", ".css", ".html", ".json", ".xml", ".svg",
    ".png", ".jpg", ".jpeg", ".gif", ".webp", ".woff", ".woff2", ".ttf",
}


def _line_col(text: str, offset: int) -> tuple:
    line = text.count("\n", 0, offset) + 1
    line_start = text.rfind("\n", 0, offset) + 1
    return line, offset - line_start + 1


def find_entropy_findings(
    text: str,
    url: str,
    cfg: ScanConfig,
    allowlist: Optional[Allowlist] = None,
) -> List[dict]:
    """Return generic high-entropy findings (only when ``--entropy-scan`` is on)."""
    if not cfg.entropy_scan or not text:
        return []

    findings: List[dict] = []
    for match in _TOKEN_RE.finditer(text):
        token = match.group(0).strip(".,;:)]}'\"")
        if len(token) < cfg.entropy_min_length:
            continue
        if token.startswith(("http://", "https://")) or "://" in token:
            continue
        if token.count(".") > 2 or any(token.lower().endswith(s) for s in _COMMON_SUFFIXES):
            continue
        if not is_likely_secret(
            token,
            min_length=cfg.entropy_min_length,
            threshold=cfg.entropy_scan_threshold,
        ):
            continue

        before = text[max(0, match.start() - 48):match.start()]
        if _HASH_CONTEXT_RE.search(before):
            continue
        if allowlist is not None and allowlist.is_ignored("high_entropy_string", token, url):
            continue
        if has_inline_ignore(text, match.start()):
            continue

        start = match.start()
        end = start + len(token)
        line, column = _line_col(text, start)
        finding = {
            "type": "high_entropy_string",
            "value": token,
            "url": url,
            "confidence": 0.62,
            "severity": "medium",
            "category": "secret",
            "description": "High-entropy string not matched by a specific rule",
            "start": start,
            "end": end,
            "line": line,
            "column": column,
            "entropy": round(shannon_entropy(token), 2),
        }
        if cfg.show_context:
            finding["context"] = extract_context(text, start, end)
        findings.append(finding)
    return findings
