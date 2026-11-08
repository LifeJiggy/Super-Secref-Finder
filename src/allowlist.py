"""Allowlist / false-positive suppression for Super Secref Finder.

Supports a ``.secrefignore`` file::

    # Entries are merged. Blank lines and # comments are ignored.
    rule: aws_access_key_id          # regex against the rule id
    value: ^AKIAIOSFODNN7EXAMPLE$    # regex against the secret value
    path: tests/fixtures/*           # glob against file path / URL
    url: https://example.com/*       # glob against URL

A bare line is treated as a value regex. Inline suppression is also supported
by placing ``secref:ignore`` on the same line as code, or in the preceding
comment line.
"""

from __future__ import annotations

import fnmatch
import hashlib
import os
import re
from dataclasses import dataclass, field
from typing import Iterable, List, Optional, Pattern
from urllib.parse import urlparse


def fingerprint(rule_id: str, value: str) -> str:
    """Match the hashed finding fingerprint used by differential baselines."""
    return hashlib.sha256(f"{rule_id}:{value}".encode("utf-8")).hexdigest()[:32]


@dataclass
class Allowlist:
    rule_patterns: List[Pattern] = field(default_factory=list)
    value_patterns: List[Pattern] = field(default_factory=list)
    path_globs: List[str] = field(default_factory=list)
    url_globs: List[str] = field(default_factory=list)
    fingerprint_patterns: List[Pattern] = field(default_factory=list)

    def merge(self, other: "Allowlist") -> "Allowlist":
        self.rule_patterns.extend(other.rule_patterns)
        self.value_patterns.extend(other.value_patterns)
        self.path_globs.extend(other.path_globs)
        self.url_globs.extend(other.url_globs)
        self.fingerprint_patterns.extend(other.fingerprint_patterns)
        return self

    def is_ignored(self, rule_id: str, value: str, url: str = "") -> bool:
        if any(p.search(rule_id) for p in self.rule_patterns):
            return True
        if any(p.search(value) for p in self.value_patterns):
            return True
        if self.fingerprint_patterns:
            fp = fingerprint(rule_id, value)
            if any(p.search(fp) for p in self.fingerprint_patterns):
                return True
        target = url or ""
        normalized = target.replace("\\", "/")
        if any(fnmatch.fnmatch(normalized.lower(), g.lower()) for g in self.path_globs):
            return True
        if any(fnmatch.fnmatch(target.lower(), g.lower()) for g in self.url_globs):
            return True
        return False


def _compile(pattern: str) -> Optional[Pattern]:
    try:
        return re.compile(pattern)
    except re.error:
        return None


def load_ignore_file(path: str) -> Allowlist:
    """Load allowlist entries from ``path``. Missing/invalid lines are skipped."""
    allow = Allowlist()
    if not path or not os.path.isfile(path):
        return allow

    try:
        with open(path, "r", encoding="utf-8") as fh:
            lines = fh.readlines()
    except OSError:
        return allow

    for raw in lines:
        line = raw.strip()
        if not line or line.startswith("#"):
            continue

        key, sep, body = line.partition(":")
        if sep and key.strip().lower() in {
            "rule", "value", "path", "url", "fingerprint",
        }:
            kind = key.strip().lower()
            body = body.strip()
        else:
            kind, body = "value", line

        if not body:
            continue

        if kind == "rule":
            compiled = _compile(body)
            if compiled:
                allow.rule_patterns.append(compiled)
        elif kind == "value":
            compiled = _compile(body)
            if compiled:
                allow.value_patterns.append(compiled)
        elif kind == "path":
            allow.path_globs.append(body)
        elif kind == "url":
            allow.url_globs.append(body)
        elif kind == "fingerprint":
            compiled = _compile(body)
            if compiled:
                allow.fingerprint_patterns.append(compiled)

    return allow


def load_allowlist(paths: Optional[Iterable[str]] = None, project_dir: str = ".") -> Allowlist:
    """Load one or more ignore files, plus ``.secrefignore`` if present."""
    allow = Allowlist()
    candidates: List[str] = []
    if paths:
        candidates.extend(paths)
    default_path = os.path.join(project_dir, ".secrefignore")
    if os.path.isfile(default_path) and default_path not in candidates:
        candidates.append(default_path)
    for path in candidates:
        allow.merge(load_ignore_file(path))
    return allow


_INLINE_IGNORE_RE = re.compile(r"secref\s*:\s*ignore", re.IGNORECASE)


def has_inline_ignore(text: str, start: int) -> bool:
    """Return True if ``secref:ignore`` appears on the match line or line above."""
    line_start = text.rfind("\n", 0, start) + 1
    line_end = text.find("\n", start)
    if line_end == -1:
        line_end = len(text)
    current_line = text[line_start:line_end]
    if _INLINE_IGNORE_RE.search(current_line):
        return True
    previous_start = text.rfind("\n", 0, max(0, line_start - 1)) + 1
    previous_line = text[previous_start:max(0, line_start - 1)]
    return bool(_INLINE_IGNORE_RE.search(previous_line))


def _safe_url(url: str) -> str:
    """Drop query/fragment from a URL before writing it into a comment."""
    try:
        parsed = urlparse(url)
        if parsed.scheme:
            return parsed._replace(query="", fragment="").geturl()
    except ValueError:
        pass
    return str(url).split("?", 1)[0].split("#", 1)[0]


def write_ignore_file(
    path: str,
    findings: Iterable[dict],
    include_values: bool = False,
) -> int:
    """Write a precise allowlist from current findings.

    Fingerprints suppress the exact rule+value pair without storing the secret.
    ``include_values=True`` additionally writes exact regexes, which does store
    the secret in the allowlist file.
    """
    fingerprints = set()
    values = set()
    entries = []
    for finding in findings:
        rule_id = str(finding.get("type", "unknown"))
        value = str(finding.get("value", ""))
        if not value:
            continue
        fp = fingerprint(rule_id, value)
        if fp in fingerprints:
            continue
        fingerprints.add(fp)
        entries.append((
            f"# {rule_id} ({finding.get('severity', 'info')}) @ "
            f"{_safe_url(str(finding.get('url', '')))}",
            f"fingerprint: {fp}",
        ))
        if include_values and value not in values:
            values.add(value)
            entries.append(("", f"value: ^{re.escape(value)}$"))

    directory = os.path.dirname(os.path.abspath(path))
    if directory:
        os.makedirs(directory, exist_ok=True)
    lines = [
        "# Generated by super-secref-finder --write-ignore",
        "# Fingerprints suppress an exact rule+value pair without storing the secret.",
        "# Review before committing.",
        "",
    ]
    for comment, entry in entries:
        if comment:
            lines.append(comment)
        lines.append(entry)
    with open(path, "w", encoding="utf-8") as fp:
        fp.write("\n".join(lines) + "\n")
    return len(fingerprints)
