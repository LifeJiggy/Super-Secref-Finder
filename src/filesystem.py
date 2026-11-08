"""Local filesystem and stdin scanning support.

The scanner can operate on a web target or on local paths::

    super-secref-finder --path .
    super-secref-finder --path src/ config.yaml
    cat env.txt | super-secref-finder --path -

Binary files, dependency directories, and oversized files are skipped.
"""

from __future__ import annotations

import fnmatch
import os
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Iterator, List, Optional, Sequence, Set

# Directories that are almost never worth scanning.
SKIP_DIRS: Set[str] = {
    ".git", ".hg", ".svn", ".bzr",
    "node_modules", "bower_components", ".pnpm-store",
    "venv", ".venv", "env", ".env.d", "virtualenv",
    "__pycache__", ".mypy_cache", ".pytest_cache", ".ruff_cache", ".tox",
    "dist", "build", "target", "out", ".next", ".nuxt", ".svelte-kit",
    "coverage", "htmlcov", ".nyc_output",
    ".idea", ".vscode", ".vs",
    ".terraform", ".serverless",
}

# Tool-generated artifacts should not be scanned on the next run.
_ARTIFACT_RE = re.compile(
    r"^(?:"
    r"findings_\d{8}_\d{6}\.(?:json|jsonl|csv|md|html|sarif|junit|xml)"
    r"|findings\.json"
    r"|secref(?:_audit|_errors)?\.log(?:\.\d+)?"
    r"|\.secref_checkpoint\.json(?:\.tmp)?"
    r"|scan_results\.json"
    r")$",
    re.IGNORECASE,
)

# Extensions that are definitely binary / not useful.
SKIP_EXTENSIONS: Set[str] = {
    ".png", ".jpg", ".jpeg", ".gif", ".webp", ".avif", ".ico", ".bmp",
    ".tiff", ".psd", ".pdf", ".zip", ".gz", ".bz2", ".xz", ".7z", ".rar",
    ".tar", ".jar", ".war", ".ear", ".class", ".pyc", ".pyo", ".pyd",
    ".so", ".dylib", ".dll", ".exe", ".bin", ".o", ".a", ".lib",
    ".mp3", ".mp4", ".avi", ".mov", ".mkv", ".wav", ".flac", ".ogg",
    ".woff", ".woff2", ".ttf", ".eot", ".otf",
    ".sqlite", ".db", ".mdb", ".lockb",
}


@dataclass
class LocalSource:
    """A text source discovered on disk or stdin."""

    path: str
    url: str
    text: str


def _matches_any(path: str, globs: Sequence[str]) -> bool:
    """Match a path against globs *or* regular expressions."""
    normalized = path.replace("\\", "/")
    base = os.path.basename(normalized)
    for pattern in globs:
        if fnmatch.fnmatch(normalized, pattern) or fnmatch.fnmatch(base, pattern):
            return True
        try:
            if re.search(pattern, normalized, re.IGNORECASE):
                return True
        except re.error:
            continue
    return False


def _looks_binary(sample: bytes) -> bool:
    if not sample:
        return False
    if b"\x00" in sample:
        return True
    # Heuristic: too many non-text bytes.
    text_bytes = bytes(range(32, 127)) + b"\n\r\t\f\b"
    non_text = sum(1 for b in sample if b not in text_bytes)
    return non_text / max(1, len(sample)) > 0.30


def _read_text(path: str, max_size: int) -> Optional[str]:
    try:
        size = os.path.getsize(path)
        if size == 0 or size > max_size:
            return None
        with open(path, "rb") as fh:
            raw = fh.read(max_size + 1)
    except OSError:
        return None
    if len(raw) > max_size or _looks_binary(raw[:8192]):
        return None
    return raw.decode("utf-8", errors="replace")


def _iter_files(
    root: str,
    exclude_globs: Sequence[str],
    max_size: int,
) -> Iterator[str]:
    if os.path.isfile(root):
        if not _matches_any(root, exclude_globs):
            yield root
        return

    for current, dirs, files in os.walk(root):
        dirs[:] = sorted(
            d for d in dirs
            if d not in SKIP_DIRS and not d.startswith(".")
        )
        for name in sorted(files):
            if _ARTIFACT_RE.match(name):
                continue
            path = os.path.join(current, name)
            if os.path.splitext(name)[1].lower() in SKIP_EXTENSIONS:
                continue
            if _matches_any(path, exclude_globs):
                continue
            try:
                if os.path.getsize(path) > max_size:
                    continue
            except OSError:
                continue
            yield path


def iter_local_sources(
    paths: Iterable[str],
    exclude_globs: Optional[Sequence[str]] = None,
    max_size: int = 5 * 1024 * 1024,
) -> Iterator[LocalSource]:
    """Yield text sources for local files, directories, or ``-`` (stdin)."""
    globs = list(exclude_globs or [])
    seen: Set[str] = set()

    for raw_path in paths:
        if raw_path == "-":
            data = sys.stdin.read(max_size + 1)
            if data:
                yield LocalSource(path="<stdin>", url="stdin://", text=data[:max_size])
            continue

        expanded = os.path.abspath(os.path.expanduser(raw_path))
        if not os.path.exists(expanded):
            continue

        if os.path.isfile(expanded):
            # A direct file argument is scanned unless explicitly excluded.
            if _ARTIFACT_RE.match(os.path.basename(expanded)):
                continue
            if _matches_any(expanded, globs):
                continue
            real = os.path.realpath(expanded)
            if real in seen:
                continue
            text = _read_text(expanded, max_size)
            if text is not None:
                seen.add(real)
                yield LocalSource(
                    path=expanded,
                    url=Path(expanded).as_uri(),
                    text=text,
                )
            continue

        for path in _iter_files(expanded, globs, max_size):
            real = os.path.realpath(path)
            if real in seen:
                continue
            text = _read_text(path, max_size)
            if text is None:
                continue
            seen.add(real)
            if len(seen) > 100_000:  # hard safety valve
                return
            yield LocalSource(
                path=path,
                url=Path(path).as_uri(),
                text=text,
            )
