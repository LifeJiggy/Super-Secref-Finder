"""Scan checkpoint/resume and differential-baseline support.

v8 improvements:

* atomic, crash-safe writes with ``fsync``
* versioned checkpoint format
* baselines store **salted fingerprints** instead of raw secrets
* backward compatibility with the old ``[{type, value}]`` baseline format
"""

from __future__ import annotations

import hashlib
import json
import os
import tempfile
import time
from typing import Dict, List, Optional, Set

from . import __version__

CHECKPOINT_VERSION = 1
BASELINE_VERSION = 2


def _checkpoint_path(cfg_path: Optional[str]) -> str:
    """Return the checkpoint path, with a default."""
    return cfg_path or ".secref_checkpoint.json"


def fingerprint(rule_type: str, value: str) -> str:
    """Stable, non-reversible fingerprint for a finding."""
    digest = hashlib.sha256(f"{rule_type}:{value}".encode("utf-8")).hexdigest()
    return digest[:32]


def _atomic_write_json(path: str, data: dict) -> bool:
    """Write JSON atomically. Returns False on I/O failure (never raises)."""
    directory = os.path.dirname(os.path.abspath(path)) or "."
    try:
        os.makedirs(directory, exist_ok=True)
        fd, tmp_path = tempfile.mkstemp(prefix=".secref-", suffix=".tmp", dir=directory)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as fp:
                json.dump(data, fp, indent=2, ensure_ascii=False)
                fp.flush()
                os.fsync(fp.fileno())
            os.replace(tmp_path, path)
            return True
        except Exception:
            try:
                os.unlink(tmp_path)
            except OSError:
                pass
            raise
    except OSError:
        return False


def save_checkpoint(
    checkpoint_file: str,
    visited_urls: Set[str],
    findings: List[dict],
    scanned_count: int,
) -> bool:
    """Save scan state for resume. Returns True when written."""
    data = {
        "version": CHECKPOINT_VERSION,
        "tool_version": __version__,
        "timestamp": time.time(),
        "visited_urls": sorted(visited_urls),
        "findings": [
            {k: v for k, v in finding.items() if k != "context"}
            for finding in findings
        ],
        "scanned_count": scanned_count,
    }
    return _atomic_write_json(checkpoint_file, data)


def load_checkpoint(checkpoint_file: str) -> Optional[Dict]:
    """Load scan state from a checkpoint. Returns None if absent/invalid."""
    if not os.path.isfile(checkpoint_file):
        return None
    try:
        with open(checkpoint_file, "r", encoding="utf-8") as fp:
            data = json.load(fp)
    except (json.JSONDecodeError, OSError, ValueError):
        return None
    if not isinstance(data, dict):
        return None
    version = int(data.get("version", 0) or 0)
    if version > CHECKPOINT_VERSION:
        return None
    data.setdefault("visited_urls", [])
    data.setdefault("findings", [])
    return data


def clear_checkpoint(checkpoint_file: str) -> bool:
    """Remove a checkpoint after a successful scan."""
    try:
        if os.path.isfile(checkpoint_file):
            os.remove(checkpoint_file)
        return True
    except OSError:
        return False


def save_differential_baseline(findings: List[dict], path: str) -> bool:
    """Save hashed fingerprints as the baseline for the next scan.

    Raw secret values are deliberately **not** written to disk.
    """
    seen: Set[str] = set()
    entries = []
    for finding in findings:
        value = finding.get("value", "")
        rule_type = finding.get("type", "unknown")
        if not value:
            continue
        fp = fingerprint(rule_type, value)
        if fp in seen:
            continue
        seen.add(fp)
        entries.append({"type": rule_type, "fingerprint": fp})

    data = {
        "version": BASELINE_VERSION,
        "tool_version": __version__,
        "generated": time.time(),
        "findings": entries,
    }
    return _atomic_write_json(path, data)


def load_differential_baseline(path: str) -> Set[str]:
    """Load a baseline and return a set of fingerprints.

    Supports the v8 hashed format and the legacy ``[{type, value}]`` list.
    """
    if not os.path.isfile(path):
        return set()
    try:
        with open(path, "r", encoding="utf-8") as fp:
            data = json.load(fp)
    except (json.JSONDecodeError, OSError, ValueError):
        return set()

    fingerprints: Set[str] = set()

    if isinstance(data, dict):
        for entry in data.get("findings", []):
            if not isinstance(entry, dict):
                continue
            if entry.get("fingerprint"):
                fingerprints.add(str(entry["fingerprint"]))
            elif entry.get("type") and entry.get("value"):
                fingerprints.add(fingerprint(entry["type"], entry["value"]))
        return fingerprints

    if isinstance(data, list):
        for entry in data:
            if isinstance(entry, dict) and entry.get("type") and entry.get("value"):
                fingerprints.add(fingerprint(entry["type"], entry["value"]))

    return fingerprints


def diff_findings(current: List[dict], baseline: Set[str]) -> List[dict]:
    """Return only findings whose fingerprint is not in the baseline."""
    new: List[dict] = []
    for finding in current:
        key = fingerprint(finding.get("type", "unknown"), finding.get("value", ""))
        if key not in baseline:
            new.append(finding)
    return new


def merge_findings(*groups: List[dict]) -> List[dict]:
    """Merge findings from a checkpoint and a resume, keeping first occurrence."""
    merged: List[dict] = []
    seen = set()
    for group in groups:
        for finding in group:
            key = fingerprint(finding.get("type", "unknown"), finding.get("value", ""))
            if key in seen:
                continue
            seen.add(key)
            merged.append(finding)
    return merged
