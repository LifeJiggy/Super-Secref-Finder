"""Webhook notifications for scan summaries.

Supported payloads: Slack, Discord, and a generic JSON shape. Values are always
redacted before leaving the process.
"""

from __future__ import annotations

from collections import Counter
from typing import Dict, List, Optional, Tuple

import requests

from . import __version__
from .rules import SEVERITY_RANK


def _redact(value: str, keep: int = 4) -> str:
    if not value:
        return ""
    return f"***{len(value)}-char-value***"


def _summary(findings: List[dict], meta: Optional[dict]) -> Dict[str, object]:
    severities = Counter(f.get("severity", "info") for f in findings)
    categories = Counter(f.get("category", "unknown") for f in findings)
    return {
        "tool": "super-secref-finder",
        "version": __version__,
        "target": (meta or {}).get("target", ""),
        "total": len(findings),
        "by_severity": {
            name: severities.get(name, 0)
            for name in ("critical", "high", "medium", "low", "info")
        },
        "by_category": dict(categories.most_common()),
        "findings": [
            {
                "severity": f.get("severity", "info"),
                "type": f.get("type", "unknown"),
                "value": _redact(str(f.get("value", ""))),
                "url": f.get("url", ""),
                "line": f.get("line"),
                "validated": f.get("validated"),
            }
            for f in findings[:50]
        ],
    }


def _text_summary(summary: Dict[str, object]) -> str:
    lines = [
        f"Super Secref Finder v{__version__}",
        f"Target: {summary['target']}",
        f"Total findings: {summary['total']}",
    ]
    by_sev = summary["by_severity"]
    assert isinstance(by_sev, dict)
    lines.append(
        "Severity: " + ", ".join(f"{name}={count}" for name, count in by_sev.items() if count)
    )
    findings = summary["findings"]
    assert isinstance(findings, list)
    for finding in findings[:10]:
        lines.append(
            f"- [{str(finding['severity']).upper()}] {finding['type']} "
            f"{finding['value']} @ {finding['url']}"
        )
    return "\n".join(lines)


def send_notification(
    url: str,
    findings: List[dict],
    meta: Optional[dict] = None,
    fmt: str = "slack",
    min_severity: str = "high",
    timeout: int = 15,
) -> Tuple[bool, str]:
    """Send a redacted scan summary. Returns ``(ok, detail)``."""
    if not url:
        return False, "no webhook URL"
    floor = SEVERITY_RANK.get((min_severity or "high").lower())
    if floor is not None:
        findings = [
            f for f in findings
            if SEVERITY_RANK.get(f.get("severity", "info"), 0) >= floor
        ]

    summary = _summary(findings, meta)
    text = _text_summary(summary)

    if fmt == "discord":
        payload = {"content": text}
    elif fmt == "generic":
        payload = summary
    else:
        payload = {"text": text}

    try:
        response = requests.post(url, json=payload, timeout=timeout)
    except requests.RequestException as exc:
        return False, str(exc)
    if response.status_code >= 400:
        return False, f"HTTP {response.status_code}: {response.text[:200]}"
    return True, f"HTTP {response.status_code}"
