"""Example plugin: flag TODO markers containing the word SECRET.

Load with:

    secref --path . --plugin-dir examples

Plugins execute in-process; only load code you trust.
"""

from __future__ import annotations

import re

from plugins import register_plugin

_PATTERN = re.compile(r"TODO[^\n]{0,80}SECRET", re.IGNORECASE)


@register_plugin("example_todo_secret")
def example_todo_secret(url: str, text: str, findings: list) -> list:
    results = []
    for match in _PATTERN.finditer(text):
        results.append({
            "type": "todo_secret_marker",
            "value": match.group(0)[:80],
            "url": url,
            "severity": "info",
            "category": "code-risk",
            "confidence": 0.6,
            "start": match.start(),
            "end": match.end(),
        })
    return results
