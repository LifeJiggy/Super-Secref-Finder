"""Multi-format output: JSON, JSONL, CSV, HTML, Markdown, SARIF."""

from __future__ import annotations

import csv
import hashlib
import html
import json
import os
import xml.etree.ElementTree as ET
from collections import Counter
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from . import __version__
from .rules import SEVERITY_RANK

_SEVERITY_ORDER = ("critical", "high", "medium", "low", "info")

_SEVERITY_COLORS = {
    "critical": "#f85149",
    "high": "#ff7b72",
    "medium": "#d29922",
    "low": "#58a6ff",
    "info": "#8b949e",
}

_SARIF_LEVEL = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
    "info": "note",
}

_SECURITY_SEVERITY = {
    "critical": "9.5",
    "high": "8.0",
    "medium": "6.0",
    "low": "3.5",
    "info": "0.0",
}


def _redact(value: str, keep: int = 4) -> str:
    """Redact a secret, keeping only the first/last ``keep`` characters."""
    if not value:
        return ""
    if len(value) <= keep * 2:
        return "*" * len(value)
    return value[:keep] + "*" * (len(value) - keep * 2) + value[-keep:]


def _redact_in_context(context: str, value: str) -> str:
    if not context or not value:
        return context
    return context.replace(value, _redact(value))


def _base_finding(f: dict, redact: bool = False, show_context: bool = False) -> dict:
    """Return a cleaned, serializable finding."""
    value = f.get("value", "")
    if redact:
        value = _redact(value)

    result = {
        "type": f.get("type", "unknown"),
        "value": value,
        "url": f.get("url", ""),
        "severity": f.get("severity", "info"),
        "category": f.get("category", "unknown"),
        "confidence": f.get("confidence", 0),
        "validated": f.get("validated"),
        "line": f.get("line"),
        "column": f.get("column"),
        "description": f.get("description", ""),
    }
    if f.get("rotation_url"):
        result["rotation_url"] = f["rotation_url"]
    if show_context and f.get("context"):
        context = f["context"]
        if redact:
            context = _redact_in_context(context, f.get("value", ""))
        result["context"] = context
    if f.get("validation_detail") and f.get("validated") is not None:
        detail = dict(f["validation_detail"])
        detail.pop("reason", None)  # reasons are kept in the console/log only
        result["validation"] = detail
    for key in (
        "source", "repo", "path", "commit", "author", "author_email",
        "commit_date", "commit_message", "entropy",
    ):
        if f.get(key) is not None:
            result[key] = f[key]
    return result


def _sort_findings(findings: List[dict]) -> List[dict]:
    return sorted(
        findings,
        key=lambda f: (
            SEVERITY_RANK.get(f.get("severity", "info"), 0),
            float(f.get("confidence", 0) or 0),
        ),
        reverse=True,
    )


def _summary(findings: List[dict]) -> Dict[str, Any]:
    severities = Counter(f.get("severity", "info") for f in findings)
    categories = Counter(f.get("category", "unknown") for f in findings)
    rules = Counter(f.get("type", "unknown") for f in findings)
    return {
        "total": len(findings),
        "by_severity": {name: severities.get(name, 0) for name in _SEVERITY_ORDER},
        "by_category": dict(categories.most_common()),
        "top_rules": dict(rules.most_common(10)),
        "validated": sum(1 for f in findings if f.get("validated") is True),
    }


def save_json(
    findings: List[dict],
    path: str,
    redact: bool = False,
    meta: Optional[dict] = None,
    show_context: bool = False,
) -> str:
    """Save findings as JSON with a summary block."""
    ordered = _sort_findings(findings)
    data = {
        "tool": "super-secref-finder",
        "version": __version__,
        "scan_time": datetime.now(timezone.utc).isoformat(),
        "meta": meta or {},
        "summary": _summary(ordered),
        "findings": [_base_finding(f, redact, show_context) for f in ordered],
    }
    with open(path, "w", encoding="utf-8") as fp:
        json.dump(data, fp, indent=2, ensure_ascii=False)
    return path


def save_jsonl(
    findings: List[dict],
    path: str,
    redact: bool = False,
    meta: Optional[dict] = None,
    show_context: bool = False,
) -> str:
    """Save findings as JSONL (one object per line) for streaming."""
    with open(path, "w", encoding="utf-8") as fp:
        for f in _sort_findings(findings):
            fp.write(json.dumps(_base_finding(f, redact, show_context), ensure_ascii=False) + "\n")
    return path


def save_csv(
    findings: List[dict],
    path: str,
    redact: bool = False,
    meta: Optional[dict] = None,
    show_context: bool = False,
) -> str:
    """Save findings as CSV."""
    fieldnames = [
        "severity", "category", "type", "value", "url",
        "confidence", "validated", "line", "column", "description",
        "source", "repo", "commit", "author", "commit_date", "rotation_url",
    ]
    with open(path, "w", newline="", encoding="utf-8") as fp:
        writer = csv.DictWriter(fp, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        for f in _sort_findings(findings):
            row = _base_finding(f, redact, show_context)
            writer.writerow(row)
    return path


def save_markdown(
    findings: List[dict],
    path: str,
    redact: bool = False,
    meta: Optional[dict] = None,
    show_context: bool = False,
) -> str:
    """Save findings as a shareable Markdown report."""
    ordered = _sort_findings(findings)
    summary = _summary(ordered)
    target = (meta or {}).get("target", "")
    lines = [
        "# Super Secref Finder — Scan Report",
        "",
        f"**Tool version:** {__version__}  ",
        f"**Scan time:** {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}  ",
        f"**Target:** `{html.escape(str(target))}`  ",
        f"**Total findings:** {summary['total']}  ",
        f"**Live-validated:** {summary['validated']}",
        "",
        "## Severity summary",
        "",
        "| Severity | Count |",
        "|----------|------:|",
    ]
    for severity in _SEVERITY_ORDER:
        lines.append(f"| {severity.capitalize()} | {summary['by_severity'][severity]} |")

    lines.extend(["", "## Category summary", "", "| Category | Count |", "|----------|------:|"])
    for category, count in summary["by_category"].items():
        lines.append(f"| {html.escape(category)} | {count} |")

    lines.extend([
        "",
        "## Findings",
        "",
        "| # | Severity | Rule | Value | URL | Line | Confidence | Rotate |",
        "|---|----------|------|-------|-----|-----:|-----------:|--------|",
    ])
    for index, f in enumerate(ordered, 1):
        value = _redact(f.get("value", ""), keep=6) if redact else f.get("value", "")[:120]
        url = f.get("url", "")
        rotation = f.get("rotation_url", "")
        rotate = f"[rotate]({html.escape(rotation)})" if rotation else ""
        lines.append(
            f"| {index} | {f.get('severity', 'info').upper()} | {html.escape(f.get('type', ''))} "
            f"| `{html.escape(value)}` | <{html.escape(url)}> "
            f"| {f.get('line') or ''} | {float(f.get('confidence', 0)) * 100:.0f}% | {rotate} |"
        )

    with open(path, "w", encoding="utf-8") as fp:
        fp.write("\n".join(lines))
    return path


_HTML_CSS = """
:root { color-scheme: dark; }
* { box-sizing: border-box; }
body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
       margin: 0; padding: 2rem; background: #0d1117; color: #c9d1d9; }
h1 { color: #58a6ff; margin: 0 0 .25rem; }
.sub { color: #8b949e; margin-bottom: 1.5rem; }
.cards { display: grid; grid-template-columns: repeat(auto-fit, minmax(140px, 1fr));
         gap: .75rem; margin-bottom: 1.5rem; }
.card { background: #161b22; border: 1px solid #30363d; border-radius: 10px; padding: 1rem; }
.card .n { font-size: 1.8rem; font-weight: 700; }
.card .l { color: #8b949e; font-size: .8rem; text-transform: uppercase; letter-spacing: .05em; }
.toolbar { display: flex; gap: .5rem; flex-wrap: wrap; margin-bottom: 1rem; }
button, input { background: #161b22; color: #c9d1d9; border: 1px solid #30363d;
                border-radius: 8px; padding: .45rem .7rem; font-size: .85rem; }
button { cursor: pointer; }
button.active { border-color: #58a6ff; color: #58a6ff; }
input { min-width: 240px; flex: 1; }
table { border-collapse: collapse; width: 100%; background: #0d1117; }
th, td { border: 1px solid #30363d; padding: .55rem .7rem; text-align: left;
         vertical-align: top; font-size: .85rem; }
th { background: #161b22; color: #8b949e; position: sticky; top: 0; }
tr:hover td { background: #161b22; }
code { background: #161b22; padding: 2px 5px; border-radius: 4px; word-break: break-all; }
a { color: #58a6ff; word-break: break-all; }
.badge { display: inline-block; padding: 2px 8px; border-radius: 999px;
         font-size: .72rem; font-weight: 700; text-transform: uppercase; }
.critical { background: #3d1418; color: #f85149; }
.high { background: #3d1f1f; color: #ff7b72; }
.medium { background: #3d2f1f; color: #d29922; }
.low { background: #1f2d3d; color: #58a6ff; }
.info { background: #21262d; color: #8b949e; }
.valid { color: #3fb950; font-weight: 700; }
footer { color: #8b949e; margin-top: 1.5rem; font-size: .8rem; }
"""

_HTML_JS = """
const buttons = document.querySelectorAll('[data-filter]');
const rows = Array.from(document.querySelectorAll('tbody tr'));
const search = document.getElementById('search');
let active = 'all';
function apply() {
  const q = (search.value || '').toLowerCase();
  for (const row of rows) {
    const sev = row.dataset.severity;
    const text = row.innerText.toLowerCase();
    const okSev = active === 'all' || sev === active;
    const okText = !q || text.includes(q);
    row.style.display = (okSev && okText) ? '' : 'none';
  }
}
buttons.forEach(b => b.addEventListener('click', () => {
  active = b.dataset.filter;
  buttons.forEach(x => x.classList.toggle('active', x === b));
  apply();
}));
search.addEventListener('input', apply);
"""


def save_html(
    findings: List[dict],
    path: str,
    redact: bool = False,
    meta: Optional[dict] = None,
    show_context: bool = False,
) -> str:
    """Save findings as a self-contained, filterable HTML dashboard."""
    ordered = _sort_findings(findings)
    summary = _summary(ordered)
    target = html.escape(str((meta or {}).get("target", "")))

    cards = []
    cards.append(("Total", summary["total"], ""))
    for severity in _SEVERITY_ORDER:
        cards.append((severity, summary["by_severity"][severity], _SEVERITY_COLORS[severity]))
    cards.append(("Validated", summary["validated"], "#3fb950"))
    card_html = "".join(
        f'<div class="card"><div class="n" style="color:{color or "#c9d1d9"}">{count}</div>'
        f'<div class="l">{html.escape(label)}</div></div>'
        for label, count, color in cards
    )

    filter_buttons = '<button data-filter="all" class="active">All</button>' + "".join(
        f'<button data-filter="{severity}">{severity.capitalize()}</button>'
        for severity in _SEVERITY_ORDER
    )

    rows = []
    for index, f in enumerate(ordered, 1):
        value = _redact(f.get("value", ""), keep=6) if redact else f.get("value", "")[:160]
        context = ""
        if show_context and f.get("context"):
            context = f.get("context", "")
            if redact:
                context = _redact_in_context(context, f.get("value", ""))
        severity = f.get("severity", "info")
        validated = "<span class='valid'>YES</span>" if f.get("validated") is True else ""
        rotation = f.get("rotation_url", "")
        rotate = f"<a href='{html.escape(rotation)}'>rotate</a>" if rotation else ""
        rows.append(
            "<tr data-severity='{sev}'>"
            "<td>{i}</td>"
            "<td><span class='badge {sev}'>{sev}</span></td>"
            "<td><code>{rule}</code></td>"
            "<td>{cat}</td>"
            "<td><code>{val}</code>{ctx}</td>"
            "<td><a href='{url}'>{url_short}</a></td>"
            "<td>{line}</td>"
            "<td>{conf:.0f}%</td>"
            "<td>{validated}</td>"
            "<td>{rotate}</td>"
            "</tr>".format(
                sev=html.escape(severity),
                i=index,
                rule=html.escape(f.get("type", "")),
                cat=html.escape(f.get("category", "")),
                val=html.escape(value),
                ctx=(
                    f"<br><small class='sub'>{html.escape(context[:300])}</small>"
                    if context else ""
                ),
                url=html.escape(f.get("url", "")),
                url_short=html.escape(f.get("url", "")[:90]),
                line=f.get("line") or "",
                conf=float(f.get("confidence", 0)) * 100,
                validated=validated,
                rotate=rotate,
            )
        )

    html_content = (
        "<!DOCTYPE html><html lang='en'><head><meta charset='UTF-8'>"
        "<meta name='viewport' content='width=device-width, initial-scale=1'>"
        "<title>Super Secref Finder Report</title>"
        f"<style>{_HTML_CSS}</style></head><body>"
        "<h1>Super Secref Finder</h1>"
        f"<div class='sub'>v{__version__} &middot; {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}"
        f" &middot; target: {target}</div>"
        f"<div class='cards'>{card_html}</div>"
        f"<div class='toolbar'>{filter_buttons}"
        "<input id='search' type='search' placeholder='Search rule, value, URL...'></div>"
        "<table><thead><tr><th>#</th><th>Severity</th><th>Rule</th><th>Category</th>"
        "<th>Value / evidence</th><th>URL</th><th>Line</th><th>Confidence</th>"
        f"<th>Validated</th><th>Rotate</th></tr></thead><tbody>{''.join(rows)}</tbody></table>"
        "<footer>Generated by Super Secref Finder. Treat this report as sensitive: "
        "it can contain live credentials.</footer>"
        f"<script>{_HTML_JS}</script></body></html>"
    )

    with open(path, "w", encoding="utf-8") as fp:
        fp.write(html_content)
    return path


def save_sarif(
    findings: List[dict],
    path: str,
    redact: bool = False,
    meta: Optional[dict] = None,
    show_context: bool = False,
) -> str:
    """Save findings as SARIF 2.1.0 for GitHub code scanning / CI."""
    ordered = _sort_findings(findings)
    rules: Dict[str, dict] = {}
    rule_index: Dict[str, int] = {}
    results = []

    for f in ordered:
        rule_id = f.get("type", "unknown")
        severity = f.get("severity", "info")
        if rule_id not in rules:
            rule_index[rule_id] = len(rules)
            rules[rule_id] = {
                "id": rule_id,
                "name": rule_id,
                "shortDescription": {"text": f.get("description") or f"Pattern: {rule_id}"},
                "fullDescription": {"text": f.get("description") or f"Pattern: {rule_id}"},
                "defaultConfiguration": {"level": _SARIF_LEVEL.get(severity, "warning")},
                "properties": {
                    "security-severity": _SECURITY_SEVERITY.get(severity, "0.0"),
                    "tags": [f.get("category", "secret")],
                },
            }

        fingerprint = hashlib.sha256(
            f"{rule_id}:{f.get('value', '')}".encode("utf-8")
        ).hexdigest()[:32]

        results.append({
            "ruleId": rule_id,
            "ruleIndex": rule_index[rule_id],
            "level": _SARIF_LEVEL.get(severity, "warning"),
            "message": {
                "text": (
                    f"{f.get('description') or rule_id} detected"
                    + (f" (value: {_redact(f.get('value', ''), 4)})" if redact else "")
                )
            },
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": f.get("url", "")},
                    "region": {
                        "startLine": max(1, int(f.get("line") or 1)),
                        "startColumn": max(1, int(f.get("column") or 1)),
                    },
                }
            }],
            "partialFingerprints": {"secretHash/v1": fingerprint},
            "properties": {
                "severity": severity,
                "category": f.get("category", "unknown"),
                "confidence": f.get("confidence", 0),
                "validated": f.get("validated"),
                "source": f.get("source"),
                "commit": f.get("commit"),
                "author": f.get("author"),
                "rotationUrl": f.get("rotation_url"),
            },
        })

    sarif = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "SuperSecrefFinder",
                    "informationUri": "https://github.com/LifeJiggy/Super-Secref-Finder",
                    "version": __version__,
                    "rules": list(rules.values()),
                }
            },
            "results": results,
            "properties": {"meta": meta or {}},
        }],
    }

    with open(path, "w", encoding="utf-8") as fp:
        json.dump(sarif, fp, indent=2, ensure_ascii=False)
    return path


def save_junit(
    findings: List[dict],
    path: str,
    redact: bool = False,
    meta: Optional[dict] = None,
    show_context: bool = False,
) -> str:
    """Save findings as JUnit XML for CI test reporters."""
    ordered = _sort_findings(findings)
    root = ET.Element("testsuites")
    suite = ET.SubElement(
        root,
        "testsuite",
        name="Super Secref Finder",
        tests=str(len(ordered)),
        failures=str(len(ordered)),
        errors="0",
        skipped="0",
    )
    target = str((meta or {}).get("target", ""))
    if target:
        suite.set("target", target)

    for f in ordered:
        value = _redact(f.get("value", "")) if redact else str(f.get("value", ""))
        case = ET.SubElement(
            suite,
            "testcase",
            classname=f"secref.{f.get('severity', 'info')}",
            name=str(f.get("type", "unknown")),
            file=str(f.get("url", "")),
            line=str(max(1, int(f.get("line") or 1))),
        )
        failure = ET.SubElement(
            case,
            "failure",
            message=f"{f.get('severity', 'info').upper()}: {f.get('description', '')}",
            type=str(f.get("type", "unknown")),
        )
        failure.text = (
            f"value: {value}\n"
            f"url: {f.get('url', '')}\n"
            f"line: {f.get('line') or ''} column: {f.get('column') or ''}\n"
            f"confidence: {float(f.get('confidence', 0)) * 100:.0f}%\n"
            f"validated: {f.get('validated')}\n"
            f"rotation: {f.get('rotation_url') or ''}\n"
        )

    if hasattr(ET, "indent"):
        ET.indent(root, space="  ")
    tree = ET.ElementTree(root)
    tree.write(path, encoding="utf-8", xml_declaration=True)
    return path


SAVE_FNS = {
    "json": save_json,
    "jsonl": save_jsonl,
    "csv": save_csv,
    "md": save_markdown,
    "markdown": save_markdown,
    "html": save_html,
    "sarif": save_sarif,
    "junit": save_junit,
}


def save_findings(
    findings: List[dict],
    output_dir: str,
    formats: List[str],
    redact: bool = False,
    meta: Optional[dict] = None,
    show_context: bool = False,
) -> List[str]:
    """Save findings in all requested formats. Returns the written paths."""
    os.makedirs(output_dir, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    saved: List[str] = []
    seen_formats = set()

    for fmt in formats:
        fmt = (fmt or "").lower()
        if fmt in seen_formats:
            continue
        seen_formats.add(fmt)
        fn = SAVE_FNS.get(fmt)
        if not fn:
            continue
        ext = "md" if fmt == "markdown" else fmt
        if fmt == "junit":
            ext = "xml"
        path = os.path.join(output_dir, f"findings_{timestamp}.{ext}")
        fn(findings, path, redact, meta, show_context)
        saved.append(path)

    return saved
