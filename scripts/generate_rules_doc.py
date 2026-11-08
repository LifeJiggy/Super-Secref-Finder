"""Generate RULES.md from the canonical rule registry.

Usage:
    python scripts/generate_rules_doc.py
"""

from __future__ import annotations

import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.patterns import get_rules  # noqa: E402
from src.rules import BUILTIN_RULES  # noqa: E402

OUT = ROOT / "RULES.md"


def main() -> int:
    default_ids = {rule.id for rule in get_rules()}
    severity = Counter(rule.severity for rule in BUILTIN_RULES)
    category = Counter(rule.category for rule in BUILTIN_RULES)

    lines = [
        "# Detection Rules",
        "",
        "> Generated from `src/rules.py` by `python scripts/generate_rules_doc.py`.",
        f"> **{len(BUILTIN_RULES)} built-in rules** - **{len(default_ids)} enabled by default**.",
        "",
        "Default scans enable real secret/token/credential/cloud rules plus",
        "high-value exposure checks. Code smells, PII, and endpoint discovery are",
        "opt-in so the first run stays readable.",
        "",
        "| Opt-in | Flag | Count |",
        "|---|---|---:|",
        f"| Code smells | `--include-noise` | {sum(1 for r in BUILTIN_RULES if r.noise)} |",
        f"| PII | `--include-pii` | {sum(1 for r in BUILTIN_RULES if r.pii)} |",
        f"| Endpoints | `--include-endpoints` | {sum(1 for r in BUILTIN_RULES if r.category == 'endpoint')} |",
        "",
        "## Severity distribution",
        "",
        "| Severity | Rules |",
        "|---|---:|",
    ]
    for name in ("critical", "high", "medium", "low", "info"):
        lines.append(f"| {name} | {severity.get(name, 0)} |")

    lines += [
        "",
        "## Category distribution",
        "",
        "| Category | Rules |",
        "|---|---:|",
    ]
    for name, count in sorted(category.items(), key=lambda item: (-item[1], item[0])):
        lines.append(f"| {name} | {count} |")

    lines += [
        "",
        "## All rules",
        "",
        "| Rule | Severity | Category | Default | Description |",
        "|---|---|---|---|---|",
    ]
    for rule in sorted(BUILTIN_RULES, key=lambda r: (r.category, r.id)):
        if rule.id in default_ids:
            state = "yes"
        elif rule.noise:
            state = "noise"
        elif rule.pii:
            state = "pii"
        elif rule.category == "endpoint":
            state = "endpoint"
        else:
            state = "no"
        description = rule.description.replace("|", "\\|")
        lines.append(
            f"| `{rule.id}` | {rule.severity} | {rule.category} | {state} | {description} |"
        )

    lines += [
        "",
        "## Add a rule",
        "",
        "1. Add a `Rule(...)` entry to `src/rules.py`.",
        "2. Capture the secret value with a group and set `secret_group`.",
        "3. Set `entropy_min` only when the value itself benefits from it.",
        "4. Mark code smells with `noise=True`, PII with `pii=True`, and use",
        "   `category=\"endpoint\"` for endpoint discovery.",
        "5. Run `python scripts/generate_rules_doc.py` and `pytest -q`.",
        "",
    ]

    OUT.write_text("\n".join(lines), encoding="utf-8")
    print(f"Wrote {OUT} with {len(BUILTIN_RULES)} rules")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
