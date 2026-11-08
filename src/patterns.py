"""Pattern loading — compatibility layer over the v8 rule registry.

The canonical rule definitions live in :mod:`src.rules`. This module keeps the
old ``SENSITIVE_PATTERNS`` dict API working while exposing the richer
``get_rules()`` API used by the scanner.
"""

from __future__ import annotations

import json
import os
import re
from typing import Dict, Iterable, List, Optional

import yaml

from .rules import (
    BUILTIN_RULES,
    SEVERITY_RANK,
    SEVERITIES,
    Rule,
    builtin_patterns,
    compile_rules,
    all_rule_ids,
)

# Backward-compatible views -------------------------------------------------
SENSITIVE_PATTERNS: Dict[str, str] = builtin_patterns(include_noise=False, include_pii=False)
NOISE_PATTERNS: Dict[str, str] = {
    r.id: r.pattern for r in BUILTIN_RULES if r.noise
}
PII_PATTERNS: Dict[str, str] = {
    r.id: r.pattern for r in BUILTIN_RULES if r.pii
}


def _coerce_rule(name: str, info) -> Optional[Rule]:
    """Build a Rule from a custom-pattern YAML/JSON entry."""
    if isinstance(info, dict):
        regex = info.get("regex") or info.get("pattern") or ""
        description = info.get("description", "")
        severity = str(info.get("severity", "medium")).lower()
        category = str(info.get("category", "custom")).lower()
        group = int(info.get("group", info.get("secret_group", 0)) or 0)
        entropy = float(info.get("entropy", info.get("entropy_min", 0.0)) or 0.0)
        noise = bool(info.get("noise", False))
        pii = bool(info.get("pii", False))
    else:
        regex = str(info)
        description = ""
        severity = "medium"
        category = "custom"
        group = 0
        entropy = 0.0
        noise = False
        pii = False

    if not regex:
        return None

    if severity not in SEVERITIES:
        severity = "medium"
    try:
        compiled = re.compile(regex)
    except re.error:
        return None
    if group > compiled.groups:
        group = 0

    return Rule(
        id=name,
        pattern=regex,
        category=category if category in {
            "secret", "cloud", "credential", "token", "exposure", "endpoint",
            "pii", "supply-chain", "code-risk", "config", "custom",
        } else "custom",
        severity=severity,
        description=description or f"Custom pattern: {name}",
        secret_group=group,
        entropy_min=entropy,
        noise=noise,
        pii=pii,
        tags=("custom",),
    )


def load_custom_rules(file_path: str) -> List[Rule]:
    """Load custom rules from a YAML or JSON file."""
    if not os.path.isfile(file_path):
        return []

    try:
        with open(file_path, "r", encoding="utf-8") as f:
            if file_path.lower().endswith((".yaml", ".yml")):
                data = yaml.safe_load(f) or {}
            else:
                data = json.load(f) or {}
    except (OSError, ValueError, yaml.YAMLError):
        return []

    rules: List[Rule] = []
    for name, info in (data.get("patterns") or {}).items():
        rule = _coerce_rule(str(name), info)
        if rule is not None:
            rules.append(rule)
    return rules


def load_custom_patterns(file_path: str) -> Dict[str, str]:
    """Legacy helper: return ``id -> regex`` for a custom rules file."""
    return {rule.id: rule.pattern for rule in load_custom_rules(file_path)}


def get_rules(
    custom_files: Optional[List[str]] = None,
    include_noise: bool = False,
    include_pii: bool = False,
    include_types: Optional[Iterable[str]] = None,
    exclude_types: Optional[Iterable[str]] = None,
    min_severity: Optional[str] = None,
    include_endpoints: bool = False,
) -> List[Rule]:
    """Return the compiled rule set for a scan.

    Args:
        custom_files: YAML/JSON rule files.
        include_noise: include code-smell rules (off by default).
        include_pii: include PII rules (off by default).
        include_types: only these rule IDs (custom files still filtered).
        exclude_types: drop these rule IDs.
        min_severity: minimum severity name.
        include_endpoints: include endpoint-discovery rules (off by default).
    """
    rules: List[Rule] = []
    explicit = set(include_types or [])
    for rule in BUILTIN_RULES:
        if rule.noise and not include_noise and rule.id not in explicit:
            continue
        if rule.pii and not include_pii and rule.id not in explicit:
            continue
        if (
            rule.category == "endpoint"
            and not (include_endpoints or include_noise)
            and rule.id not in explicit
        ):
            continue
        rules.append(rule)

    for path in custom_files or []:
        rules.extend(load_custom_rules(path))

    include_set = set(include_types) if include_types else None
    exclude_set = set(exclude_types) if exclude_types else set()

    if include_set is not None:
        rules = [r for r in rules if r.id in include_set]
    if exclude_set:
        rules = [r for r in rules if r.id not in exclude_set]

    if min_severity:
        floor = SEVERITY_RANK.get(min_severity.lower())
        if floor is not None:
            rules = [r for r in rules if SEVERITY_RANK.get(r.severity, 0) >= floor]

    # Deduplicate by id (custom rule wins) and compile once.
    deduped: Dict[str, Rule] = {}
    for rule in rules:
        deduped[rule.id] = rule
    return compile_rules(deduped.values())


def get_all_patterns(
    custom_files: Optional[List[str]] = None,
    include_noise: bool = False,
    include_pii: bool = False,
    include_endpoints: bool = False,
) -> Dict[str, str]:
    """Return merged ``id -> regex`` map (built-ins + custom files)."""
    return {
        rule.id: rule.pattern
        for rule in get_rules(
            custom_files,
            include_noise,
            include_pii,
            include_endpoints=include_endpoints,
        )
    }


__all__ = [
    "SENSITIVE_PATTERNS",
    "NOISE_PATTERNS",
    "PII_PATTERNS",
    "Rule",
    "get_rules",
    "get_all_patterns",
    "load_custom_rules",
    "load_custom_patterns",
    "all_rule_ids",
]
