"""Import Semgrep-compatible YAML rule packs.

Semgrep rules are usually AST-aware. This adapter intentionally imports the
practical regex subset that covers most secret and configuration rules:

* ``pattern-regex``
* ``pattern-either`` containing ``pattern-regex`` alternatives
* ``pattern-not-regex``
* ``paths.include`` / ``paths.exclude``
* ``metadata.category`` and ``metadata.tags``
* ``fix`` suggestions

Unsupported AST predicates (plain ``pattern``, ``pattern-inside``,
``metavariable-regex``, taint mode, ...) are skipped with a warning rather than
producing misleading matches. The goal is safe interoperability, not a full
Semgrep engine.
"""

from __future__ import annotations

import logging
import os
import re
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

import yaml

from .rules import CATEGORIES, SEVERITIES, Rule

logger = logging.getLogger("secref.semgrep")

_SEMGREP_SEVERITY = {
    "ERROR": "high",
    "WARNING": "medium",
    "INFO": "low",
    "CRITICAL": "critical",
    "HIGH": "high",
    "MEDIUM": "medium",
    "LOW": "low",
}


def _string_list(value: Any) -> Tuple[str, ...]:
    if value is None:
        return ()
    if isinstance(value, str):
        return (value,)
    if isinstance(value, (list, tuple, set)):
        return tuple(str(item) for item in value if str(item).strip())
    return ()


def _severity(entry: Dict[str, Any], metadata: Dict[str, Any]) -> str:
    for candidate in (metadata.get("severity"), entry.get("severity")):
        if candidate is None:
            continue
        text = str(candidate).strip()
        if text.lower() in SEVERITIES:
            return text.lower()
        mapped = _SEMGREP_SEVERITY.get(text.upper())
        if mapped:
            return mapped
    return "medium"


def _category(rule_id: str, metadata: Dict[str, Any], tags: Tuple[str, ...]) -> str:
    explicit = str(metadata.get("category") or "").strip().lower()
    if explicit in CATEGORIES:
        return explicit
    lowered = {tag.lower() for tag in tags}
    if lowered & {"aws", "gcp", "azure", "cloud", "kubernetes", "k8s"}:
        return "cloud"
    if lowered & {"private-key", "private_key", "ssh", "certificate"}:
        return "credential"
    if "token" in rule_id or "key" in rule_id or "secret" in rule_id:
        return "token"
    return "secret"


def _metadata(entry: Dict[str, Any]) -> Dict[str, Any]:
    value = entry.get("metadata")
    return value if isinstance(value, dict) else {}


def _regex_from_alternative(item: Any, rule_id: str) -> Optional[str]:
    if isinstance(item, str):
        logger.warning(
            "Skipping Semgrep AST pattern in %s; use pattern-regex for regex rules", rule_id
        )
        return None
    if not isinstance(item, dict):
        return None
    if isinstance(item.get("pattern-regex"), str):
        return item["pattern-regex"]
    if "patterns" in item:
        collected, _ = _collect_patterns(item.get("patterns"), rule_id, allow_multiple=False)
        return collected[0] if collected else None
    if "pattern-either" in item:
        alternatives = [
            regex
            for regex in (
                _regex_from_alternative(alt, rule_id)
                for alt in item.get("pattern-either") or []
            )
            if regex
        ]
        if alternatives:
            return _combine(alternatives, any_of=True)
    return None


def _collect_patterns(
    patterns: Any,
    rule_id: str,
    allow_multiple: bool,
) -> Tuple[List[str], List[str]]:
    positives: List[str] = []
    negatives: List[str] = []
    if not isinstance(patterns, list):
        return positives, negatives

    for item in patterns:
        if not isinstance(item, dict):
            logger.warning("Skipping non-mapping Semgrep pattern in %s", rule_id)
            continue
        if isinstance(item.get("pattern-regex"), str):
            positives.append(item["pattern-regex"])
        elif "pattern-either" in item:
            alternatives = [
                regex
                for regex in (
                    _regex_from_alternative(alt, rule_id)
                    for alt in item.get("pattern-either") or []
                )
                if regex
            ]
            if alternatives:
                positives.append(_combine(alternatives, any_of=True))
        elif isinstance(item.get("pattern-not-regex"), str):
            negatives.append(item["pattern-not-regex"])
        elif "patterns" in item:
            nested_pos, nested_neg = _collect_patterns(
                item.get("patterns"), rule_id, allow_multiple=allow_multiple
            )
            positives.extend(nested_pos)
            negatives.extend(nested_neg)
        else:
            logger.warning(
                "Skipping unsupported Semgrep predicate in %s: %s",
                rule_id,
                ", ".join(sorted(str(key) for key in item)),
            )

    if len(positives) > 1 and not allow_multiple:
        logger.warning(
            "Skipping Semgrep rule %s: multiple positive patterns require AND "
            "semantics; combine them with pattern-either or one pattern-regex",
            rule_id,
        )
        return [], negatives
    return positives, negatives


def _combine(patterns: Sequence[str], any_of: bool) -> str:
    if len(patterns) == 1:
        return patterns[0]
    operator = "|" if any_of else ""
    if any_of:
        return "(?:" + ")|(?:".join(patterns) + ")"
    return operator.join(patterns)


def _extract_regex(entry: Dict[str, Any], rule_id: str) -> Optional[str]:
    if isinstance(entry.get("pattern-regex"), str):
        return entry["pattern-regex"]

    if "pattern-either" in entry:
        alternatives = [
            regex
            for regex in (
                _regex_from_alternative(alt, rule_id)
                for alt in entry.get("pattern-either") or []
            )
            if regex
        ]
        if alternatives:
            return _combine(alternatives, any_of=True)

    if "patterns" in entry:
        positives, _ = _collect_patterns(entry.get("patterns"), rule_id, allow_multiple=False)
        if positives:
            return positives[0]

    unsupported = [key for key in entry if key in {
        "pattern", "pattern-inside", "pattern-not-inside", "metavariable-pattern",
        "metavariable-regex", "metavariable-comparison", "taint",
    }]
    if unsupported:
        logger.warning(
            "Skipping Semgrep rule %s: unsupported predicate(s) %s",
            rule_id,
            ", ".join(unsupported),
        )
    return None


def _extract_negative(entry: Dict[str, Any], rule_id: str) -> Optional[str]:
    negatives: List[str] = []
    if isinstance(entry.get("pattern-not-regex"), str):
        negatives.append(entry["pattern-not-regex"])
    if "patterns" in entry:
        _, found = _collect_patterns(entry.get("patterns"), rule_id, allow_multiple=True)
        negatives.extend(found)
    if not negatives:
        return None
    return _combine(negatives, any_of=True)


def _paths(entry: Dict[str, Any]) -> Tuple[Tuple[str, ...], Tuple[str, ...]]:
    paths = entry.get("paths")
    if not isinstance(paths, dict):
        return (), ()
    return _string_list(paths.get("include")), _string_list(paths.get("exclude"))


def _coerce_int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _coerce_float(value: Any, default: float = 0.0) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def load_semgrep_rules(path: str) -> List[Rule]:
    """Load the supported subset of a Semgrep YAML configuration."""
    if not os.path.isfile(path):
        logger.warning("Semgrep config not found: %s", path)
        return []

    try:
        with open(path, "r", encoding="utf-8") as handle:
            data = yaml.safe_load(handle) or {}
    except (OSError, ValueError, yaml.YAMLError) as exc:
        logger.warning("Could not read Semgrep config %s: %s", path, exc)
        return []

    raw_rules: Iterable[Any]
    if isinstance(data, dict) and isinstance(data.get("rules"), list):
        raw_rules = data["rules"]
    elif isinstance(data, list):
        raw_rules = data
    elif isinstance(data, dict):
        raw_rules = [data]
    else:
        raw_rules = []

    rules: List[Rule] = []
    for entry in raw_rules:
        if not isinstance(entry, dict):
            continue
        rule_id = str(entry.get("id") or "").strip()
        if not rule_id:
            continue

        metadata = _metadata(entry)
        pattern = _extract_regex(entry, rule_id)
        if not pattern:
            continue
        try:
            compiled = re.compile(pattern)
        except re.error as exc:
            logger.warning("Skipping Semgrep rule %s: invalid regex (%s)", rule_id, exc)
            continue

        tags = _string_list(metadata.get("tags")) + _string_list(metadata.get("technology"))
        path_include, path_exclude = _paths(entry)
        default_group = 1 if compiled.groups == 1 else 0
        secret_group = _coerce_int(metadata.get("secret_group"), default_group)
        if secret_group > compiled.groups:
            secret_group = 0

        rules.append(
            Rule(
                id=rule_id,
                pattern=pattern,
                category=_category(rule_id, metadata, tags),
                severity=_severity(entry, metadata),
                description=str(entry.get("message") or metadata.get("description") or f"Semgrep rule: {rule_id}"),
                secret_group=secret_group,
                entropy_min=_coerce_float(metadata.get("entropy", metadata.get("entropy_min", 0.0))),
                tags=tags + ("semgrep",),
                path_include=path_include,
                path_exclude=path_exclude,
                negative_pattern=_extract_negative(entry, rule_id),
                fix=str(entry["fix"]) if isinstance(entry.get("fix"), str) else None,
            )
        )

    logger.info("Imported %d Semgrep rule(s) from %s", len(rules), path)
    return rules


__all__ = ["load_semgrep_rules"]
