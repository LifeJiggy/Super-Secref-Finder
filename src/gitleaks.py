"""Import gitleaks TOML rule packs.

Gitleaks has a large community-maintained rule format.  This adapter converts
the common ``[[rules]]`` subset into Super Secref Finder :class:`Rule` objects
so teams can reuse an existing pack instead of maintaining two rule sets.

Unsupported gitleaks features (path allowlists, regex targets, custom
validators) are ignored; invalid regular expressions are skipped with a log
message rather than failing the whole scan.
"""

from __future__ import annotations

import logging
import os
import re
from typing import Any, Dict, List, Optional, Tuple

from .rules import SEVERITIES, Rule

logger = logging.getLogger("secref.gitleaks")

_CLOUD_TAGS = {"aws", "gcp", "azure", "cloud", "digitalocean", "cloudflare"}
_CREDENTIAL_TAGS = {"private-key", "private_key", "certificate", "ssh"}


def _load_toml(path: str) -> Dict[str, Any]:
    try:
        import tomllib  # type: ignore[import-not-found]
    except ImportError:  # Python < 3.11
        try:
            import tomli as tomllib  # type: ignore[no-redef]
        except ImportError as exc:  # pragma: no cover - dependency is declared
            raise RuntimeError(
                "TOML support requires Python 3.11+ or the 'tomli' package"
            ) from exc
    with open(path, "rb") as fp:
        return tomllib.load(fp)


def _severity_from_tags(tags: Tuple[str, ...]) -> str:
    for tag in tags:
        candidate = tag.lower()
        if candidate in SEVERITIES:
            return candidate
    return "high"


def _category_from_rule(rule_id: str, tags: Tuple[str, ...]) -> str:
    lowered_tags = {tag.lower() for tag in tags}
    lowered_id = rule_id.lower()
    if lowered_tags & _CLOUD_TAGS:
        return "cloud"
    if lowered_tags & _CREDENTIAL_TAGS or "private" in lowered_id:
        return "credential"
    if "token" in lowered_id or "key" in lowered_id or "secret" in lowered_id:
        return "token"
    return "secret"


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


def load_gitleaks_rules(path: str) -> List[Rule]:
    """Load the supported subset of a gitleaks ``.toml`` config."""
    if not os.path.isfile(path):
        logger.warning(f"Gitleaks config not found: {path}")
        return []
    try:
        data = _load_toml(path)
    except (OSError, ValueError, RuntimeError) as exc:
        logger.warning(f"Could not read gitleaks config {path}: {exc}")
        return []

    rules: List[Rule] = []
    for entry in data.get("rules") or []:
        if not isinstance(entry, dict):
            continue
        rule_id = str(entry.get("id") or "").strip()
        pattern = entry.get("regex") or entry.get("pattern")
        if not rule_id or not isinstance(pattern, str) or not pattern:
            continue
        tags = tuple(str(tag) for tag in (entry.get("tags") or ()))
        group = _coerce_int(entry.get("secretGroup", entry.get("secret_group", 0)))
        try:
            compiled = re.compile(pattern)
        except re.error as exc:
            logger.warning(f"Skipping gitleaks rule {rule_id}: invalid regex ({exc})")
            continue
        if group > compiled.groups:
            group = 0
        rules.append(
            Rule(
                id=rule_id,
                pattern=pattern,
                category=_category_from_rule(rule_id, tags),
                severity=_severity_from_tags(tags),
                description=str(entry.get("description") or f"Gitleaks rule: {rule_id}"),
                secret_group=group,
                entropy_min=_coerce_float(entry.get("entropy", 0.0)),
                tags=tags + ("gitleaks",),
            )
        )

    logger.info(f"Imported {len(rules)} gitleaks rule(s) from {path}")
    return rules


__all__ = ["load_gitleaks_rules"]
