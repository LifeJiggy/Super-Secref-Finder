"""Plugin system for community-contributed scanners.

Plugin files can use either import style::

    from plugins import register_plugin          # legacy
    from src.plugins import register_plugin      # package-relative

The loader aliases ``plugins`` to this module before executing a plugin so both
forms register into the same registry.
"""

from __future__ import annotations

import importlib.util
import logging
import os
import sys
from typing import Callable, Dict, List

logger = logging.getLogger("secref.plugins")

PLUGIN_API_VERSION = 1

# Built-in plugins that are only useful for endpoint/attack-surface discovery.
OPTIONAL_PLUGINS = {"api_discovery", "hardcoded_ip"}

# Plugin registry
_PLUGINS: Dict[str, Callable] = {}


def register_plugin(name: str):
    """Decorator to register a plugin function."""
    def decorator(fn):
        _PLUGINS[name] = fn
        logger.debug(f"Registered plugin: {name}")
        return fn
    return decorator


def registered_plugins() -> Dict[str, Callable]:
    """Return a copy of the plugin registry (useful for tests/inspection)."""
    return dict(_PLUGINS)


def discover_plugins(plugin_dir: str) -> List[str]:
    """Discover and load all ``.py`` plugin files in a directory."""
    loaded: List[str] = []
    if not os.path.isdir(plugin_dir):
        logger.warning(f"Plugin directory not found: {plugin_dir}")
        return loaded

    # Make ``from plugins import register_plugin`` resolve to *this* module.
    sys.modules["plugins"] = sys.modules[__name__]

    for filename in sorted(os.listdir(plugin_dir)):
        if not filename.endswith(".py") or filename.startswith("_"):
            continue
        filepath = os.path.join(plugin_dir, filename)
        module_name = f"secref_plugin_{filename[:-3]}"
        try:
            spec = importlib.util.spec_from_file_location(module_name, filepath)
            if spec is None or spec.loader is None:
                continue
            module = importlib.util.module_from_spec(spec)
            sys.modules[module_name] = module
            spec.loader.exec_module(module)
            loaded.append(filename)
            logger.info(f"Loaded plugin: {filename}")
        except Exception as exc:  # pragma: no cover - user code
            logger.warning(f"Failed to load plugin {filename}: {exc}")

    return loaded


def run_plugins(
    url: str,
    text: str,
    findings: List[dict],
    include_optional: bool = False,
) -> List[dict]:
    """Run all registered plugins and merge their findings.

    ``include_optional`` enables attack-surface plugins such as API discovery.
    """
    extra: List[dict] = []
    for name, fn in list(_PLUGINS.items()):
        if name in OPTIONAL_PLUGINS and not include_optional:
            continue
        try:
            result = fn(url=url, text=text, findings=findings)
            if result and isinstance(result, list):
                extra.extend(item for item in result if isinstance(item, dict))
        except Exception as exc:  # pragma: no cover - user code
            logger.warning(f"Plugin {name} failed: {exc}")

    return extra


# ---------------------------------------------------------------------------
# Built-in plugins
# ---------------------------------------------------------------------------

@register_plugin("api_discovery")
def api_endpoint_plugin(url: str, text: str, findings: List[dict]) -> List[dict]:
    """Discover API endpoints, GraphQL, and OpenAPI specs."""
    import re

    results = []
    patterns = [
        (r"https?://[^\"'\s<>]+/api/[^\"'\s<>]+", "api_url"),
        (r"https?://[^\"'\s<>]+/graphql", "graphql_endpoint"),
        (r"https?://[^\"'\s<>]+/(?:swagger|api-docs|openapi|redoc)(?:\.json|\.yaml)?", "swagger_endpoint"),
        (r"https?://[^\"'\s<>]+/v\d+/[^\"'\s<>]+", "versioned_api"),
    ]
    for pattern, ptype in patterns:
        for match in re.finditer(pattern, text, re.IGNORECASE):
            value = match.group(0)
            if not any(f.get("value") == value for f in findings + results):
                results.append({
                    "type": ptype,
                    "value": value,
                    "url": url,
                    "confidence": 0.7,
                    "severity": "low",
                    "category": "endpoint",
                    "start": match.start(),
                    "end": match.end(),
                })
    return results


@register_plugin("firebase_detection")
def firebase_plugin(url: str, text: str, findings: List[dict]) -> List[dict]:
    """Detect Firebase configuration."""
    import re

    results = []
    patterns = [
        (r"firebaseio\.com", "firebase_url"),
        (r"firebase\.js", "firebase_sdk"),
        (r"firebaseConfig\s*=\s*\{[^}]+\}", "firebase_config"),
        (r"firebase\.initializeApp\s*\(\s*\{[^}]+\}", "firebase_init"),
    ]
    for pattern, ptype in patterns:
        for match in re.finditer(pattern, text):
            value = match.group(0)
            if not any(f.get("value") == value for f in findings + results):
                results.append({
                    "type": ptype,
                    "value": value,
                    "url": url,
                    "confidence": 0.8,
                    "severity": "medium",
                    "category": "exposure",
                    "start": match.start(),
                    "end": match.end(),
                })
    return results


@register_plugin("s3_bucket_enum")
def s3_bucket_enum_plugin(url: str, text: str, findings: List[dict]) -> List[dict]:
    """Enumerate S3 bucket references."""
    import re

    results = []
    bucket_pattern = r"(?:https?://)?([a-zA-Z0-9.\-]{3,63})\.s3(?:-[a-z\-]+)?\.amazonaws\.com"
    for match in re.finditer(bucket_pattern, text):
        value = match.group(0)
        if not any(f.get("value") == value for f in findings + results):
            results.append({
                "type": "s3_bucket_reference",
                "value": value,
                "url": url,
                "confidence": 0.85,
                "severity": "low",
                "category": "exposure",
                "start": match.start(),
                "end": match.end(),
            })
    return results


@register_plugin("hardcoded_ip")
def hardcoded_ip_plugin(url: str, text: str, findings: List[dict]) -> List[dict]:
    """Detect hardcoded private IP addresses."""
    import re

    results = []
    ip_pattern = r"(?:['\"])?(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(?:['\"])?"
    private_ranges = [
        r"^10\.",
        r"^172\.(?:1[6-9]|2\d|3[01])\.",
        r"^192\.168\.",
        r"^127\.",
        r"^0\.",
    ]
    for match in re.finditer(ip_pattern, text):
        ip = match.group(1)
        if any(re.match(pattern, ip) for pattern in private_ranges):
            value = match.group(0)
            if not any(f.get("value") == value for f in findings + results):
                results.append({
                    "type": "hardcoded_private_ip",
                    "value": value,
                    "url": url,
                    "confidence": 0.6,
                    "severity": "info",
                    "category": "exposure",
                    "start": match.start(),
                    "end": match.end(),
                })
    return results
