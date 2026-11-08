"""Rule-aware validation — placeholders, checksums, entropy, and context.

v8 replaces the old ad-hoc ``if pattern_name == ...`` chain with validation
driven by :class:`src.rules.Rule` metadata. The legacy ``validate_pattern``
API is preserved for third-party code.
"""

from __future__ import annotations

import base64
import binascii
import json
import re
from typing import Optional

from .entropy import shannon_entropy
from .rules import Rule, all_rule_ids

# Values that are almost always documentation/placeholder material.
_PLACEHOLDER_EXACT = {
    "password", "passwd", "pwd", "secret", "token", "apikey", "api_key",
    "api-key", "access_token", "client_secret", "changeme", "change_me",
    "change-me", "example", "sample", "dummy", "test", "testing",
    "placeholder", "insert_key_here", "insert-key-here", "your_api_key",
    "your-api-key", "your_token", "your-token", "your_password",
    "your-password", "your_secret", "your-secret", "null", "none",
    "undefined", "true", "false", "localhost", "xxxxxxxx", "xxxxxxxxxxxxxxxx",
    "00000000-0000-0000-0000-000000000000",
    "akiaiosfodnn7example", "wjalrxutnfemi/k7mdeng/bpxrficyexamplekey",
}

_PLACEHOLDER_RE = re.compile(
    r"(?:"
    r"^[xX*0.\-_\s]{4,}$"
    r"|^(?:your|my|the)[_-]?(?:api|secret|token|key|pass|auth)"
    r"|(?:example|sample|dummy|placeholder|changeme|change[_-]?me|xxxx+)"
    r"|<[^>]{1,40}>|\{\{[^}]{1,40}\}\}|\$\{[^}]{1,40}\}|%[A-Za-z_]{1,20}%"
    r"|^\*{3,}$"
    r")",
    re.IGNORECASE,
)

_NON_SECRET_RE = re.compile(
    r"(?:"
    r"^(?:https?|wss?|file)://"
    r"|^(?:process\.env|import\.meta|window\.|globalThis\.|localStorage|sessionStorage)"
    r"|^[./~][^\s]*$"
    r"|^\d+$"
    r")"
)

_IMAGE_OR_ASSET_EXT_RE = re.compile(
    r"\.(?:png|jpe?g|gif|svg|webp|avif|ico|bmp|css|js|mjs|map|woff2?|ttf|eot|mp4|webm|pdf)$",
    re.IGNORECASE,
)


def _is_placeholder(value: str) -> bool:
    """Return True for obvious documentation/example values."""
    cleaned = value.strip().strip("'\"")
    low = cleaned.lower()
    if not cleaned or len(cleaned) < 4:
        return True
    if low in _PLACEHOLDER_EXACT:
        return True
    if _PLACEHOLDER_RE.search(cleaned):
        return True
    # Single character repeated (aaaa..., 1111...)
    if len(set(low)) == 1 and len(low) >= 6:
        return True
    return False


def _looks_like_non_secret(value: str) -> bool:
    """Reject values that are identifiers, paths, env references, or URLs."""
    if _NON_SECRET_RE.search(value):
        return True
    # camelCase identifier with no digits/symbols is likely a variable name
    if re.fullmatch(r"[A-Za-z][A-Za-z0-9]{7,}", value) and not re.search(r"\d", value):
        return shannon_entropy(value) < 4.0
    return False


def _luhn_valid(number: str) -> bool:
    """Validate a credit-card number with the Luhn checksum."""
    digits = [int(c) for c in number if c.isdigit()]
    if not 13 <= len(digits) <= 19:
        return False
    checksum = 0
    parity = len(digits) % 2
    for index, digit in enumerate(digits):
        if index % 2 == parity:
            digit *= 2
            if digit > 9:
                digit -= 9
        checksum += digit
    return checksum % 10 == 0


def _jwt_header_is_json(value: str) -> bool:
    """Best-effort check that a JWT header decodes to JSON with an ``alg``."""
    try:
        header = value.split(".", 1)[0]
        padded = header + "=" * (-len(header) % 4)
        decoded = base64.urlsafe_b64decode(padded.encode("ascii"))
        data = json.loads(decoded.decode("utf-8"))
        return isinstance(data, dict) and "alg" in data
    except (ValueError, UnicodeDecodeError, binascii.Error, json.JSONDecodeError):
        return False


def _is_asset_email(value: str) -> bool:
    """Filter out icon filenames and documentation email domains."""
    low = value.lower()
    if _IMAGE_OR_ASSET_EXT_RE.search(low):
        return True
    if re.match(r"^[^@]+@\d+x", low):  # icon@2x.png
        return True
    domain = low.rsplit("@", 1)[-1]
    if domain in {"example.com", "example.org", "example.net", "test.com", "localhost"}:
        return True
    if domain.endswith((".png", ".jpg", ".jpeg", ".gif", ".svg", ".webp", ".css", ".js")):
        return True
    return False


def _inside_comment(text: str, start: int) -> bool:
    """Return True when ``start`` is inside a line/block comment."""
    line_start = text.rfind("\n", 0, start) + 1
    prefix = text[line_start:start]
    stripped = prefix.lstrip()
    if stripped.startswith(("//", "#", ";", "*")):
        return True
    if "//" in prefix:
        return True
    last_open = text.rfind("/*", 0, start)
    last_close = text.rfind("*/", 0, start)
    return last_open > last_close


def validate_rule(
    rule: Rule,
    value: str,
    text: str,
    match: re.Match,
    entropy_floor: Optional[float] = None,
) -> bool:
    """Return True if a rule match is likely a true positive."""
    value = value.strip().strip("'\"")
    if not value or len(value) < 4:
        return False
    if _is_placeholder(value):
        return False

    # --- Rule-specific checks ------------------------------------------------
    if rule.id == "aws_access_key_id":
        if not value.startswith(("AKIA", "ASIA", "AIDA", "AROA", "AIPA", "ANPA", "ANVA", "ABIA", "ACCA")):
            return False

    elif rule.id == "jwt_token":
        parts = value.split(".")
        if len(parts) != 3 or len(value) < 40:
            return False
        # Shape is enough; header JSON is a bonus confidence signal elsewhere.
        if not _jwt_header_is_json(value) and len(value) < 60:
            return False

    elif rule.id == "credit_card":
        if not _luhn_valid(value):
            return False

    elif rule.id in ("email_address", "us_ssn", "us_phone"):
        if rule.id == "email_address" and _is_asset_email(value):
            return False

    elif rule.id == "private_key_header":
        # Header alone is a strong signal; reject the word "public".
        if "PUBLIC KEY" in value.upper():
            return False

    elif rule.id in (
        "hardcoded_credential",
        "generic_secret_assignment",
        "api_key",
        "client_secret",
        "encryption_key",
        "signing_key",
        "django_secret_key",
        "flask_secret_key",
        "session_id",
        "ci_cd_token",
    ):
        if _looks_like_non_secret(value):
            return False

    elif rule.id == "database_uri_with_credentials":
        if re.search(r"://[^/]*:(?:password|pass|secret|changeme)@", value, re.IGNORECASE):
            return False

    # --- Entropy floor (only where the rule opts in) -------------------------
    floor = rule.entropy_min if entropy_floor is None else entropy_floor
    if floor > 0 and shannon_entropy(value) < floor:
        return False

    # Very short values are only allowed for structured rules.
    if len(value) < 8 and rule.category not in ("exposure", "endpoint", "pii", "code-risk"):
        return False

    # --- Context: secrets in comments are still leaks, but we do not boost ----
    # ``_inside_comment`` is intentionally informational for callers/tests.
    _ = _inside_comment(text, match.start())

    return True


def confidence_for(
    rule: Rule,
    value: str,
    text: str,
    match: re.Match,
    entropy_floor: Optional[float] = None,
) -> float:
    """Base confidence from severity + entropy + context."""
    base = {
        "critical": 0.96,
        "high": 0.9,
        "medium": 0.8,
        "low": 0.7,
        "info": 0.6,
    }.get(rule.severity, 0.7)

    floor = rule.entropy_min if entropy_floor is None else entropy_floor
    if floor > 0:
        entropy = shannon_entropy(value)
        if entropy >= floor + 1.0:
            base += 0.02
        elif entropy < floor + 0.2:
            base -= 0.03

    if _inside_comment(text, match.start()):
        # A leaked secret in a comment is still real; no penalty, just metadata.
        pass

    return round(min(0.99, max(0.05, base)), 2)


# ---------------------------------------------------------------------------
# Legacy API
# ---------------------------------------------------------------------------
def extract_context(text: str, start: int, end: int, context_length: int = 160) -> str:
    """Extract surrounding text for a match (single line, trimmed)."""
    start_ctx = max(0, start - context_length)
    end_ctx = min(len(text), end + context_length)
    return text[start_ctx:end_ctx].replace("\r", " ").replace("\n", " ").strip()


def validate_pattern(
    pattern_name: str,
    match_str: str,
    text: str,
    match: re.Match,
    entropy_threshold: float = 3.5,
) -> bool:
    """Backward-compatible validator used by older callers/plugins.

    New code should use :func:`validate_rule`.
    """
    rule = all_rule_ids().get(pattern_name)
    if rule is not None:
        value = rule.value_of(match) if match.string == text else match_str
        return validate_rule(rule, value, text, match)

    # Unknown/custom pattern: conservative placeholder + entropy checks.
    if _is_placeholder(match_str):
        return False
    if len(match_str) < 20 and shannon_entropy(match_str) < entropy_threshold:
        return False
    return True


# Public aliases (useful for plugins and tests).
is_placeholder = _is_placeholder
luhn_valid = _luhn_valid
looks_like_non_secret = _looks_like_non_secret

__all__ = [
    "validate_rule",
    "validate_pattern",
    "confidence_for",
    "extract_context",
    "is_placeholder",
    "luhn_valid",
    "looks_like_non_secret",
]
