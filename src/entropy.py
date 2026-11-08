"""Shannon entropy and heuristics for false-positive reduction."""

from __future__ import annotations

import math
import re
from collections import Counter
from typing import Dict

_COMMON_WORDS = {
    "password", "secret", "token", "apikey", "api_key", "example",
    "sample", "dummy", "test", "testing", "changeme", "placeholder",
    "localhost", "undefined", "null", "function", "return", "default",
}


def shannon_entropy(data: str) -> float:
    """Bits per character (0 for empty input).

    High entropy (>4.0) suggests random/secret data; low entropy (<3.0)
    suggests human-readable text.
    """
    if not data:
        return 0.0
    length = len(data)
    entropy = 0.0
    for count in Counter(data).values():
        probability = count / length
        if probability > 0:
            entropy -= probability * math.log2(probability)
    return entropy


def unique_ratio(data: str) -> float:
    """Fraction of distinct characters (0-1)."""
    if not data:
        return 0.0
    return len(set(data)) / len(data)


def char_classes(data: str) -> Dict[str, bool]:
    """Return which character classes appear in ``data``."""
    return {
        "lower": bool(re.search(r"[a-z]", data)),
        "upper": bool(re.search(r"[A-Z]", data)),
        "digit": bool(re.search(r"\d", data)),
        "symbol": bool(re.search(r"[^A-Za-z0-9]", data)),
    }


def is_high_entropy(data: str, threshold: float = 4.0) -> bool:
    """Check if a string has high entropy (likely a secret)."""
    return shannon_entropy(data) >= threshold


def is_likely_secret(
    data: str,
    min_length: int = 12,
    threshold: float = 3.2,
) -> bool:
    """Heuristic for high-entropy tokens used by generic-secret rules.

    Requires length, entropy, character diversity, and rejects obvious
    placeholders/URLs/paths.
    """
    value = data.strip().strip("'\"")
    if len(value) < min_length:
        return False
    if value.lower() in _COMMON_WORDS:
        return False
    if value.startswith(("http://", "https://", "/", "./", "~/", "process.env")):
        return False
    classes = char_classes(value)
    if sum(classes.values()) < 2:
        return False
    if shannon_entropy(value) < threshold:
        return False
    if unique_ratio(value) < 0.35:
        return False
    return True


def entropy_label(data: str) -> str:
    """Return a human-readable entropy classification."""
    entropy = shannon_entropy(data)
    if entropy >= 4.5:
        return "VERY_HIGH"
    if entropy >= 4.0:
        return "HIGH"
    if entropy >= 3.5:
        return "MEDIUM"
    if entropy >= 3.0:
        return "LOW"
    return "VERY_LOW"
