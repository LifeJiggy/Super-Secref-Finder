"""Backward-compatible wrapper — imports from the src package.

Legacy usage:
    from sensitive_patterns import SENSITIVE_PATTERNS, validate_pattern
"""

import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from src.patterns import SENSITIVE_PATTERNS  # noqa: F401
from src.validators import extract_context, validate_pattern  # noqa: F401
