"""Compatibility shim for legacy scripts that put ``src/`` on ``sys.path``.

Examples that keep working::

    from _compat import ScanConfig, run_scan
    from sensitive_patterns import SENSITIVE_PATTERNS

New code should import the package directly::

    from src import ScanConfig, get_rules, run_scan
"""

from __future__ import annotations

import os
import sys

_SRC_DIR = os.path.dirname(os.path.abspath(__file__))
if _SRC_DIR not in sys.path:
    sys.path.insert(0, _SRC_DIR)

# Keep the historical names importable without eagerly importing every module
# (interactive imports colorama, scanner imports requests, etc.).
_LAZY_EXPORTS = {
    "__version__": ("src", "__version__"),
    "ScanConfig": ("src.config", "ScanConfig"),
    "setup_logging": ("src.logging_config", "setup_logging"),
    "print_banner": ("src.interactive", "print_banner"),
    "interactive_menu": ("src.interactive", "interactive_menu"),
    "parse_args": ("src.cli", "parse_args"),
    "run_scan": ("src.scanner", "run_scan"),
    "print_summary": ("src.scanner", "print_summary"),
    "compute_exit_code": ("src.scanner", "compute_exit_code"),
    "get_rules": ("src.patterns", "get_rules"),
    "scan_text": ("src.scanner", "scan_text"),
    "Rule": ("src.rules", "Rule"),
}

__all__ = list(_LAZY_EXPORTS)


def __getattr__(name: str):
    target = _LAZY_EXPORTS.get(name)
    if target is None:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
    import importlib

    module_name, attribute = target
    value = getattr(importlib.import_module(module_name), attribute)
    globals()[name] = value
    return value
