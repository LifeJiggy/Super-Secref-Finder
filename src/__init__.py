"""Super Secref Finder — high-signal secret scanner.

Public API::

    from src import ScanConfig, get_rules, scan_text, run_scan

Heavy modules are imported lazily so ``import src`` stays cheap.
"""

from __future__ import annotations

__version__ = "8.1.0"
__author__ = "ArkhAngelLifeJiggy"

__all__ = [
    "__version__",
    "__author__",
    "ScanConfig",
    "Rule",
    "get_rules",
    "scan_text",
    "run_scan",
    "print_summary",
    "compute_exit_code",
]

_LAZY_EXPORTS = {
    "ScanConfig": ("src.config", "ScanConfig"),
    "Rule": ("src.rules", "Rule"),
    "get_rules": ("src.patterns", "get_rules"),
    "scan_text": ("src.scanner", "scan_text"),
    "run_scan": ("src.scanner", "run_scan"),
    "print_summary": ("src.scanner", "print_summary"),
    "compute_exit_code": ("src.scanner", "compute_exit_code"),
}


def __getattr__(name: str):
    """Lazily resolve public API names (PEP 562)."""
    target = _LAZY_EXPORTS.get(name)
    if target is None:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
    import importlib

    module_name, attribute = target
    module = importlib.import_module(module_name)
    value = getattr(module, attribute)
    globals()[name] = value
    return value
