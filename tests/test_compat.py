"""Compatibility shim and package API tests."""

import src
from src import ScanConfig, get_rules, scan_text
from src._compat import ScanConfig as CompatConfig
from src._compat import get_rules as compat_get_rules
from src._compat import scan_text as compat_scan_text


def test_package_public_api():
    assert src.__version__ == "8.1.0"
    assert ScanConfig is not None
    assert get_rules() is not None
    assert callable(scan_text)


def test_legacy_compat_shim():
    assert CompatConfig is ScanConfig
    assert compat_get_rules() is not None
    assert callable(compat_scan_text)
