"""Validator tests."""

import re

from src.rules import all_rule_ids
from src.validators import _is_placeholder, _luhn_valid, confidence_for, validate_rule


def _match(rule_id, text):
    rule = all_rule_ids()[rule_id].compile()
    return rule, next(rule.compiled.finditer(text))


def test_placeholder_detection():
    assert _is_placeholder("your_api_key_here")
    assert _is_placeholder("changeme")
    assert _is_placeholder("xxxxxxxxxxxxxxxx")
    assert _is_placeholder("AKIAIOSFODNN7EXAMPLE")
    assert not _is_placeholder("aB3dE9fG2hJ4kL6mN8pQ")


def test_luhn():
    assert _luhn_valid("4242424242424242")
    assert not _luhn_valid("4242424242424241")


def test_aws_example_is_rejected():
    rule, match = _match("aws_access_key_id", 'key = "AKIAIOSFODNN7EXAMPLE"')
    assert validate_rule(rule, match.group(0), match.string, match) is False


def test_real_aws_key_is_accepted():
    rule, match = _match("aws_access_key_id", 'key = "AKIA1234567890ABCDEF"')
    assert validate_rule(rule, match.group(0), match.string, match) is True


def test_credit_card_requires_luhn():
    good_rule, good_match = _match("credit_card", "card 4242424242424242")
    assert validate_rule(good_rule, good_match.group(0), good_match.string, good_match)
    bad_rule, bad_match = _match("credit_card", "card 4242424242424241")
    assert not validate_rule(bad_rule, bad_match.group(0), bad_match.string, bad_match)


def test_asset_email_is_rejected():
    rule, match = _match("email_address", "icon@2x.png")
    assert validate_rule(rule, match.group(0), match.string, match) is False

    rule, match = _match("email_address", "real@company.io")
    assert validate_rule(rule, match.group(0), match.string, match) is True


def test_jwt_shape():
    token = (
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
        "eyJzdWIiOiIxMjM0NTY3ODkwIn0."
        "abcdefghijklmnopqrstuvwxyz1234567890"
    )
    rule, match = _match("jwt_token", token)
    assert validate_rule(rule, match.group(0), match.string, match) is True


def test_confidence_is_bounded():
    rule, match = _match("aws_access_key_id", "AKIA1234567890ABCDEF")
    confidence = confidence_for(rule, match.group(0), match.string, match)
    assert 0.05 <= confidence <= 0.99
