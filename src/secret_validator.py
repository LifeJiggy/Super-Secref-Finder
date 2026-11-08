"""Active validation of discovered secrets where it is safe to do so.

Only read-only, identity-checking endpoints are used. Validation is opt-in at
runtime through ``safe_mode`` (on by default in CI examples). AWS access-key
IDs cannot be validated without their paired secret key, so they are reported
as unvalidated rather than guessed.
"""

from __future__ import annotations

import logging
from typing import Dict, Optional

import requests

logger = logging.getLogger("secref.secret_validator")

_TIMEOUT = 8

# Fix the set of endpoints the tool is allowed to contact.
_ALLOWED_HOSTS = {
    "api.github.com",
    "gitlab.com",
    "slack.com",
    "api.openai.com",
    "api.anthropic.com",
    "api.sendgrid.com",
    "api.stripe.com",
    "api.mailgun.net",
    "api.digitalocean.com",
    "huggingface.co",
    "registry.npmjs.org",
    "api.telegram.org",
}


def _safe_request(
    method: str,
    url: str,
    *,
    headers: Optional[Dict[str, str]] = None,
    auth: Optional[tuple] = None,
) -> Optional[requests.Response]:
    """Issue a request only to an allow-listed host."""
    from urllib.parse import urlparse

    host = urlparse(url).netloc.lower()
    if host not in _ALLOWED_HOSTS:
        logger.warning(f"Refusing validation request to non-allow-listed host: {host}")
        return None
    try:
        return requests.request(
            method,
            url,
            headers=headers or {},
            auth=auth,
            timeout=_TIMEOUT,
            allow_redirects=False,
        )
    except requests.RequestException as exc:
        logger.debug(f"Validation request failed for {host}: {exc}")
        return None


def validate_github_token(token: str) -> Dict:
    """Test a GitHub token against ``/user``."""
    resp = _safe_request(
        "GET",
        "https://api.github.com/user",
        headers={
            "Authorization": f"token {token}",
            "Accept": "application/vnd.github+json",
        },
    )
    if resp is None:
        return {"valid": None, "reason": "request failed"}
    if resp.status_code == 200:
        data = resp.json()
        return {
            "valid": True,
            "login": data.get("login"),
            "scope": resp.headers.get("X-OAuth-Scopes", ""),
        }
    return {"valid": False, "reason": f"HTTP {resp.status_code}"}


def validate_gitlab_token(token: str) -> Dict:
    resp = _safe_request(
        "GET",
        "https://gitlab.com/api/v4/user",
        headers={"PRIVATE-TOKEN": token},
    )
    if resp is None:
        return {"valid": None, "reason": "request failed"}
    if resp.status_code == 200:
        data = resp.json()
        return {"valid": True, "username": data.get("username")}
    return {"valid": False, "reason": f"HTTP {resp.status_code}"}


def validate_slack_token(token: str) -> Dict:
    resp = _safe_request(
        "POST",
        "https://slack.com/api/auth.test",
        headers={"Authorization": f"Bearer {token}"},
    )
    if resp is None:
        return {"valid": None, "reason": "request failed"}
    data = resp.json()
    if data.get("ok"):
        return {"valid": True, "team": data.get("team"), "user": data.get("user")}
    return {"valid": False, "reason": data.get("error", "unknown")}


def validate_openai_key(key: str) -> Dict:
    resp = _safe_request(
        "GET",
        "https://api.openai.com/v1/models",
        headers={"Authorization": f"Bearer {key}"},
    )
    if resp is None:
        return {"valid": None, "reason": "request failed"}
    if resp.status_code == 200:
        return {"valid": True, "reason": "key is active"}
    return {"valid": False, "reason": f"HTTP {resp.status_code}"}


def validate_anthropic_key(key: str) -> Dict:
    resp = _safe_request(
        "GET",
        "https://api.anthropic.com/v1/models",
        headers={
            "x-api-key": key,
            "anthropic-version": "2023-06-01",
        },
    )
    if resp is None:
        return {"valid": None, "reason": "request failed"}
    if resp.status_code == 200:
        return {"valid": True, "reason": "key is active"}
    return {"valid": False, "reason": f"HTTP {resp.status_code}"}


def validate_sendgrid_key(key: str) -> Dict:
    resp = _safe_request(
        "GET",
        "https://api.sendgrid.com/v3/user/profile",
        headers={"Authorization": f"Bearer {key}"},
    )
    if resp is None:
        return {"valid": None, "reason": "request failed"}
    if resp.status_code == 200:
        return {"valid": True, "reason": "key is active"}
    return {"valid": False, "reason": f"HTTP {resp.status_code}"}


def validate_stripe_key(key: str) -> Dict:
    resp = _safe_request(
        "GET",
        "https://api.stripe.com/v1/balance",
        headers={"Authorization": f"Bearer {key}"},
    )
    if resp is None:
        return {"valid": None, "reason": "request failed"}
    if resp.status_code == 200:
        return {"valid": True, "reason": "key is active"}
    return {"valid": False, "reason": f"HTTP {resp.status_code}"}


def validate_mailgun_key(key: str) -> Dict:
    resp = _safe_request(
        "GET",
        "https://api.mailgun.net/v3/domains",
        auth=("api", key),
    )
    if resp is None:
        return {"valid": None, "reason": "request failed"}
    if resp.status_code == 200:
        return {"valid": True, "reason": "key is active"}
    return {"valid": False, "reason": f"HTTP {resp.status_code}"}


def validate_digitalocean_token(token: str) -> Dict:
    resp = _safe_request(
        "GET",
        "https://api.digitalocean.com/v2/account",
        headers={"Authorization": f"Bearer {token}"},
    )
    if resp is None:
        return {"valid": None, "reason": "request failed"}
    if resp.status_code == 200:
        data = resp.json().get("account", {})
        return {"valid": True, "email": data.get("email"), "status": data.get("status")}
    return {"valid": False, "reason": f"HTTP {resp.status_code}"}


def validate_huggingface_token(token: str) -> Dict:
    resp = _safe_request(
        "GET",
        "https://huggingface.co/api/whoami-v2",
        headers={"Authorization": f"Bearer {token}"},
    )
    if resp is None:
        return {"valid": None, "reason": "request failed"}
    if resp.status_code == 200:
        data = resp.json()
        return {"valid": True, "name": data.get("name"), "type": data.get("type")}
    return {"valid": False, "reason": f"HTTP {resp.status_code}"}


def validate_npm_token(token: str) -> Dict:
    resp = _safe_request(
        "GET",
        "https://registry.npmjs.org/-/whoami",
        headers={"Authorization": f"Bearer {token}"},
    )
    if resp is None:
        return {"valid": None, "reason": "request failed"}
    if resp.status_code == 200:
        return {"valid": True, "username": resp.json().get("username")}
    return {"valid": False, "reason": f"HTTP {resp.status_code}"}


def validate_telegram_bot_token(token: str) -> Dict:
    resp = _safe_request("GET", f"https://api.telegram.org/bot{token}/getMe")
    if resp is None:
        return {"valid": None, "reason": "request failed"}
    data = resp.json()
    if data.get("ok"):
        return {"valid": True, "username": data.get("result", {}).get("username")}
    return {"valid": False, "reason": data.get("description", "invalid token")}


def validate_aws_access_key(access_key_id: str, secret_key: Optional[str] = None) -> Dict:
    """AWS keys cannot be checked from an access-key ID alone."""
    if not secret_key:
        return {
            "valid": None,
            "reason": "AWS access key ID alone cannot be validated; paired secret required",
        }
    try:
        import boto3
        from botocore.exceptions import ClientError
    except ImportError:
        return {"valid": None, "reason": "boto3 not installed"}

    try:
        client = boto3.client(
            "sts",
            aws_access_key_id=access_key_id,
            aws_secret_access_key=secret_key,
        )
        identity = client.get_caller_identity()
        return {
            "valid": True,
            "account": identity.get("Account"),
            "arn": identity.get("Arn"),
            "user_id": identity.get("UserId"),
        }
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code", "unknown")
        return {"valid": False, "reason": code}
    except Exception as exc:  # pragma: no cover - network/boto variability
        return {"valid": None, "reason": str(exc)}


VALIDATORS = {
    "github_token": validate_github_token,
    "github_fine_grained_pat": validate_github_token,
    "github_oauth_access_token": validate_github_token,
    "gitlab_token": validate_gitlab_token,
    "slack_token": validate_slack_token,
    "openai_api_key": validate_openai_key,
    "anthropic_api_key": validate_anthropic_key,
    "sendgrid_api_key": validate_sendgrid_key,
    "stripe_secret_key": validate_stripe_key,
    "mailgun_api_key": validate_mailgun_key,
    "digitalocean_personal_access_token": validate_digitalocean_token,
    "digitalocean_oauth_token": validate_digitalocean_token,
    "huggingface_token": validate_huggingface_token,
    "npm_token": validate_npm_token,
    "telegram_bot_token": validate_telegram_bot_token,
}


def validate_secret(pattern_name: str, value: str, safe_mode: bool = False) -> Dict:
    """Dispatch to the validator for ``pattern_name``.

    Returns ``{"valid": bool, ...}`` or ``{"valid": None, "reason": ...}``.
    """
    if safe_mode:
        return {"valid": None, "reason": "skipped (safe mode)"}

    validator = VALIDATORS.get(pattern_name)
    if not validator:
        return {"valid": None, "reason": "no validator available"}

    try:
        return validator(value)
    except Exception as exc:  # pragma: no cover - defensive
        return {"valid": None, "reason": f"validation error: {exc}"}
