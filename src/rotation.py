"""Secret-rotation guidance for findings.

Every report should answer the operational question that follows a finding:
*where do I revoke this credential?*  This module keeps a single, auditable
mapping from rule IDs to provider rotation pages, with category fallbacks for
custom and plugin rules.
"""

from __future__ import annotations

from typing import Iterable, Optional

# Rotate the exact credential at the provider, not just the copy in the repo.
ROTATION_URLS = {
    # Cloud -----------------------------------------------------------------
    "aws_access_key_id": "https://console.aws.amazon.com/iam/home#/security_credentials",
    "aws_secret_access_key": "https://console.aws.amazon.com/iam/home#/security_credentials",
    "aws_session_token": "https://console.aws.amazon.com/iam/home#/security_credentials",
    "aws_mws_key": "https://console.aws.amazon.com/iam/home#/security_credentials",
    "google_api_key": "https://console.cloud.google.com/apis/credentials",
    "gcp_service_account_key": "https://console.cloud.google.com/iam-admin/serviceaccounts",
    "azure_storage_connection_string": "https://portal.azure.com/#view/HubsExtension/BrowseResource/resourceType/Microsoft.Storage%2FStorageAccounts",
    "azure_client_secret": "https://portal.azure.com/#view/Microsoft_AAD_RegisteredApps/ApplicationsListBlade",
    "azure_sas_token": "https://portal.azure.com/#view/HubsExtension/BrowseResource/resourceType/Microsoft.Storage%2FStorageAccounts",
    "cloudflare_api_token": "https://dash.cloudflare.com/profile/api-tokens",
    "digitalocean_personal_access_token": "https://cloud.digitalocean.com/account/api/tokens",
    "digitalocean_oauth_token": "https://cloud.digitalocean.com/account/api/tokens",
    "heroku_api_key": "https://dashboard.heroku.com/account",
    # AI / model providers ---------------------------------------------------
    "openai_api_key": "https://platform.openai.com/api-keys",
    "anthropic_api_key": "https://console.anthropic.com/settings/keys",
    "huggingface_token": "https://huggingface.co/settings/tokens",
    "replicate_api_token": "https://replicate.com/account/api-tokens",
    "groq_api_key": "https://console.groq.com/keys",
    "openrouter_api_key": "https://openrouter.ai/keys",
    "perplexity_api_key": "https://www.perplexity.ai/settings/api",
    "cohere_api_key": "https://dashboard.cohere.com/api-keys",
    # Source control / packages ---------------------------------------------
    "github_token": "https://github.com/settings/tokens",
    "github_fine_grained_pat": "https://github.com/settings/tokens",
    "github_oauth_access_token": "https://github.com/settings/applications",
    "gitlab_token": "https://gitlab.com/-/user_settings/personal_access_tokens",
    "gitlab_runner_token": "https://gitlab.com/-/user_settings/personal_access_tokens",
    "atlassian_token": "https://id.atlassian.com/manage-profile/security/api-tokens",
    "npm_token": "https://www.npmjs.com/settings/~tokens",
    "pypi_token": "https://pypi.org/manage/account/token/",
    "npmrc_auth_token": "https://www.npmjs.com/settings/~tokens",
    "docker_registry_auth": "https://hub.docker.com/settings/security",
    # Payments / email / comms ---------------------------------------------
    "stripe_secret_key": "https://dashboard.stripe.com/apikeys",
    "stripe_webhook_secret": "https://dashboard.stripe.com/webhooks",
    "twilio_api_key": "https://console.twilio.com/account/auth-tokens",
    "sendgrid_api_key": "https://app.sendgrid.com/settings/api_keys",
    "mailgun_api_key": "https://app.mailgun.com/settings/api_security",
    "mailchimp_api_key": "https://us1.admin.mailchimp.com/account/api/",
    "slack_token": "https://api.slack.com/apps",
    "slack_webhook": "https://api.slack.com/apps",
    "discord_token": "https://discord.com/developers/applications",
    "discord_webhook": "https://discord.com/developers/applications",
    "telegram_bot_token": "https://t.me/BotFather",
    "shopify_access_token": "https://admin.shopify.com/settings/apps",
    "shopify_shared_secret": "https://admin.shopify.com/settings/apps",
    # Data / observability ---------------------------------------------------
    "sentry_dsn": "https://sentry.io/settings/",
    "new_relic_api_key": "https://one.newrelic.com/api-keys",
    "datadog_api_key": "https://app.datadoghq.com/organization-settings/api-keys",
    "algolia_api_key": "https://dashboard.algolia.com/account/api-keys",
    "fastly_api_key": "https://manage.fastly.com/account/personal/tokens",
    "supabase_service_role_key": "https://app.supabase.com/project/_/settings/api",
    "firebase_config": "https://console.firebase.google.com/",
}

# Rules that represent credentials without a single provider console.
GENERIC_SECRETS = {
    "private_key_header",
    "database_uri_with_credentials",
    "basic_auth_url",
    "http_authorization_bearer",
    "hardcoded_credential",
    "generic_secret_assignment",
    "api_key",
    "client_secret",
    "django_secret_key",
    "flask_secret_key",
    "rails_secret_key",
    "encryption_key",
    "signing_key",
    "session_id",
    "jwt_token",
    "ci_cd_token",
}

GENERIC_ROTATION_URL = (
    "https://github.com/LifeJiggy/Super-Secref-Finder/blob/main/SECURITY.md"
    "#rotation-guidance"
)

_CATEGORY_FALLBACKS = {
    "secret": GENERIC_ROTATION_URL,
    "credential": GENERIC_ROTATION_URL,
    "token": GENERIC_ROTATION_URL,
    "cloud": GENERIC_ROTATION_URL,
    "supply-chain": GENERIC_ROTATION_URL,
}


def rotation_guidance(
    rule_id: str,
    category: Optional[str] = None,
    tags: Optional[Iterable[str]] = None,
) -> str:
    """Return a safe provider rotation URL for a rule, or an empty string."""
    if rule_id in ROTATION_URLS:
        return ROTATION_URLS[rule_id]
    if rule_id in GENERIC_SECRETS:
        return GENERIC_ROTATION_URL
    for tag in tags or ():
        if tag in ROTATION_URLS:
            return ROTATION_URLS[tag]
    return _CATEGORY_FALLBACKS.get((category or "").lower(), "")


__all__ = [
    "GENERIC_ROTATION_URL",
    "ROTATION_URLS",
    "rotation_guidance",
]
