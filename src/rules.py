"""Canonical rule registry for Super Secref Finder v8.

Every detection is a :class:`Rule` with metadata:

* ``id``            stable rule identifier (used by output + allowlists)
* ``pattern``       regular expression
* ``category``      secret | cloud | credential | token | exposure | endpoint | pii | supply-chain | code-risk
* ``severity``      critical | high | medium | low | info
* ``secret_group``  capture group holding the actual secret (0 = whole match)
* ``entropy_min``   optional Shannon-entropy floor for the captured value
* ``noise``         opt-in only (code smells, not secrets)
* ``pii``           opt-in only (emails, phones, ...)

Rules were deliberately curated: high-signal defaults, noisy patterns behind
``--include-noise`` / ``--include-pii``.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Optional, Tuple

SEVERITIES = ("critical", "high", "medium", "low", "info")
SEVERITY_RANK = {name: len(SEVERITIES) - i for i, name in enumerate(SEVERITIES)}
CATEGORIES = (
    "secret",
    "cloud",
    "credential",
    "token",
    "exposure",
    "endpoint",
    "pii",
    "supply-chain",
    "code-risk",
    "config",
    "custom",
)


@dataclass
class Rule:
    id: str
    pattern: str
    category: str = "secret"
    severity: str = "medium"
    description: str = ""
    secret_group: int = 0
    entropy_min: float = 0.0
    noise: bool = False
    pii: bool = False
    tags: Tuple[str, ...] = ()
    compiled: Optional[re.Pattern] = field(default=None, compare=False, repr=False)

    def __post_init__(self) -> None:
        if self.severity not in SEVERITIES:
            raise ValueError(f"invalid severity {self.severity!r} for rule {self.id!r}")
        if self.category not in CATEGORIES:
            raise ValueError(f"invalid category {self.category!r} for rule {self.id!r}")

    def compile(self) -> "Rule":
        """Compile the pattern once (idempotent)."""
        if self.compiled is None:
            self.compiled = re.compile(self.pattern, re.MULTILINE)
        return self

    def value_span(self, match: re.Match) -> Tuple[int, int]:
        """Return the span of the *secret* (capture group when available)."""
        if self.secret_group:
            try:
                if match.group(self.secret_group) is not None:
                    return match.span(self.secret_group)
            except IndexError:
                pass
        return match.span(0)

    def value_of(self, match: re.Match) -> str:
        start, end = self.value_span(match)
        return match.string[start:end]


def R(
    rule_id: str,
    pattern: str,
    category: str = "secret",
    severity: str = "high",
    description: str = "",
    group: int = 0,
    entropy: float = 0.0,
    noise: bool = False,
    pii: bool = False,
    tags: Iterable[str] = (),
) -> Rule:
    """Compact rule constructor."""
    return Rule(
        id=rule_id,
        pattern=pattern,
        category=category,
        severity=severity,
        description=description,
        secret_group=group,
        entropy_min=entropy,
        noise=noise,
        pii=pii,
        tags=tuple(tags),
    )


# ---------------------------------------------------------------------------
# Built-in rules
# ---------------------------------------------------------------------------
BUILTIN_RULES: List[Rule] = [
    # =====================================================================
    # Cloud providers
    # =====================================================================
    R("aws_access_key_id", r"\b(?:AKIA|ASIA|AIDA|AROA|AIPA|ANPA|ANVA|ABIA|ACCA)[0-9A-Z]{16}\b",
      "cloud", "critical", "AWS access key ID", tags=("aws",)),
    R("aws_secret_access_key",
      r"(?i)\b(?:aws[_-]?secret[_-]?access[_-]?key|aws[_-]?secret|secret[_-]?access[_-]?key)\s*[:=]\s*['\"]?([A-Za-z0-9/+=]{40})['\"]?",
      "cloud", "critical", "AWS secret access key", group=1, entropy=3.2, tags=("aws",)),
    R("aws_session_token", r"\b(?:FQoGZXIvYXdzE|IQoJb3JpZ2luX2VjE)[A-Za-z0-9/+=]{50,}\b",
      "cloud", "critical", "AWS temporary session token", tags=("aws",)),
    R("aws_mws_key",
      r"\bAMZN\.MWS\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b",
      "cloud", "high", "Amazon MWS auth token", tags=("aws",)),
    R("google_api_key", r"\bAIza[0-9A-Za-z\-_]{35}\b",
      "cloud", "high", "Google API key", tags=("gcp",)),
    R("google_oauth_client_id",
      r"\b[0-9]{6,}-[0-9A-Za-z_]{20,}\.apps\.googleusercontent\.com\b",
      "exposure", "low", "Google OAuth client ID (public identifier)", tags=("gcp",)),
    R("gcp_service_account_key", r"\"type\"\s*:\s*\"service_account\"",
      "cloud", "high", "GCP service-account JSON document", tags=("gcp",)),
    R("azure_storage_connection_string",
      r"(?i)\bDefaultEndpointsProtocol=https?;AccountName=[^;]+;AccountKey=[A-Za-z0-9+/=]{40,}",
      "cloud", "critical", "Azure Storage connection string", tags=("azure",)),
    R("azure_client_secret",
      r"(?i)\b(?:azure|aad)[_-]?client[_-]?secret\s*[:=]\s*['\"]?([A-Za-z0-9\-_\.~]{32,})['\"]?",
      "cloud", "high", "Azure AD client secret", group=1, entropy=3.0, tags=("azure",)),
    R("azure_sas_token", r"(?i)[?&]sig=[A-Za-z0-9%+/=]{20,}",
      "cloud", "medium", "Azure shared-access-signature token", tags=("azure",)),
    R("cloudflare_api_token",
      r"(?i)\b(?:cloudflare|cf)[_-]?(?:api[_-]?)?(?:token|key)\s*[:=]\s*['\"]?([A-Za-z0-9_\-]{32,})['\"]?",
      "cloud", "high", "Cloudflare API token", group=1, entropy=3.0),
    R("digitalocean_personal_access_token", r"\bdop_v1_[a-f0-9]{64}\b",
      "cloud", "high", "DigitalOcean personal access token"),
    R("digitalocean_oauth_token", r"\bdoo_v1_[a-f0-9]{64}\b",
      "cloud", "high", "DigitalOcean OAuth token"),
    R("heroku_api_key",
      r"(?i)\bheroku[_-]?(?:api[_-]?)?key\s*[:=]\s*['\"]?([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})['\"]?",
      "cloud", "high", "Heroku API key", group=1),

    # =====================================================================
    # AI providers
    # =====================================================================
    R("openai_api_key", r"\bsk-(?:proj-|svcacct-|admin-)?[A-Za-z0-9_-]{20,}\b",
      "token", "critical", "OpenAI API key", tags=("ai",)),
    R("anthropic_api_key", r"\bsk-ant-[A-Za-z0-9\-_]{20,}\b",
      "token", "critical", "Anthropic API key", tags=("ai",)),
    R("huggingface_token", r"\bhf_[A-Za-z0-9]{30,}\b",
      "token", "high", "Hugging Face access token", tags=("ai",)),
    R("replicate_api_token", r"\br8_[A-Za-z0-9]{30,}\b",
      "token", "high", "Replicate API token", tags=("ai",)),
    R("groq_api_key", r"\bgsk_[A-Za-z0-9]{30,}\b",
      "token", "high", "Groq API key", tags=("ai",)),
    R("openrouter_api_key", r"\bsk-or-v1-[A-Za-z0-9]{32,}\b",
      "token", "high", "OpenRouter API key", tags=("ai",)),
    R("perplexity_api_key", r"\bpplx-[A-Za-z0-9]{32,}\b",
      "token", "high", "Perplexity API key", tags=("ai",)),
    R("cohere_api_key",
      r"(?i)\bcohere[_-]?(?:api[_-]?)?key\s*[:=]\s*['\"]?([A-Za-z0-9]{32,})['\"]?",
      "token", "high", "Cohere API key", group=1, entropy=3.0, tags=("ai",)),

    # =====================================================================
    # Source control / CI
    # =====================================================================
    R("github_token", r"\bgh[pousr]_[A-Za-z0-9]{30,}\b",
      "token", "critical", "GitHub personal/OAuth token", tags=("github",)),
    R("github_fine_grained_pat", r"\bgithub_pat_[A-Za-z0-9_]{22,}\b",
      "token", "critical", "GitHub fine-grained personal access token", tags=("github",)),
    R("gitlab_token", r"\bglpat-[A-Za-z0-9_\-]{20,}\b",
      "token", "critical", "GitLab personal access token", tags=("gitlab",)),
    R("gitlab_runner_token", r"\bglrt-[A-Za-z0-9_\-]{20,}\b",
      "token", "high", "GitLab runner token", tags=("gitlab",)),
    R("atlassian_token", r"\bATATT[A-Za-z0-9_\-]{20,}\b",
      "token", "high", "Atlassian API token"),
    R("npm_token", r"\bnpm_[A-Za-z0-9]{30,}\b",
      "token", "high", "npm access token"),
    R("pypi_token", r"\bpypi-[A-Za-z0-9_\-]{40,}\b",
      "token", "high", "PyPI upload token"),
    R("github_actions_secret", r"(?i)\bsecrets\.[A-Z0-9_]+\b",
      "supply-chain", "info", "GitHub Actions secret reference (not a value)"),
    R("npmrc_auth_token",
      r"(?i)//(?:registry\.npmjs\.org|npm\.pkg\.dev)[^\s]*:_authToken\s*=\s*([^\s]+)",
      "supply-chain", "high", "npm registry auth token", group=1),
    R("docker_registry_auth", r"(?i)\"auth\"\s*:\s*\"([A-Za-z0-9+/=]{16,})\"",
      "supply-chain", "medium", "Docker registry auth blob", group=1),
    R("ci_cd_token",
      r"(?i)\b(?:CI_JOB_TOKEN|CI_BUILD_TOKEN|TRAVIS_TOKEN|CIRCLE_TOKEN)\s*[:=]\s*['\"]?([^\s\"']{12,})",
      "supply-chain", "high", "CI/CD job token", group=1, entropy=2.5),

    # =====================================================================
    # Payments / communications
    # =====================================================================
    R("stripe_secret_key", r"\b(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{16,}\b",
      "token", "critical", "Stripe secret/restricted key", tags=("stripe",)),
    R("stripe_publishable_key", r"\bpk_(?:live|test)_[A-Za-z0-9]{16,}\b",
      "exposure", "low", "Stripe publishable key (public identifier)", tags=("stripe",)),
    R("stripe_webhook_secret", r"\bwhsec_[A-Za-z0-9]{20,}\b",
      "token", "high", "Stripe webhook signing secret", tags=("stripe",)),
    R("twilio_api_key", r"\bSK[0-9a-fA-F]{32}\b",
      "token", "high", "Twilio API key", tags=("twilio",)),
    R("twilio_account_sid", r"\bAC[0-9a-fA-F]{32}\b",
      "exposure", "low", "Twilio account SID", tags=("twilio",)),
    R("sendgrid_api_key", r"\bSG\.[A-Za-z0-9_\-]{16,}\.[A-Za-z0-9_\-]{30,}\b",
      "token", "high", "SendGrid API key", tags=("sendgrid",)),
    R("mailgun_api_key", r"\bkey-[0-9a-f]{32}\b",
      "token", "high", "Mailgun API key", entropy=2.8, tags=("mailgun",)),
    R("mailchimp_api_key", r"\b[0-9a-f]{32}-us[0-9]{1,2}\b",
      "token", "high", "Mailchimp API key", tags=("mailchimp",)),
    R("slack_token", r"\bxox[baprs]-[0-9A-Za-z\-]{10,}\b",
      "token", "critical", "Slack token", tags=("slack",)),
    R("slack_webhook",
      r"https://hooks\.slack\.com/services/T[A-Za-z0-9]+/B[A-Za-z0-9]+/[A-Za-z0-9]+",
      "token", "high", "Slack incoming webhook", tags=("slack",)),
    R("discord_token", r"\b[MN][A-Za-z0-9_-]{23,28}\.[A-Za-z0-9_-]{6}\.[A-Za-z0-9_-]{27,40}\b",
      "token", "critical", "Discord bot/user token", tags=("discord",)),
    R("discord_webhook",
      r"https://(?:discord|discordapp)\.com/api/webhooks/[0-9]+/[A-Za-z0-9_-]+",
      "token", "high", "Discord webhook", tags=("discord",)),
    R("telegram_bot_token", r"\b[0-9]{8,10}:[A-Za-z0-9_-]{35}\b",
      "token", "high", "Telegram bot token", tags=("telegram",)),
    R("shopify_access_token", r"\bshpat_[a-fA-F0-9]{32}\b",
      "token", "high", "Shopify access token", tags=("shopify",)),
    R("shopify_shared_secret", r"\bshpss_[a-fA-F0-9]{32}\b",
      "token", "high", "Shopify shared secret", tags=("shopify",)),

    # =====================================================================
    # Tokens / credentials
    # =====================================================================
    R("jwt_token", r"\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b",
      "token", "high", "JSON Web Token"),
    R("private_key_header",
      r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----",
      "credential", "critical", "Private key block"),
    R("database_uri_with_credentials",
      r"\b(?:mongodb(?:\+srv)?|postgres(?:ql)?|mysql|mariadb|redis|rediss|amqps?|mssql|oracle(?:\+thin)?|cassandra|elasticsearch)://[^/\s:@'\"]+:[^/\s@'\"]+@[^/\s'\"]+",
      "credential", "critical", "Database URI containing credentials"),
    R("basic_auth_url", r"\bhttps?://[^/\s:@'\"]+:[^/\s@'\"]+@[^/\s'\"]+",
      "credential", "high", "URL containing HTTP basic-auth credentials"),
    R("http_authorization_bearer",
      r"(?i)\bAuthorization\s*[:=]\s*['\"]?Bearer\s+([A-Za-z0-9\-._~+/]{16,}=*)",
      "credential", "high", "Authorization: Bearer credential", group=1),
    R("hardcoded_credential",
      r"(?i)\b(?:user(?:name)?|pass(?:word)?|passwd|pwd|cred(?:ential)?|secret|api[_-]?secret|auth[_-]?token)\s*[:=]\s*['\"]([^'\"\s]{8,128})['\"]",
      "credential", "high", "Hardcoded credential assignment", group=1, entropy=3.0),
    R("generic_secret_assignment",
      r"(?i)\b(?:secret|token|api[_-]?key|apikey|auth[_-]?token|access[_-]?key|private[_-]?key|client[_-]?secret)\s*[:=]\s*['\"]([A-Za-z0-9_\-\/+=.]{16,128})['\"]",
      "secret", "high", "Generic secret assignment with high-entropy value", group=1, entropy=3.2),
    R("api_key",
      r"(?i)\b(?:api[_-]?key|access[_-]?token|client[_-]?secret|bearer[_-]?token)\s*[:=]\s*['\"]?([A-Za-z0-9\-_]{24,128})['\"]?",
      "secret", "high", "API key or access token", group=1, entropy=3.0),
    R("client_secret",
      r"(?i)\bclient[_-]?secret\s*[:=]\s*['\"]?([A-Za-z0-9\-_\.]{16,128})['\"]?",
      "credential", "high", "OAuth client secret", group=1, entropy=3.0),
    R("django_secret_key", r"(?i)\bSECRET_KEY\s*=\s*['\"]([^'\"]{32,})['\"]",
      "credential", "high", "Django SECRET_KEY", group=1, entropy=3.0),
    R("flask_secret_key", r"(?i)\b(?:app\.)?secret[_-]?key\s*[:=]\s*['\"]([^'\"]{16,})['\"]",
      "credential", "medium", "Flask application secret key", group=1, entropy=2.8),
    R("rails_secret_key", r"(?i)\bsecret_key_base\s*[:=]\s*['\"]([a-f0-9]{64,})['\"]",
      "credential", "high", "Rails secret_key_base", group=1),
    R("encryption_key",
      r"(?i)\b(?:encryption|encrypt|aes)[_-]?key\s*[:=]\s*['\"]?([A-Za-z0-9+/=]{16,64})['\"]?",
      "credential", "high", "Encryption key", group=1, entropy=3.0),
    R("signing_key",
      r"(?i)\b(?:signing|sign|hmac)[_-]?key\s*[:=]\s*['\"]?([A-Za-z0-9+/=]{16,64})['\"]?",
      "credential", "high", "Signing/HMAC key", group=1, entropy=3.0),
    R("session_id",
      r"(?i)\b(?:session[_-]?id|phpsessid|jsessionid|connect\.sid)\s*[:=]\s*['\"]?([\w\-]{16,128})['\"]?",
      "credential", "medium", "Session identifier", group=1, entropy=2.5),
    R("sentry_dsn", r"https://[a-f0-9]{20,}@[a-z0-9.\-]+/\d+",
      "exposure", "medium", "Sentry DSN"),
    R("new_relic_api_key", r"\bNRAK-[A-Za-z0-9]{20,}\b",
      "token", "high", "New Relic API key"),
    R("datadog_api_key",
      r"(?i)\b(?:datadog|dd)[_-]?(?:api[_-]?)?key\s*[:=]\s*['\"]?([a-f0-9]{32})['\"]?",
      "token", "high", "Datadog API key", group=1),
    R("algolia_api_key",
      r"(?i)\balgolia[_-]?(?:api[_-]?)?key\s*[:=]\s*['\"]?([a-f0-9]{32})['\"]?",
      "token", "medium", "Algolia API key", group=1),
    R("fastly_api_key",
      r"(?i)\bfastly[_-]?(?:api[_-]?)?key\s*[:=]\s*['\"]?([A-Za-z0-9_\-]{32})['\"]?",
      "token", "high", "Fastly API key", group=1),
    R("paypal_client_id",
      r"(?i)\bpaypal[_-]?client[_-]?id\s*[:=]\s*['\"]?(A[A-Za-z0-9_-]{20,60})['\"]?",
      "exposure", "low", "PayPal client ID (public identifier)", group=1),
    R("supabase_service_role_key",
      r"(?i)\bservice[_-]?role[_-]?key\s*[:=]\s*['\"](eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)['\"]",
      "token", "critical", "Supabase service-role key", group=1),

    # =====================================================================
    # Ad-tech / app config exposure
    # =====================================================================
    R("firebase_config", r"(?i)firebaseConfig\s*=\s*\{[^}]{20,800}\}",
      "exposure", "medium", "Firebase client configuration"),
    R("firebase_url", r"https?://[a-z0-9\-]+\.firebaseio\.com",
      "exposure", "low", "Firebase realtime-database URL"),
    R("supabase_url", r"https?://[a-z0-9\-]+\.supabase\.co",
      "exposure", "low", "Supabase project URL"),
    R("s3_bucket_url", r"https?://[a-z0-9.\-]+\.s3(?:[.-][a-z0-9\-]+)?\.amazonaws\.com",
      "exposure", "low", "S3 bucket reference"),
    R("gcp_bucket_url", r"https?://storage\.googleapis\.com/[A-Za-z0-9._\-]+",
      "exposure", "low", "Google Cloud Storage bucket reference"),
    R("azure_blob_url", r"https?://[a-z0-9]+\.blob\.core\.windows\.net",
      "exposure", "low", "Azure Blob storage reference"),
    R("aws_arn", r"\barn:aws:[a-z0-9\-]+:[a-z0-9\-]*:\d{12}:[^\s\"']+",
      "exposure", "info", "AWS ARN"),
    R("aws_rds_endpoint", r"\b[a-z0-9\-]+\.rds\.amazonaws\.com\b",
      "exposure", "info", "AWS RDS endpoint"),
    R("aws_dynamodb_url", r"\bdynamodb\.[a-z0-9\-]+\.amazonaws\.com\b",
      "exposure", "info", "AWS DynamoDB endpoint"),

    # =====================================================================
    # Endpoint / debug exposure (quoted paths only, low noise)
    # =====================================================================
    R("api_endpoint", r"\bhttps?://[^\s\"'<>]+/api/(?:v\d+|graphql|rest|internal)[^\s\"'<>]*",
      "endpoint", "low", "API endpoint"),
    R("admin_endpoint", r"(?i)[\"'](/[^\"']*/admin(?:/[^\"']*)?)[\"']",
      "endpoint", "low", "Admin path", group=1),
    R("debug_endpoint", r"(?i)[\"'](/[^\"']*/debug(?:/[^\"']*)?)[\"']",
      "endpoint", "low", "Debug path", group=1),
    R("test_endpoint", r"(?i)[\"'](/[^\"']*/test(?:/[^\"']*)?)[\"']",
      "endpoint", "info", "Test path", group=1),
    R("oauth_endpoint", r"(?i)[\"'](/[^\"']*/oauth/(?:authorize|token|callback)[^\"']*)[\"']",
      "endpoint", "info", "OAuth endpoint", group=1),
    R("openid_connect_endpoint", r"(?i)[\"']([^\"']*/\.well-known/openid-configuration)[\"']",
      "endpoint", "info", "OpenID Connect discovery endpoint", group=1),
    R("graphql_endpoint", r"(?i)[\"'](/[^\"']*/(?:graphql|graphiql))[\"']",
      "endpoint", "low", "GraphQL endpoint", group=1),
    R("swagger_endpoint", r"(?i)[\"'](/[^\"']*/(?:swagger|api-docs|openapi|redoc)(?:\.json|\.yaml)?)[\"']",
      "endpoint", "low", "API documentation endpoint", group=1),
    R("internal_api", r"(?i)[\"'](/[^\"']*/(?:internal|private)[_-]?api[^\"']*)[\"']",
      "endpoint", "medium", "Internal API path", group=1),
    R("websocket_endpoint", r"\bwss?://[^\s\"'<>]+",
      "endpoint", "info", "WebSocket endpoint"),

    # =====================================================================
    # PII (opt-in with --include-pii)
    # =====================================================================
    R("email_address", r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,24}\b",
      "pii", "low", "Email address", pii=True),
    R("us_ssn", r"\b\d{3}-\d{2}-\d{4}\b",
      "pii", "high", "US Social Security Number", pii=True),
    R("credit_card",
      r"\b(?:4\d{12}(?:\d{3})?|5[1-5]\d{14}|3[47]\d{13}|6(?:011|5\d{2})\d{12})\b",
      "pii", "high", "Credit card number", pii=True, tags=("pci",)),
    R("us_phone", r"\b(?:\+1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b",
      "pii", "low", "US phone number", pii=True),

    # =====================================================================
    # Noise / code-smell rules (opt-in with --include-noise)
    # =====================================================================
    R("ipv4_address", r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b",
      "exposure", "low", "IPv4 address", noise=True),
    R("path_traversal", r"\.\.[\\/]+", "code-risk", "info", "Relative path traversal sequence", noise=True),
    R("lfi_vector", r"\.\.[\\/]\.\.[\\/]", "code-risk", "low", "Local file inclusion vector", noise=True),
    R("dangerous_eval", r"\b(?:eval|execScript)\s*\(", "code-risk", "medium", "Dynamic code evaluation", noise=True),
    R("dangerous_innerhtml", r"\.innerHTML\s*=", "code-risk", "low", "innerHTML assignment (DOM XSS risk)", noise=True),
    R("dangerous_outerhtml", r"\.outerHTML\s*=", "code-risk", "low", "outerHTML assignment (DOM XSS risk)", noise=True),
    R("dangerous_document_cookie", r"\bdocument\.cookie\s*=", "code-risk", "medium", "Client-side cookie write", noise=True),
    R("dangerous_postmessage", r"\bpostMessage\s*\(", "code-risk", "info", "postMessage usage", noise=True),
    R("dangerous_window_open", r"\bwindow\.open\s*\(", "code-risk", "info", "window.open usage", noise=True),
    R("dangerous_redirect", r"\blocation\.(?:assign|replace)\s*\(", "code-risk", "low", "Client-side redirect", noise=True),
    R("dangerous_createobjecturl", r"\bURL\.createObjectURL\s*\(", "code-risk", "info", "createObjectURL usage", noise=True),
    R("command_execution",
      r"\b(?:exec|spawn|system|popen|shell_exec|passthru|proc_open|subprocess|os\.system|os\.popen)\s*\(",
      "code-risk", "medium", "Command execution sink", noise=True),
    R("file_operation",
      r"\b(?:readFile|writeFile|copyFile|moveFile|deleteFile|unlink|fs\.(?:read|write|copy|rename|unlink)|file_(?:get|put)_contents)\s*\(",
      "code-risk", "low", "File operation", noise=True),
    R("file_inclusion", r"\b(?:require|include|import)\s*\(\s*['\"][^\"']+['\"]\s*\)",
      "code-risk", "info", "Dynamic file inclusion", noise=True),
    R("xss_payload", r"<img\s+src=['\"][^\"']*onerror=['\"][^\"']*['\"]",
      "code-risk", "medium", "Potential XSS payload", noise=True),
    R("xxe_vector", r"(?i)<!DOCTYPE[^>]*\[.*<!ENTITY", "code-risk", "high", "Potential XXE declaration", noise=True),
    R("sql_query", r"(?i)\b(?:SELECT|INSERT|UPDATE|DELETE|DROP|UNION|ALTER)\s+.+\s+FROM\b",
      "code-risk", "info", "SQL query string", noise=True),
    R("sql_injection", r"(?i)(?:['\"]\s*\+|\+\s*['\"]).{0,80}(?:SELECT|INSERT|UPDATE|DELETE|DROP|UNION)",
      "code-risk", "low", "Potential SQL string concatenation", noise=True),
    R("command_injection", r"(?i)\b(?:exec|system|passthru|shell_exec|popen|proc_open)\s*\(\s*\$",
      "code-risk", "medium", "Potential command injection", noise=True),
    R("ssrf_url_fetch", r"(?i)\b(?:fetch|axios|request|urllib|http\.get|http\.request|curl)\s*\(\s*['\"]https?://",
      "code-risk", "info", "Outbound request call", noise=True),
    R("console_log", r"\bconsole\.(?:log|debug|warn|error|trace|info|dir|table)\s*\(",
      "code-risk", "info", "Console logging", noise=True),
    R("debugger_statement", r"\bdebugger\s*;", "code-risk", "info", "Debugger statement", noise=True),
    R("todo_comment", r"(?://|/\*|#)\s*TODO[:!]?\s+.+", "code-risk", "info", "TODO comment", noise=True),
    R("fixme_comment", r"(?://|/\*|#)\s*FIXME[:]?", "code-risk", "info", "FIXME comment", noise=True),
    R("hack_comment", r"(?://|/\*|#)\s*(?:HACK|WORKAROUND|XXX|TEMP)[:!]?\s+.+",
      "code-risk", "info", "Hack/workaround comment", noise=True),
    R("debug_code", r"(?://|/\*|#)\s*(?:DEBUG|TESTING)[:!]?\s+.+",
      "code-risk", "info", "Debug code comment", noise=True),
    R("inline_script", r"<script[^>]*>.*?</script>", "code-risk", "info", "Inline script block", noise=True),
    R("dangerous_iframe", r"<iframe[^>]+src=['\"][^\"']+['\"]", "code-risk", "info", "iFrame", noise=True),
    R("cors_wildcard", r"(?i)\bAccess-Control-Allow-Origin:\s*\*", "code-risk", "medium", "Wildcard CORS", noise=True),
    R("cookie_missing_flags", r"(?i)\bSet-Cookie:\s*([^;\r\n]+)(?![^\r\n]*(?:HttpOnly|Secure))",
      "code-risk", "low", "Cookie without HttpOnly/Secure flags", noise=True),
    R("missing_security_header", r"(?i)\b(?:X-Frame-Options|Strict-Transport-Security|Content-Security-Policy):",
      "code-risk", "info", "Security header present", noise=True),
    R("local_storage", r"\blocalStorage\.(?:setItem|getItem)\s*\(", "code-risk", "info", "localStorage usage", noise=True),
    R("session_storage", r"\bsessionStorage\.(?:setItem|getItem)\s*\(", "code-risk", "info", "sessionStorage usage", noise=True),
    R("indexeddb_operation", r"\bindexedDB\.(?:open|deleteDatabase)\s*\(", "code-risk", "info", "IndexedDB usage", noise=True),
    R("error_message", r"\b(?:Exception|Error|Traceback|Stacktrace)\s*:?\s*[^\s\"']+\s*(?:at\s+[^\s\"']+|\([^)]+\))",
      "code-risk", "info", "Stack trace fragment", noise=True),
]


# ---------------------------------------------------------------------------
# Registry helpers
# ---------------------------------------------------------------------------
def compile_rules(rules: Iterable[Rule]) -> List[Rule]:
    """Compile every rule, skipping invalid patterns (with a warning)."""
    compiled: List[Rule] = []
    for rule in rules:
        try:
            compiled.append(rule.compile())
        except re.error as exc:  # pragma: no cover - defensive
            # Import here to avoid a hard logging dependency at import time.
            import logging

            logging.getLogger("secref.rules").warning("Skipping invalid rule %s: %s", rule.id, exc)
    return compiled


def iter_builtin_rules() -> Iterable[Rule]:
    return BUILTIN_RULES


def builtin_patterns(include_noise: bool = False, include_pii: bool = False) -> Dict[str, str]:
    """Backward-compatible ``id -> regex`` view of the built-in rules."""
    rules = [r for r in BUILTIN_RULES if not r.noise or include_noise]
    if not include_pii:
        rules = [r for r in rules if not r.pii]
    return {r.id: r.pattern for r in rules}


def all_rule_ids() -> Dict[str, Rule]:
    return {r.id: r for r in BUILTIN_RULES}


def validate_rule_metadata() -> List[str]:
    """Return human-readable consistency problems (used by tests)."""
    problems: List[str] = []
    seen = set()
    for rule in BUILTIN_RULES:
        if rule.id in seen:
            problems.append(f"duplicate rule id: {rule.id}")
        seen.add(rule.id)
        try:
            compiled = re.compile(rule.pattern)
        except re.error as exc:
            problems.append(f"{rule.id}: invalid regex: {exc}")
            continue
        groups = compiled.groups
        if rule.secret_group > groups:
            problems.append(f"{rule.id}: secret_group {rule.secret_group} > {groups} groups")
        if rule.noise and rule.pii:
            problems.append(f"{rule.id}: cannot be both noise and pii")
    return problems
