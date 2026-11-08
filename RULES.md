# Detection Rules

> Generated from `src/rules.py` by `python scripts/generate_rules_doc.py`.
> **128 built-in rules** - **79 enabled by default**.

Default scans enable real secret/token/credential/cloud rules plus
high-value exposure checks. Code smells, PII, and endpoint discovery are
opt-in so the first run stays readable.

| Opt-in | Flag | Count |
|---|---|---:|
| Code smells | `--include-noise` | 35 |
| PII | `--include-pii` | 4 |
| Endpoints | `--include-endpoints` | 10 |

## Severity distribution

| Severity | Rules |
|---|---:|
| critical | 15 |
| high | 47 |
| medium | 14 |
| low | 24 |
| info | 28 |

## Category distribution

| Category | Rules |
|---|---:|
| code-risk | 34 |
| token | 34 |
| exposure | 15 |
| cloud | 13 |
| credential | 12 |
| endpoint | 10 |
| pii | 4 |
| supply-chain | 4 |
| secret | 2 |

## All rules

| Rule | Severity | Category | Default | Description |
|---|---|---|---|---|
| `aws_access_key_id` | critical | cloud | yes | AWS access key ID |
| `aws_mws_key` | high | cloud | yes | Amazon MWS auth token |
| `aws_secret_access_key` | critical | cloud | yes | AWS secret access key |
| `aws_session_token` | critical | cloud | yes | AWS temporary session token |
| `azure_client_secret` | high | cloud | yes | Azure AD client secret |
| `azure_sas_token` | medium | cloud | yes | Azure shared-access-signature token |
| `azure_storage_connection_string` | critical | cloud | yes | Azure Storage connection string |
| `cloudflare_api_token` | high | cloud | yes | Cloudflare API token |
| `digitalocean_oauth_token` | high | cloud | yes | DigitalOcean OAuth token |
| `digitalocean_personal_access_token` | high | cloud | yes | DigitalOcean personal access token |
| `gcp_service_account_key` | high | cloud | yes | GCP service-account JSON document |
| `google_api_key` | high | cloud | yes | Google API key |
| `heroku_api_key` | high | cloud | yes | Heroku API key |
| `command_execution` | medium | code-risk | noise | Command execution sink |
| `command_injection` | medium | code-risk | noise | Potential command injection |
| `console_log` | info | code-risk | noise | Console logging |
| `cookie_missing_flags` | low | code-risk | noise | Cookie without HttpOnly/Secure flags |
| `cors_wildcard` | medium | code-risk | noise | Wildcard CORS |
| `dangerous_createobjecturl` | info | code-risk | noise | createObjectURL usage |
| `dangerous_document_cookie` | medium | code-risk | noise | Client-side cookie write |
| `dangerous_eval` | medium | code-risk | noise | Dynamic code evaluation |
| `dangerous_iframe` | info | code-risk | noise | iFrame |
| `dangerous_innerhtml` | low | code-risk | noise | innerHTML assignment (DOM XSS risk) |
| `dangerous_outerhtml` | low | code-risk | noise | outerHTML assignment (DOM XSS risk) |
| `dangerous_postmessage` | info | code-risk | noise | postMessage usage |
| `dangerous_redirect` | low | code-risk | noise | Client-side redirect |
| `dangerous_window_open` | info | code-risk | noise | window.open usage |
| `debug_code` | info | code-risk | noise | Debug code comment |
| `debugger_statement` | info | code-risk | noise | Debugger statement |
| `error_message` | info | code-risk | noise | Stack trace fragment |
| `file_inclusion` | info | code-risk | noise | Dynamic file inclusion |
| `file_operation` | low | code-risk | noise | File operation |
| `fixme_comment` | info | code-risk | noise | FIXME comment |
| `hack_comment` | info | code-risk | noise | Hack/workaround comment |
| `indexeddb_operation` | info | code-risk | noise | IndexedDB usage |
| `inline_script` | info | code-risk | noise | Inline script block |
| `lfi_vector` | low | code-risk | noise | Local file inclusion vector |
| `local_storage` | info | code-risk | noise | localStorage usage |
| `missing_security_header` | info | code-risk | noise | Security header present |
| `path_traversal` | info | code-risk | noise | Relative path traversal sequence |
| `session_storage` | info | code-risk | noise | sessionStorage usage |
| `sql_injection` | low | code-risk | noise | Potential SQL string concatenation |
| `sql_query` | info | code-risk | noise | SQL query string |
| `ssrf_url_fetch` | info | code-risk | noise | Outbound request call |
| `todo_comment` | info | code-risk | noise | TODO comment |
| `xss_payload` | medium | code-risk | noise | Potential XSS payload |
| `xxe_vector` | high | code-risk | noise | Potential XXE declaration |
| `basic_auth_url` | high | credential | yes | URL containing HTTP basic-auth credentials |
| `client_secret` | high | credential | yes | OAuth client secret |
| `database_uri_with_credentials` | critical | credential | yes | Database URI containing credentials |
| `django_secret_key` | high | credential | yes | Django SECRET_KEY |
| `encryption_key` | high | credential | yes | Encryption key |
| `flask_secret_key` | medium | credential | yes | Flask application secret key |
| `hardcoded_credential` | high | credential | yes | Hardcoded credential assignment |
| `http_authorization_bearer` | high | credential | yes | Authorization: Bearer credential |
| `private_key_header` | critical | credential | yes | Private key block |
| `rails_secret_key` | high | credential | yes | Rails secret_key_base |
| `session_id` | medium | credential | yes | Session identifier |
| `signing_key` | high | credential | yes | Signing/HMAC key |
| `admin_endpoint` | low | endpoint | endpoint | Admin path |
| `api_endpoint` | low | endpoint | endpoint | API endpoint |
| `debug_endpoint` | low | endpoint | endpoint | Debug path |
| `graphql_endpoint` | low | endpoint | endpoint | GraphQL endpoint |
| `internal_api` | medium | endpoint | endpoint | Internal API path |
| `oauth_endpoint` | info | endpoint | endpoint | OAuth endpoint |
| `openid_connect_endpoint` | info | endpoint | endpoint | OpenID Connect discovery endpoint |
| `swagger_endpoint` | low | endpoint | endpoint | API documentation endpoint |
| `test_endpoint` | info | endpoint | endpoint | Test path |
| `websocket_endpoint` | info | endpoint | endpoint | WebSocket endpoint |
| `aws_arn` | info | exposure | yes | AWS ARN |
| `aws_dynamodb_url` | info | exposure | yes | AWS DynamoDB endpoint |
| `aws_rds_endpoint` | info | exposure | yes | AWS RDS endpoint |
| `azure_blob_url` | low | exposure | yes | Azure Blob storage reference |
| `firebase_config` | medium | exposure | yes | Firebase client configuration |
| `firebase_url` | low | exposure | yes | Firebase realtime-database URL |
| `gcp_bucket_url` | low | exposure | yes | Google Cloud Storage bucket reference |
| `google_oauth_client_id` | low | exposure | yes | Google OAuth client ID (public identifier) |
| `ipv4_address` | low | exposure | noise | IPv4 address |
| `paypal_client_id` | low | exposure | yes | PayPal client ID (public identifier) |
| `s3_bucket_url` | low | exposure | yes | S3 bucket reference |
| `sentry_dsn` | medium | exposure | yes | Sentry DSN |
| `stripe_publishable_key` | low | exposure | yes | Stripe publishable key (public identifier) |
| `supabase_url` | low | exposure | yes | Supabase project URL |
| `twilio_account_sid` | low | exposure | yes | Twilio account SID |
| `credit_card` | high | pii | pii | Credit card number |
| `email_address` | low | pii | pii | Email address |
| `us_phone` | low | pii | pii | US phone number |
| `us_ssn` | high | pii | pii | US Social Security Number |
| `api_key` | high | secret | yes | API key or access token |
| `generic_secret_assignment` | high | secret | yes | Generic secret assignment with high-entropy value |
| `ci_cd_token` | high | supply-chain | yes | CI/CD job token |
| `docker_registry_auth` | medium | supply-chain | yes | Docker registry auth blob |
| `github_actions_secret` | info | supply-chain | yes | GitHub Actions secret reference (not a value) |
| `npmrc_auth_token` | high | supply-chain | yes | npm registry auth token |
| `algolia_api_key` | medium | token | yes | Algolia API key |
| `anthropic_api_key` | critical | token | yes | Anthropic API key |
| `atlassian_token` | high | token | yes | Atlassian API token |
| `cohere_api_key` | high | token | yes | Cohere API key |
| `datadog_api_key` | high | token | yes | Datadog API key |
| `discord_token` | critical | token | yes | Discord bot/user token |
| `discord_webhook` | high | token | yes | Discord webhook |
| `fastly_api_key` | high | token | yes | Fastly API key |
| `github_fine_grained_pat` | critical | token | yes | GitHub fine-grained personal access token |
| `github_token` | critical | token | yes | GitHub personal/OAuth token |
| `gitlab_runner_token` | high | token | yes | GitLab runner token |
| `gitlab_token` | critical | token | yes | GitLab personal access token |
| `groq_api_key` | high | token | yes | Groq API key |
| `huggingface_token` | high | token | yes | Hugging Face access token |
| `jwt_token` | high | token | yes | JSON Web Token |
| `mailchimp_api_key` | high | token | yes | Mailchimp API key |
| `mailgun_api_key` | high | token | yes | Mailgun API key |
| `new_relic_api_key` | high | token | yes | New Relic API key |
| `npm_token` | high | token | yes | npm access token |
| `openai_api_key` | critical | token | yes | OpenAI API key |
| `openrouter_api_key` | high | token | yes | OpenRouter API key |
| `perplexity_api_key` | high | token | yes | Perplexity API key |
| `pypi_token` | high | token | yes | PyPI upload token |
| `replicate_api_token` | high | token | yes | Replicate API token |
| `sendgrid_api_key` | high | token | yes | SendGrid API key |
| `shopify_access_token` | high | token | yes | Shopify access token |
| `shopify_shared_secret` | high | token | yes | Shopify shared secret |
| `slack_token` | critical | token | yes | Slack token |
| `slack_webhook` | high | token | yes | Slack incoming webhook |
| `stripe_secret_key` | critical | token | yes | Stripe secret/restricted key |
| `stripe_webhook_secret` | high | token | yes | Stripe webhook signing secret |
| `supabase_service_role_key` | critical | token | yes | Supabase service-role key |
| `telegram_bot_token` | high | token | yes | Telegram bot token |
| `twilio_api_key` | high | token | yes | Twilio API key |

## Add a rule

1. Add a `Rule(...)` entry to `src/rules.py`.
2. Capture the secret value with a group and set `secret_group`.
3. Set `entropy_min` only when the value itself benefits from it.
4. Mark code smells with `noise=True`, PII with `pii=True`, and use
   `category="endpoint"` for endpoint discovery.
5. Run `python scripts/generate_rules_doc.py` and `pytest -q`.
