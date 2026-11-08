# Super Secref Finder

### High-signal secret scanning for web apps, JavaScript bundles, and local files.

[![CI](https://github.com/LifeJiggy/Super-Secref-Finder/actions/workflows/ci.yml/badge.svg)](https://github.com/LifeJiggy/Super-Secref-Finder/actions/workflows/ci.yml)
[![Python 3.8+](https://img.shields.io/badge/python-3.8%2B-blue.svg)](https://www.python.org/downloads/)
[![Rules](https://img.shields.io/badge/rules-128-brightgreen.svg)](RULES.md)
[![SARIF](https://img.shields.io/badge/SARIF-supported-purple.svg)](#ci-and-github-code-scanning)
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![PRs welcome](https://img.shields.io/badge/PRs-welcome-ff69b4.svg)](CONTRIBUTING.md)

Most regex secret scanners are noisy. They flag every 32-character string, every UUID,
every `<script>` tag, and every `../` path, then leave you to triage hundreds of
non-findings. **Super Secref Finder v8 is built around one rule: signal over noise.**

It scans web pages, linked JavaScript, local repositories, and stdin, but only reports
findings that have a plausible secret shape, context, and severity. Code smells, PII,
and endpoint discovery are opt-in.

```text
$ secref --path . --min-severity high

CRITICAL  aws_access_key_id              src/.env:2
HIGH      github_token                   src/.env:3
CRITICAL  database_uri_with_credentials  src/.env:4
```

---

## Why v8 is different

| Problem in v7 | What v8 does |
|---|---|
| 35 findings, 0 real secrets on a real site | 79 curated default rules; broad UUID/32-char rules rewritten with context |
| `inline_script`, `path_traversal`, `console.log` in every report | Code smells moved behind `--include-noise` |
| `match.group(0)` stored the whole `key = "value"` line | Rules capture the actual secret group |
| No severity, category, or rule metadata | Every rule has `severity`, `category`, `description`, tags |
| No way to suppress accepted risks | `.secrefignore`, inline `secref:ignore`, `--ignore-file` |
| No CI behaviour | `--fail-on` exit codes and SARIF output |
| Only scanned URLs | `--path .` and `--path -` for local files and stdin |
| No tests, CI, or container | 91 pytest tests, GitHub Actions matrix, Docker image |

---

## Features

- **128 built-in rules** across AWS, GCP, Azure, GitHub, GitLab, Slack, Stripe,
  OpenAI, Anthropic, Hugging Face, npm, SendGrid, Mailgun, DigitalOcean, JWT,
  private keys, database URIs, webhooks, and more. See [RULES.md](RULES.md).
- **High-signal defaults** - 79 rules enabled by default. Code smells, PII, and
  endpoints are opt-in.
- **Local scanning** - scan a file, a directory, or stdin. Skips `.git`,
  `node_modules`, binaries, and tool-generated artifacts.
- **Live GitHub scanning** - scan `owner/repo`, a GitHub URL, or every public
  repository in an org/user. Private repos use a token. History scans clone the
  repository and report commit/author provenance.
- **Git history and pre-commit modes** - `--git-history`, `--staged`, and
  `--changed` catch secrets that were committed or are about to be committed.
- **Web and JavaScript scanning** - crawl links, discover JS bundles, respect scope,
  robots.txt, exclusions, and request delays.
- **Entropy and workflow audit** - opt-in generic high-entropy detection and
  GitHub Actions supply-chain checks (unpinned actions, unsafe checkouts,
  script injection, `write-all`, inherited secrets).
- **Evidence, not just matches** - line/column, context snippet, confidence,
  severity, category, and optional live validation.
- **CI-first output** - JSON, JSONL, CSV, Markdown, HTML dashboard, SARIF, and
  JUnit XML. `--fail-on high` makes the scan a quality gate.
- **Allowlist engine** - ignore by rule, value, path, URL, or hashed
  fingerprint; inline suppression with `# secref:ignore`; generate a precise
  allowlist with `--write-ignore`.
- **Differential scans** - store a hashed baseline and report only new findings.
- **Webhook notifications** - post a redacted summary to Slack, Discord, or a
  generic endpoint.
- **Custom rules and plugins** - YAML/JSON rule files and a Python plugin API.
- **Safe by default** - live validation is allow-listed, read-only, and can be
  disabled with `--safe-mode`.

---

## Install

```bash
pip install super-secref-finder
```

From source:

```bash
git clone https://github.com/LifeJiggy/Super-Secref-Finder.git
cd Super-Secref-Finder
pip install -e ".[dev]"
```

Requirements: Python 3.8+, `requests`, `colorama`, `pyyaml`.

---

## Quick start

### Scan a local project

```bash
secref --path .
```

### Scan a website and its JavaScript

```bash
secref https://example.com --depth 2 --max-urls 200
```

### Scan stdin

```bash
cat config.yml | secref --path -
```

### Scan a live GitHub repository

```bash
secref --github owner/repo
secref --github https://github.com/owner/repo/tree/dev
secref --github owner/repo --github-token "$GITHUB_TOKEN"   # private repos
```

### Scan every public repository in an org or user

```bash
secref --github-org acme --github-limit 25
secref --github-user octocat --github-limit 10
```

### Scan git history or the files you are about to commit

```bash
secref --path . --git-history --git-history-depth 200
secref --staged --fail-on high
secref --changed
```

### Audit GitHub Actions workflows

```bash
secref --path . --audit-github-actions
```

### Produce reports for a pull request

```bash
secref --path . \
  --format json sarif junit \
  --fail-on high \
  --min-severity medium \
  -o reports
```

### See the rule catalogue

```bash
secref --list-rules
```

### Guided interactive mode

```bash
secref --interactive
# or
python Regex_patterns.py
```

---

## What gets scanned

| Target | Command |
|---|---|
| Current directory | `secref --path .` |
| One file | `secref --path src/config.py` |
| Stdin | `secref --path -` |
| Website | `secref https://example.com` |
| Specific JS files | `secref https://example.com --js https://example.com/app.js` |
| Authenticated area | `secref https://app.example.com --header "Authorization: Bearer ..."` |
| Through Burp/ZAP | `secref https://example.com --proxy http://127.0.0.1:8080` |
| GitHub repository | `secref --github owner/repo` |
| GitHub org / user | `secref --github-org acme --github-limit 25` |
| Staged files | `secref --staged` |
| Modified files | `secref --changed` |
| Git history | `secref --path . --git-history` |

Local scans skip common noise automatically: `.git`, `node_modules`, `venv`,
`dist`, `build`, `__pycache__`, images, archives, binaries, oversized files, and
previous `findings_*.json` / `secref*.log` artifacts.

GitHub repositories are downloaded through the GitHub API as zipballs (or cloned
when `--git-history` is used) and extracted with zip-slip and size protections.
Findings use `github://owner/repo/path` URLs instead of temporary paths.

---

## Detection model

Every rule is a `Rule` object with:

```python
Rule(
    id="github_token",
    pattern=r"\b(ghp_[A-Za-z0-9]{30,})\b",
    category="token",
    severity="critical",
    description="GitHub personal access token",
    secret_group=1,
    entropy_min=0.0,
    noise=False,
    pii=False,
    tags=("github", "scm"),
)
```

The scanner:

1. Applies the curated rule set once per scan.
2. Extracts the captured secret value (not the surrounding assignment).
3. Rejects placeholders, documentation values, and non-secret shapes.
4. Applies rule-specific entropy floors only where they help.
5. Deduplicates by rule + value + location and caps findings per rule per document.
6. Optionally validates the token against a read-only provider endpoint.

### Opt-in rule groups

| Group | Flag | Examples |
|---|---|---|
| Code smells | `--include-noise` | `eval`, `console.log`, `innerHTML`, `path_traversal` |
| PII | `--include-pii` | emails, phone numbers, SSNs, credit cards |
| Endpoint discovery | `--include-endpoints` | API paths, admin panels, GraphQL endpoints |
| Generic entropy | `--entropy-scan` | random tokens not matched by a specific rule |
| Workflow audit | `--audit-github-actions` | unpinned actions, unsafe checkouts, script injection |

`--entropy-scan` is deliberately conservative: it skips URLs, file paths, and
values near `sha`, `md5`, `hash`, `checksum`, or `integrity` labels. Tune it with
`--entropy-min-length` and `--entropy-scan-threshold`.

### Severity

| Severity | Meaning |
|---|---|
| `critical` | Direct credential with high abuse impact (AWS keys, private keys, DB URIs) |
| `high` | Service token or signed credential (GitHub, Slack, OpenAI, JWT) |
| `medium` | Contextual secret or client-side configuration with limited impact |
| `low` | Exposure metadata, publishable keys, weak indicators |
| `info` | Informational code/endpoint discoveries |

Use `--min-severity` to tune the report, and `--fail-on` to decide which
severities break CI.

---

## Allowlisting

Create `.secrefignore` in the project root:

```text
# Exact rule IDs
rule: ^generic_secret_assignment$

# A known test value (regex)
value: ^ghp_b{36}$

# A hashed fingerprint (rule + value, no secret stored)
fingerprint: ^a1b2c3d4e5f6

# Generated or vendored paths
path: */vendor/*
path: *.min.js

# Known-safe URLs
url: ^https://example\.com/sandbox/
```

Suppress a single line inline:

```python
EXAMPLE_TOKEN = "ghp_..."  # secref:ignore
```

Use another file with `--ignore-file path/to/ignore`.

Generate a precise allowlist from the current findings:

```bash
# Hashed fingerprints: suppresses exact findings without storing secrets
secref --path . --write-ignore .secrefignore

# Also write raw value regexes (review before committing)
secref --path . --write-ignore .secrefignore --allowlist-values
```

---

## Custom rules

```yaml
patterns:
  internal_api_key:
    regex: "(?i)\\binternal[_-]?api[_-]?key\\s*[:=]\\s*['\"]([A-Za-z0-9]{32,})['\"]"
    description: "Internal API key"
    severity: high
    category: secret
    group: 1
    entropy: 3.0
```

```bash
secref --path . --custom-patterns custom_patterns.yaml
```

See [`src/custom_patterns_example.yaml`](src/custom_patterns_example.yaml) for the
full schema. Simple `name: regex` entries still work.

---

## Plugins

Drop a Python file into a plugin directory and register a function:

```python
from plugins import register_plugin

@register_plugin("my_scanner")
def my_scanner(url, text, findings):
    return [{
        "type": "custom_finding",
        "value": "example",
        "url": url,
        "confidence": 0.8,
        "start": 0,
        "end": 7,
    }]
```

```bash
secref https://example.com --plugin-dir ./plugins
```

Built-in plugins cover Firebase configuration, S3 bucket references, API
discovery, and hardcoded IP addresses. API discovery and hardcoded-IP results
are opt-in with `--include-endpoints` or `--include-noise`.

---

## Output formats

| Format | Flag | Best for |
|---|---|---|
| JSON | `--format json` | Automation, full metadata, severity summary |
| JSONL | `--format jsonl` | Streaming pipelines |
| CSV | `--format csv` | Spreadsheets and triage queues |
| Markdown | `--format md` | Pull request comments and reports |
| HTML | `--format html` | Shareable dashboard with filters |
| SARIF | `--format sarif` | GitHub code scanning and CI security tabs |
| JUnit XML | `--format junit` | Jenkins/GitLab/Azure test reporters |

Every finding includes `type`, `value`, `url`, `severity`, `category`,
`confidence`, `validated`, `line`, `column`, and optional `context`. Findings
from GitHub/history scans also include `source`, `repo`, `commit`, `author`, and
`commit_date` when available. Use `--redact` to mask values in output.

---

## CI and GitHub Code Scanning

Use the first-party composite action (SARIF is uploaded automatically):

```yaml
name: Secret scan
on: [push, pull_request]

permissions:
  contents: read
  security-events: write

jobs:
  secref:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: LifeJiggy/Super-Secref-Finder@v8
        with:
          path: "."
          formats: "json sarif"
          fail-on: high
          args: "--min-severity medium"
```

Or run the CLI directly:

```yaml
name: Secret scan
on: [push, pull_request]

jobs:
  secref:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.12"
      - run: pip install super-secref-finder
      - run: secref --path . --format sarif --fail-on high -o reports
      - uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: reports/findings_*.sarif
```

### Pre-commit hook

```yaml
# .pre-commit-config.yaml
repos:
  - repo: https://github.com/LifeJiggy/Super-Secref-Finder
    rev: v8.1.0
    hooks:
      - id: secref
      - id: secref-workflow-audit
```

`secref` scans staged files only and fails on high-severity findings. See
[`.pre-commit-hooks.yaml`](.pre-commit-hooks.yaml).

### Notifications

```bash
secref --path . \
  --webhook https://hooks.slack.com/services/... \
  --webhook-format slack \
  --webhook-min-severity high
```

Values are redacted before they leave the process. Discord and generic JSON
payloads are supported with `--webhook-format`.

Exit codes:

| Code | Meaning |
|---|---|
| `0` | No findings at or above `--fail-on` |
| `1` | Findings at or above `--fail-on` |
| `2` | Usage/configuration error |

### Differential scans

```bash
# Create a hashed baseline (raw secrets are never stored)
secref --path . --update-baseline .secref-baseline.json

# Report only new findings
secref --path . --baseline .secref-baseline.json
```

---

## Docker

```bash
docker build -t secref .
docker run --rm -v "$PWD:/scan" secref --path /scan --format json
```

---

## Rule coverage

| Category | Rules |
|---|---:|
| Token | 34 |
| Code smells (opt-in) | 34 |
| Exposure / configuration | 15 |
| Cloud | 13 |
| Credential / connection string | 12 |
| Endpoint discovery (opt-in) | 10 |
| PII (opt-in) | 4 |
| Supply chain | 4 |
| Secret / generic | 2 |
| **Total** | **128** |

Run `secref --list-rules` or open [RULES.md](RULES.md) for the full table.

---

## How it compares

| Capability | Super Secref Finder v8.1 | gitleaks | trufflehog | detect-secrets |
|---|---|---|---|---|
| Local files/directories | Yes | Yes | Yes | Yes |
| Live GitHub repo/org scanning | Yes | No | Yes | No |
| Web pages + JS crawling | Yes | No | No | No |
| Staged/changed pre-commit mode | Yes | Yes | Partial | Yes |
| Git history scanning | Yes | Yes | Yes | No |
| Whole-file entropy scan | Yes (opt-in) | Yes | Yes | Partial |
| GitHub Actions workflow audit | Yes | Partial | No | No |
| Rule severity/category | Yes | Yes | Partial | Partial |
| Allowlist + inline ignore | Yes | Yes | Partial | Yes |
| Fingerprint allowlists | Yes | No | No | No |
| CI exit codes | Yes | Yes | Partial | Yes |
| SARIF / JUnit | Yes | SARIF | SARIF | Partial |
| HTML dashboard | Yes | No | No | No |
| Custom YAML/JSON rules | Yes | TOML | No | Yes |
| Plugin API | Yes | Yes | Yes | Partial |
| Live validation | Yes (allow-listed) | Partial | Yes | No |

Super Secref Finder combines working-tree, web/JS, GitHub, history, and
workflow checks in one tool. It remains complementary to specialized
history scanners and to provider-side secret management.

---

## Architecture

```text
src/
  __init__.py          # Public API + lazy exports
  __main__.py          # python -m src entry point
  cli.py               # argparse CLI
  config.py            # ScanConfig dataclass + validation
  rules.py             # Canonical 128-rule registry with metadata
  patterns.py          # Rule selection + custom YAML/JSON loading
  validators.py        # Placeholder, Luhn, JWT, entropy, confidence
  entropy.py           # Shannon entropy + secret-likeness heuristics
  entropy_scan.py      # Opt-in generic high-entropy token scan
  allowlist.py         # .secrefignore, fingerprints, inline suppression
  filesystem.py        # Local file/dir/stdin scanning
  github.py            # Live repo download, org/user discovery, safe unzip
  gitscan.py           # Staged/changed files + git history documents
  workflow_audit.py    # GitHub Actions supply-chain checks
  fetcher.py           # HTTP session, retries, proxies, size limits
  crawler.py           # BFS crawling, JS discovery, robots, scope
  scanner.py           # Orchestration, dedupe, validation, exit codes
  output.py            # JSON/JSONL/CSV/MD/HTML/SARIF/JUnit writers
  checkpoint.py        # Resume + hashed differential baselines
  notify.py            # Redacted Slack/Discord/generic webhooks
  plugins.py           # Plugin registry + built-in plugins
  secret_validator.py  # Allow-listed read-only token validation
  logging_config.py    # Rotating logs + separate audit logger
  interactive.py       # Guided prompts
tests/                 # 91 pytest tests
scripts/               # Rule documentation generator
action.yml             # Composite GitHub Action with SARIF upload
```

---

## Development

```bash
python -m pip install -e ".[dev]"
pytest -q
pytest --cov=src --cov-report=term-missing
ruff check src tests
python scripts/generate_rules_doc.py
```

The CI workflow runs the test suite on Python 3.8-3.13 and a lint pass.

---

## Roadmap

- [ ] Source-map and bundler chunk discovery
- [ ] gitleaks TOML rule import
- [ ] `--serve` web dashboard
- [ ] Per-host rate-limit scheduler and adaptive concurrency
- [ ] Secret rotation guidance links per rule
- [ ] Provider-side validation for more token types

---

## Security

This is a defensive tool. Live validation is **read-only**, allow-listed, and
disabled by `--safe-mode`. Baselines store salted fingerprints instead of raw
secrets. Reports can contain real credentials: treat them as sensitive and use
`--redact` when sharing.

Report vulnerabilities privately as described in [SECURITY.md](SECURITY.md).

## Contributing

Issues, rule contributions, and false-positive reports are welcome. Please read
[CONTRIBUTING.md](CONTRIBUTING.md) first.

## License

MIT - see [LICENSE](LICENSE).

## Disclaimer

Use this tool only on systems you own or have explicit permission to test.
Unauthorized scanning may be illegal. The maintainers are not responsible for
misuse.

---

If this project saves you triage time, **star the repo** so more developers can
find it.

[![Star History Chart](https://api.star-history.com/svg?repos=LifeJiggy/Super-Secref-Finder&type=Date)](https://star-history.com/#LifeJiggy/Super-Secref-Finder&Date)
