# Changelog

All notable changes to this project are documented here.
The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)
and the project uses [Semantic Versioning](https://semver.org/).

## [8.1.0] - 2026-11-07

This release turns the scanner into a live repository and pre-commit security
tool.

### Added

- **Live GitHub repository scanning**: `--github owner/repo` downloads a
  zipball through the GitHub API (or clones when history is requested), safely
  extracts it, scans the tree, and reports `github://owner/repo/...` URLs.
  Private repositories use `--github-token`, `GITHUB_TOKEN`, or `GH_TOKEN`.
- **GitHub org/user discovery**: `--github-org` / `--github-user` with
  `--github-limit` and `--github-include-forks` scans public repositories in
  bulk. A failed repository does not abort the batch.
- **Git history scanning**: `--git-history`, `--git-history-depth`, and
  `--git-since` scan added lines across commits with commit, author, date, and
  message provenance.
- **Staged/changed scanning**: `--staged` and `--changed` for pre-commit and
  local workflows; includes untracked files for `--changed`.
- **Whole-file entropy scanning**: opt-in `--entropy-scan`,
  `--entropy-min-length`, and `--entropy-scan-threshold` detect generic
  high-entropy tokens while ignoring URLs, paths, and hash contexts.
- **GitHub Actions supply-chain audit**: `--audit-github-actions` detects
  unpinned actions, unsafe `pull_request_target` checkouts, script injection,
  `permissions: write-all`, and inherited secrets.
- **JUnit XML output**: `--format junit` for CI reporters.
- **Webhook notifications**: `--webhook`, `--webhook-format` (Slack, Discord,
  generic), and `--webhook-min-severity`; values are always redacted.
- **Auto allowlisting**: `--write-ignore PATH` writes precise hashed
  fingerprints; `--allowlist-values` optionally writes exact value regexes.
- **Fingerprint allowlists**: `.secrefignore` now supports
  `fingerprint: <sha256-prefix>` entries, so an allowlist can suppress a
  finding without storing the secret.
- **First-party GitHub Action** (`action.yml`) with SARIF upload, and
  `.pre-commit-hooks.yaml` hooks for staged scans.

### Changed

- `--include-endpoints` is now the explicit switch for endpoint discovery;
  endpoint rules and optional plugins are off by default.
- Output metadata includes `source`, `repo`, `commit`, `author`, and
  `commit_date` when available.
- Version bumped to `8.1.0`.

## [8.0.0] - 2026-11-07

**Signal over noise.** This release rebuilds the detection layer, adds local
scanning, and makes the tool usable as a CI gate.

### Added

- Canonical `Rule` registry with 128 built-in rules and per-rule metadata:
  `severity`, `category`, `description`, `secret_group`, `entropy_min`, `noise`,
  `pii`, and tags.
- High-signal defaults: 79 rules enabled by default. Code smells, PII, and
  endpoint discovery are opt-in via `--include-noise`, `--include-pii`, and
  `--include-endpoints`.
- Local filesystem scanning with `--path <file|dir>` and stdin scanning with
  `--path -`, including binary detection, size limits, skip directories, and
  artifact filtering.
- Allowlist engine: `.secrefignore`, `--ignore-file`, and inline
  `# secref:ignore` suppression by rule, value, path, or URL.
- CI exit codes via `--fail-on {never,low,medium,high,critical}`.
- Severity/category metadata in every output format, plus severity summaries.
- HTML dashboard with severity filters and SARIF rule metadata with
  `security-severity`.
- `--show-context` evidence snippets and `--redact` output.
- `--include-type` / `--exclude-type` and `--min-severity` rule filtering.
- `--max-per-rule` cap and rule/value/location deduplication.
- Hashed differential baselines with `--baseline` and `--update-baseline`.
  Raw secrets are no longer written to baseline files.
- Concurrent, allow-listed read-only validation for GitHub, GitLab, Slack,
  OpenAI, Anthropic, SendGrid, Stripe, Mailgun, DigitalOcean, Hugging Face,
  npm, and Telegram tokens.
- 64 pytest tests, a Python 3.8-3.13 CI matrix, package build checks, Docker
  image, and a rule documentation generator ([RULES.md](RULES.md)).
- `CHANGELOG.md`, `SECURITY.md`, `.gitignore`, `.dockerignore`, and
  `CONTRIBUTING.md` guidance for rule and plugin contributions.

### Changed

- Rule-aware validation replaces blanket entropy checks. Entropy is applied
  only where a rule benefits from it; default global floor is `0.0`.
- Captured secret groups are reported instead of the entire matched assignment.
- Default request delay is now `1.0s`; default scan rules are curated rather
  than "every regex in the file".
- `--baseline` only filters results. Use `--update-baseline PATH` to write a
  new baseline.
- AWS access-key IDs are reported but never live-validated (an ID alone is not
  sufficient to verify a key pair).
- Plugin registry now works for both `from src.plugins` and
  `from plugins import register_plugin`.
- Crawler reuses prefetched pages instead of fetching every URL twice.
- Interactive mode offers local/web/stdin targets and endpoint discovery.

### Fixed

- `--interactive` is now honored by the entry point.
- 429 retries are iterative instead of recursive.
- Duplicate log handlers on repeated setup.
- Checkpoint monitor now waits on `unfinished_tasks` instead of `empty()`.
- Worker exceptions are contained and no longer kill the scan silently.
- Robots.txt is implemented for `--respect-robots`.
- Proxy authentication is applied correctly.
- Cookie files support `#HttpOnly_` entries.
- Local scans no longer re-scan their own logs and findings files.

### Security

- Baselines store salted SHA-256 fingerprints, not secret values.
- Live validation is disabled by `--safe-mode` and never auto-runs AWS checks.
- Reports may contain live credentials; use `--redact` before sharing.

## [7.0.0] - 2025-01-01

### Added

- Scriptable argparse CLI with proxy, custom headers, cookies, POST body, and
  crawl scope/depth/exclusion controls.
- Six output formats: JSON, JSONL, CSV, Markdown, HTML, SARIF.
- Checkpoint/resume and differential baselines.
- Plugin system, custom YAML/JSON patterns, and built-in discovery plugins.
- Optional active validation for several providers.
- Structured rotating logs and an audit stream.

## [6.0.0] - 2024-01-01

### Added

- Modular package layout under `src/`.
- Multi-threaded website and JavaScript scanning.
- Initial regex pattern collection, entropy checks, and interactive menu.

[8.1.0]: https://github.com/LifeJiggy/Super-Secref-Finder/compare/v8.0.0...v8.1.0
[8.0.0]: https://github.com/LifeJiggy/Super-Secref-Finder/compare/v7.0.0...v8.0.0
[7.0.0]: https://github.com/LifeJiggy/Super-Secref-Finder/releases/tag/v7.0.0
[6.0.0]: https://github.com/LifeJiggy/Super-Secref-Finder/releases/tag/v6.0.0
