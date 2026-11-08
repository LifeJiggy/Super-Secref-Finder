# Changelog

All notable changes to this project are documented here.
The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)
and the project uses [Semantic Versioning](https://semver.org/).

## [8.3.0] - 2026-11-08

This release adds interoperability with rules and suppression comments from
Semgrep, gitleaks, secretlint, detect-secrets, and Bandit.

### Added

- **Semgrep-compatible YAML import**: `--semgrep-config PATH` imports the safe
  regex subset of Semgrep rules: `pattern-regex`, `pattern-either`,
  `pattern-not-regex`, `paths.include`/`paths.exclude`, `metadata.category`,
  `metadata.tags`, `metadata.entropy`, severity mapping, and `fix`.
  AST-only predicates are skipped with a warning.
- **Path-scoped rules**: custom rules and Semgrep imports can restrict matches
  to include globs and exclude vendored, test, or generated paths.
- **Negative patterns**: `pattern_not` / `pattern-not-regex` suppresses
  placeholder and example matches without a separate allowlist.
- **Cross-tool inline suppression**: `secref:ignore`,
  `secref:disable-line`, `secref:disable-next-line`, `gitleaks:allow`,
  `trufflehog:ignore`, `secretlint-disable-line`,
  `secretlint-disable-next-line`, `pragma: allowlist secret`, and `nosec`.
- **Fix suggestions**: imported Semgrep `fix` text is attached to findings in
  JSON output.
- **Benchmark results**: reproducible harness and published comparison against
  five open-source scanners under `benchmarks/`.

### Changed

- Version bumped to `8.3.0`.
- The test suite grew from 112 to 119 tests.
- README, CHANGELOG, CURRENT_STATE, and architecture documentation describe the
  new compatibility layer.

## [8.2.0] - 2026-11-07

This release closes the remaining P2 roadmap and adds reproducible benchmark
tooling.

### Added

- **Source-map and chunk discovery**: `--source-maps` follows
  `sourceMappingURL` comments and quoted webpack/Vite/Rollup chunk paths,
  including JavaScript discovered at the crawl-depth boundary.
- **Gitleaks TOML import**: `--gitleaks-config PATH` converts `[[rules]]` packs
  (id, description, regex, secretGroup, entropy, tags) into native rules.
  `tomli` is installed automatically on Python < 3.11.
- **Local report dashboard**: `--serve`, `--serve-host`, `--serve-port`, and
  `--open-browser` start a read-only server over the output directory, with a
  report index and traversal protection.
- **Per-host scheduling**: `--per-host-delay` and `--per-host-concurrency`
  bound each host independently. 429 responses call an adaptive `penalize`
  path so one throttled host does not stall unrelated workers.
- **Rotation guidance**: provider credential findings now include
  `rotation_url` in JSON, CSV, Markdown, HTML, SARIF, and JUnit output.
  `src/rotation.py` maps 50+ providers and generic credential rules.
- **More live validators**: Cloudflare, Groq, OpenRouter, Replicate, and Cohere
  tokens use read-only, allow-listed checks. All are mocked in tests.
- **Git history filters**: `--git-from`, `--git-to`, and `--git-author` select a
  commit range or author without abandoning the existing `--git-since` and
  depth controls.
- **Plugin marketplace convention**: `--entrypoint-plugins` loads packages from
  the `secref.plugins` entry-point group; `PLUGINS.md` documents the API,
  packaging convention, and contribution checklist.
- **Benchmark harness**: `benchmarks/` contains a synthetic corpus and adapters
  for five open-source scanners.

### Changed

- Version bumped to `8.2.0`.
- The test suite grew from 91 to 112 tests.
- The report HTML/Markdown tables include a rotation link and dashboard server
  support.
- README, CURRENT_STATE, and architecture documentation reflect the completed
  roadmap.

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

[8.3.0]: https://github.com/LifeJiggy/Super-Secref-Finder/compare/v8.2.0...v8.3.0
[8.2.0]: https://github.com/LifeJiggy/Super-Secref-Finder/compare/v8.1.0...v8.2.0
[8.1.0]: https://github.com/LifeJiggy/Super-Secref-Finder/compare/v8.0.0...v8.1.0
[8.0.0]: https://github.com/LifeJiggy/Super-Secref-Finder/compare/v7.0.0...v8.0.0
[7.0.0]: https://github.com/LifeJiggy/Super-Secref-Finder/releases/tag/v7.0.0
[6.0.0]: https://github.com/LifeJiggy/Super-Secref-Finder/releases/tag/v6.0.0
