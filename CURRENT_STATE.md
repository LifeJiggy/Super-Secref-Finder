# Super Secref Finder — Current State & v8 Upgrade Plan

> **Audit date:** 2026-11-08
> **Repo state:** `main` branch. The last pushed commit before the v8.2/v8.3 work is `2a996c0`; the current release commit is pushed after final verification.
> **Version in repo:** `8.3.0`
> **Baseline version:** `8.0.0` — “Signal over noise”
> **Current release:** `8.3.0` — benchmarked scanner plus Semgrep/gitleaks/secretlint interoperability

---

## 1. Executive summary

The v7 refactor is a **solid architectural foundation** — a real Python package, an argparse CLI, modular scanner/fetcher/crawler/output, six report formats, checkpoints, plugins, and optional active secret validation. It is much better structured than the original single-file script.

But it is **not yet a powerful secret scanner**. The core detection layer is the weak point:

- Rules are mostly raw regexes with no severity, category, or rule metadata.
- Several “detection” rules match **any 32-character string**, **any UUID**, **any `<script>` tag**, or **any `../` sequence**. These are not secrets.
- The default run includes code-smell rules (`inline_script`, `console.log`, `innerHTML`, `path_traversal`, `sql_injection`) mixed in with real secrets.
- `findings.json` in the repo proves the problem: **35 findings, 0 secrets**. 29 were `inline_script`, the rest were paths, UUIDs, and a stack trace.
- There are real bugs (unused `--interactive`, broken plugin registry wiring, duplicate fetches, AWS “validation” that cannot work, queue/checkpoint races).
- There are **no tests, no CI, no Docker image, no GitHub Action, and no allowlist support** — the things that turn a 10-star repo into a tool people trust and share.

**Conclusion:** v8 should not add more raw regexes. It should make the tool **high-signal, explainable, testable, and CI-friendly**, then ship it with the developer-experience assets that earn stars.

---

## 2. What already exists (v7 inventory)

### 2.1 Package layout

| File | Purpose | Assessment |
|---|---|---|
| `src/__init__.py` | Version/author | ✅ fine |
| `src/__main__.py` | Entry point | ⚠️ ignores `--interactive` |
| `src/_compat.py` | Import shim for legacy roots | ⚠️ fragile, re-exports |
| `src/cli.py` | argparse CLI | ⚠️ many flags, one unused |
| `src/config.py` | `ScanConfig` dataclass | ✅ good foundation |
| `src/scanner.py` | Threaded orchestrator | ⚠️ races, double fetches, serial validation |
| `src/fetcher.py` | Requests session/retries/cookies | ⚠️ recursive 429, no content-type handling |
| `src/crawler.py` | BFS crawl/scope/exclude | ⚠️ fetches pages twice, JS discovery limited |
| `src/patterns.py` | 147 regex patterns | ❌ no metadata; multiple broad/noisy rules |
| `src/validators.py` | Context/entropy filters | ⚠️ ad-hoc, blanket entropy kills valid short secrets |
| `src/entropy.py` | Shannon entropy | ✅ fine |
| `src/output.py` | JSON/JSONL/CSV/MD/HTML/SARIF | ⚠️ no severity/category/evidence; HTML is plain |
| `src/checkpoint.py` | Resume + baseline diff | ⚠️ checkpoint races |
| `src/plugins.py` | Plugin loader + 4 built-ins | ❌ registry bug; plugins can silently not register |
| `src/secret_validator.py` | Live checks (AWS/GitHub/Slack/AI/etc.) | ⚠️ AWS check cannot succeed with only an access key ID |
| `src/logging_config.py` | JSON logs + rotation + audit | ⚠️ duplicate handlers on repeated setup |
| `src/interactive.py` | Guided prompts | ✅ works via legacy script |

### 2.2 Advertised feature set

- 147 regex patterns (README says 151)
- Multi-threaded web + JS scanning
- Proxy, custom headers, cookies, POST, SSL toggle
- Crawl depth/scope/exclusion/max URLs
- Entropy/confidence/context filtering
- Six output formats including SARIF
- Checkpoint/resume + differential baseline
- Plugins + custom YAML/JSON patterns
- UA rotation, jitter, structured audit logging
- Optional active validation (safe mode opt-out)

### 2.3 Real artifacts in the working tree

- `findings.json` — 35 findings / 0 secrets (noise proof)
- `scan_results.json`
- `secref.log`, `secref_audit.log`, `secref_errors.log`
- `Docs/` — legacy JS experiment, achievements notes, false-positive log
- Root compatibility wrappers `Regex_patterns.py`, `sensitive_patterns.py`

---

## 3. Verified weaknesses (with evidence)

### 3.1 Signal-to-noise is the #1 problem

`findings.json` from a real scan of `robinhood.com`:

| Rule | Count | Why it is noise |
|---|---:|---|
| `inline_script` | 29 | Every `<script>` tag is “sensitive” — that is just HTML |
| `path_traversal` | 2 | `../../` in webpack runtime is normal bundler code |
| `mobile_appcenter_secret` | 2 | Rule matches **any UUID** (tracking IDs, PDF asset IDs) |
| `error_message` | 1 | A minified `new Error` in webpack |
| **Total real secrets** | **0** | — |

**Root causes:**

1. `mobile_appcenter_secret`, `heroku_api_key_v2` use generic UUID regexes with no context.
2. `cohere_api_key`, `cloudflare_api_key`, `fastly_api_key`, `algolia_api_key`, `datadog_api_key` match **any** 32–40 char string.
3. `inline_script`, `path_traversal`, `lfi_vector`, `dangerous_*`, `console.log`, TODO comments are code smells, not secrets, yet run by default.
4. No allowlist/placeholder engine and no per-rule severity.
5. `match.group(0)` returns the whole `key = "value"` line instead of the captured secret value.
6. Blanket entropy check rejects short but valid secrets while broad regexes still pass.

### 3.2 Correctness and reliability bugs

| # | Bug | Impact |
|---|---|---|
| 1 | `--interactive` parsed but never used in `__main__.main()` | Flag does nothing |
| 2 | Plugin registry: plugin file does `from plugins import register_plugin`, which may import a **different module instance** than `src.plugins` | Plugins silently never run |
| 3 | `build_target_list()` fetches every crawled page, then `scanner` fetches it again | 2× requests, 2× delay, slower scans |
| 4 | `num_threads = min(threads, queue.qsize())` | Requests 20 threads, gets 1 if only one seed |
| 5 | Worker exceptions are uncaught | A single bad URL kills a worker silently |
| 6 | `while not url_queue.empty(): sleep(5)` then `join()` | Checkpoint loop can exit early; checkpoint races |
| 7 | 429 handling recurses into `fetch_url()` | Unbounded recursion / stack risk |
| 8 | `--respect-robots` never implemented | Flag is a lie |
| 9 | AWS validator passes a dummy secret | Always fails; “validated” never possible |
| 10 | `extract_secrets_from_text` recompiles ~147 regexes **per URL** | Wasted CPU on large scans |
| 11 | `setup_logging()` appends handlers on every call | Duplicated log lines in long sessions |
| 12 | HTML/SARIF severity derives only from confidence | Misleading severity |

### 3.3 Missing capabilities vs. modern secret scanners

| Capability | gitleaks | trufflehog | detect-secrets | **This repo (v7)** |
|---|---|---|---|---|
| Local files/directories | ✅ | ✅ | ✅ | ❌ |
| Git history | ✅ | ✅ | ❌ | ❌ |
| Rule severity/category | ✅ | ✅ | partial | ❌ |
| Allowlist / inline ignore | ✅ | ✅ | ✅ | ❌ |
| CI exit code (`--fail-on`) | ✅ | ✅ | ✅ | ❌ |
| Baseline / diff | ✅ | partial | ✅ | ✅ (baseline) |
| SARIF | ✅ | ✅ | ✅ | ✅ |
| Plugin API | ✅ | ✅ | ✅ | partial/broken |
| Tests + CI | ✅ | ✅ | ✅ | ❌ |
| Docker image | ✅ | ✅ | ✅ | ❌ |
| GitHub Action | ✅ | ✅ | — | ❌ |
| Live validation | partial | ✅ | ❌ | partial/AWS broken |

---

## 4. v8 upgrade plan (implemented)

### v8.0.0 — Signal over noise

### P0 — Make detection trustworthy

- [x] **Rule registry with metadata**: every rule gets `id`, `regex`, `category`, `severity`, `description`, `secret_group`, `entropy_min`, `noise`, `pii`.
- [x] **Curated high-signal defaults**: real token formats only; noisy code-smell rules moved to opt-in `--include-noise`.
- [x] **Contextual rewrites** for UUID/32-char rules (`mobile_appcenter_secret`, `heroku`, `datadog`, `algolia`, `fastly`, `cloudflare`, `cohere`, `api_key`, credentials).
- [x] **Capture-group extraction**: store the actual secret, not the whole assignment.
- [x] **Rule-aware validation**: placeholder detection, Luhn for cards, JWT shape, email/asset filtering, entropy only where it helps.
- [x] **Per-rule cap per page** (`--max-per-rule`, default 5) to stop `<script>` floods.
- [x] **Value/URL dedupe** and severity-aware confidence.
- [x] **Allowlist engine** (`.secrefignore`, built-in placeholder values, `--ignore-file`).
- [x] **PII split** behind `--include-pii`.

### P0 — Fix the engine

- [x] Compile rules once per scan.
- [x] Crawl cache: no duplicate fetches.
- [x] Robust worker `try/finally`, correct thread count, checkpoint loop based on unfinished work.
- [x] Iterative 429 retry with backoff (no recursion).
- [x] Content-type filtering and safer decoding.
- [x] Implement `--respect-robots`.
- [x] Fix plugin registry alias and plugin errors.
- [x] Concurrent active validation.
- [x] Fix duplicate log handlers.
- [x] AWS validation removed from “auto” path (documented: needs paired secret).

### P1 — New power features

- [x] **Local filesystem scanning** (`--path .`) with binary detection, ignore globs, and skip dirs (`.git`, `node_modules`, …).
- [x] **stdin scanning** (`--path -`).
- [x] **`--fail-on {never,low,medium,high,critical}`** for CI exit codes.
- [x] **`--min-severity`** and **`--include-type` / `--exclude-type`** filtering.
- [x] **`--include-noise`** and **`--include-pii`**.
- [x] **`--show-context`** evidence snippets.
- [x] **Richer reports**: severity/category/validated/line, severity summary, sortable/filterable HTML dashboard, SARIF rule metadata + security-severity.
- [x] **Validate-only-real-types** active checks (GitHub, GitLab, Slack, OpenAI, Anthropic, SendGrid, Stripe, Mailgun, DigitalOcean, Hugging Face, npm).

### P1 — Distribution & trust (star drivers)

- [x] Test suite (`pytest`) with fixtures for noise and true positives.
- [x] GitHub Actions CI matrix (Python 3.8–3.13).
- [x] Release workflow (build + PyPI trusted publishing on tags).
- [x] `Dockerfile` + `.dockerignore`.
- [x] `.gitignore` for scan artifacts/logs.
- [x] Rewritten README (badges, quickstart, accurate features, comparison, architecture, roadmap).
- [x] `CHANGELOG.md`, `SECURITY.md`.
- [x] Version bump to `8.0.0`.

### v8.1.0 — Live repository and pre-commit security

#### Live targets
- [x] `--github owner/repo` and GitHub URL support.
- [x] Private repository token support (`--github-token`, `GITHUB_TOKEN`, `GH_TOKEN`).
- [x] Release/tag/commit selection with `--github-ref`.
- [x] `--github-org` / `--github-user` discovery with `--github-limit` and `--github-include-forks`.
- [x] Zipball download, zip-slip protection, symlink skipping, and extraction/size limits.
- [x] Real git clone when history is requested; token passed via git config env, not the process list.
- [x] Safe temporary-checkout cleanup and `github://owner/repo/...` URL relabeling.

#### Git and developer workflow
- [x] `--git-history`, `--git-history-depth`, `--git-since` with commit/author/date/message provenance.
- [x] `--staged` and `--changed` scans, including untracked files for `--changed`.
- [x] `.pre-commit-hooks.yaml` hooks for staged secrets and workflow checks.

#### Detection and response
- [x] Opt-in whole-file entropy scanning (`--entropy-scan`, `--entropy-min-length`, `--entropy-scan-threshold`).
- [x] GitHub Actions supply-chain audit (`--audit-github-actions`): unpinned actions, unsafe `pull_request_target` checkout, script injection, `write-all`, inherited secrets.
- [x] Lockfile/exposure findings retained; workflow findings use the `supply-chain` category.
- [x] JUnit XML output (`--format junit`).
- [x] Redacted Slack/Discord/generic webhooks (`--webhook`, `--webhook-format`, `--webhook-min-severity`).
- [x] Precise auto-allowlisting (`--write-ignore`, `--allowlist-values`).
- [x] Hashed `fingerprint:` entries in `.secrefignore` (no raw secret stored).
- [x] Finding provenance in output (`source`, `repo`, `commit`, `author`, `commit_date`, `entropy`).

#### Distribution
- [x] First-party composite GitHub Action (`action.yml`) with SARIF upload.
- [x] `.secrefignore` for the project’s own fixtures; self-scan returns 0.
- [x] Version bump to `8.1.0`; README/CHANGELOG/CURRENT_STATE updated.
- [x] 91 passing tests and clean `ruff check src tests scripts examples`.

### P2 — Remaining roadmap (completed in v8.2/v8.3)

- [x] Source-map and bundler chunk discovery / deeper JS AST analysis.
- [x] YAML rule packs compatible with gitleaks TOML import (plus a Semgrep regex subset).
- [x] Web UI / dashboard mode (`--serve`).
- [x] Rate-limit scheduler per host and adaptive concurrency.
- [x] Secret rotation guidance links per rule.
- [x] Provider-side validation for more token types.
- [x] Commit-range and author filters for `--git-history`.
- [x] Plugin marketplace / rule contribution guide.

### v8.3.0 — Interoperability and proof

- [x] `--semgrep-config` imports `pattern-regex`, `pattern-either`,
  `pattern-not-regex`, `paths.include`/`exclude`, metadata, severity, and `fix`.
- [x] Path-scoped custom rules (`paths.include` / `paths.exclude`).
- [x] Negative patterns (`pattern_not` / `pattern-not-regex`).
- [x] Cross-tool suppression comments: `secref:ignore`, `gitleaks:allow`,
  `trufflehog:ignore`, `secretlint-disable-line`,
  `secretlint-disable-next-line`, `pragma: allowlist secret`, and `nosec`.
- [x] Benchmark harness against gitleaks, trufflehog, detect-secrets,
  secretlint, and whispers, with JSON and Markdown results.
- [x] 119 passing tests and clean `ruff check src tests scripts examples`.

---

## 5. Acceptance criteria for v8.1

1. Running the scanner on the real `robinhood.com` sample returns **0 secret findings by default** (no `inline_script`, no UUID, no `../`).
2. A fixture containing AWS/OpenAI/GitHub/private-key/DB-URI/JWT samples returns **all of them** with correct severity.
3. Placeholder values (`your_api_key_here`, `AKIAIOSFODNN7EXAMPLE`, `changeme`) are rejected.
4. `pytest` passes (currently **119 tests**) and `ruff check src tests scripts examples` is clean.
5. `--fail-on high` exits `1` when a high finding exists and `0` otherwise.
6. `--path .` scans local files and emits JSON/HTML/SARIF/JUnit.
7. `--github owner/repo` scans a live public repository and reports `github://` URLs.
8. `--github-user owner --github-limit N` discovers and scans public repositories.
9. `--git-history` finds a secret that was committed and later removed, with commit metadata.
10. `--staged` scans only staged files and works as a pre-commit gate.
11. `--audit-github-actions` reports unpinned actions, unsafe checkouts, script injection, `write-all`, and inherited secrets.
12. `--write-ignore` writes hashed fingerprints and never stores raw values by default.
13. Webhook payloads are redacted and filtered by `--webhook-min-severity`.
14. README, `--help`, and output formats describe the actual behavior.
15. The project’s own scan returns 0 findings by default (`.secrefignore` excludes synthetic test fixtures).

### v8.3 acceptance criteria

1. `--semgrep-config` imports `pattern-regex`, `pattern-either`, and
   `pattern-not-regex` rules and preserves severity/category metadata.
2. `paths.include` and `paths.exclude` restrict matches to the expected files.
3. `pattern_not` / `pattern-not-regex` suppresses placeholder matches.
4. All supported inline suppression comments suppress only the intended line.
5. `--no-default-ignore` bypasses `.secrefignore`.
6. `benchmarks/run_benchmark.py` writes JSON and Markdown results, and missing
   tools are reported without aborting the run.
7. `pytest` passes and `ruff check src tests scripts examples` is clean.

---

## 6. How to verify locally

```bash
python -m pip install -e ".[dev]"
pytest -q
ruff check src tests scripts examples
python -m src --version
python -m src --path . --format json --fail-on high
python -m src --github octocat/Hello-World --safe-mode --format json
python -m src --github-user octocat --github-limit 2 --safe-mode
python -m src --path . --git-history --git-history-depth 20
python -m src --path . --audit-github-actions --format sarif
python -m src --path . --entropy-scan --format junit
python -m src --path . --semgrep-config vendor/semgrep.yml
python benchmarks/run_benchmark.py --tools super-secref-finder detect-secrets
```

---

## 7. Files changed in v8

New:
- `src/rules.py` — canonical rule registry + metadata + compilation
- `src/github.py` — live repo download, org/user discovery, safe extraction
- `src/gitscan.py` — staged/changed files + git history documents
- `src/entropy_scan.py` — opt-in generic high-entropy token scan
- `src/workflow_audit.py` — GitHub Actions supply-chain checks
- `src/notify.py` — redacted webhook notifications
- `src/allowlist.py` — `.secrefignore`, fingerprints, placeholder engine, auto-allowlist writer
- `src/filesystem.py` — local file/stdin scanning
- `src/gitleaks.py` — gitleaks TOML rule importer
- `src/semgrep.py` — Semgrep YAML regex-subset importer
- `src/server.py` — read-only report dashboard
- `src/ratelimit.py` — per-host scheduler and adaptive backoff
- `src/rotation.py` — provider rotation guidance
- `benchmarks/` — synthetic corpus, five-scanner harness, results
- `tests/` — 119 unit/integration tests
- `.github/workflows/ci.yml`, `.github/workflows/release.yml`
- `action.yml`, `.pre-commit-hooks.yaml`
- `.secrefignore`
- `Dockerfile`, `.dockerignore`, `.gitignore`
- `CHANGELOG.md`, `SECURITY.md`
- `CURRENT_STATE.md` (this file)

Rewritten / upgraded:
- `src/patterns.py`, `src/validators.py`, `src/scanner.py`, `src/crawler.py`, `src/fetcher.py`, `src/output.py`, `src/plugins.py`, `src/secret_validator.py`, `src/logging_config.py`, `src/cli.py`, `src/config.py`, `src/__main__.py`, `src/interactive.py`, `src/__init__.py`, `src/checkpoint.py`, `src/entropy.py`
- `README.md`, `RULES.md`, `pyproject.toml`, `requirements.txt`, `requirements-dev.txt`

---

## 8. Final v8.3 verification

| Check | Result |
|---|---|
| `pytest -q` | **119 passed** |
| `ruff check src tests scripts examples` | **clean** |
| Semgrep import (`tests/test_semgrep.py`) | regex, either, negative, path filters, metadata verified |
| Cross-tool suppression comments | gitleaks, secretlint, detect-secrets, Bandit, trufflehog markers verified |
| Benchmark harness | `super-secref-finder` 14 TP / 0 FP / 2 FN; `detect-secrets` 11 TP / 2 FP / 5 FN |
| Self-scan `python -m src --path . --format json -q` | **0 findings** |
| Live GitHub repo `octocat/Hello-World` | **0 findings**, source `github`, target resolved |
| Live GitHub user discovery (`octocat`, limit 2) | **completed**, target `user:octocat` |
| Demo fixture (AWS/GitHub/DB URI) | all detected with correct severity |
| Output formats | JSON, JSONL, CSV, Markdown, HTML, SARIF, JUnit verified |
| Endpoint opt-in | endpoint rules/plugins off by default; `--include-endpoints` enables them |
| GitHub history clone | real clone path supported via `--git-history`; token kept out of process args |

### Known constraints

- GitHub API discovery is unauthenticated by default and subject to GitHub rate limits; use `--github-token` for private repositories or larger batch scans.
- Zipball scans do not include `.git`; combine `--github` with `--git-history` to clone and scan history.
- `--entropy-scan` and `--include-noise` are intentionally opt-in because they trade signal for coverage.
- Active validation remains allow-listed and read-only. AWS access-key-ID-only validation is not auto-run because it cannot be verified without the paired secret.
- The published benchmark snapshot currently scores Super Secref Finder and detect-secrets. gitleaks, trufflehog, secretlint, and whispers are reported as `not installed`; install them with the commands in `benchmarks/README.md` and rerun the harness to fill those rows. Corpus values are base64-encoded in `benchmarks/secrets.b64.json` and materialized into a temporary directory at runtime, so secret-shaped strings are not committed.
- Semgrep import is deliberately limited to the regex subset. AST-only predicates are skipped with a warning instead of approximated.
