# Secret Scanner Benchmark

Generated: `2026-11-08T15:18:17.999432+00:00`

Corpus: **16 synthetic secrets** in 5 files, plus 2 clean control files containing placeholders and known example values. No live credentials are used.

Scoring: a true positive is a unique finding on the same corpus-relative file and line as a ground-truth secret, with a value fallback when a scanner reports a shifted line. Extra unique findings count as false positives; multiple hits on the same line count once.

## Results

| Scanner | Status | TP | FP | FN | Precision | Recall | F1 | Runtime |
|---|---|---:|---:|---:|---:|---:|---:|---:|
| super-secref-finder | ok | 14 | 0 | 2 | 100.0% | 87.5% | 93.3% | 0.850s |
| gitleaks | not installed | — | — | — | — | — | — | — |
| trufflehog | not installed | — | — | — | — | — | — | — |
| detect-secrets | ok | 11 | 2 | 5 | 84.6% | 68.8% | 75.9% | 4.678s |
| secretlint | not installed | — | — | — | — | — | — | — |
| whispers | not installed | — | — | — | — | — | — | — |

Highest F1 in this run: **super-secref-finder** (93.3%; 14 TP, 0 FP, 2 FN).

## Missed secrets

- **super-secref-finder** (2): `app/config.py:4` (aws_secret_access_key), `web/app.js:5` (telegram_bot_token)
- **detect-secrets** (5): `app/config.py:7` (digitalocean_personal_access_token), `web/app.js:3` (discord_webhook), `web/app.js:4` (mailchimp_api_key), `web/app.js:5` (telegram_bot_token), `.env:3` (npm_token)

## False positives

- **super-secref-finder**: none.
- **detect-secrets** (2): `clean/README.md:6` (AWS Access Key), `clean/clean.py:8` (AWS Access Key)

## Tool details

### super-secref-finder

- Status: `ok`
- Version: `super-secref-finder 8.3.0`
- Command: `python -m src --path <corpus> --format json --safe-mode --no-default-ignore -q -o <report>`
- Runtime: 0.850s
- Unique detections: 14 (raw: 14, duplicate hits: 0)

### gitleaks

- Status: `not installed`
- Version: `unknown`
- Command: `gitleaks detect --source <corpus> --no-git --report-format json --report-path <report.json> --exit-code 0`
- Runtime: —
- Unique detections: 0 (raw: 0, duplicate hits: 0)
- Note: `gitleaks` was not found on PATH

### trufflehog

- Status: `not installed`
- Version: `unknown`
- Command: `trufflehog filesystem <corpus> --json --no-update --no-verification`
- Runtime: —
- Unique detections: 0 (raw: 0, duplicate hits: 0)
- Note: `trufflehog` was not found on PATH

### detect-secrets

- Status: `ok`
- Version: `1.5.0`
- Command: `detect-secrets.EXE scan <corpus> --all-files`
- Runtime: 4.678s
- Unique detections: 13 (raw: 17, duplicate hits: 4)

### secretlint

- Status: `not installed`
- Version: `unknown`
- Command: `secretlint --format json <every-corpus-file>`
- Runtime: —
- Unique detections: 0 (raw: 0, duplicate hits: 0)
- Note: `secretlint` was not found on PATH

### whispers

- Status: `not installed`
- Version: `unknown`
- Command: `whispers <corpus>`
- Runtime: —
- Unique detections: 0 (raw: 0, duplicate hits: 0)
- Note: `whispers` was not found on PATH

## Reproduce

```bash
python benchmarks/run_benchmark.py
python benchmarks/run_benchmark.py --tools super-secref-finder detect-secrets
```

See [`benchmarks/README.md`](README.md) for corpus details, tool versions, install commands, and scoring limitations.
