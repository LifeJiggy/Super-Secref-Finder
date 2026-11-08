# Benchmark: Super Secref Finder vs. five open-source scanners

This directory contains a small, reproducible benchmark corpus and a harness
that compares **Super Secref Finder** with **gitleaks**, **trufflehog**,
**detect-secrets**, **secretlint**, and **whispers**.

The corpus is deliberately tiny and synthetic. It is a signal-quality check,
not a claim about performance on every real repository. No live credentials
are used; every value is fabricated for testing. To keep secret-shaped strings
out of the repository and avoid provider push-protection false alarms, the
corpus files contain `{{TOKEN}}` placeholders and the values are stored
base64-encoded in `secrets.b64.json`. The harness materializes a temporary
corpus directory for each run. Some entries are split into base64 chunks so
provider push-protection scanners do not treat the repository's own benchmark
metadata as a leaked credential.

## Quick start

```bash
# Run every scanner that is installed on PATH
python benchmarks/run_benchmark.py

# Run only the scanners you have right now
python benchmarks/run_benchmark.py --tools super-secref-finder detect-secrets

# Fail if a requested scanner is missing (useful in CI)
python benchmarks/run_benchmark.py --require-all
```

The checked-in snapshot in [`results/latest.md`](results/latest.md) was produced
with Super Secref Finder and detect-secrets installed. The other four tools are
listed as `not installed`; install them with the commands below and rerun to
fill in those rows.

Results are written to `benchmarks/results/`:

- `benchmark_<UTC timestamp>.json` — full machine-readable record
- `benchmark_<UTC timestamp>.md` — human-readable report
- `latest.json` / `latest.md` — copies of the newest run

## Corpus

| File | Purpose |
|---|---|
| `app/config.py` | AWS key pair, GitHub token, OpenAI key, DigitalOcean token, database URI placeholders |
| `web/app.js` | Google key, JWT, Discord webhook, Mailchimp key, Telegram token, private-key header placeholders |
| `.env` | SendGrid, GitLab, npm, and Twilio token placeholders |
| `clean/clean.py` | Benign hashes, UUIDs, placeholders, and AWS's documented example key |
| `clean/README.md` | Documentation placeholders and example values |
| `secrets.b64.json` | Base64-encoded synthetic values substituted into the placeholders |

`ground_truth.json` lists all 16 expected secrets and the two clean control
files. Each entry names a token in `secrets.b64.json`, so the raw value exists
only in the materialized temporary corpus during a run. The AWS example value
in the clean controls is intentionally a known trap: scanners that flag it are
recording a false positive.

## Scoring

A **true positive** is a unique finding on the same corpus-relative file and
line as a ground-truth secret. If a scanner reports a value, a value match is
also accepted when the reported line has shifted. A **false positive** is any
other unique finding, including findings in the clean control files. Multiple
hits on one line count once. **False negatives** are ground-truth secrets with
no matching finding.

`precision = TP / (TP + FP)`, `recall = TP / (TP + FN)`, and
`F1 = 2 * precision * recall / (precision + recall)`.

## Install the scanners

Super Secref Finder is always available from this repository:

```bash
python -m pip install -e .
```

The other tools are optional. Install only what you want to benchmark.

### gitleaks

```powershell
winget install gitleaks.gitleaks
# or download a release:
# https://github.com/gitleaks/gitleaks/releases
```

### trufflehog

```powershell
winget install trufflesecurity.trufflehog
# or download a release:
# https://github.com/trufflesecurity/trufflehog/releases
```

### detect-secrets

```bash
python -m pip install detect-secrets
```

### secretlint

```bash
npm install -g secretlint @secretlint/secretlint-rule-preset-recommend
```

The harness passes `benchmarks/.secretlintrc.json` automatically when the file
exists, so the recommended preset is enabled even if the global config is
empty.

### whispers

```bash
python -m pip install whispers
```

Whispers is archived upstream and may not support every Python version. If it
cannot be installed, the harness reports it as unavailable and still runs the
other tools.

## Interpreting the result

A missing tool is shown as `not installed`, not as a score of zero. Do not
compare F1 numbers across different runs unless the same scanner versions,
corpus, and command-line flags were used. The JSON result records the command,
version, runtime, per-file findings, false positives, and missed secrets so a
reviewer can audit every number. Raw finding values are deliberately omitted
from result files.

## Limitations

- The corpus is synthetic and intentionally small.
- Detection is scored at file/line granularity, not at exact character spans.
- Encoded or split secrets in scanned targets are out of scope. The base64
  encoding used by the benchmark itself is only repository hygiene, not a
  detection challenge.
- Active verification is disabled for every scanner that supports it. This is
  a static-detection benchmark.
- `detect-secrets` stores hashed values, so value fallback is unavailable for
  that tool; line matching is used.
- Tool CLIs change. Pin versions in CI if you publish numbers over time.
