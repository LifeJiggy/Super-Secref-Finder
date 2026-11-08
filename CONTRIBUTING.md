# Contributing to Super Secref Finder

Thanks for helping make secret scanning less noisy. Contributions are welcome:
new detection rules, false-positive fixes, crawler improvements, docs, tests,
and integrations.

## Quick start

```bash
git clone https://github.com/LifeJiggy/Super-Secref-Finder.git
cd Super-Secref-Finder
python -m venv .venv
# Windows: .venv\Scripts\activate
# macOS/Linux: source .venv/bin/activate
python -m pip install -e ".[dev]"
pytest -q
```

Run the CLI from the checkout:

```bash
python -m src --version
python -m src --list-rules
python -m src --path src --format json html sarif -o /tmp/secref-reports
```

## Project layout

| Path | Purpose |
|---|---|
| `src/rules.py` | Canonical rule registry (source of truth) |
| `src/patterns.py` | Rule selection and custom YAML/JSON loading |
| `src/validators.py` | Placeholder, Luhn, JWT, entropy, confidence filtering |
| `src/allowlist.py` | `.secrefignore` and inline suppression |
| `src/filesystem.py` | Local file/directory/stdin scanning |
| `src/scanner.py` | Orchestration, dedupe, validation, exit codes |
| `src/output.py` | JSON, JSONL, CSV, Markdown, HTML, SARIF |
| `src/crawler.py`, `src/fetcher.py` | Web crawling and HTTP transport |
| `tests/` | Pytest suite |
| `scripts/generate_rules_doc.py` | Regenerates `RULES.md` |
| `RULES.md` | Generated rule catalogue (do not hand-edit) |

## Adding or changing a rule

1. Add a `Rule(...)` to `src/rules.py`.
2. Capture the actual secret in a group and set `secret_group`.
3. Use a specific regex. Avoid matching "any 32-character string" or "any UUID";
   add surrounding context such as a variable name, prefix, or API host.
4. Set `severity` and `category` deliberately.
5. Set `entropy_min` only when the captured value benefits from it.
6. Mark code smells with `noise=True`, PII with `pii=True`, and endpoint
   discovery with `category="endpoint"`.
7. Add positive and negative tests in `tests/test_rules.py` or
   `tests/test_scanner.py`.
8. Regenerate the docs:

   ```bash
   python scripts/generate_rules_doc.py
   ```

9. Run the suite and lint:

   ```bash
   pytest -q
   ruff check src tests scripts
   ```

### Rule metadata

```python
Rule(
    id="example_token",
    pattern=r"\b(example_[A-Za-z0-9]{24,})\b",
    category="token",              # secret|token|cloud|credential|exposure|
                                   # endpoint|pii|code-risk|supply-chain|...
    severity="high",               # critical|high|medium|low|info
    description="Example service token",
    secret_group=1,                # 0 means the whole match
    entropy_min=3.0,
    noise=False,
    pii=False,
    tags=("example", "token"),
)
```

## False-positive reports

A useful false-positive report contains:

- the finding JSON (redact the value)
- the rule ID
- the surrounding snippet (redacted)
- why it is not a secret
- whether an allowlist entry or a regex change is the right fix

If the value is a known-safe constant, prefer a targeted allowlist example in
the tests instead of disabling a whole rule.

## Plugins

Plugins live in `src/plugins.py` or an external `--plugin-dir`. They receive
`url`, `text`, and already-found findings, and return a list of dicts with at
least `type`, `value`, `url`, `confidence`, `start`, and `end`.

- Keep plugins read-only and deterministic.
- Do not perform network requests unless the plugin is explicitly opt-in.
- Handle exceptions locally; the registry logs and continues.

## Output formats

Every new output writer must include `severity`, `category`, `confidence`,
`validated`, and location fields. Add a test in `tests/test_output.py` and
update the format table in `README.md`.

## Code style

- Python 3.8+ compatible syntax.
- Type hints on public functions.
- Keep functions focused and avoid new runtime dependencies.
- Prefer the standard library.
- No secrets, real tokens, customer data, or internal hostnames in tests.
- Use ASCII in runtime log messages (Windows consoles often use cp1252).

## Pull request checklist

- [ ] Tests added or updated
- [ ] `pytest -q` passes
- [ ] `ruff check src tests scripts` passes
- [ ] `RULES.md` regenerated if rules changed
- [ ] README/CHANGELOG updated for user-visible changes
- [ ] No real credentials or personal data in the diff
- [ ] PR description explains the signal/noise impact

## Commit messages

Conventional, imperative messages are appreciated:

```text
feat(rules): detect Example service tokens with context
fix(crawler): avoid fetching prefetched pages twice
docs: clarify CI exit codes
```

## Code of Conduct

Be respectful and constructive. Harassment or disclosure of another person's
secrets is not acceptable. See [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).

## License

By contributing, you agree that your contributions are licensed under the MIT
License that covers this project.
