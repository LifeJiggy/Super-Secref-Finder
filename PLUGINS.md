# Plugin and Rule Contribution Guide

Super Secref Finder has two extension points:

1. **Rules** — declarative YAML/JSON, imported gitleaks TOML, or the regex
   subset of Semgrep YAML.
2. **Plugins** — Python callables that add findings or metadata.

This guide covers both, plus the lightweight plugin marketplace convention.

---

## Rule packs

### Native YAML/JSON

```yaml
patterns:
  internal_service_token:
    regex: "(?i)\\binternal_service_token\\s*[:=]\\s*['\"]([A-Za-z0-9_-]{32,})['\"]"
    description: "Internal service token"
    severity: high
    category: token
    group: 1
    entropy: 3.2
```

```bash
secref --path . --custom-patterns rules/internal.yaml
```

Use `group` to report only the secret value rather than the whole assignment.
Rules with `noise: true` or `pii: true` are opt-in by design.

Optional path and negative filters:

```yaml
patterns:
  internal_service_token:
    regex: "(?i)\\binternal_service_token\\s*[:=]\\s*['\"]([A-Za-z0-9_-]{32,})['\"]"
    description: "Internal service token"
    severity: high
    category: token
    group: 1
    paths:
      include: ["src/**", "services/**"]
      exclude: ["tests/**", "vendor/**"]
    pattern_not: "example|placeholder"
```

### Gitleaks TOML import

```bash
secref --path . --gitleaks-config vendor/gitleaks.toml
```

The importer supports the common `[[rules]]` fields:

- `id`
- `description`
- `regex` / `pattern`
- `secretGroup` / `secret_group`
- `entropy`
- `tags`

Unsupported gitleaks-only features (path allowlists, regex targets, custom
validators) are ignored. Invalid regexes are skipped with a warning.

### Semgrep YAML import

```bash
secref --path . --semgrep-config vendor/semgrep-secrets.yml
```

Supported Semgrep keys: `pattern-regex`, `pattern-either`,
`pattern-not-regex`, `paths.include`/`paths.exclude`,
`metadata.category`, `metadata.tags`, `metadata.entropy`, `severity`, and
`fix`. AST-only predicates (`pattern`, `pattern-inside`,
`metavariable-regex`, taint mode) are skipped with a warning because they need
a full Semgrep engine to evaluate correctly.

A native YAML pack can be combined with gitleaks and Semgrep packs:

```bash
secref --path . \
  --custom-patterns rules/company.yaml \
  --gitleaks-config vendor/gitleaks.toml \
  --semgrep-config vendor/semgrep-secrets.yml
```

---

## Local plugins

A plugin file is a normal Python module that registers one or more callables:

```python
from plugins import register_plugin

@register_plugin("company_headers")
def company_headers(url, text, findings):
    if "X-Company-Debug" in text:
        return [{
            "type": "company_debug_header",
            "value": "X-Company-Debug",
            "url": url,
            "confidence": 0.8,
            "severity": "medium",
            "category": "exposure",
        }]
    return []
```

```bash
secref https://app.example.com --plugin-dir ./plugins
```

Plugin callables receive:

| Argument | Meaning |
|---|---|
| `url` | Final URL or file URL being scanned |
| `text` | Document body |
| `findings` | Findings already extracted by built-in rules |

They return a list of dicts with at least `type` and `value`. Optional fields:
`url`, `confidence`, `severity`, `category`, `description`, `start`, `end`.

Plugins run after built-in rules and are deduplicated with the same
`(url, value)` key. A plugin exception is logged and does not abort the scan.

---

## Installed / marketplace plugins

Publish a Python package with an entry point:

```toml
[project.entry-points."secref.plugins"]
company_headers = "company_secref_plugin"
```

The module can register itself at import time, or expose a zero-argument
callable that registers plugins when called. Load installed plugins with:

```bash
secref --path . --entrypoint-plugins
```

Entry-point loading is opt-in so installing an unrelated package cannot change
scan behaviour unexpectedly.

### Marketplace convention

There is no centralized server. To make a plugin discoverable, publish it on
PyPI with the topic/keyword `secref-plugin` and add the entry point above.
Include this in the package metadata:

```toml
keywords = ["secref-plugin", "secret-scanning", "security"]
```

A marketplace index can then be generated with:

```bash
python - <<'PY'
from importlib.metadata import entry_points
for ep in entry_points(group="secref.plugins"):
    print(ep.name, ep.value)
PY
```

---

## Contribution checklist

Before opening a rule or plugin pull request:

- [ ] The rule has a narrow, testable shape and a stable `id`.
- [ ] The regex captures only the credential, not the surrounding assignment.
- [ ] Placeholder values (documentation examples, `changeme`, UUIDs) are rejected.
- [ ] The default rule set remains high-signal; noisy rules are `noise: true`.
- [ ] A fixture and a unit test are included.
- [ ] No live credentials, tokens, or personal data are committed.
- [ ] `python -m pytest -q` and `ruff check src tests scripts examples` pass.
- [ ] If the rule is provider-specific, it has a rotation URL in
  `src/rotation.py`.
- [ ] If live validation is added, it is read-only, allow-listed in
  `src/secret_validator.py`, and covered by a mocked test.

---

## Security notes

Rules and plugins execute in the scanner process. Review third-party packs
before use, pin plugin versions in CI, and run untrusted scans in a container
or low-privilege account. Plugins can read the document body and URL; they must
not transmit those values to external services without explicit user consent.
