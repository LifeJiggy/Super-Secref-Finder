# Security Policy

## Supported versions

| Version | Supported |
|---|---|
| 8.x | Yes |
| 7.x and older | No |

## Reporting a vulnerability

Please **do not open a public issue** for security vulnerabilities.

Report privately using one of these channels:

- GitHub Security Advisories:
  <https://github.com/LifeJiggy/Super-Secref-Finder/security/advisories/new>
- Email: <Bloomtonjovish@gmail.com>

Include:

- affected version and platform
- a minimal reproduction
- expected vs actual behavior
- impact assessment (for example, SSRF, credential leakage, path traversal)
- whether the issue requires a malicious rule file or plugin

We aim to acknowledge reports within 72 hours and to publish a fix and advisory
for confirmed issues.

## Scope

In scope:

- the scanner engine, crawler, fetcher, rule engine, allowlist, baselines,
  output writers, CLI, and plugin loader
- credential leakage caused by the tool itself
- path traversal or arbitrary file read through `--path`
- unsafe handling of untrusted rule files or plugins

Out of scope:

- findings in third-party systems you scanned without permission
- false positives/negatives that are ordinary rule-tuning issues (open a normal
  issue with a reproducible sample)
- reports that contain real secrets; redact them first

## Safe operation

- Only scan systems you own or have explicit permission to test.
- Live validation performs read-only requests to allow-listed provider APIs.
  Use `--safe-mode` to disable it entirely.
- Reports can contain real credentials. Treat them as sensitive, store them
  securely, and use `--redact` when sharing.
- Differential baselines store hashed fingerprints rather than raw values.
- Custom rules and plugins execute code or regular expressions. Review them
  before use, especially from untrusted sources.

## Disclosure

We follow coordinated disclosure. Once a fix is available, we publish a GitHub
Security Advisory and credit the reporter unless anonymity is requested.
