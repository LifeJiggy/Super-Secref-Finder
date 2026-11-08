# Examples

These files show the extension points without committing real credentials.

## Custom rules

```bash
secref --path . --custom-patterns examples/custom_rules.yaml
```

See `src/custom_patterns_example.yaml` for the full schema.

## Plugin

```bash
secref --path . --plugin-dir examples
```

Plugins are regular Python modules. Only load plugins you trust: they execute
code in the scanner process.

## CI demo

```bash
mkdir -p /tmp/secref-demo
printf 'GITHUB_TOKEN=ghp_%s\n' "$(python -c 'print("a"*36)')" > /tmp/secref-demo/.env
secref --path /tmp/secref-demo --format json html sarif --fail-on high -o /tmp/secref-demo/reports
```

The demo token is synthetic and matches the GitHub token shape. Do not commit
real `.env` files.
