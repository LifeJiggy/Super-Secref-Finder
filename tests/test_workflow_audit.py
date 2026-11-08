"""GitHub Actions workflow supply-chain audit tests."""

from src.workflow_audit import audit_github_actions

WORKFLOW = """\
name: CI
on:
  pull_request_target:
permissions: write-all
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
      - uses: some/third-party-action@main
      - run: echo "${{ github.event.issue.title }}"
      - uses: org/reusable/.github/workflows/build.yml@v1
        secrets: inherit
"""


def test_workflow_audit_finds_supply_chain_issues(tmp_path):
    workflows = tmp_path / ".github" / "workflows"
    workflows.mkdir(parents=True)
    path = workflows / "ci.yml"
    path.write_text(WORKFLOW, encoding="utf-8")

    findings = audit_github_actions([str(tmp_path)])
    types = {finding["type"] for finding in findings}
    assert "gha_untrusted_checkout" in types
    assert "gha_unpinned_action" in types
    assert "gha_script_injection" in types
    assert "gha_write_all_permissions" in types
    assert "gha_secrets_inherit" in types
    assert all(finding["category"] == "supply-chain" for finding in findings)
    assert all(finding["line"] >= 1 for finding in findings)


def test_workflow_audit_clean_workflow(tmp_path):
    workflows = tmp_path / ".github" / "workflows"
    workflows.mkdir(parents=True)
    (workflows / "safe.yml").write_text(
        "name: safe\non: push\njobs:\n  test:\n    runs-on: ubuntu-latest\n"
        "    steps:\n      - uses: actions/checkout@0123456789abcdef0123456789abcdef01234567\n"
        "      - run: echo hello\n",
        encoding="utf-8",
    )
    assert audit_github_actions([str(tmp_path)]) == []


def test_workflow_audit_ignores_non_workflow_files(tmp_path):
    (tmp_path / "ci.yml").write_text(WORKFLOW, encoding="utf-8")
    assert audit_github_actions([str(tmp_path)]) == []
