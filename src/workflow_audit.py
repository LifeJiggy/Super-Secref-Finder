"""Security checks for GitHub Actions workflow files.

Opt-in with ``--audit-github-actions``. These are defensive supply-chain checks,
not secret detections, and are reported alongside secret findings.
"""

from __future__ import annotations

import glob
import os
import re
from typing import Iterable, List, Optional

try:
    import yaml
except Exception:  # pragma: no cover - dependency is declared
    yaml = None

_USES_RE = re.compile(r"(?m)^\s*(?:-\s*)?uses:\s*([^\s#]+)")
_REF_PR_RE = re.compile(
    r"(?m)^\s*(?:-\s*)?ref:\s*.*(?:github\.event\.pull_request\.head|github\.head_ref)"
)
_DANGEROUS_EXPR_RE = re.compile(
    r"\$\{\{\s*(?:github\.(?:event\.|head_ref|event_path)|inputs\.)[^}]*\}\}"
)
_WRITE_ALL_RE = re.compile(r"(?m)^\s*permissions:\s*write-all\s*$")
_SECRETS_INHERIT_RE = re.compile(r"(?m)^\s*secrets:\s*inherit\s*$")
_PULL_REQUEST_TARGET_RE = re.compile(
    r"(?m)^\s*(?:on:\s*)?(?:-\s*)?pull_request_target\b"
)
_PINNED_RE = re.compile(r"@[0-9a-fA-F]{40}$")


def _line_col(text: str, offset: int) -> tuple:
    line = text.count("\n", 0, offset) + 1
    line_start = text.rfind("\n", 0, offset) + 1
    return line, offset - line_start + 1


def _finding(
    rule_type: str,
    severity: str,
    value: str,
    description: str,
    path: str,
    text: str,
    pos: int,
    confidence: float = 0.9,
) -> dict:
    line, column = _line_col(text, max(0, pos))
    return {
        "type": rule_type,
        "value": value[:200],
        "url": "file://" + os.path.abspath(path).replace("\\", "/"),
        "severity": severity,
        "category": "supply-chain",
        "confidence": confidence,
        "description": description,
        "start": max(0, pos),
        "end": max(0, pos) + len(value),
        "line": line,
        "column": column,
        "source": "workflow-audit",
    }


def _find_position(text: str, needle: str) -> int:
    pos = text.find(needle)
    return pos if pos >= 0 else 0


def _audit_text(path: str, text: str) -> List[dict]:
    findings: List[dict] = []

    # 1. Unpinned third-party actions.
    for match in _USES_RE.finditer(text):
        uses = match.group(1).strip("'\"")
        if uses.startswith(("./", "docker://")):
            continue
        if "@" not in uses or not _PINNED_RE.search(uses):
            findings.append(_finding(
                "gha_unpinned_action",
                "medium",
                uses,
                "Third-party action is not pinned to a full commit SHA",
                path,
                text,
                match.start(1),
                0.88,
            ))

    # 2. pull_request_target checking out untrusted PR code.
    target_trigger = _PULL_REQUEST_TARGET_RE.search(text)
    ref_match = _REF_PR_RE.search(text)
    if target_trigger and ref_match:
        findings.append(_finding(
            "gha_untrusted_checkout",
            "critical",
            ref_match.group(0).strip(),
            "pull_request_target checks out PR-controlled code; this can expose secrets",
            path,
            text,
            ref_match.start(),
            0.95,
        ))

    # 3. Script injection through github.event / inputs in run blocks.
    parsed = None
    if yaml is not None:
        try:
            parsed = yaml.safe_load(text)
        except Exception:
            parsed = None

    dangerous_values = []
    if isinstance(parsed, dict):
        jobs = parsed.get("jobs", {})
        if isinstance(jobs, dict):
            for job in jobs.values():
                if not isinstance(job, dict):
                    continue
                steps = job.get("steps", [])
                if not isinstance(steps, list):
                    continue
                for step in steps:
                    if not isinstance(step, dict):
                        continue
                    run = step.get("run")
                    if isinstance(run, str):
                        dangerous_values.extend(_DANGEROUS_EXPR_RE.findall(run))
    else:
        # YAML parse failed: fall back to raw expressions after run:.
        for line in text.splitlines():
            if "run:" in line:
                dangerous_values.extend(_DANGEROUS_EXPR_RE.findall(line))

    for expression in dict.fromkeys(dangerous_values):
        findings.append(_finding(
            "gha_script_injection",
            "high",
            expression,
            "Untrusted GitHub event or input is interpolated into a shell command",
            path,
            text,
            _find_position(text, expression),
            0.9,
        ))

    # 4. Over-broad workflow permissions.
    for match in _WRITE_ALL_RE.finditer(text):
        findings.append(_finding(
            "gha_write_all_permissions",
            "high",
            "permissions: write-all",
            "Workflow grants write-all token permissions",
            path,
            text,
            match.start(),
            0.9,
        ))

    # 5. Secrets inherited by a reusable workflow.
    for match in _SECRETS_INHERIT_RE.finditer(text):
        findings.append(_finding(
            "gha_secrets_inherit",
            "medium",
            "secrets: inherit",
            "Reusable workflow inherits all caller secrets",
            path,
            text,
            match.start(),
            0.85,
        ))

    return findings


def _find_workflow_files(paths: Iterable[str]) -> List[str]:
    files = set()
    for raw in paths:
        if not raw or raw == "-":
            continue
        path = os.path.abspath(raw)
        if os.path.isfile(path):
            if path.endswith((".yml", ".yaml")) and (
                f"{os.sep}.github{os.sep}workflows{os.sep}" in path
                or os.path.basename(os.path.dirname(path)) in {"workflows", "workflow"}
            ):
                files.add(path)
            continue
        if not os.path.isdir(path):
            continue
        patterns = [
            os.path.join(path, ".github", "workflows", "*.yml"),
            os.path.join(path, ".github", "workflows", "*.yaml"),
        ]
        if os.path.basename(path) == "workflows":
            patterns.extend([os.path.join(path, "*.yml"), os.path.join(path, "*.yaml")])
        for pattern in patterns:
            files.update(glob.glob(pattern))
    return sorted(files)


def audit_github_actions(paths: Iterable[str], max_size: int = 1024 * 1024) -> List[dict]:
    """Audit workflow files under the given paths and return findings."""
    findings: List[dict] = []
    for path in _find_workflow_files(paths):
        try:
            if os.path.getsize(path) > max_size:
                continue
            with open(path, "r", encoding="utf-8", errors="replace") as fp:
                text = fp.read()
        except OSError:
            continue
        findings.extend(_audit_text(path, text))

    # Stable dedupe in case a path was supplied twice.
    seen = set()
    unique = []
    for finding in findings:
        key = (finding["type"], finding["value"], finding["url"])
        if key in seen:
            continue
        seen.add(key)
        unique.append(finding)
    return unique
