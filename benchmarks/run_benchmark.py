#!/usr/bin/env python3
"""Reproducible benchmark for Super Secref Finder against five secret scanners.

The corpus contains only synthetic, non-live credentials. Every tool scans the
same files and results are scored at file/line granularity, with a value
fallback for scanners that emit a value but a shifted line number.

Usage:
    python benchmarks/run_benchmark.py
    python benchmarks/run_benchmark.py --tools super-secref-finder detect-secrets
    python benchmarks/run_benchmark.py --require-all

Only tools found on PATH are executed. Missing tools are reported as
"not installed" with the install instructions from ``benchmarks/README.md``.
"""

from __future__ import annotations

import argparse
import base64
import contextlib
import json
import os
import platform
import re
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.parse
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, Iterator, List, Optional, Sequence, Tuple

BENCH_DIR = Path(__file__).resolve().parent
REPO_ROOT = BENCH_DIR.parent
DEFAULT_CORPUS = BENCH_DIR / "corpus"
DEFAULT_GROUND_TRUTH = BENCH_DIR / "ground_truth.json"
DEFAULT_SECRETS = BENCH_DIR / "secrets.b64.json"
DEFAULT_OUTPUT_DIR = BENCH_DIR / "results"
SECRETLINT_CONFIG = BENCH_DIR / ".secretlintrc.json"
PLACEHOLDER_RE = re.compile(r"\{\{([A-Z0-9_]+)\}\}")

TOOL_ORDER = [
    "super-secref-finder",
    "gitleaks",
    "trufflehog",
    "detect-secrets",
    "secretlint",
    "whispers",
]


@dataclass
class Detection:
    """One normalized scanner finding."""

    file: str
    line: Optional[int]
    rule: str
    value: Optional[str] = None


@dataclass
class Truth:
    """One synthetic secret from ground_truth.json."""

    file: str
    line: int
    rule: str
    value: str

    @property
    def key(self) -> Tuple[str, int]:
        return (self.file, self.line)

    def label(self) -> str:
        return f"{self.file}:{self.line} ({self.rule})"


@dataclass
class ToolResult:
    name: str
    status: str
    available: bool = True
    version: Optional[str] = None
    command: Optional[str] = None
    runtime_seconds: Optional[float] = None
    returncode: Optional[int] = None
    error: Optional[str] = None
    total_detections: int = 0
    unique_detections: int = 0
    tp: int = 0
    fp: int = 0
    fn: int = 0
    duplicates: int = 0
    precision: float = 0.0
    recall: float = 0.0
    f1: float = 0.0
    matched: List[Dict[str, Any]] = field(default_factory=list)
    false_positives: List[Dict[str, Any]] = field(default_factory=list)
    missed: List[Dict[str, Any]] = field(default_factory=list)
    duplicate_findings: List[Dict[str, Any]] = field(default_factory=list)
    stderr_tail: Optional[str] = None

    @property
    def scoreable(self) -> bool:
        return self.status in {"ok", "partial"}

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "status": self.status,
            "available": self.available,
            "version": self.version,
            "command": self.command,
            "runtime_seconds": None if self.runtime_seconds is None else round(self.runtime_seconds, 3),
            "returncode": self.returncode,
            "error": self.error,
            "total_detections": self.total_detections,
            "unique_detections": self.unique_detections,
            "tp": self.tp,
            "fp": self.fp,
            "fn": self.fn,
            "duplicates": self.duplicates,
            "precision": round(self.precision, 4),
            "recall": round(self.recall, 4),
            "f1": round(self.f1, 4),
            "matched": self.matched,
            "false_positives": self.false_positives,
            "missed": self.missed,
            "duplicate_findings": self.duplicate_findings,
            "stderr_tail": self.stderr_tail,
        }


def _read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8-sig", errors="replace"))


def _read_json_or_jsonl(text: str) -> Any:
    """Parse a JSON document or a stream of JSON objects."""
    stripped = text.strip()
    if not stripped:
        return []
    try:
        return json.loads(stripped)
    except json.JSONDecodeError:
        items = []
        for line in stripped.splitlines():
            line = line.strip()
            if not line or not line.startswith("{"):
                continue
            try:
                items.append(json.loads(line))
            except json.JSONDecodeError:
                continue
        return items


def _as_int(value: Any) -> Optional[int]:
    try:
        number = int(str(value).strip())
    except (TypeError, ValueError):
        return None
    return number if number > 0 else None


def _clean_value(value: Any) -> Optional[str]:
    if value is None:
        return None
    text = str(value).strip()
    if not text:
        return None
    return text.strip("'\"`").strip() or None


def _normalise_file(raw: Any, corpus: Path) -> str:
    """Return a corpus-relative POSIX path from any scanner path format."""
    if raw is None:
        return ""
    text = str(raw).strip().strip("'\"")
    if not text:
        return ""
    if text.startswith("file://"):
        parsed = urllib.parse.urlparse(text)
        text = urllib.parse.unquote(parsed.path)
        # Windows file URLs look like /C:/path/to/file.
        if re.match(r"^/[A-Za-z]:/", text):
            text = text[1:]

    corpus = corpus.resolve()
    candidate_path = Path(text)
    candidates: List[Path] = []
    if candidate_path.is_absolute():
        candidates.append(candidate_path)
    else:
        candidates.append(REPO_ROOT / candidate_path)
        candidates.append(corpus / candidate_path)

    for candidate in candidates:
        try:
            return candidate.resolve().relative_to(corpus).as_posix()
        except (OSError, ValueError):
            continue

    slash_path = text.replace("\\", "/")
    root_slash = corpus.as_posix().rstrip("/") + "/"
    if slash_path.startswith(root_slash):
        return slash_path[len(root_slash) :]
    marker = "/" + corpus.name + "/"
    if marker in slash_path:
        return slash_path.split(marker, 1)[1]
    if slash_path.startswith(corpus.name + "/"):
        return slash_path[len(corpus.name) + 1 :]
    return slash_path.lstrip("./")


def _normalise_value(value: Optional[str]) -> str:
    if not value:
        return ""
    return re.sub(r"\s+", "", value.strip().strip("'\"`")).lower()


def _values_overlap(left: Optional[str], right: Optional[str]) -> bool:
    a = _normalise_value(left)
    b = _normalise_value(right)
    if len(a) < 8 or len(b) < 8:
        return False
    return a in b or b in a


class Adapter:
    """Base class for scanner command/parse adapters."""

    name = ""
    executable = ""

    def resolve_command(self) -> Optional[str]:
        return shutil.which(self.executable)

    def version(self, command: str, cwd: Path, timeout: int) -> Optional[str]:
        try:
            completed = subprocess.run(
                [command, "--version"],
                cwd=str(cwd),
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=min(timeout, 20),
                env=_tool_env(),
            )
        except (OSError, subprocess.SubprocessError):
            return None
        output = (completed.stdout or completed.stderr or "").strip()
        return output.splitlines()[0].strip() if output else None

    def run(self, corpus: Path, timeout: int) -> Tuple[List[Detection], str, Optional[int], str]:
        raise NotImplementedError

    def command_display(self, corpus: Path) -> str:
        return "<unsupported>"


class SuperSecrefAdapter(Adapter):
    name = "super-secref-finder"
    executable = sys.executable

    def resolve_command(self) -> Optional[str]:
        return sys.executable

    def version(self, command: str, cwd: Path, timeout: int) -> Optional[str]:
        try:
            completed = subprocess.run(
                [command, "-m", "src", "--version"],
                cwd=str(cwd),
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=min(timeout, 20),
                env=_tool_env(),
            )
        except (OSError, subprocess.SubprocessError):
            return None
        output = (completed.stdout or completed.stderr or "").strip()
        return output.splitlines()[0].strip() if output else None

    def command_display(self, corpus: Path) -> str:
        return (
            f'"{Path(sys.executable).name}" -m src --path <corpus> '
            "--format json --safe-mode --no-default-ignore -q -o <report-dir>"
        )

    def run(self, corpus: Path, timeout: int) -> Tuple[List[Detection], str, Optional[int], str]:
        with tempfile.TemporaryDirectory(prefix="secref-bench-ours-") as report_dir:
            command = [
                sys.executable,
                "-m",
                "src",
                "--path",
                str(corpus),
                "--format",
                "json",
                "--safe-mode",
                "--no-default-ignore",
                "-q",
                "-o",
                report_dir,
            ]
            completed = subprocess.run(
                command,
                cwd=str(REPO_ROOT),
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=timeout,
                env=_tool_env(),
            )
            reports = sorted(Path(report_dir).glob("*.json"))
            if not reports:
                raise RuntimeError("scanner did not write a JSON report")
            payload = _read_json(reports[-1])

        detections: List[Detection] = []
        for finding in payload.get("findings", []):
            detections.append(
                Detection(
                    file=_normalise_file(finding.get("url"), corpus),
                    line=_as_int(finding.get("line")),
                    rule=str(finding.get("type") or "unknown"),
                    value=_clean_value(finding.get("value")),
                )
            )
        return detections, " ".join(command), completed.returncode, completed.stderr or ""


class GitleaksAdapter(Adapter):
    name = "gitleaks"
    executable = "gitleaks"

    def version(self, command: str, cwd: Path, timeout: int) -> Optional[str]:
        try:
            completed = subprocess.run(
                [command, "version"],
                cwd=str(cwd),
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=min(timeout, 20),
                env=_tool_env(),
            )
        except (OSError, subprocess.SubprocessError):
            return None
        output = (completed.stdout or completed.stderr or "").strip()
        return output.splitlines()[0].strip() if output else None

    def command_display(self, corpus: Path) -> str:
        return (
            "gitleaks detect --source <corpus> --no-git --report-format json "
            "--report-path <report.json> --exit-code 0"
        )

    def run(self, corpus: Path, timeout: int) -> Tuple[List[Detection], str, Optional[int], str]:
        with tempfile.TemporaryDirectory(prefix="secref-bench-gitleaks-") as report_dir:
            report = Path(report_dir) / "gitleaks.json"
            command = [
                self.resolve_command() or self.executable,
                "detect",
                "--source",
                str(corpus),
                "--no-git",
                "--report-format",
                "json",
                "--report-path",
                str(report),
                "--exit-code",
                "0",
            ]
            completed = subprocess.run(
                command,
                cwd=str(REPO_ROOT),
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=timeout,
                env=_tool_env(),
            )
            if not report.exists():
                raise RuntimeError("gitleaks did not write a JSON report")
            payload = _read_json(report)

        detections: List[Detection] = []
        for item in payload if isinstance(payload, list) else []:
            detections.append(
                Detection(
                    file=_normalise_file(item.get("File") or item.get("file"), corpus),
                    line=_as_int(item.get("StartLine") or item.get("startLine") or item.get("line")),
                    rule=str(item.get("RuleID") or item.get("ruleId") or "unknown"),
                    value=_clean_value(item.get("Secret") or item.get("secret") or item.get("Match")),
                )
            )
        return detections, " ".join(command), completed.returncode, completed.stderr or ""


class TrufflehogAdapter(Adapter):
    name = "trufflehog"
    executable = "trufflehog"

    def command_display(self, corpus: Path) -> str:
        return "trufflehog filesystem <corpus> --json --no-update --no-verification"

    def run(self, corpus: Path, timeout: int) -> Tuple[List[Detection], str, Optional[int], str]:
        command = [
            self.resolve_command() or self.executable,
            "filesystem",
            str(corpus),
            "--json",
            "--no-update",
            "--no-verification",
        ]
        completed = subprocess.run(
            command,
            cwd=str(REPO_ROOT),
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
            env=_tool_env(),
        )
        detections: List[Detection] = []
        for item in _read_json_or_jsonl(completed.stdout or ""):
            if not isinstance(item, dict):
                continue
            source_data = item.get("SourceMetadata", {}).get("Data", {})
            file_path = None
            line = None
            if isinstance(source_data, dict):
                for source in source_data.values():
                    if isinstance(source, dict) and (source.get("file") or source.get("File")):
                        file_path = source.get("file") or source.get("File")
                        line = source.get("line") or source.get("Line")
                        break
            detections.append(
                Detection(
                    file=_normalise_file(file_path, corpus),
                    line=_as_int(line),
                    rule=str(item.get("DetectorName") or item.get("DetectorType") or "unknown"),
                    value=_clean_value(item.get("Raw") or item.get("RawV2") or item.get("Redacted")),
                )
            )
        return detections, " ".join(command), completed.returncode, completed.stderr or ""


class DetectSecretsAdapter(Adapter):
    name = "detect-secrets"
    executable = "detect-secrets"

    def command_display(self, corpus: Path) -> str:
        return "detect-secrets scan <corpus> --all-files"

    def run(self, corpus: Path, timeout: int) -> Tuple[List[Detection], str, Optional[int], str]:
        command = [self.resolve_command() or self.executable, "scan", str(corpus), "--all-files"]
        completed = subprocess.run(
            command,
            cwd=str(corpus),
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
            env=_tool_env(),
        )
        payload = _read_json_or_jsonl(completed.stdout or "")
        if not isinstance(payload, dict):
            raise RuntimeError("detect-secrets did not return a JSON object")
        results = payload.get("results", {})
        detections: List[Detection] = []
        for filename, items in results.items():
            for item in items if isinstance(items, list) else []:
                detections.append(
                    Detection(
                        file=_normalise_file(filename, corpus),
                        line=_as_int(item.get("line_number") or item.get("line")),
                        rule=str(item.get("type") or "unknown"),
                    )
                )
        return detections, " ".join(command), completed.returncode, completed.stderr or ""


class SecretlintAdapter(Adapter):
    name = "secretlint"
    executable = "secretlint"

    def command_display(self, corpus: Path) -> str:
        return "secretlint --format json <every-corpus-file>"

    def run(self, corpus: Path, timeout: int) -> Tuple[List[Detection], str, Optional[int], str]:
        files = [str(path) for path in sorted(corpus.rglob("*")) if path.is_file()]
        command = [self.resolve_command() or self.executable, "--format", "json"]
        if SECRETLINT_CONFIG.exists():
            command.extend(["--secretlintrc", str(SECRETLINT_CONFIG)])
        command.extend(files)
        completed = subprocess.run(
            command,
            cwd=str(REPO_ROOT),
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
            env=_tool_env(),
        )
        payload = _read_json_or_jsonl(completed.stdout or "")
        detections: List[Detection] = []
        for item in payload if isinstance(payload, list) else []:
            if not isinstance(item, dict):
                continue
            filename = item.get("filePath") or item.get("file") or item.get("path")
            for message in item.get("messages", []):
                detections.append(
                    Detection(
                        file=_normalise_file(filename, corpus),
                        line=_as_int(message.get("line") or message.get("lineNumber")),
                        rule=str(message.get("ruleId") or message.get("rule") or "unknown"),
                    )
                )
        return detections, " ".join(command), completed.returncode, completed.stderr or ""


class WhispersAdapter(Adapter):
    name = "whispers"
    executable = "whispers"

    def command_display(self, corpus: Path) -> str:
        return "whispers <corpus>"

    def run(self, corpus: Path, timeout: int) -> Tuple[List[Detection], str, Optional[int], str]:
        command = [self.resolve_command() or self.executable, str(corpus)]
        completed = subprocess.run(
            command,
            cwd=str(REPO_ROOT),
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
            env=_tool_env(),
        )
        payload = _read_json_or_jsonl(completed.stdout or "")
        detections: List[Detection] = []
        for item in _iter_whispers_items(payload):
            filename = item.get("file") or item.get("filename") or item.get("path")
            line = item.get("line") or item.get("line_number") or item.get("lineNumber")
            rule = item.get("rule_id") or item.get("rule") or item.get("key") or item.get("message")
            value = item.get("value") or item.get("secret") or item.get("match")
            detections.append(
                Detection(
                    file=_normalise_file(filename, corpus),
                    line=_as_int(line),
                    rule=str(rule or "unknown"),
                    value=_clean_value(value),
                )
            )
        return detections, " ".join(command), completed.returncode, completed.stderr or ""


def _iter_whispers_items(payload: Any) -> Iterable[Dict[str, Any]]:
    if isinstance(payload, list):
        for item in payload:
            if isinstance(item, dict):
                yield item
        return
    if isinstance(payload, dict):
        for key in ("results", "findings", "secrets"):
            if isinstance(payload.get(key), list):
                for item in payload[key]:
                    if isinstance(item, dict):
                        yield item
                return
        for value in payload.values():
            if isinstance(value, list):
                for item in value:
                    if isinstance(item, dict):
                        yield item


ADAPTERS: Dict[str, Adapter] = {
    adapter.name: adapter
    for adapter in (
        SuperSecrefAdapter(),
        GitleaksAdapter(),
        TrufflehogAdapter(),
        DetectSecretsAdapter(),
        SecretlintAdapter(),
        WhispersAdapter(),
    )
}


def _tool_env() -> Dict[str, str]:
    env = os.environ.copy()
    env.setdefault("PYTHONIOENCODING", "utf-8")
    env.setdefault("NO_COLOR", "1")
    env.setdefault("TERM", "dumb")
    return env


def load_secret_values(path: Path) -> Dict[str, str]:
    """Decode the base64 token map used to materialize the corpus."""
    payload = _read_json(path)
    if not isinstance(payload, dict):
        raise ValueError(f"{path} must contain a JSON object")
    values: Dict[str, str] = {}
    for name, encoded in payload.items():
        if isinstance(encoded, list):
            encoded = "".join(str(part) for part in encoded)
        try:
            values[str(name)] = base64.b64decode(str(encoded)).decode("utf-8")
        except (ValueError, UnicodeDecodeError) as exc:
            raise ValueError(f"{path}: invalid base64 for {name}: {exc}") from exc
    return values


@contextlib.contextmanager
def materialized_corpus(template_dir: Path, values: Dict[str, str]) -> Iterator[Path]:
    """Copy corpus templates to a temporary directory and fill placeholders."""
    with tempfile.TemporaryDirectory(prefix="secref-bench-corpus-") as tmp:
        root = Path(tmp)
        shutil.copytree(template_dir, root, dirs_exist_ok=True)
        for path in sorted(root.rglob("*")):
            if not path.is_file():
                continue
            try:
                text = path.read_text(encoding="utf-8")
            except UnicodeDecodeError:
                continue

            def replace(match: re.Match) -> str:
                name = match.group(1)
                if name not in values:
                    raise ValueError(f"{path}: no value for placeholder {name}")
                return values[name]

            rendered = PLACEHOLDER_RE.sub(replace, text)
            if rendered != text:
                with path.open("w", encoding="utf-8", newline="\n") as handle:
                    handle.write(rendered)
        yield root


def load_truth(path: Path, corpus: Path, values: Optional[Dict[str, str]] = None) -> List[Truth]:
    payload = _read_json(path)
    truths: List[Truth] = []
    for item in payload.get("secrets", []):
        token = item.get("token")
        value = str(item.get("value") or "")
        if token:
            value = str((values or {}).get(str(token), ""))
        truths.append(
            Truth(
                file=_normalise_file(item["file"], corpus),
                line=int(item["line"]),
                rule=str(item.get("rule") or "unknown"),
                value=value,
            )
        )
    return truths


def _truth_payload(truth: Truth) -> Dict[str, Any]:
    return {"file": truth.file, "line": truth.line, "rule": truth.rule}


def _detection_payload(detection: Detection) -> Dict[str, Any]:
    # Deliberately omit the raw value: benchmark artifacts are committed and
    # must not duplicate secret-shaped strings in a second location.
    return {
        "file": detection.file,
        "line": detection.line,
        "rule": detection.rule,
    }


def deduplicate(detections: Sequence[Detection]) -> List[Detection]:
    """Collapse duplicate file/line findings, keeping a representative."""
    unique: Dict[Tuple[str, int], Detection] = {}
    for detection in detections:
        if not detection.file:
            continue
        key = (detection.file, detection.line or 0)
        unique.setdefault(key, detection)
    return sorted(unique.values(), key=lambda item: (item.file, item.line or 0, item.rule))


def score(detections: Sequence[Detection], truths: Sequence[Truth]) -> Dict[str, Any]:
    unique = deduplicate(detections)
    by_line: Dict[Tuple[str, int], int] = {truth.key: index for index, truth in enumerate(truths)}
    by_file: Dict[str, List[int]] = {}
    for index, truth in enumerate(truths):
        by_file.setdefault(truth.file, []).append(index)

    used: set = set()
    matched: List[Dict[str, Any]] = []
    false_positives: List[Dict[str, Any]] = []
    duplicates: List[Dict[str, Any]] = []

    def unused_in_file(filename: str) -> List[int]:
        return [idx for idx in by_file.get(filename, []) if idx not in used]

    for detection in unique:
        truth_index: Optional[int] = None
        if detection.line:
            candidate = by_line.get((detection.file, detection.line))
            if candidate is not None and candidate not in used:
                truth_index = candidate

        if truth_index is None and detection.value:
            for idx in unused_in_file(detection.file):
                if _values_overlap(detection.value, truths[idx].value):
                    truth_index = idx
                    break

        if truth_index is None and not detection.line:
            candidates = unused_in_file(detection.file)
            if len(candidates) == 1:
                truth_index = candidates[0]

        if truth_index is not None:
            used.add(truth_index)
            matched.append(
                {
                    "truth": _truth_payload(truths[truth_index]),
                    "detection": _detection_payload(detection),
                }
            )
            continue

        # A second detector hit for an already-matched secret is a duplicate,
        # not a false positive.
        duplicate_of = None
        if detection.value:
            for idx in by_file.get(detection.file, []):
                if _values_overlap(detection.value, truths[idx].value):
                    duplicate_of = idx
                    break
        if duplicate_of is not None:
            duplicates.append(_detection_payload(detection))
        else:
            false_positives.append(_detection_payload(detection))

    missed = [truth for index, truth in enumerate(truths) if index not in used]
    tp = len(matched)
    fp = len(false_positives)
    fn = len(missed)
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / len(truths) if truths else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0

    return {
        "total_detections": len(detections),
        "unique_detections": len(unique),
        "tp": tp,
        "fp": fp,
        "fn": fn,
        "duplicates": (len(detections) - len(unique)) + len(duplicates),
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "matched": matched,
        "false_positives": false_positives,
        "missed": [_truth_payload(truth) for truth in missed],
        "duplicate_findings": duplicates,
    }


def run_tool(name: str, corpus: Path, truths: Sequence[Truth], timeout: int, verbose: bool) -> ToolResult:
    adapter = ADAPTERS[name]
    command = adapter.resolve_command()
    if not command:
        return ToolResult(
            name=name,
            status="not installed",
            available=False,
            command=adapter.command_display(corpus),
            error=f"`{adapter.executable}` was not found on PATH",
        )

    version = adapter.version(command, REPO_ROOT, timeout)
    started = time.perf_counter()
    try:
        detections, command_display, returncode, stderr = adapter.run(corpus, timeout)
    except subprocess.TimeoutExpired:
        elapsed = time.perf_counter() - started
        return ToolResult(
            name=name,
            status="error",
            version=version,
            command=adapter.command_display(corpus),
            runtime_seconds=elapsed,
            error=f"timed out after {timeout}s",
        )
    except (OSError, RuntimeError, ValueError) as exc:
        elapsed = time.perf_counter() - started
        return ToolResult(
            name=name,
            status="error",
            version=version,
            command=adapter.command_display(corpus),
            runtime_seconds=elapsed,
            error=str(exc),
        )

    elapsed = time.perf_counter() - started
    scored = score(detections, truths)
    status = "ok"
    error = None
    if returncode not in (0, 1):
        if not scored["unique_detections"]:
            status = "error"
            error = f"exit code {returncode} with no parseable findings"
        else:
            status = "partial"
            error = f"exit code {returncode}; findings parsed anyway"

    if verbose:
        print(
            f"  {name}: {scored['tp']} TP, {scored['fp']} FP, {scored['fn']} FN "
            f"({scored['precision']:.1%} precision, {scored['recall']:.1%} recall)",
            file=sys.stderr,
        )

    return ToolResult(
        name=name,
        status=status,
        version=version,
        command=_sanitize_command(command_display, corpus),
        runtime_seconds=elapsed,
        returncode=returncode,
        error=error,
        total_detections=scored["total_detections"],
        unique_detections=scored["unique_detections"],
        tp=scored["tp"],
        fp=scored["fp"],
        fn=scored["fn"],
        duplicates=scored["duplicates"],
        precision=scored["precision"],
        recall=scored["recall"],
        f1=scored["f1"],
        matched=scored["matched"],
        false_positives=scored["false_positives"],
        missed=scored["missed"],
        duplicate_findings=scored["duplicate_findings"],
        stderr_tail=_tail(stderr),
    )


def _sanitize_command(command: Optional[str], corpus: Path) -> Optional[str]:
    """Remove machine-specific paths so the JSON result is portable."""
    if not command:
        return command
    text = command.replace(sys.executable, "python")
    text = text.replace(str(corpus), "<corpus>")
    text = text.replace(str(REPO_ROOT), "<repo>")
    text = re.sub(r"[^\s\"']*secref-bench-[^\s\"']*", "<report>", text)
    text = re.sub(r"[A-Za-z]:[\\/][^\s\"']*[\\/]([^\\/\s\"']+\.(?:exe|EXE))", r"\1", text)
    return text


def _tail(text: str, limit: int = 500) -> Optional[str]:
    text = (text or "").strip()
    if not text:
        return None
    return text[-limit:]


def _percent(value: float) -> str:
    return f"{value * 100:.1f}%"


def _seconds(value: Optional[float]) -> str:
    return "—" if value is None else f"{value:.3f}s"


def render_markdown(metadata: Dict[str, Any], results: Sequence[ToolResult]) -> str:
    lines: List[str] = []
    lines.append("# Secret Scanner Benchmark")
    lines.append("")
    lines.append(f"Generated: `{metadata['generated_at']}`")
    lines.append("")
    lines.append(
        "Corpus: **{secrets} synthetic secrets** in {files} files, plus {clean} clean "
        "control files containing placeholders and known example values. No live "
        "credentials are used.".format(
            secrets=metadata["corpus"]["secrets"],
            files=metadata["corpus"]["files"],
            clean=metadata["corpus"]["clean_files"],
        )
    )
    lines.append("")
    lines.append(
        "Scoring: a true positive is a unique finding on the same corpus-relative "
        "file and line as a ground-truth secret, with a value fallback when a scanner "
        "reports a shifted line. Extra unique findings count as false positives; "
        "multiple hits on the same line count once."
    )
    lines.append("")
    lines.append("## Results")
    lines.append("")
    lines.append("| Scanner | Status | TP | FP | FN | Precision | Recall | F1 | Runtime |")
    lines.append("|---|---|---:|---:|---:|---:|---:|---:|---:|")
    for result in results:
        if result.scoreable:
            lines.append(
                f"| {result.name} | {result.status} | {result.tp} | {result.fp} | "
                f"{result.fn} | {_percent(result.precision)} | {_percent(result.recall)} | "
                f"{_percent(result.f1)} | {_seconds(result.runtime_seconds)} |"
            )
        else:
            lines.append(
                f"| {result.name} | {result.status} | — | — | — | — | — | — | "
                f"{_seconds(result.runtime_seconds)} |"
            )
    lines.append("")

    available = [result for result in results if result.scoreable]
    if available:
        ranked = sorted(available, key=lambda item: (item.f1, item.recall, item.precision), reverse=True)
        winner = ranked[0]
        lines.append(
            f"Highest F1 in this run: **{winner.name}** "
            f"({_percent(winner.f1)}; {winner.tp} TP, {winner.fp} FP, {winner.fn} FN)."
        )
        lines.append("")

    lines.append("## Missed secrets")
    lines.append("")
    any_missed = False
    for result in results:
        if not result.scoreable:
            continue
        any_missed = True
        if not result.missed:
            lines.append(f"- **{result.name}**: none.")
            continue
        missed = ", ".join(
            f"`{item['file']}:{item['line']}` ({item['rule']})" for item in result.missed
        )
        lines.append(f"- **{result.name}** ({len(result.missed)}): {missed}")
    if not any_missed:
        lines.append("No scanners were available.")
    lines.append("")

    lines.append("## False positives")
    lines.append("")
    any_fp = False
    for result in results:
        if not result.scoreable:
            continue
        any_fp = True
        if not result.false_positives:
            lines.append(f"- **{result.name}**: none.")
            continue
        fps = ", ".join(
            f"`{item['file']}:{item['line']}` ({item['rule']})"
            for item in result.false_positives
        )
        lines.append(f"- **{result.name}** ({len(result.false_positives)}): {fps}")
    if not any_fp:
        lines.append("No scanners were available.")
    lines.append("")

    lines.append("## Tool details")
    lines.append("")
    for result in results:
        lines.append(f"### {result.name}")
        lines.append("")
        lines.append(f"- Status: `{result.status}`")
        lines.append(f"- Version: `{result.version or 'unknown'}`")
        lines.append(f"- Command: `{result.command or '—'}`")
        lines.append(f"- Runtime: {_seconds(result.runtime_seconds)}")
        lines.append(
            f"- Unique detections: {result.unique_detections} "
            f"(raw: {result.total_detections}, duplicate hits: {result.duplicates})"
        )
        if result.error:
            lines.append(f"- Note: {result.error}")
        lines.append("")

    lines.append("## Reproduce")
    lines.append("")
    lines.append("```bash")
    lines.append("python benchmarks/run_benchmark.py")
    lines.append("python benchmarks/run_benchmark.py --tools super-secref-finder detect-secrets")
    lines.append("```")
    lines.append("")
    lines.append(
        "See [`benchmarks/README.md`](README.md) for corpus details, tool versions, "
        "install commands, and scoring limitations."
    )
    lines.append("")
    return "\n".join(lines)


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--corpus", type=Path, default=DEFAULT_CORPUS, help="Corpus template directory")
    parser.add_argument("--ground-truth", type=Path, default=DEFAULT_GROUND_TRUTH, help="Ground-truth JSON")
    parser.add_argument("--secrets", type=Path, default=DEFAULT_SECRETS, help="Base64-encoded corpus token map")
    parser.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT_DIR, help="Result directory")
    parser.add_argument(
        "--tools",
        nargs="+",
        default=["all"],
        help=f"Tools to run (default: all). Available: {', '.join(TOOL_ORDER)}",
    )
    parser.add_argument("--timeout", type=int, default=300, help="Per-tool timeout in seconds")
    parser.add_argument("--require-all", action="store_true", help="Exit 2 if any requested tool is missing")
    parser.add_argument("--quiet", action="store_true", help="Suppress progress output")
    args = parser.parse_args(argv)

    corpus = args.corpus.resolve()
    ground_truth = args.ground_truth.resolve()
    secrets_path = args.secrets.resolve()
    if not corpus.is_dir():
        parser.error(f"corpus directory not found: {corpus}")
    if not ground_truth.is_file():
        parser.error(f"ground truth not found: {ground_truth}")
    if not secrets_path.is_file():
        parser.error(f"secret map not found: {secrets_path}")

    try:
        secret_values = load_secret_values(secrets_path)
    except ValueError as exc:
        parser.error(str(exc))

    requested = list(args.tools)
    if "all" in requested:
        requested = list(TOOL_ORDER)
    unknown = [name for name in requested if name not in ADAPTERS]
    if unknown:
        parser.error(f"unknown tool(s): {', '.join(unknown)}")
    # Keep a stable display order.
    requested = [name for name in TOOL_ORDER if name in requested]

    truths = load_truth(ground_truth, corpus, secret_values)
    if not truths:
        parser.error("ground truth contains no secrets")
    missing_tokens = sorted({truth.rule for truth in truths if not truth.value})
    if missing_tokens:
        parser.error(f"missing secret values for: {', '.join(missing_tokens)}")

    if not args.quiet:
        print(f"Benchmark corpus template: {corpus}")
        print(f"Ground truth: {len(truths)} synthetic secrets")
        print(f"Tools: {', '.join(requested)}")

    with materialized_corpus(corpus, secret_values) as scan_corpus:
        results: List[ToolResult] = []
        for name in requested:
            if not args.quiet:
                print(f"Running {name} ...", file=sys.stderr)
            results.append(run_tool(name, scan_corpus, truths, args.timeout, verbose=not args.quiet))

        corpus_files = [path for path in sorted(corpus.rglob("*")) if path.is_file()]
        truth_payload = _read_json(ground_truth)
        metadata = {
            "schema_version": 1,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "corpus": {
                "path": corpus.relative_to(REPO_ROOT).as_posix() if _is_relative_to(corpus, REPO_ROOT) else str(corpus),
                "files": len(corpus_files),
                "secrets": len(truths),
                "clean_files": len(truth_payload.get("clean_files", [])),
                "file_list": [
                    path.relative_to(corpus).as_posix() for path in corpus_files
                ],
                "materialized_at_runtime": True,
            },
            "environment": {
                "platform": platform.platform(),
                "python": platform.python_version(),
            },
            "methodology": (
                "Corpus placeholders are materialized from base64-encoded synthetic values in a "
                "temporary directory. Unique file/line detections are compared with ground truth. "
                "A value fallback matches findings whose reported line shifted. Extra unique "
                "findings are false positives; multiple hits on one line count once."
            ),
            "tools": [result.to_dict() for result in results],
        }

    output_dir = args.output_dir.resolve()
    output_dir.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    json_path = output_dir / f"benchmark_{timestamp}.json"
    markdown_path = output_dir / f"benchmark_{timestamp}.md"
    latest_json = output_dir / "latest.json"
    latest_md = output_dir / "latest.md"

    json_text = json.dumps(metadata, indent=2, sort_keys=False) + "\n"
    markdown_text = render_markdown(metadata, results)
    json_path.write_text(json_text, encoding="utf-8")
    markdown_path.write_text(markdown_text, encoding="utf-8")
    shutil.copyfile(json_path, latest_json)
    shutil.copyfile(markdown_path, latest_md)

    if not args.quiet:
        print("")
        print(markdown_text)
        print(f"Wrote {json_path}")
        print(f"Wrote {markdown_path}")

    missing = [result.name for result in results if not result.available]
    if args.require_all and missing:
        print(f"Missing requested tools: {', '.join(missing)}", file=sys.stderr)
        return 2
    return 0


def _is_relative_to(path: Path, parent: Path) -> bool:
    try:
        path.relative_to(parent)
        return True
    except ValueError:
        return False


if __name__ == "__main__":
    raise SystemExit(main())
