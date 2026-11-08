"""Git helpers: staged/changed files and history document extraction."""

from __future__ import annotations

import os
import re
import shutil
import subprocess
from typing import Dict, Iterable, List, Optional

_FIELD = "\x1f"
_RECORD = "\x1e"
_HUNK_RE = re.compile(r"\+(\d+)(?:,(\d+))?")


class GitError(RuntimeError):
    """Raised when a git command is unavailable or fails."""


def git_available() -> bool:
    return shutil.which("git") is not None


def _run_git(args: List[str], cwd: str, timeout: int = 120) -> str:
    if not git_available():
        raise GitError("git is not installed or not on PATH")
    try:
        proc = subprocess.run(
            ["git", *args],
            cwd=cwd,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise GitError(str(exc)) from exc
    if proc.returncode != 0:
        raise GitError((proc.stderr or proc.stdout or "git command failed").strip())
    return proc.stdout


def repo_root(path: str = ".") -> str:
    """Return the absolute git repository root for ``path``."""
    start = path if os.path.isdir(path) else os.path.dirname(os.path.abspath(path))
    return _run_git(["rev-parse", "--show-toplevel"], start).strip()


def is_git_repo(path: str = ".") -> bool:
    try:
        repo_root(path)
        return True
    except GitError:
        return False


def _split_z(output: str) -> List[str]:
    return [item for item in output.split("\0") if item]


def _resolve_files(root: str, relative_paths: Iterable[str]) -> List[str]:
    files = []
    for rel in relative_paths:
        absolute = os.path.abspath(os.path.join(root, rel))
        if os.path.isfile(absolute):
            files.append(absolute)
    return sorted(set(files))


def staged_files(path: str = ".") -> List[str]:
    """Return files staged in the index (for pre-commit hooks)."""
    root = repo_root(path)
    output = _run_git(
        ["diff", "--cached", "--name-only", "--diff-filter=ACMR", "-z"],
        root,
    )
    return _resolve_files(root, _split_z(output))


def changed_files(path: str = ".") -> List[str]:
    """Return modified/staged/untracked files relative to HEAD."""
    root = repo_root(path)
    names = _split_z(
        _run_git(["diff", "--name-only", "--diff-filter=ACMR", "-z", "HEAD"], root)
    )
    try:
        untracked = _split_z(
            _run_git(["ls-files", "--others", "--exclude-standard", "-z"], root)
        )
    except GitError:
        untracked = []
    return _resolve_files(root, names + untracked)


def iter_history_documents(
    path: str = ".",
    max_commits: int = 100,
    since: Optional[str] = None,
) -> Iterable[Dict]:
    """Yield ``{text, path, url, commit, author, ...}`` for added lines in history.

    Each document contains only added lines from one file in one commit. This
    keeps history scans focused on what was introduced, not on the whole file
    once per commit.
    """
    root = repo_root(path)
    repo_name = os.path.basename(root.rstrip("/\\")) or "repo"
    args = [
        "log",
        "--all",
        "-p",
        "-U0",
        "--no-color",
        "--no-ext-diff",
        f"--pretty=format:{_RECORD}%H{_FIELD}%an{_FIELD}%ae{_FIELD}%aI{_FIELD}%s",
    ]
    if max_commits and max_commits > 0:
        args.extend(["-n", str(max_commits)])
    if since:
        args.append(f"--since={since}")

    output = _run_git(args, root, timeout=300)

    for record in output.split(_RECORD):
        if not record.strip():
            continue
        newline = record.find("\n")
        header = record[:newline] if newline >= 0 else record
        body = record[newline + 1:] if newline >= 0 else ""
        fields = header.split(_FIELD)
        if len(fields) < 5:
            continue
        commit, author, email, date, message = fields[:5]

        groups: List[Dict] = []
        current: Optional[Dict] = None
        new_line: Optional[int] = None

        for line in body.splitlines():
            if line.startswith("+++ b/"):
                current = {
                    "path": line[6:],
                    "lines": [],
                    "offset": None,
                }
                groups.append(current)
                new_line = None
                continue
            if line.startswith("+++ "):  # deleted file / /dev/null
                current = None
                new_line = None
                continue
            if line.startswith("@@"):
                match = _HUNK_RE.search(line)
                new_line = int(match.group(1)) if match else None
                continue
            if line.startswith("+") and not line.startswith("+++"):
                if current is not None and new_line is not None:
                    current["lines"].append(line[1:])
                    if current["offset"] is None:
                        current["offset"] = max(0, new_line - 1)
                    new_line += 1
            elif line.startswith("-"):
                continue
            elif new_line is not None:
                new_line += 1

        for group in groups:
            if not group["lines"]:
                continue
            file_path = group["path"]
            yield {
                "text": "\n".join(group["lines"]),
                "path": file_path,
                "url": f"git://{repo_name}/{commit}/{file_path}",
                "commit": commit,
                "author": author,
                "author_email": email,
                "commit_date": date,
                "commit_message": message,
                "line_offset": int(group["offset"] or 0),
                "repo": repo_name,
            }
