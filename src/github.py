"""Live GitHub repository fetching and discovery.

Public repositories are downloaded as zipballs. Private repositories use the
same API with a token. When git history is requested, a real clone is used so
``git log`` is available.
"""

from __future__ import annotations

import os
import re
import shutil
import stat
import subprocess
import tempfile
import zipfile
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple
from urllib.parse import unquote, urlparse

import requests

API_ROOT = "https://api.github.com"
USER_AGENT = "super-secref-finder"


class GitHubError(RuntimeError):
    """Raised for GitHub API, download, or extraction failures."""


@dataclass
class GitHubRepo:
    owner: str
    name: str
    default_branch: str = "main"
    archived: bool = False
    fork: bool = False
    html_url: str = ""

    @property
    def slug(self) -> str:
        return f"{self.owner}/{self.name}"


def _headers(token: Optional[str] = None) -> Dict[str, str]:
    headers = {
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": USER_AGENT,
    }
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return headers


def parse_repo_spec(spec: str) -> Tuple[str, str, Optional[str]]:
    """Parse ``owner/repo``, a GitHub URL, or ``git@github.com:owner/repo``.

    Returns ``(owner, repo, ref)``. ``ref`` is set for URLs containing
    ``/tree/<ref>``.
    """
    raw = (spec or "").strip()
    if not raw:
        raise GitHubError("empty GitHub repository specification")

    ref: Optional[str] = None
    if raw.startswith("git@github.com:"):
        raw = raw[len("git@github.com:"):]
    elif "://" in raw:
        parsed = urlparse(raw)
        if parsed.netloc.lower() not in {"github.com", "www.github.com"}:
            raise GitHubError(f"not a github.com URL: {spec}")
        parts = [part for part in parsed.path.split("/") if part]
        if len(parts) >= 2:
            owner, repo = parts[0], parts[1]
            if len(parts) >= 4 and parts[2] == "tree":
                ref = "/".join(parts[3:])
            raw = f"{owner}/{repo}"
        else:
            raise GitHubError(f"could not parse repository from URL: {spec}")

    raw = raw.strip("/")
    if raw.endswith(".git"):
        raw = raw[:-4]
    parts = raw.split("/")
    if len(parts) != 2 or not all(parts):
        raise GitHubError(
            f"expected owner/repo or a GitHub URL, got: {spec!r}"
        )
    owner, repo = parts
    if not re.fullmatch(r"[A-Za-z0-9_.-]+", owner) or not re.fullmatch(
        r"[A-Za-z0-9_.-]+", repo
    ):
        raise GitHubError(f"invalid GitHub repository: {spec!r}")
    return owner, repo, ref


def _api_get(url: str, token: Optional[str], timeout: int, **kwargs):
    try:
        response = requests.get(url, headers=_headers(token), timeout=timeout, **kwargs)
    except requests.RequestException as exc:
        raise GitHubError(f"GitHub request failed: {exc}") from exc
    if response.status_code >= 400:
        raise GitHubError(
            f"GitHub API {response.status_code} for {url}: {response.text[:200]}"
        )
    return response


def list_repos(
    owner: str,
    token: Optional[str] = None,
    limit: int = 50,
    include_forks: bool = False,
    is_org: bool = True,
    timeout: int = 30,
) -> List[GitHubRepo]:
    """List public repositories for a GitHub org or user."""
    kind = "orgs" if is_org else "users"
    endpoint = f"{API_ROOT}/{kind}/{owner}/repos"
    repos: List[GitHubRepo] = []
    page = 1
    while len(repos) < limit:
        response = _api_get(
            endpoint,
            token,
            timeout,
            params={
                "type": "public",
                "sort": "updated",
                "per_page": min(100, max(1, limit - len(repos))),
                "page": page,
            },
        )
        try:
            payload = response.json()
        except ValueError as exc:
            raise GitHubError("GitHub returned invalid JSON") from exc
        if not isinstance(payload, list) or not payload:
            break
        for item in payload:
            if not isinstance(item, dict):
                continue
            if item.get("archived"):
                continue
            if item.get("fork") and not include_forks:
                continue
            full_name = item.get("full_name") or ""
            if "/" not in full_name:
                continue
            name_owner, name = full_name.split("/", 1)
            repos.append(GitHubRepo(
                owner=name_owner,
                name=name,
                default_branch=item.get("default_branch") or "main",
                archived=bool(item.get("archived")),
                fork=bool(item.get("fork")),
                html_url=item.get("html_url") or "",
            ))
            if len(repos) >= limit:
                break
        if len(payload) < 100:
            break
        page += 1
    return repos


def _safe_extract(zip_path: str, dest: str, max_bytes: int) -> str:
    """Extract a GitHub zipball while preventing zip-slip and zip bombs."""
    dest = os.path.abspath(dest)
    os.makedirs(dest, exist_ok=True)
    total = 0
    with zipfile.ZipFile(zip_path) as archive:
        for info in archive.infolist():
            name = info.filename.replace("\\", "/")
            normalized = os.path.normpath(name)
            if normalized.startswith(("..", "/")) or os.path.isabs(normalized):
                raise GitHubError(f"unsafe path in zipball: {info.filename}")
            target = os.path.abspath(os.path.join(dest, normalized))
            if os.path.commonpath([dest, target]) != dest:
                raise GitHubError(f"zip-slip attempt: {info.filename}")

            mode = (info.external_attr >> 16) & 0o170000
            if mode == stat.S_IFLNK:
                continue  # never follow symlinks from an archive

            if info.is_dir():
                os.makedirs(target, exist_ok=True)
                continue

            total += info.file_size
            if total > max_bytes:
                raise GitHubError(
                    f"zipball exceeds extraction limit ({max_bytes} bytes)"
                )
            os.makedirs(os.path.dirname(target), exist_ok=True)
            with archive.open(info) as source, open(target, "wb") as output:
                shutil.copyfileobj(source, output)
            try:
                os.chmod(target, 0o644)
            except OSError:
                pass

    entries = [
        entry for entry in os.listdir(dest)
        if os.path.isdir(os.path.join(dest, entry)) or os.path.isfile(os.path.join(dest, entry))
    ]
    if not entries:
        raise GitHubError("zipball was empty")
    roots = [os.path.join(dest, entry) for entry in entries]
    directory_roots = [path for path in roots if os.path.isdir(path)]
    return directory_roots[0] if len(directory_roots) == 1 else dest


def extract_zipball(zip_path: str, dest: str, max_bytes: int = 200 * 1024 * 1024) -> str:
    """Public wrapper used by tests and callers."""
    return _safe_extract(zip_path, dest, max_bytes)


def _git_clone(
    owner: str,
    repo: str,
    ref: Optional[str],
    token: Optional[str],
    dest: str,
    history: bool,
    timeout: int,
) -> str:
    if not shutil.which("git"):
        raise GitHubError("git is required for --git-history clones")
    url = f"https://github.com/{owner}/{repo}.git"
    env = os.environ.copy()
    if token:
        # Keep the token out of the command line / process list.
        env.update({
            "GIT_CONFIG_COUNT": "1",
            "GIT_CONFIG_KEY_0": "http.extraheader",
            "GIT_CONFIG_VALUE_0": f"Authorization: Bearer {token}",
        })
    args = ["git", "clone", "--quiet", "--no-tags"]
    if not history:
        args.extend(["--depth", "1"])
    args.extend([url, dest])
    try:
        proc = subprocess.run(
            args,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            env=env,
            timeout=timeout,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise GitHubError(f"git clone failed: {exc}") from exc
    if proc.returncode != 0:
        raise GitHubError((proc.stderr or "git clone failed").strip())
    if ref:
        try:
            subprocess.run(
                ["git", "-C", dest, "checkout", "--quiet", ref],
                capture_output=True,
                text=True,
                env=env,
                timeout=timeout,
                check=True,
            )
        except (OSError, subprocess.SubprocessError) as exc:
            raise GitHubError(f"git checkout {ref!r} failed: {exc}") from exc
    return dest


def _download_zipball(
    owner: str,
    repo: str,
    ref: Optional[str],
    token: Optional[str],
    dest: str,
    timeout: int,
    max_bytes: int,
) -> str:
    suffix = f"/{ref}" if ref else ""
    url = f"{API_ROOT}/repos/{owner}/{repo}/zipball{suffix}"
    try:
        response = requests.get(
            url,
            headers=_headers(token),
            timeout=timeout,
            stream=True,
            allow_redirects=True,
        )
    except requests.RequestException as exc:
        raise GitHubError(f"zipball download failed: {exc}") from exc
    if response.status_code >= 400:
        raise GitHubError(
            f"GitHub zipball {response.status_code}: {response.text[:200]}"
        )

    os.makedirs(dest, exist_ok=True)
    fd, zip_path = tempfile.mkstemp(prefix="secref-gh-", suffix=".zip", dir=dest)
    try:
        written = 0
        with os.fdopen(fd, "wb") as output:
            for chunk in response.iter_content(chunk_size=64 * 1024):
                if not chunk:
                    continue
                written += len(chunk)
                if written > max_bytes:
                    raise GitHubError(
                        f"zipball exceeds download limit ({max_bytes} bytes)"
                    )
                output.write(chunk)
        return _safe_extract(zip_path, os.path.join(dest, "repo"), max_bytes)
    finally:
        try:
            os.unlink(zip_path)
        except OSError:
            pass


def download_repo(
    owner: str,
    repo: str,
    ref: Optional[str] = None,
    token: Optional[str] = None,
    dest: Optional[str] = None,
    timeout: int = 120,
    max_bytes: int = 200 * 1024 * 1024,
    history: bool = False,
) -> str:
    """Download a repository and return the scan root.

    Uses a git clone when ``history`` is requested (so ``git log`` works), and
    a fast zipball otherwise. Falls back to git if the API path fails.
    """
    target = dest or tempfile.mkdtemp(prefix="secref-gh-")
    os.makedirs(target, exist_ok=True)
    if history:
        return _git_clone(owner, repo, ref, token, target, True, timeout)

    try:
        return _download_zipball(owner, repo, ref, token, target, timeout, max_bytes)
    except GitHubError as zip_error:
        if not shutil.which("git"):
            raise zip_error
        try:
            return _git_clone(owner, repo, ref, token, target, False, timeout)
        except GitHubError as clone_error:
            raise GitHubError(
                f"zipball failed ({zip_error}); git fallback failed ({clone_error})"
            ) from clone_error


def cleanup_repo(path: str) -> None:
    """Remove a temporary repository checkout."""
    try:
        shutil.rmtree(path, ignore_errors=True)
    except OSError:
        pass


def _normalized_path(path: str) -> str:
    return os.path.normcase(os.path.abspath(path)).replace("\\", "/").rstrip("/")


def relabel_results(results: List[dict], root: str, label: str) -> None:
    """Rewrite temp checkout paths to ``github://owner/repo/...`` URLs."""
    root_norm = _normalized_path(root)
    for finding in results:
        url = str(finding.get("url", ""))
        path = url
        if url.startswith("file://"):
            path = unquote(urlparse(url).path)
            if os.name == "nt" and re.match(r"^/[A-Za-z]:/", path):
                path = path[1:]
        elif "://" in url and not url.startswith("github://"):
            continue
        elif url.startswith("github://"):
            continue

        path_norm = _normalized_path(path)
        if path_norm == root_norm or path_norm.startswith(root_norm + "/"):
            relative = path_norm[len(root_norm):].lstrip("/")
            finding["url"] = f"github://{label}/{relative}"
            finding["repo"] = label
