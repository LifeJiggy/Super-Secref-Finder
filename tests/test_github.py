"""GitHub repository discovery and zipball extraction tests."""

import io
import zipfile

import pytest

from src.github import (
    GitHubError,
    extract_zipball,
    list_repos,
    parse_repo_spec,
    relabel_results,
)


def test_parse_repo_specs():
    assert parse_repo_spec("owner/repo") == ("owner", "repo", None)
    assert parse_repo_spec("https://github.com/owner/repo") == ("owner", "repo", None)
    assert parse_repo_spec("https://github.com/owner/repo.git") == ("owner", "repo", None)
    assert parse_repo_spec("https://github.com/owner/repo/tree/dev") == (
        "owner", "repo", "dev",
    )
    assert parse_repo_spec("git@github.com:owner/repo.git") == ("owner", "repo", None)


def test_parse_repo_spec_rejects_non_github():
    with pytest.raises(GitHubError):
        parse_repo_spec("https://gitlab.com/owner/repo")
    with pytest.raises(GitHubError):
        parse_repo_spec("not-a-repo")


def test_extract_zipball(tmp_path):
    archive = tmp_path / "repo.zip"
    with zipfile.ZipFile(archive, "w") as zf:
        zf.writestr("owner-repo-sha/README.md", "hello")
        zf.writestr("owner-repo-sha/src/app.py", "print('ok')\n")
    root = extract_zipball(str(archive), str(tmp_path / "out"))
    assert root.endswith("owner-repo-sha")
    assert (tmp_path / "out" / "owner-repo-sha" / "src" / "app.py").is_file()


def test_extract_zipball_rejects_zip_slip(tmp_path):
    archive = tmp_path / "evil.zip"
    with zipfile.ZipFile(archive, "w") as zf:
        zf.writestr("../evil.txt", "no")
    with pytest.raises(GitHubError):
        extract_zipball(str(archive), str(tmp_path / "out"))


def test_list_repos_filters_forks_and_respects_limit(monkeypatch):
    payload = [
        {"full_name": "acme/one", "default_branch": "main", "fork": False, "archived": False},
        {"full_name": "acme/fork", "default_branch": "main", "fork": True, "archived": False},
        {"full_name": "acme/two", "default_branch": "dev", "fork": False, "archived": True},
        {"full_name": "acme/three", "default_branch": "main", "fork": False, "archived": False},
    ]

    class Response:
        status_code = 200
        text = ""

        def json(self):
            return payload

    monkeypatch.setattr("src.github.requests.get", lambda *a, **k: Response())
    repos = list_repos("acme", limit=10, include_forks=False)
    assert [repo.slug for repo in repos] == ["acme/one", "acme/three"]

    repos = list_repos("acme", limit=2, include_forks=True)
    assert len(repos) == 2


def test_relabel_results():
    findings = [
        {"url": "file:///tmp/secref-gh-abc/repo/.env", "type": "x"},
        {"url": "https://other.test/a.js", "type": "y"},
    ]
    relabel_results(findings, "/tmp/secref-gh-abc/repo", "owner/repo")
    assert findings[0]["url"] == "github://owner/repo/.env"
    assert findings[0]["repo"] == "owner/repo"
    assert findings[1]["url"] == "https://other.test/a.js"


def test_empty_zipball_rejected(tmp_path):
    archive = tmp_path / "empty.zip"
    with zipfile.ZipFile(archive, "w"):
        pass
    with pytest.raises(GitHubError):
        extract_zipball(str(archive), str(tmp_path / "out"))
