"""Git staged/changed and history scanning tests."""

import os
import shutil
import subprocess

import pytest

from src.gitscan import (
    changed_files,
    iter_history_documents,
    repo_root,
    staged_files,
)

pytestmark = pytest.mark.skipif(shutil.which("git") is None, reason="git not installed")

SECRET = "AKIA1234567890ABCDEF"


def _git(repo, *args):
    subprocess.run(
        ["git", *args],
        cwd=repo,
        check=True,
        capture_output=True,
        text=True,
    )


def _repo(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    _git(repo, "init")
    _git(repo, "config", "user.email", "test@example.com")
    _git(repo, "config", "user.name", "Test")
    return repo


def test_repo_root_and_staged_files(tmp_path):
    repo = _repo(tmp_path)
    (repo / "app.py").write_text("print('ok')\n", encoding="utf-8")
    _git(repo, "add", ".")
    _git(repo, "commit", "-m", "initial")

    assert os.path.normcase(os.path.realpath(repo_root(str(repo)))) == (
        os.path.normcase(os.path.realpath(str(repo)))
    )

    (repo / "app.py").write_text(f"KEY={SECRET}\n", encoding="utf-8")
    _git(repo, "add", "app.py")
    staged = staged_files(str(repo))
    assert any(path.endswith("app.py") for path in staged)


def test_changed_files_includes_untracked(tmp_path):
    repo = _repo(tmp_path)
    (repo / "app.py").write_text("print('ok')\n", encoding="utf-8")
    _git(repo, "add", ".")
    _git(repo, "commit", "-m", "initial")

    (repo / "app.py").write_text(f"KEY={SECRET}\n", encoding="utf-8")
    (repo / "new.env").write_text(f"TOKEN={SECRET}\n", encoding="utf-8")
    changed = changed_files(str(repo))
    assert any(path.endswith("app.py") for path in changed)
    assert any(path.endswith("new.env") for path in changed)


def test_history_documents_only_added_lines(tmp_path):
    repo = _repo(tmp_path)
    (repo / "app.py").write_text("print('ok')\n", encoding="utf-8")
    _git(repo, "add", ".")
    _git(repo, "commit", "-m", "initial")

    (repo / "app.py").write_text(f"KEY={SECRET}\nprint('ok')\n", encoding="utf-8")
    _git(repo, "add", ".")
    _git(repo, "commit", "-m", "add secret")

    (repo / "app.py").write_text("print('ok')\n", encoding="utf-8")
    _git(repo, "add", ".")
    _git(repo, "commit", "-m", "remove secret")

    documents = list(iter_history_documents(str(repo), max_commits=10))
    assert documents
    added = "\n".join(doc["text"] for doc in documents)
    assert SECRET in added
    assert all(doc["commit"] for doc in documents)
    assert any(doc["commit_message"] == "add secret" for doc in documents)


def test_history_author_and_range_filters(tmp_path):
    repo = _repo(tmp_path)
    (repo / "app.py").write_text("print('ok')\n", encoding="utf-8")
    _git(repo, "add", ".")
    _git(repo, "commit", "-m", "initial")

    _git(repo, "config", "user.name", "Alice")
    _git(repo, "config", "user.email", "alice@example.com")
    (repo / "app.py").write_text(f"KEY={SECRET}\n", encoding="utf-8")
    _git(repo, "add", ".")
    _git(repo, "commit", "-m", "alice secret")

    log = subprocess.check_output(
        ["git", "log", "--format=%H%x20%s"], cwd=repo, text=True
    ).splitlines()
    subjects = {line.split(" ", 1)[1]: line.split(" ", 1)[0] for line in log}
    initial = subjects["initial"]
    secret_commit = subjects["alice secret"]

    alice_docs = list(iter_history_documents(str(repo), author="Alice"))
    assert alice_docs
    assert all(doc["author"] == "Alice" for doc in alice_docs)
    assert any(SECRET in doc["text"] for doc in alice_docs)

    ranged = list(iter_history_documents(
        str(repo), from_ref=initial, to_ref=secret_commit
    ))
    assert ranged
    assert {doc["commit"] for doc in ranged} == {secret_commit}

    head_only = list(iter_history_documents(str(repo), to_ref=initial))
    assert {doc["commit"] for doc in head_only} == {initial}
