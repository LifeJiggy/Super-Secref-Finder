"""Local filesystem scanning tests."""

from src.filesystem import iter_local_sources


def test_scans_files_and_skips_noise_dirs(tmp_path):
    (tmp_path / ".env").write_text("AWS_ACCESS_KEY_ID=AKIA1234567890ABCDEF\n", encoding="utf-8")
    (tmp_path / "app.py").write_text("print('hello')\n", encoding="utf-8")
    node_modules = tmp_path / "node_modules"
    node_modules.mkdir()
    (node_modules / "lib.js").write_text("ghp_" + "a" * 36, encoding="utf-8")

    sources = list(iter_local_sources([str(tmp_path)]))
    names = {source.path.replace("\\", "/") for source in sources}

    assert any(name.endswith("/.env") for name in names)
    assert any(name.endswith("/app.py") for name in names)
    assert not any("node_modules" in name for name in names)


def test_skips_binary_files(tmp_path):
    binary = tmp_path / "image.png"
    binary.write_bytes(b"\x89PNG\r\n\x1a\n\x00\x00\x00")
    assert list(iter_local_sources([str(tmp_path)])) == []


def test_respects_size_limit(tmp_path):
    big = tmp_path / "big.txt"
    big.write_text("A" * 2048, encoding="utf-8")
    assert list(iter_local_sources([str(tmp_path)], max_size=1024)) == []


def test_exclude_globs(tmp_path):
    (tmp_path / "keep.txt").write_text("keep", encoding="utf-8")
    (tmp_path / "skip.log").write_text("skip", encoding="utf-8")
    sources = list(iter_local_sources([str(tmp_path)], exclude_globs=["*.log"]))
    assert len(sources) == 1
    assert sources[0].path.endswith("keep.txt")


def test_direct_file_and_missing_path(tmp_path):
    file_path = tmp_path / "config.yaml"
    file_path.write_text("token: abcdefghijklmnopqrstuvwxyz\n", encoding="utf-8")
    sources = list(iter_local_sources([str(file_path), str(tmp_path / "missing.txt")]))
    assert len(sources) == 1
    assert sources[0].url.startswith("file://")


def test_skips_tool_artifacts(tmp_path):
    (tmp_path / "app.py").write_text("print('ok')\n", encoding="utf-8")
    (tmp_path / "findings_20260101_000000.json").write_text("{}", encoding="utf-8")
    (tmp_path / "secref.log").write_text("{}", encoding="utf-8")
    sources = list(iter_local_sources([str(tmp_path)]))
    assert len(sources) == 1
    assert sources[0].path.endswith("app.py")
