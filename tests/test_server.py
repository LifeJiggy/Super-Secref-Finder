"""Report dashboard server tests."""

import threading
import urllib.request

from src.server import build_dashboard_index, create_server, latest_report, list_reports


def test_report_listing_and_index(tmp_path):
    (tmp_path / "findings_20260101_010101.html").write_text("<html>old</html>", encoding="utf-8")
    (tmp_path / "findings_20260102_010101.html").write_text("<html>new</html>", encoding="utf-8")
    (tmp_path / "ignore.txt").write_text("not a report", encoding="utf-8")

    reports = list_reports(str(tmp_path))
    assert reports[0] == "findings_20260102_010101.html"
    assert latest_report(str(tmp_path)) == "findings_20260102_010101.html"
    index = build_dashboard_index(str(tmp_path))
    assert "Super Secref Finder" in index
    assert "findings_20260102_010101.html" in index


def test_server_serves_index_and_report(tmp_path):
    report = tmp_path / "findings_20260101_010101.html"
    report.write_text("<html>report body</html>", encoding="utf-8")
    server = create_server(str(tmp_path), host="127.0.0.1", port=0)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        host, port = server.server_address[:2]
        with urllib.request.urlopen(f"http://{host}:{port}/", timeout=5) as response:
            index = response.read().decode("utf-8")
        with urllib.request.urlopen(
            f"http://{host}:{port}/{report.name}", timeout=5
        ) as response:
            body = response.read().decode("utf-8")
        assert "findings_20260101_010101.html" in index
        assert body == "<html>report body</html>"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
