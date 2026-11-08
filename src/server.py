"""Local report dashboard for ``--serve``.

The scanner already writes self-contained HTML reports.  This module adds a
small, dependency-free, read-only web server that presents the latest reports
with a report index and optional browser launch.  It never exposes anything
outside the configured output directory.
"""

from __future__ import annotations

import html
import os
import webbrowser
from datetime import datetime, timezone
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from typing import List, Optional, Tuple
from urllib.parse import unquote, urlparse

from . import __version__

_REPORT_EXTENSIONS = (".html", ".json", ".sarif", ".xml", ".md", ".csv", ".jsonl")


def list_reports(directory: str) -> List[str]:
    """Return report files in ``directory``, newest first."""
    try:
        names = [
            name for name in os.listdir(directory)
            if name.lower().endswith(_REPORT_EXTENSIONS)
            and os.path.isfile(os.path.join(directory, name))
        ]
    except OSError:
        return []
    return sorted(
        names,
        key=lambda name: (
            os.path.getmtime(os.path.join(directory, name)),
            name,
        ),
        reverse=True,
    )


def latest_report(directory: str, extension: str = ".html") -> Optional[str]:
    """Return the newest report with ``extension``, if one exists."""
    for name in list_reports(directory):
        if name.lower().endswith(extension.lower()):
            return name
    return None


def build_dashboard_index(directory: str) -> str:
    """Build a minimal report index page."""
    reports = list_reports(directory)
    rows = []
    for name in reports:
        path = os.path.join(directory, name)
        try:
            size = os.path.getsize(path)
            modified = datetime.fromtimestamp(
                os.path.getmtime(path), tz=timezone.utc
            ).strftime("%Y-%m-%d %H:%M:%S UTC")
        except OSError:
            size = 0
            modified = ""
        rows.append(
            "<tr><td><a href='/{name}'>{name}</a></td><td>{size}</td>"
            "<td>{modified}</td></tr>".format(
                name=html.escape(name),
                size=f"{size:,}",
                modified=html.escape(modified),
            )
        )
    body = "".join(rows) or "<tr><td colspan='3'>No reports yet.</td></tr>"
    return (
        "<!DOCTYPE html><html lang='en'><head><meta charset='UTF-8'>"
        "<meta name='viewport' content='width=device-width, initial-scale=1'>"
        "<title>Super Secref Finder reports</title>"
        "<style>"
        "body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;"
        "margin:2rem;background:#0d1117;color:#c9d1d9}"
        "a{color:#58a6ff}table{border-collapse:collapse;width:100%;max-width:1000px}"
        "th,td{border:1px solid #30363d;padding:.6rem;text-align:left}"
        "th{background:#161b22;color:#8b949e}code{color:#8b949e}"
        "</style></head><body>"
        "<h1>Super Secref Finder</h1>"
        f"<p class='sub'>v{html.escape(__version__)} &middot; report dashboard "
        f"&middot; {html.escape(directory)}</p>"
        "<table><thead><tr><th>Report</th><th>Bytes</th><th>Modified</th></tr></thead>"
        f"<tbody>{body}</tbody></table>"
        "<p><small>Read-only local server. Reports can contain live credentials; "
        "do not expose this port to untrusted networks.</small></p>"
        "</body></html>"
    )


def make_handler(root: str):
    """Create a request handler bound to ``root``."""
    root_abs = os.path.realpath(root)

    class ReportHandler(SimpleHTTPRequestHandler):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, directory=root_abs, **kwargs)

        def do_GET(self):  # noqa: N802 - stdlib handler name
            path = unquote(urlparse(self.path).path)
            if path in ("", "/", "/index.html"):
                self._send_index()
                return
            # Refuse traversal outside the output directory.
            candidate = os.path.realpath(os.path.join(root_abs, path.lstrip("/")))
            if os.path.commonpath([root_abs, candidate]) != root_abs:
                self.send_error(403, "Forbidden")
                return
            super().do_GET()

        def _send_index(self) -> None:
            payload = build_dashboard_index(root_abs).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

        def log_message(self, fmt, *args):  # quieter default logging
            return

    return ReportHandler


def create_server(
    directory: str,
    host: str = "127.0.0.1",
    port: int = 8000,
) -> ThreadingHTTPServer:
    """Create (but do not start) the report server."""
    return ThreadingHTTPServer((host, int(port)), make_handler(directory))


def serve_report(
    directory: str,
    host: str = "127.0.0.1",
    port: int = 8000,
    open_browser: bool = False,
) -> Tuple[str, int]:
    """Serve reports until interrupted. Returns the bound ``(host, port)``."""
    server = create_server(directory, host, port)
    bound_host, bound_port = server.server_address[:2]
    url = f"http://{bound_host}:{bound_port}/"
    print(f"\n[+] Report dashboard: {url}")
    print("[+] Press Ctrl+C to stop.")
    if open_browser:
        webbrowser.open(url)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[!] Report server stopped.")
    finally:
        server.server_close()
    return str(bound_host), int(bound_port)


__all__ = [
    "build_dashboard_index",
    "create_server",
    "latest_report",
    "list_reports",
    "make_handler",
    "serve_report",
]
