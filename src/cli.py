"""CLI argument parsing — the non-interactive entry point."""

from __future__ import annotations

import argparse
from typing import List, Optional

from . import __version__
from .rules import SEVERITIES


def _split_commas(values: Optional[List[str]]) -> List[str]:
    out: List[str] = []
    for value in values or []:
        out.extend(part.strip() for part in value.split(",") if part.strip())
    return out


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="super-secref-finder",
        description=(
            "Super Secref Finder — high-signal secret scanner for web apps, "
            "JavaScript bundles, and local files."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Scan a website + its JavaScript
  %(prog)s https://example.com

  # Scan a local repository (fast, no network)
  %(prog)s --path . --format json html sarif --fail-on high

  # Scan specific files / pipe stdin
  %(prog)s --path src/ config.yaml .env
  cat .env | %(prog)s --path -

  # Through Burp/ZAP, with auth and multiple reports
  %(prog)s https://app.example.com --proxy http://127.0.0.1:8080 \\
      --header "Authorization: Bearer TOKEN" --format json html sarif -v

  # Differential scan: only new secrets since the baseline
  %(prog)s https://example.com --baseline known.json

  # Tune signal: include PII or code-smell rules, raise minimum severity
  %(prog)s --path . --include-pii --min-severity high

  # Discover every rule (and its severity)
  %(prog)s --list-rules
        """,
    )

    # Target ---------------------------------------------------------------
    parser.add_argument("url", nargs="?", help="Target URL to scan (optional with --path)")
    parser.add_argument("--js", nargs="*", default=[], help="Direct JavaScript URLs to scan")
    parser.add_argument(
        "--path", nargs="+", default=None, metavar="PATH",
        help="Local file(s) or directory(ies) to scan; '-' reads stdin",
    )
    parser.add_argument(
        "--github", metavar="OWNER/REPO",
        help="Scan a live GitHub repository (owner/repo or GitHub URL)",
    )
    parser.add_argument("--github-ref", help="Branch, tag, or commit for --github")
    parser.add_argument(
        "--github-token",
        help="GitHub token for private repos (or GITHUB_TOKEN / GH_TOKEN)",
    )
    parser.add_argument(
        "--github-org", metavar="ORG",
        help="Scan public repositories in a GitHub organization",
    )
    parser.add_argument(
        "--github-user", metavar="USER",
        help="Scan public repositories for a GitHub user",
    )
    parser.add_argument(
        "--github-limit", type=int, default=50,
        help="Max repositories to discover for --github-org/--github-user (default: 50)",
    )
    parser.add_argument(
        "--github-include-forks", action="store_true",
        help="Include forked repositories during discovery",
    )
    parser.add_argument(
        "--github-keep", action="store_true",
        help="Keep the downloaded checkout (debugging)",
    )
    parser.add_argument("--staged", action="store_true",
                        help="Scan files staged in git (pre-commit mode)")
    parser.add_argument("--changed", action="store_true",
                        help="Scan modified and untracked git files")
    parser.add_argument("--git-history", action="store_true",
                        help="Scan secrets introduced across git history")
    parser.add_argument("--git-history-depth", type=int, default=100,
                        help="Max commits for --git-history (default: 100; 0 = all)")
    parser.add_argument("--git-since", help="Only history after this date (git --since)")
    parser.add_argument("--git-from", metavar="REV",
                        help="Start of history range (exclusive), e.g. v8.0.0")
    parser.add_argument("--git-to", metavar="REV",
                        help="End of history range (inclusive, default HEAD)")
    parser.add_argument("--git-author", metavar="PATTERN",
                        help="Only commits whose author matches this git pattern")

    # Threading ------------------------------------------------------------
    parser.add_argument("-t", "--threads", type=int, default=10,
                        help="Worker threads, 1-100 (default: 10)")
    parser.add_argument("-d", "--delay", type=float, default=1.0,
                        help="Delay between web requests in seconds (default: 1.0)")
    parser.add_argument("--per-host-delay", type=float, default=0.0,
                        help="Minimum seconds between request starts per host (default: 0)")
    parser.add_argument("--per-host-concurrency", type=int, default=0,
                        help="Max concurrent requests per host, 0 = unlimited (default: 0)")

    # Network --------------------------------------------------------------
    parser.add_argument("--proxy", help="Proxy URL (e.g. http://127.0.0.1:8080)")
    parser.add_argument("--proxy-auth", help="Proxy auth (user:pass)")
    parser.add_argument("--timeout", type=int, default=30,
                        help="Request timeout in seconds (default: 30)")
    parser.add_argument("--max-retries", type=int, default=3,
                        help="Max retries per request (default: 3)")
    parser.add_argument("--no-verify", action="store_true", help="Disable SSL verification")
    parser.add_argument(
        "--user-agent",
        default="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                "(KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
        help="Custom User-Agent string (use 'random' for rotation)",
    )

    # Headers / auth -------------------------------------------------------
    parser.add_argument("--header", action="append", default=[], metavar="NAME: VALUE",
                        help="Custom header (repeatable)")
    parser.add_argument("--cookie-file", help="Cookie file (Netscape or key=value format)")
    parser.add_argument("--auth", help="Authorization header value")

    # Crawling -------------------------------------------------------------
    parser.add_argument("--depth", type=int, default=1, help="Crawl depth (default: 1)")
    parser.add_argument("--max-urls", type=int, default=500,
                        help="Max URLs to scan (default: 500)")
    parser.add_argument("--scope", help="Scope regex — restrict scanned URLs")
    parser.add_argument("--exclude", action="append", default=[],
                        help="URL/file exclusion regex or glob (repeatable)")
    parser.add_argument("--allow-external", action="store_true",
                        help="Follow links to other hosts (off by default)")
    parser.add_argument("--respect-robots", action="store_true",
                        help="Respect robots.txt during crawling")
    parser.add_argument("--source-maps", action="store_true",
                        help="Discover sourceMappingURL maps and quoted JS chunks")

    # HTTP -----------------------------------------------------------------
    parser.add_argument("--method", choices=["GET", "POST"], default="GET",
                        help="HTTP method (default: GET)")
    parser.add_argument("--data", help="POST body data")
    parser.add_argument("--max-size", type=int, default=5242880,
                        help="Max response/file size in bytes (default: 5 MB)")

    # Detection ------------------------------------------------------------
    parser.add_argument("--confidence", type=float, default=0.6,
                        help="Minimum confidence, 0-1 (default: 0.6)")
    parser.add_argument("--entropy", type=float, default=0.0,
                        help="Global entropy floor for secret rules; 0 = rule defaults")
    parser.add_argument("--custom-patterns", nargs="*", default=[],
                        help="Custom rule files (YAML/JSON)")
    parser.add_argument("--gitleaks-config", action="append", default=[], metavar="PATH",
                        help="Import rules from a gitleaks TOML config (repeatable)")
    parser.add_argument("--semgrep-config", action="append", default=[], metavar="PATH",
                        help="Import the regex subset of a Semgrep YAML config (repeatable)")
    parser.add_argument("--include-noise", action="store_true",
                        help="Also report code smells (eval, console.log, inline scripts, ...)")
    parser.add_argument("--include-pii", action="store_true",
                        help="Also report PII (emails, phones, SSNs, credit cards)")
    parser.add_argument("--include-endpoints", action="store_true",
                        help="Also report endpoint discovery (API, admin, debug, GraphQL, ...)")
    parser.add_argument("--entropy-scan", action="store_true",
                        help="Also report generic high-entropy strings")
    parser.add_argument("--entropy-min-length", type=int, default=20,
                        help="Min token length for --entropy-scan (default: 20)")
    parser.add_argument("--entropy-scan-threshold", type=float, default=3.5,
                        help="Entropy threshold for --entropy-scan (default: 3.5)")
    parser.add_argument("--audit-github-actions", action="store_true",
                        help="Audit .github/workflows for supply-chain risks")
    parser.add_argument("--min-severity", choices=list(SEVERITIES),
                        help="Only rules at or above this severity")
    parser.add_argument("--include-type", action="append", default=[], metavar="RULE",
                        help="Only these rule IDs (repeatable/comma-separated)")
    parser.add_argument("--exclude-type", action="append", default=[], metavar="RULE",
                        help="Exclude these rule IDs (repeatable/comma-separated)")
    parser.add_argument("--max-per-rule", type=int, default=5,
                        help="Max findings per rule per document (default: 5)")
    parser.add_argument("--ignore-file", action="append", default=[],
                        help="Allowlist file (repeatable); default .secrefignore")
    parser.add_argument("--no-default-ignore", action="store_true",
                        help="Do not load .secrefignore from the current directory")
    parser.add_argument("--show-context", action="store_true",
                        help="Include an evidence snippet in reports")
    parser.add_argument("--list-rules", action="store_true",
                        help="Print all detection rules and exit")
    parser.add_argument("--safe-mode", action="store_true",
                        help="Skip active secret validation (no outbound checks)")
    parser.add_argument("--validate-workers", type=int, default=4,
                        help="Concurrent live validators (default: 4)")
    parser.add_argument("--validate-max", type=int, default=100,
                        help="Max live validations per scan (default: 100)")

    # Output ---------------------------------------------------------------
    parser.add_argument("-o", "--output-dir", default=".", help="Output directory (default: .)")
    parser.add_argument(
        "--format", nargs="+", default=["json"],
        choices=["json", "jsonl", "csv", "md", "markdown", "html", "sarif", "junit"],
        help="Output format(s) (default: json)",
    )
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    parser.add_argument("-q", "--quiet", action="store_true", help="Suppress console output")
    parser.add_argument("--redact", action="store_true", help="Redact secret values in output")
    parser.add_argument("--write-ignore", metavar="PATH",
                        help="Write a precise allowlist from findings (hashed fingerprints)")
    parser.add_argument("--allowlist-values", action="store_true",
                        help="Also write raw value regexes to --write-ignore (sensitive)")
    parser.add_argument("--serve", action="store_true",
                        help="Serve a local report dashboard after the scan (forces HTML)")
    parser.add_argument("--serve-host", default="127.0.0.1",
                        help="Dashboard bind address (default: 127.0.0.1)")
    parser.add_argument("--serve-port", type=int, default=8000,
                        help="Dashboard port (default: 8000)")
    parser.add_argument("--open-browser", action="store_true",
                        help="Open the report dashboard in the default browser")

    # CI -------------------------------------------------------------------
    parser.add_argument(
        "--fail-on", choices=["never", "low", "medium", "high", "critical"],
        default="never", help="Exit 1 if a finding at/above this severity exists",
    )

    # Resume / diff --------------------------------------------------------
    parser.add_argument("--resume", help="Checkpoint file for resume")
    parser.add_argument("--baseline", help="Baseline file for differential scanning")
    parser.add_argument("--update-baseline", metavar="PATH",
                        help="Write current findings as a hashed baseline and exit")

    # Anti-detection -------------------------------------------------------
    parser.add_argument("--jitter", action="store_true", help="Add random request jitter")

    # Plugins --------------------------------------------------------------
    parser.add_argument("--plugin-dir", help="Directory containing plugin .py files")
    parser.add_argument("--entrypoint-plugins", action="store_true",
                        help="Load installed plugins from the 'secref.plugins' entry-point group")

    # Notifications --------------------------------------------------------
    parser.add_argument("--webhook", metavar="URL",
                        help="Post a redacted summary to a Slack/Discord/generic webhook")
    parser.add_argument("--webhook-format", choices=["slack", "discord", "generic"],
                        default="slack", help="Webhook payload format (default: slack)")
    parser.add_argument("--webhook-min-severity",
                        choices=["never", "low", "medium", "high", "critical"],
                        default="high", help="Min severity included in webhook (default: high)")

    # Misc -----------------------------------------------------------------
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    parser.add_argument("-i", "--interactive", action="store_true", help="Use interactive menu")

    return parser


def parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    """Parse and validate command-line arguments."""
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.list_rules:
        return args

    if not (
        args.url or args.js or args.path or args.interactive or args.github
        or args.github_org or args.github_user or args.staged or args.changed
        or args.git_history or args.audit_github_actions
    ):
        parser.error(
            "provide a URL, --path, --github, --github-org, --github-user, "
            "--staged, --changed, or --interactive"
        )

    target_count = sum(bool(value) for value in (
        (args.url or args.js), args.path, args.github, args.github_org,
        args.github_user, args.staged, args.changed,
    ))
    if target_count > 1:
        parser.error("choose one target: URL, --path, --github, --github-org, --github-user, --staged, or --changed")

    if args.interactive and target_count:
        parser.error("--interactive cannot be combined with another target")

    if args.github_org and args.github_user:
        parser.error("use either --github-org or --github-user, not both")
    if args.github_ref and not args.github:
        parser.error("--github-ref requires --github")
    if args.staged and args.changed:
        parser.error("use either --staged or --changed, not both")
    if (args.git_from or args.git_to or args.git_author) and not args.git_history:
        parser.error("--git-from, --git-to, and --git-author require --git-history")

    if not 1 <= args.threads <= 100:
        parser.error("--threads must be between 1 and 100")
    if args.delay < 0 or args.delay > 100:
        parser.error("--delay must be between 0 and 100 seconds")
    if args.per_host_delay < 0 or args.per_host_delay > 300:
        parser.error("--per-host-delay must be between 0 and 300 seconds")
    if not 0 <= args.per_host_concurrency <= 100:
        parser.error("--per-host-concurrency must be between 0 and 100")
    if not 1 <= args.serve_port <= 65535:
        parser.error("--serve-port must be between 1 and 65535")
    if not 0 <= args.confidence <= 1:
        parser.error("--confidence must be between 0 and 1")
    if args.max_per_rule < 1:
        parser.error("--max-per-rule must be >= 1")
    if args.validate_workers < 1:
        parser.error("--validate-workers must be >= 1")
    if args.validate_max < 0:
        parser.error("--validate-max must be >= 0")
    if args.github_limit < 1:
        parser.error("--github-limit must be >= 1")
    if args.git_history_depth < 0:
        parser.error("--git-history-depth must be >= 0")
    if args.entropy_min_length < 8:
        parser.error("--entropy-min-length must be >= 8")
    if not 1 <= args.entropy_scan_threshold <= 8:
        parser.error("--entropy-scan-threshold must be between 1 and 8")

    args.include_type = _split_commas(args.include_type)
    args.exclude_type = _split_commas(args.exclude_type)
    args.ignore_file = _split_commas(args.ignore_file)

    args.parsed_headers = {}
    for header in args.header:
        if ":" in header:
            name, value = header.split(":", 1)
            args.parsed_headers[name.strip()] = value.strip()

    return args
