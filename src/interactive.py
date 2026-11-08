"""Interactive guided setup for people who prefer prompts over flags."""

from __future__ import annotations

import os
import sys

from colorama import Fore, init

from . import __version__
from .config import ScanConfig
from .crawler import validate_url

init(autoreset=True)

_FORMATS = ["json", "jsonl", "csv", "md", "html", "sarif", "junit"]


def print_banner() -> None:
    """Print the tool banner."""
    print(Fore.CYAN + r"""
   _____                         _____                     __
  / ____|                       / ____|                   / _|
 | (___  _   _ _ __   ___ _ __| (___   ___  ___ _ __ ___| |_
  \___ \| | | | '_ \ / _ \ '__|\___ \ / _ \/ __| '__/ _ \  _|
  ____) | |_| | |_) |  __/ |   ____) |  __/ (__| | |  __/ |
 |_____/ \__,_| .__/ \___|_|  |_____/ \___|\___|_|  \___|_|
              | |
              |_|
    """)
    print(Fore.MAGENTA + f"Super Secref Finder v{__version__}\n")
    print(Fore.YELLOW + "[*] High-signal secret scanner for web, JS, and local files\n")
    print(Fore.GREEN + "[*] GitHub: https://github.com/LifeJiggy/Super-Secref-Finder")
    print()


def _ask(prompt: str, default: str = "", required: bool = False) -> str:
    suffix = f" [{default}]" if default else ""
    while True:
        value = input(Fore.YELLOW + f"{prompt}{suffix}: ").strip()
        if value:
            return value
        if default:
            return default
        if not required:
            return ""
        print(Fore.RED + "  This value is required.")


def _ask_bool(prompt: str, default: bool = False) -> bool:
    hint = "Y/n" if default else "y/N"
    value = input(Fore.YELLOW + f"{prompt} ({hint}): ").strip().lower()
    if not value:
        return default
    return value in {"y", "yes", "1", "true"}


def _ask_int(prompt: str, default: int, minimum: int, maximum: int) -> int:
    while True:
        raw = _ask(prompt, str(default))
        try:
            value = int(raw)
        except ValueError:
            print(Fore.RED + f"  Enter a number between {minimum} and {maximum}.")
            continue
        if minimum <= value <= maximum:
            return value
        print(Fore.RED + f"  Enter a number between {minimum} and {maximum}.")


def _ask_float(prompt: str, default: float, minimum: float, maximum: float) -> float:
    while True:
        raw = _ask(prompt, str(default))
        try:
            value = float(raw)
        except ValueError:
            print(Fore.RED + f"  Enter a number between {minimum} and {maximum}.")
            continue
        if minimum <= value <= maximum:
            return value
        print(Fore.RED + f"  Enter a number between {minimum} and {maximum}.")


def _ask_choice(prompt: str, choices, default: str) -> str:
    joined = "/".join(choices)
    while True:
        value = _ask(f"{prompt} ({joined})", default).lower()
        if value in choices:
            return value
        print(Fore.RED + f"  Choose one of: {joined}")


def interactive_menu() -> ScanConfig:
    """Prompt for a complete scan configuration and return it."""
    print_banner()
    cfg = ScanConfig()

    mode = _ask_choice(
        "Target type: 1=URL, 2=local path, 3=stdin, 4=GitHub repo, 5=git history",
        ["1", "2", "3", "4", "5"],
        "1",
    )
    if mode == "1":
        while True:
            url = _ask("Target URL", required=True)
            if validate_url(url):
                cfg.url = url
                break
            print(Fore.RED + "  Must start with http:// or https://")
    elif mode == "2":
        while True:
            path = _ask("File or directory", ".", required=True)
            if path == "-" or os.path.exists(os.path.expanduser(path)):
                cfg.paths = [path]
                break
            print(Fore.RED + "  Path does not exist.")
    elif mode == "4":
        cfg.github_repo = _ask("GitHub repo (owner/repo or URL)", required=True)
        cfg.github_ref = _ask("Branch/tag/commit (blank for default)")
        cfg.github_token = (
            os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN") or None
        )
    elif mode == "5":
        cfg.paths = ["."]
        cfg.git_history = True
        cfg.git_history_depth = _ask_int("History depth (0 = all)", 100, 0, 100000)
    else:
        cfg.paths = ["-"]

    advanced = _ask_bool("Configure advanced options", default=False)
    if advanced:
        cfg.threads = _ask_int("Threads", 10, 1, 100)
        if mode == "1":
            cfg.delay = _ask_float("Delay between requests (seconds)", 1.0, 0, 100)
            cfg.depth = _ask_int("Crawl depth", 1, 0, 10)
            cfg.max_urls = _ask_int("Max URLs", 500, 1, 100000)
            proxy = _ask("Proxy URL (blank for none)")
            if proxy:
                cfg.proxy = proxy
            cfg.respect_robots = _ask_bool("Respect robots.txt", default=True)
            cfg.allow_external = _ask_bool("Follow external hosts", default=False)
        cfg.include_noise = _ask_bool("Include code-smell rules (eval, console.log, ...)", default=False)
        cfg.include_pii = _ask_bool("Include PII rules (emails, phones, cards)", default=False)
        cfg.include_endpoints = _ask_bool("Include endpoint discovery (API/admin paths, GraphQL)", default=False)
        cfg.entropy_scan = _ask_bool("Include generic high-entropy strings", default=False)
        cfg.audit_github_actions = _ask_bool("Audit GitHub Actions workflows", default=False)
        cfg.git_history = cfg.git_history or _ask_bool("Scan git history too", default=False)
        cfg.min_severity = _ask_choice(
            "Minimum severity: critical/high/medium/low/info/any",
            ["critical", "high", "medium", "low", "info", "any"],
            "any",
        )
        if cfg.min_severity == "any":
            cfg.min_severity = None
        cfg.max_per_rule = _ask_int("Max findings per rule per document", 5, 1, 100)
        cfg.safe_mode = _ask_bool("Safe mode (skip live validation)", default=False)
        cfg.show_context = _ask_bool("Include evidence snippets in reports", default=False)

    print(Fore.YELLOW + "\nAdd custom headers? (blank line to finish)")
    while True:
        header = _ask("  Header (Name: Value)")
        if not header:
            break
        if ":" in header:
            name, value = header.split(":", 1)
            cfg.custom_headers[name.strip()] = value.strip()
        else:
            print(Fore.RED + "  Expected 'Name: Value'.")

    raw_formats = _ask(f"Output formats ({','.join(_FORMATS)})", "json")
    formats = [f.strip().lower() for f in raw_formats.replace(" ", ",").split(",") if f.strip()]
    cfg.output_format = [f for f in formats if f in _FORMATS] or ["json"]
    cfg.output_dir = _ask("Output directory", ".")

    cfg.verbose = _ask_bool("Verbose output", default=False)
    cfg.fail_on = _ask_choice(
        "CI exit code: fail on severity (never/low/medium/high/critical)",
        ["never", "low", "medium", "high", "critical"],
        "never",
    )

    print(Fore.CYAN + "\nConfiguration")
    print(f"  target        : {cfg.target}")
    print(f"  threads       : {cfg.threads}")
    print(f"  rules         : default"
          f"{' + noise' if cfg.include_noise else ''}"
          f"{' + pii' if cfg.include_pii else ''}"
          f"{' + endpoints' if cfg.include_endpoints else ''}"
          f"{' + entropy' if cfg.entropy_scan else ''}")
    if cfg.git_history:
        print(f"  git history   : depth {cfg.git_history_depth}")
    if cfg.audit_github_actions:
        print("  workflow audit: on")
    print(f"  min severity  : {cfg.min_severity or 'any'}")
    print(f"  formats       : {', '.join(cfg.output_format)}")
    print(f"  output dir    : {cfg.output_dir}")
    print(f"  safe mode     : {cfg.safe_mode}")
    print()

    return cfg


if __name__ == "__main__":  # pragma: no cover - manual entry
    try:
        interactive_menu()
    except KeyboardInterrupt:
        print("\nInterrupted.")
        sys.exit(130)
