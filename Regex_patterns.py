"""Backward-compatible entry point — delegates to the src package.

This file exists for legacy usage: `python Regex_patterns.py`
The new CLI entry point is: `super-secref-finder https://target.com`
"""

import sys
import os

# Ensure the src package is importable
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))


def main():
    """Legacy interactive mode entry point."""
    from src.interactive import interactive_menu
    from src.logging_config import setup_logging
    from src.scanner import run_scan, print_summary

    setup_logging(verbose=True)

    while True:
        cfg = interactive_menu()
        findings = run_scan(cfg)
        print_summary(findings)

        retry = input("\033[33mScan another URL? (yes/no): \033[0m").strip().lower()
        if retry != "yes":
            break


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\033[31m[!] Interrupted by user. Exiting...\033[0m")
        sys.exit(130)
    except Exception as e:
        print(f"\033[31m[!] Critical error: {e}\033[0m")
        retry = input("\033[33mRetry? (yes/no): \033[0m").strip().lower()
        if retry == "yes":
            main()
