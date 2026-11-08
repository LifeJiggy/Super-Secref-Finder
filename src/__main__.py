"""Entry point for ``python -m src`` and the ``super-secref-finder`` script."""

from __future__ import annotations

import os
import sys
from typing import List, Optional

from .cli import parse_args
from .config import ScanConfig
from .logging_config import setup_logging
from .scanner import compute_exit_code, print_summary, run_scan


def _config_from_args(args) -> ScanConfig:
    explicit_target = bool(
        args.url or args.js or args.path or args.github or args.github_org
        or args.github_user or args.staged or args.changed
    )
    paths = args.path or ([] if explicit_target else ["."])
    return ScanConfig(
        url=args.url or "",
        js_files=args.js or [],
        paths=paths,
        github_repo=args.github,
        github_ref=args.github_ref,
        github_token=(
            args.github_token
            or os.environ.get("GITHUB_TOKEN")
            or os.environ.get("GH_TOKEN")
        ),
        github_org=args.github_org,
        github_user=args.github_user,
        github_limit=args.github_limit,
        github_include_forks=args.github_include_forks,
        github_keep=args.github_keep,
        staged=args.staged,
        changed=args.changed,
        git_history=args.git_history,
        git_history_depth=args.git_history_depth,
        git_since=args.git_since,
        threads=args.threads,
        delay=args.delay,
        proxy=args.proxy,
        proxy_auth=args.proxy_auth,
        timeout=args.timeout,
        max_retries=args.max_retries,
        verify_ssl=not args.no_verify,
        user_agent=args.user_agent,
        custom_headers=args.parsed_headers,
        cookies=args.cookie_file,
        auth_header=args.auth,
        depth=args.depth,
        max_urls=args.max_urls,
        scope_regex=args.scope,
        exclude_patterns=args.exclude,
        allow_external=args.allow_external,
        respect_robots=args.respect_robots,
        method=args.method,
        post_data=args.data,
        max_response_size=args.max_size,
        confidence_threshold=args.confidence,
        entropy_threshold=args.entropy,
        custom_pattern_files=args.custom_patterns,
        include_noise=args.include_noise,
        include_pii=args.include_pii,
        include_endpoints=args.include_endpoints,
        entropy_scan=args.entropy_scan,
        entropy_min_length=args.entropy_min_length,
        entropy_scan_threshold=args.entropy_scan_threshold,
        audit_github_actions=args.audit_github_actions,
        min_severity=args.min_severity,
        include_types=args.include_type,
        exclude_types=args.exclude_type,
        max_per_rule=args.max_per_rule,
        ignore_files=args.ignore_file,
        show_context=args.show_context,
        validate_workers=args.validate_workers,
        validate_max=args.validate_max,
        output_dir=args.output_dir,
        output_format=args.format,
        verbose=args.verbose,
        quiet=args.quiet,
        redact_output=args.redact,
        write_ignore=args.write_ignore,
        allowlist_values=args.allowlist_values,
        webhook_url=args.webhook,
        webhook_format=args.webhook_format,
        webhook_min_severity=args.webhook_min_severity,
        checkpoint_file=args.resume,
        resume=bool(args.resume),
        baseline_file=args.baseline,
        update_baseline=args.update_baseline,
        jitter=args.jitter,
        safe_mode=args.safe_mode,
        fail_on=args.fail_on,
        plugin_dir=args.plugin_dir,
    )


def _print_rules() -> None:
    from .rules import BUILTIN_RULES, SEVERITIES

    print(f"{'SEVERITY':<10} {'CATEGORY':<13} {'RULE':<36} DESCRIPTION")
    print("-" * 110)
    for rule in sorted(
        BUILTIN_RULES,
        key=lambda r: (SEVERITIES.index(r.severity), r.id),
    ):
        marker = " (opt-in)" if (
            rule.noise or rule.pii or rule.category == "endpoint"
        ) else ""
        print(f"{rule.severity:<10} {rule.category:<13} {rule.id:<36} {rule.description}{marker}")
    print(f"\nTotal: {len(BUILTIN_RULES)} rules")


def main(argv: Optional[List[str]] = None) -> int:
    """Run the CLI. Returns a process exit code."""
    args = parse_args(argv)

    if args.list_rules:
        _print_rules()
        return 0

    if args.interactive:
        from .interactive import interactive_menu

        cfg = interactive_menu()
        cfg.output_dir = args.output_dir
        if args.quiet:
            cfg.quiet = True
    else:
        cfg = _config_from_args(args)

    setup_logging(
        log_dir=cfg.output_dir,
        verbose=cfg.verbose,
        quiet=cfg.quiet,
    )

    findings = run_scan(cfg)
    if not cfg.quiet:
        print_summary(findings)

    return compute_exit_code(findings, cfg.fail_on)


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\n\033[31m[!] Interrupted by user.\033[0m")
        sys.exit(130)
    except Exception as exc:  # pragma: no cover - top-level guard
        print(f"\033[31m[!] Critical error: {exc}\033[0m")
        sys.exit(1)
