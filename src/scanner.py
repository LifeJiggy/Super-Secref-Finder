"""Core scanner engine — orchestrates fetching, extraction, plugins, output."""

from __future__ import annotations

import logging
import os
import queue
import random
import threading
import time
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Optional, Set

from .allowlist import Allowlist, has_inline_ignore, load_allowlist, write_ignore_file
from .checkpoint import (
    clear_checkpoint,
    diff_findings,
    load_checkpoint,
    load_differential_baseline,
    save_checkpoint,
    save_differential_baseline,
)
from .config import ScanConfig
from .crawler import build_target_list
from .entropy_scan import find_entropy_findings
from .fetcher import _build_session, fetch_url
from .filesystem import iter_local_sources
from .gitleaks import load_gitleaks_rules
from .github import (
    GitHubError,
    cleanup_repo,
    download_repo,
    list_repos,
    parse_repo_spec,
    relabel_results,
)
from .gitscan import GitError, changed_files, iter_history_documents, repo_root, staged_files
from .notify import send_notification
from .output import save_findings
from .patterns import get_rules
from .plugins import discover_entrypoint_plugins, discover_plugins, run_plugins
from .ratelimit import HostRateLimiter
from .rotation import rotation_guidance
from .rules import SEVERITY_RANK, Rule
from .secret_validator import VALIDATORS, validate_secret
from .validators import confidence_for, extract_context, validate_rule
from .workflow_audit import audit_github_actions

logger = logging.getLogger("secref.scanner")
audit = logging.getLogger("secref.audit")

_SECRET_CATEGORIES = {"secret", "credential", "token", "cloud"}


def _line_col(text: str, offset: int) -> tuple:
    line = text.count("\n", 0, offset) + 1
    line_start = text.rfind("\n", 0, offset) + 1
    return line, offset - line_start + 1


def _entropy_floor(rule: Rule, cfg: ScanConfig) -> float:
    """Rule entropy floor, optionally raised by the global ``--entropy`` value."""
    floor = rule.entropy_min
    if cfg.entropy_threshold > 0 and rule.category in _SECRET_CATEGORIES:
        floor = max(floor, cfg.entropy_threshold)
    return floor


def scan_text(
    text: str,
    url: str,
    rules: List[Rule],
    cfg: ScanConfig,
    allowlist: Optional[Allowlist] = None,
) -> List[dict]:
    """Run all rules against one document and return validated findings."""
    if not text:
        return []

    findings: List[dict] = []
    per_rule = Counter()

    for rule in rules:
        if not rule.matches_path(url):
            continue
        if rule.compiled is None:
            try:
                rule.compile()
            except Exception:
                continue
        assert rule.compiled is not None

        entropy_floor = _entropy_floor(rule, cfg)
        for match in rule.compiled.finditer(text):
            value = rule.value_of(match).strip().strip("'\"")
            if not value:
                continue
            if rule.is_negative_match(value, match.group(0)):
                continue

            if allowlist is not None and allowlist.is_ignored(rule.id, value, url):
                continue
            if has_inline_ignore(text, match.start()):
                continue

            # Apply the effective entropy floor without mutating the shared
            # rule object (scans are concurrent).
            if not validate_rule(rule, value, text, match, entropy_floor=entropy_floor):
                continue

            confidence = confidence_for(rule, value, text, match, entropy_floor=entropy_floor)
            if confidence < cfg.confidence_threshold:
                continue

            per_rule[rule.id] += 1
            if per_rule[rule.id] > max(1, cfg.max_per_rule):
                break

            start, end = rule.value_span(match)
            line, column = _line_col(text, start)
            finding = {
                "type": rule.id,
                "value": value,
                "url": url,
                "confidence": confidence,
                "severity": rule.severity,
                "category": rule.category,
                "description": rule.description,
                "start": start,
                "end": end,
                "line": line,
                "column": column,
            }
            rotation_url = rotation_guidance(rule.id, rule.category, rule.tags)
            if rotation_url:
                finding["rotation_url"] = rotation_url
            if rule.fix:
                finding["fix"] = rule.fix
            if cfg.show_context:
                finding["context"] = extract_context(text, start, end)
            findings.append(finding)

    return dedupe_findings(findings)


_GENERIC_RULE_IDS = {"generic_secret_assignment", "api_key"}


def dedupe_findings(findings: List[dict]) -> List[dict]:
    """Deduplicate by (URL, value), keeping the most specific/high-confidence hit."""
    best: Dict[tuple, dict] = {}
    order: List[tuple] = []
    for finding in findings:
        value = finding.get("value", "")
        if not value:
            continue
        key = (finding.get("url", ""), value)
        current = best.get(key)
        if current is None:
            best[key] = finding
            order.append(key)
            continue
        new_rank = SEVERITY_RANK.get(finding.get("severity", "info"), 0)
        old_rank = SEVERITY_RANK.get(current.get("severity", "info"), 0)
        if new_rank > old_rank:
            best[key] = finding
            continue
        if new_rank < old_rank:
            continue

        # Same severity: prefer a specific rule (including imported Semgrep or
        # native custom rules) over the generic assignment fallback.
        new_generic = finding.get("type") in _GENERIC_RULE_IDS
        old_generic = current.get("type") in _GENERIC_RULE_IDS
        if old_generic and not new_generic:
            best[key] = finding
        elif new_generic and not old_generic:
            continue
        elif finding.get("confidence", 0) > current.get("confidence", 0):
            best[key] = finding
    return [best[key] for key in order]


def _normalize_plugin_findings(plugin_findings: List[dict], url: str, text: str) -> List[dict]:
    normalized: List[dict] = []
    for item in plugin_findings or []:
        if not isinstance(item, dict) or not item.get("value"):
            continue
        start = int(item.get("start", 0) or 0)
        end = int(item.get("end", start) or start)
        line, column = _line_col(text, start)
        category = item.get("category", "custom")
        finding = {
            "type": item.get("type", "plugin_finding"),
            "value": str(item["value"]),
            "url": item.get("url", url),
            "confidence": round(float(item.get("confidence", 0.7)), 2),
            "severity": item.get("severity", "medium"),
            "category": category,
            "description": item.get("description", "Plugin finding"),
            "start": start,
            "end": end,
            "line": line,
            "column": column,
        }
        rotation_url = rotation_guidance(finding["type"], category)
        if rotation_url:
            finding["rotation_url"] = rotation_url
        normalized.append(finding)
    return normalized


def _analyze(
    cfg: ScanConfig,
    url: str,
    text: str,
    rules: List[Rule],
    allowlist: Allowlist,
) -> List[dict]:
    """Extract secrets + run plugins for one document."""
    findings = scan_text(text, url, rules, cfg, allowlist)
    findings.extend(find_entropy_findings(text, url, cfg, allowlist))

    plugin_findings = run_plugins(
        url,
        text,
        findings,
        include_optional=cfg.include_endpoints or cfg.include_noise,
    )
    findings.extend(_normalize_plugin_findings(plugin_findings, url, text))

    for finding in findings:
        if not finding.get("rotation_url"):
            rotation_url = rotation_guidance(
                finding.get("type", ""),
                finding.get("category"),
            )
            if rotation_url:
                finding["rotation_url"] = rotation_url

    return dedupe_findings(findings)


def _worker(
    cfg: ScanConfig,
    url_queue: queue.Queue,
    results: list,
    lock: threading.Lock,
    session,
    limiter: Optional[HostRateLimiter],
    rules: List[Rule],
    allowlist: Allowlist,
    prefetched: Dict[str, tuple],
    visited: Set[str],
    counter: dict,
    total: int,
) -> None:
    """Worker thread — fetches URLs and extracts secrets."""
    while True:
        try:
            url = url_queue.get_nowait()
        except queue.Empty:
            break

        try:
            if cfg.verbose:
                logger.info(f"Scanning: {url}")
            audit.info(f"Fetched: {url}")

            cached = prefetched.get(url)
            if cached is not None:
                text, final_url = cached
            else:
                text, final_url, _ = fetch_url(cfg, url, session, limiter=limiter)

            if not text:
                logger.warning(f"Failed to fetch: {url}")
                continue

            with lock:
                visited.add(url)
                visited.add(final_url or url)

            findings = _analyze(cfg, final_url or url, text, rules, allowlist)

            if findings:
                for finding in findings:
                    conf = finding.get("confidence", 0) * 100
                    display = finding["value"][:60] + ("..." if len(finding["value"]) > 60 else "")
                    logger.info(
                        f"[+] {finding['severity'].upper():8} {finding['type']}: "
                        f"{display} @ {finding['url']} ({conf:.0f}%)"
                    )
                with lock:
                    results.extend(findings)

            with lock:
                counter["fetched"] += 1
                done = counter["fetched"]
            if total and (done % max(1, total // 10) == 0 or done == total):
                with lock:
                    found = len(results)
                logger.info(f"Progress: {done}/{total} URLs - {found} findings")

        except Exception as exc:  # pragma: no cover - defensive
            logger.error(f"Worker error on {url}: {exc}", exc_info=cfg.verbose)
        finally:
            url_queue.task_done()

            delay = cfg.delay
            if cfg.jitter:
                delay += random.uniform(-0.5, 1.0)
            if delay > 0:
                time.sleep(max(0.05, delay))


def _validate_findings(findings: List[dict], cfg: ScanConfig) -> None:
    """Run live validation concurrently for rules that support it."""
    if cfg.safe_mode or not findings:
        return

    candidates = [f for f in findings if f["type"] in VALIDATORS]
    if not candidates:
        return

    limit = getattr(cfg, "validate_max", 100)
    candidates = candidates[: max(0, limit)]
    workers = max(1, min(cfg.validate_workers, 8, len(candidates)))

    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {
            pool.submit(validate_secret, f["type"], f["value"], False): f
            for f in candidates
        }
        for future in as_completed(futures):
            finding = futures[future]
            try:
                result = future.result()
            except Exception as exc:  # pragma: no cover - defensive
                result = {"valid": None, "reason": str(exc)}
            if result.get("valid") is True:
                finding["validated"] = True
                finding["validation_detail"] = result
                finding["confidence"] = round(min(0.99, finding.get("confidence", 0.8) + 0.05), 2)
            elif result.get("valid") is False:
                finding["validated"] = False
                finding["validation_detail"] = result


def _scan_sources(
    cfg: ScanConfig,
    sources: list,
    rules: List[Rule],
    allowlist: Allowlist,
) -> List[dict]:
    """Scan a precomputed list of local sources concurrently."""
    if not sources:
        return []

    results: List[dict] = []
    total = len(sources)
    workers = max(1, min(cfg.threads, total))
    lock = threading.Lock()
    counter = {"done": 0}

    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {
            pool.submit(_analyze, cfg, source.url, source.text, rules, allowlist): source
            for source in sources
        }
        for future in as_completed(futures):
            source = futures[future]
            try:
                findings = future.result()
            except Exception as exc:  # pragma: no cover - defensive
                logger.error(f"Error scanning {source.path}: {exc}", exc_info=cfg.verbose)
                findings = []
            if findings:
                with lock:
                    results.extend(findings)
                for finding in findings:
                    logger.info(
                        f"[+] {finding['severity'].upper():8} {finding['type']}: "
                        f"{finding['value'][:60]} @ {source.path}"
                    )
            with lock:
                counter["done"] += 1
                done = counter["done"]
            if done % max(1, total // 10) == 0 or done == total:
                logger.info(f"Progress: {done}/{total} files - {len(results)} findings")

    return results


def _audit_actions(cfg: ScanConfig, paths: List[str]) -> List[dict]:
    if not cfg.audit_github_actions:
        return []
    findings = audit_github_actions(paths, cfg.max_response_size)
    if findings:
        logger.info(f"Workflow audit: {len(findings)} finding(s)")
    return findings


def _run_local(
    cfg: ScanConfig,
    rules: List[Rule],
    allowlist: Allowlist,
) -> List[dict]:
    sources = list(iter_local_sources(cfg.paths, cfg.exclude_patterns, cfg.max_response_size))
    if not sources:
        logger.warning("No readable local files found")
    else:
        logger.info(f"Local scan: {len(sources)} file(s)")

    results = _scan_sources(cfg, sources, rules, allowlist)
    for finding in results:
        finding.setdefault("source", "local")
    results.extend(_audit_actions(cfg, cfg.paths))
    return dedupe_findings(results)


def _run_staged(
    cfg: ScanConfig,
    rules: List[Rule],
    allowlist: Allowlist,
) -> List[dict]:
    root = repo_root(cfg.paths[0] if cfg.paths else ".")
    files = staged_files(root) if cfg.staged else changed_files(root)
    if not files:
        logger.info("No staged/changed files to scan")
        return []
    mode = "staged" if cfg.staged else "changed"
    logger.info(f"Git {mode} scan: {len(files)} file(s) under {root}")
    sources = list(iter_local_sources(files, cfg.exclude_patterns, cfg.max_response_size))
    results = _scan_sources(cfg, sources, rules, allowlist)
    for finding in results:
        finding.setdefault("source", mode)
    results.extend(_audit_actions(cfg, files))
    return dedupe_findings(results)


def _run_git_history(
    cfg: ScanConfig,
    rules: List[Rule],
    allowlist: Allowlist,
    root: str,
    label: Optional[str] = None,
) -> List[dict]:
    try:
        documents = list(iter_history_documents(
            root,
            max_commits=cfg.git_history_depth,
            since=cfg.git_since,
            from_ref=cfg.git_from,
            to_ref=cfg.git_to,
            author=cfg.git_author,
        ))
    except GitError as exc:
        logger.warning(f"Git history scan skipped: {exc}")
        return []

    if not documents:
        logger.info("No git history documents to scan")
        return []

    logger.info(f"Git history scan: {len(documents)} commit/file document(s)")
    results: List[dict] = []
    for index, document in enumerate(documents, 1):
        findings = _analyze(cfg, document["url"], document["text"], rules, allowlist)
        for finding in findings:
            finding["source"] = "git-history"
            finding["commit"] = document["commit"]
            finding["author"] = document["author"]
            finding["author_email"] = document["author_email"]
            finding["commit_date"] = document["commit_date"]
            finding["commit_message"] = document["commit_message"]
            finding["repo"] = label or document["repo"]
            finding["path"] = document["path"]
            finding["line"] = max(1, int(finding.get("line") or 1)) + int(
                document.get("line_offset") or 0
            )
            if label:
                finding["url"] = (
                    f"github://{label}/{document['commit']}/{document['path']}"
                )
        results.extend(findings)
        if index % 25 == 0 or index == len(documents):
            logger.info(
                f"History progress: {index}/{len(documents)} - {len(results)} findings"
            )
    return dedupe_findings(results)


def _github_targets(cfg: ScanConfig) -> List[tuple]:
    if cfg.github_repo:
        owner, repo, ref = parse_repo_spec(cfg.github_repo)
        return [(owner, repo, cfg.github_ref or ref)]
    if cfg.github_org:
        repos = list_repos(
            cfg.github_org,
            token=cfg.github_token,
            limit=cfg.github_limit,
            include_forks=cfg.github_include_forks,
            is_org=True,
        )
    elif cfg.github_user:
        repos = list_repos(
            cfg.github_user,
            token=cfg.github_token,
            limit=cfg.github_limit,
            include_forks=cfg.github_include_forks,
            is_org=False,
        )
    else:
        return []
    return [(item.owner, item.name, None) for item in repos]


def _cleanup_checkout(root: str) -> None:
    """Remove the checkout and any temporary parent created for it."""
    cleanup_repo(root)
    parent = os.path.dirname(os.path.abspath(root))
    while parent and os.path.basename(parent).startswith("secref-gh-"):
        cleanup_repo(parent)
        parent = os.path.dirname(parent)


def _run_github(
    cfg: ScanConfig,
    rules: List[Rule],
    allowlist: Allowlist,
) -> List[dict]:
    targets = _github_targets(cfg)
    if not targets:
        logger.warning("No GitHub repositories matched")
        return []

    logger.info(f"GitHub scan: {len(targets)} repository(ies)")
    results: List[dict] = []
    for owner, repo, ref in targets:
        label = f"{owner}/{repo}"
        logger.info(f"Downloading {label}" + (f"@{ref}" if ref else ""))
        try:
            checkout = download_repo(
                owner,
                repo,
                ref=ref,
                token=cfg.github_token,
                history=cfg.git_history,
                max_bytes=cfg.max_response_size * 20,
            )
        except GitHubError as exc:
            logger.warning(f"Skipping {label}: {exc}")
            continue
        try:
            sources = list(iter_local_sources(
                [checkout], cfg.exclude_patterns, cfg.max_response_size
            ))
            repo_results = _scan_sources(cfg, sources, rules, allowlist)
            relabel_results(repo_results, checkout, label)
            for finding in repo_results:
                finding["source"] = "github"
                finding["repo"] = label
            results.extend(repo_results)

            if cfg.audit_github_actions:
                audit_results = audit_github_actions([checkout], cfg.max_response_size)
                relabel_results(audit_results, checkout, label)
                for finding in audit_results:
                    finding["repo"] = label
                results.extend(audit_results)

            if cfg.git_history:
                results.extend(
                    _run_git_history(cfg, rules, allowlist, checkout, label=label)
                )
        finally:
            if cfg.github_keep:
                logger.info(f"Kept checkout: {checkout}")
            else:
                _cleanup_checkout(checkout)

    return dedupe_findings(results)


def _run_web(
    cfg: ScanConfig,
    rules: List[Rule],
    allowlist: Allowlist,
) -> List[dict]:
    session = _build_session(cfg)
    limiter = HostRateLimiter(cfg.per_host_delay, cfg.per_host_concurrency)

    def fetch_fn(url: str, method: str = "GET"):
        return fetch_url(cfg, url, session, method=method, limiter=limiter)

    crawl = build_target_list(cfg, fetch_fn=fetch_fn)
    targets = crawl.targets
    logger.info(f"Target list: {len(targets)} URLs to scan")

    if not targets:
        logger.warning("No targets to scan")
        return []

    visited: Set[str] = set()
    results: List[dict] = []
    if cfg.resume and cfg.checkpoint_file:
        checkpoint = load_checkpoint(cfg.checkpoint_file)
        if checkpoint:
            visited = set(checkpoint.get("visited_urls", []))
            results = checkpoint.get("findings", [])
            logger.info(
                f"Resumed from checkpoint: {len(visited)} visited, {len(results)} findings"
            )

    url_queue: queue.Queue = queue.Queue()
    for url in targets:
        if url not in visited:
            url_queue.put(url)

    total = url_queue.qsize()
    if total == 0:
        logger.info("All targets were already scanned")
        return results

    num_threads = max(1, min(cfg.threads, total, 100))
    logger.info(f"Starting {num_threads} threads")

    lock = threading.Lock()
    counter = {"fetched": 0}
    threads = []
    for _ in range(num_threads):
        thread = threading.Thread(
            target=_worker,
            args=(
                cfg, url_queue, results, lock, session, limiter, rules, allowlist,
                crawl.prefetched, visited, counter, total,
            ),
            daemon=True,
        )
        thread.start()
        threads.append(thread)

    # Monitor with periodic checkpoints; ``unfinished_tasks`` is the reliable
    # signal (``empty()`` can be true while workers are still processing).
    try:
        while url_queue.unfinished_tasks > 0:
            time.sleep(2)
            if cfg.checkpoint_file and counter["fetched"] > 0:
                save_checkpoint(
                    cfg.checkpoint_file, visited, results, counter["fetched"]
                )
    except KeyboardInterrupt:
        logger.info("Interrupted - saving checkpoint...")
        if cfg.checkpoint_file:
            save_checkpoint(cfg.checkpoint_file, visited, results, counter["fetched"])
        raise

    url_queue.join()
    for thread in threads:
        thread.join(timeout=15)

    if cfg.checkpoint_file:
        clear_checkpoint(cfg.checkpoint_file)

    return results


def run_scan(cfg: ScanConfig) -> List[dict]:
    """Execute a full scan (web or local) with the given configuration."""
    cfg.normalize()
    for problem in cfg.validate():
        logger.warning(f"Configuration: {problem}")

    rules = get_rules(
        custom_files=cfg.custom_pattern_files,
        include_noise=cfg.include_noise,
        include_pii=cfg.include_pii,
        include_types=cfg.include_types,
        exclude_types=cfg.exclude_types,
        min_severity=cfg.min_severity,
        include_endpoints=cfg.include_endpoints,
        gitleaks_files=cfg.gitleaks_configs,
        semgrep_files=cfg.semgrep_configs,
    )
    logger.info(f"Loaded {len(rules)} detection rules")
    if not rules:
        logger.warning("No rules enabled - check --include-type/--exclude-type/--min-severity")
        return []

    by_severity = Counter(rule.severity for rule in rules)
    logger.debug(
        "Rules by severity: "
        + ", ".join(f"{name}={by_severity.get(name, 0)}" for name in SEVERITY_RANK)
    )

    allowlist = load_allowlist(
        cfg.ignore_files,
        project_dir=os.getcwd(),
        include_default=cfg.use_default_ignore,
    )

    if cfg.plugin_dir:
        loaded = discover_plugins(cfg.plugin_dir)
        logger.info(f"Loaded {len(loaded)} plugins")
    if cfg.entrypoint_plugins:
        loaded = discover_entrypoint_plugins()
        logger.info(f"Loaded {len(loaded)} entry-point plugins")

    if cfg.github_repo or cfg.github_org or cfg.github_user:
        results = _run_github(cfg, rules, allowlist)
        source = "github"
        target = cfg.target
    elif cfg.staged or cfg.changed:
        results = _run_staged(cfg, rules, allowlist)
        source = "staged" if cfg.staged else "changed"
        target = cfg.target
    elif cfg.paths:
        results = _run_local(cfg, rules, allowlist)
        source = "local"
        target = ", ".join(cfg.paths)
    else:
        results = _run_web(cfg, rules, allowlist)
        source = "web"
        target = cfg.url or ", ".join(cfg.js_files)

    # Git history is independent of the working-tree scan. GitHub history is
    # handled inside _run_github with the real clone.
    if cfg.git_history and source != "github":
        history_root = cfg.paths[0] if cfg.paths else "."
        history_results = _run_git_history(cfg, rules, allowlist, history_root)
        if history_results:
            source = f"{source}+history"
            results.extend(history_results)

    # Active validation, then a final dedupe.
    _validate_findings(results, cfg)
    results = dedupe_findings(results)

    # Write a precise, hashed allowlist if requested.
    if cfg.write_ignore:
        written = write_ignore_file(cfg.write_ignore, results, cfg.allowlist_values)
        logger.info(f"Allowlist written: {cfg.write_ignore} ({written} fingerprints)")

    # Update a hashed baseline from the full result set (never during diff).
    if cfg.update_baseline:
        if save_differential_baseline(results, cfg.update_baseline):
            logger.info(f"Baseline updated: {cfg.update_baseline} ({len(results)} findings)")
        else:
            logger.warning(f"Could not write baseline: {cfg.update_baseline}")

    # Differential filtering against a previous baseline.
    if cfg.baseline_file and cfg.baseline_file != cfg.update_baseline:
        baseline = load_differential_baseline(cfg.baseline_file)
        logger.info(f"Loaded baseline: {len(baseline)} known secrets")
        results = diff_findings(results, baseline)
        logger.info(f"After diff: {len(results)} new findings")

    saved = save_findings(
        results,
        cfg.output_dir,
        cfg.output_format,
        cfg.redact_output,
        meta={
            "target": target,
            "source": source,
            "rules_loaded": len(rules),
            "include_noise": cfg.include_noise,
            "include_pii": cfg.include_pii,
            "include_endpoints": cfg.include_endpoints,
            "entropy_scan": cfg.entropy_scan,
            "git_history": cfg.git_history,
        },
        show_context=cfg.show_context,
    )
    for path in saved:
        logger.info(f"Saved: {path}")

    if cfg.webhook_url:
        ok, detail = send_notification(
            cfg.webhook_url,
            results,
            meta={"target": target, "source": source},
            fmt=cfg.webhook_format,
            min_severity=cfg.webhook_min_severity,
        )
        if ok:
            logger.info(f"Webhook notification sent ({detail})")
        else:
            logger.warning(f"Webhook notification failed: {detail}")

    return results


def compute_exit_code(findings: List[dict], fail_on: str = "never") -> int:
    """Return 1 when a finding meets the ``--fail-on`` severity threshold."""
    fail_on = (fail_on or "never").lower()
    if fail_on == "never":
        return 0
    floor = SEVERITY_RANK.get(fail_on)
    if floor is None:
        return 0
    for finding in findings:
        if SEVERITY_RANK.get(finding.get("severity", "info"), 0) >= floor:
            return 1
    return 0


def print_summary(findings: List[dict]) -> None:
    """Print a severity-aware summary of findings to console."""
    if not findings:
        print("\n\033[33m[!] No secrets found.\033[0m")
        return

    summary = Counter(f.get("type", "unknown") for f in findings)
    severity_summary = Counter(f.get("severity", "info") for f in findings)
    categories = Counter(f.get("category", "unknown") for f in findings)
    validated = sum(1 for f in findings if f.get("validated"))

    print(f"\n\033[36m{'=' * 64}\033[0m")
    print("\033[36m  SCAN RESULTS SUMMARY\033[0m")
    print(f"\033[36m{'=' * 64}\033[0m")
    print(f"  Total findings: \033[1m{len(findings)}\033[0m")
    if validated:
        print(f"  Live-validated: \033[32m{validated}\033[0m")

    colors = {
        "critical": "\033[91m", "high": "\033[31m", "medium": "\033[33m",
        "low": "\033[36m", "info": "\033[37m",
    }
    counts = "  ".join(
        f"{colors.get(name, '')}{name}: {severity_summary[name]}\033[0m"
        for name in ("critical", "high", "medium", "low", "info")
        if severity_summary.get(name)
    )
    if counts:
        print(f"  By severity: {counts}")
    print("  By category: " + ", ".join(f"{k}={v}" for k, v in categories.most_common()))
    print(f"\033[36m{'-' * 64}\033[0m")

    for ftype, count in summary.most_common(25):
        bar = "\033[31m" + "#" * min(count, 40) + "\033[0m"
        print(f"  {ftype:.<42} {count:>4}  {bar}")

    if len(summary) > 25:
        print(f"  ... {len(summary) - 25} more rule types")
    print(f"\033[36m{'=' * 64}\033[0m\n")
