"""Centralized configuration management."""

import os
from dataclasses import dataclass, field
from typing import List, Optional


@dataclass
class ScanConfig:
    """All scan configuration in one place."""
    # Target
    url: str = ""
    js_files: List[str] = field(default_factory=list)
    paths: List[str] = field(default_factory=list)  # local files/dirs, "-" for stdin
    github_repo: Optional[str] = None
    github_ref: Optional[str] = None
    github_token: Optional[str] = None
    github_org: Optional[str] = None
    github_user: Optional[str] = None
    github_limit: int = 50
    github_include_forks: bool = False
    github_keep: bool = False
    staged: bool = False
    changed: bool = False
    git_history: bool = False
    git_history_depth: int = 100
    git_since: Optional[str] = None
    git_from: Optional[str] = None
    git_to: Optional[str] = None
    git_author: Optional[str] = None

    # Threading
    threads: int = 10
    delay: float = 1.0
    per_host_delay: float = 0.0
    per_host_concurrency: int = 0

    # Network
    proxy: Optional[str] = None
    proxy_auth: Optional[str] = None
    timeout: int = 30
    max_retries: int = 3
    verify_ssl: bool = True
    user_agent: str = (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/125.0.0.0 Safari/537.36"
    )

    # Headers / Auth
    custom_headers: dict = field(default_factory=dict)
    cookies: Optional[str] = None  # file path or raw string
    auth_header: Optional[str] = None

    # Crawling
    depth: int = 1
    max_urls: int = 500
    scope_regex: Optional[str] = None  # restrict to domain pattern
    exclude_patterns: List[str] = field(default_factory=list)
    allow_external: bool = False  # follow links to other hosts
    respect_robots: bool = False
    source_maps: bool = False  # discover sourceMappingURL and JS chunks

    # HTTP Method
    method: str = "GET"
    post_data: Optional[str] = None

    # Response
    max_response_size: int = 5 * 1024 * 1024  # 5MB

    # Detection
    confidence_threshold: float = 0.6
    entropy_threshold: float = 0.0  # 0 = use each rule's own entropy floor
    custom_pattern_files: List[str] = field(default_factory=list)
    include_noise: bool = False
    include_pii: bool = False
    include_endpoints: bool = False
    min_severity: Optional[str] = None
    include_types: List[str] = field(default_factory=list)
    exclude_types: List[str] = field(default_factory=list)
    max_per_rule: int = 5
    ignore_files: List[str] = field(default_factory=list)
    use_default_ignore: bool = True
    show_context: bool = False
    entropy_scan: bool = False
    entropy_min_length: int = 20
    entropy_scan_threshold: float = 3.5
    audit_github_actions: bool = False
    gitleaks_configs: List[str] = field(default_factory=list)
    semgrep_configs: List[str] = field(default_factory=list)

    # Active validation
    validate_workers: int = 4
    validate_max: int = 100

    # Output
    output_dir: str = "."
    output_format: List[str] = field(default_factory=lambda: ["json"])
    verbose: bool = False
    quiet: bool = False
    redact_output: bool = False
    write_ignore: Optional[str] = None
    allowlist_values: bool = False

    # Notifications
    webhook_url: Optional[str] = None
    webhook_format: str = "slack"
    webhook_min_severity: str = "high"

    # Resume
    checkpoint_file: Optional[str] = None
    resume: bool = False

    # Differential
    baseline_file: Optional[str] = None
    update_baseline: Optional[str] = None

    # Report dashboard
    serve: bool = False
    serve_host: str = "127.0.0.1"
    serve_port: int = 8000
    open_browser: bool = False

    # Anti-detection
    jitter: bool = False

    # Safe mode
    safe_mode: bool = False

    # CI behaviour
    fail_on: str = "never"  # never|low|medium|high|critical

    # Plugin
    plugin_dir: Optional[str] = None
    entrypoint_plugins: bool = False

    @classmethod
    def from_dict(cls, d: dict) -> "ScanConfig":
        valid_fields = {f.name for f in cls.__dataclass_fields__.values()}
        return cls(**{k: v for k, v in d.items() if k in valid_fields})

    def to_dict(self) -> dict:
        from dataclasses import asdict
        return asdict(self)

    # -- convenience -------------------------------------------------------
    @property
    def is_local(self) -> bool:
        """True when scanning local paths/stdin instead of a URL."""
        return bool(self.paths or self.staged or self.changed)

    @property
    def is_github(self) -> bool:
        """True when the target is a GitHub repository, org, or user."""
        return bool(self.github_repo or self.github_org or self.github_user)

    @property
    def target(self) -> str:
        """Human-readable target description."""
        if self.github_repo:
            return self.github_repo
        if self.github_org:
            return f"org:{self.github_org}"
        if self.github_user:
            return f"user:{self.github_user}"
        if self.staged:
            return "staged files"
        if self.changed:
            return "changed files"
        if self.paths:
            return ", ".join(self.paths)
        return self.url or ", ".join(self.js_files)

    def normalize(self) -> "ScanConfig":
        """Coerce list/scalar fields into sane values (mutates in place)."""
        self.paths = [str(p) for p in (self.paths or [])]
        self.js_files = [str(js) for js in (self.js_files or [])]
        self.custom_pattern_files = [str(p) for p in (self.custom_pattern_files or [])]
        self.gitleaks_configs = [str(p) for p in (self.gitleaks_configs or [])]
        self.semgrep_configs = [str(p) for p in (self.semgrep_configs or [])]
        self.ignore_files = [str(p) for p in (self.ignore_files or [])]
        self.exclude_patterns = [str(p) for p in (self.exclude_patterns or [])]
        self.include_types = [str(t) for t in (self.include_types or [])]
        self.exclude_types = [str(t) for t in (self.exclude_types or [])]
        self.output_format = [
            str(f).lower() for f in (self.output_format or ["json"])
        ] or ["json"]

        self.threads = max(1, min(100, int(self.threads)))
        self.delay = max(0.0, min(100.0, float(self.delay)))
        self.per_host_delay = max(0.0, min(300.0, float(self.per_host_delay)))
        self.per_host_concurrency = max(0, min(100, int(self.per_host_concurrency)))
        self.serve_port = max(1, min(65535, int(self.serve_port)))
        if self.serve and "html" not in self.output_format:
            self.output_format.append("html")
        self.max_per_rule = max(1, int(self.max_per_rule))
        self.validate_workers = max(1, min(32, int(self.validate_workers)))
        self.validate_max = max(0, int(self.validate_max))
        self.max_response_size = max(1024, int(self.max_response_size))
        self.github_limit = max(1, min(1000, int(self.github_limit)))
        self.git_history_depth = max(0, int(self.git_history_depth))
        self.entropy_min_length = max(8, min(200, int(self.entropy_min_length)))
        self.entropy_scan_threshold = max(1.0, min(8.0, float(self.entropy_scan_threshold)))
        if self.webhook_format not in {"slack", "discord", "generic"}:
            self.webhook_format = "slack"
        if self.webhook_min_severity not in {
            "never", "low", "medium", "high", "critical",
        }:
            self.webhook_min_severity = "high"

        if self.fail_on not in {"never", "low", "medium", "high", "critical"}:
            self.fail_on = "never"
        if self.min_severity and self.min_severity.lower() not in {
            "critical", "high", "medium", "low", "info",
        }:
            self.min_severity = None
        return self

    def validate(self) -> list:
        """Return a list of human-readable configuration problems."""
        problems = []
        if (
            not self.url
            and not self.js_files
            and not self.paths
            and not self.is_github
            and not self.staged
            and not self.changed
            and not self.git_history
            and not self.audit_github_actions
        ):
            problems.append(
                "no target (URL, --path, --github, --github-org, --github-user, "
                "--staged, --changed, --git-history, or --audit-github-actions) provided"
            )
        targets = sum(
            1 for value in (
                (self.url or self.js_files), self.github_repo, self.github_org,
                self.github_user, self.staged, self.changed,
            ) if value
        )
        if self.paths:
            targets += 1
        if targets > 1:
            problems.append(
                "choose one target: URL, --path, --github, --github-org, "
                "--github-user, --staged, or --changed"
            )
        if not 0 <= self.confidence_threshold <= 1:
            problems.append("confidence_threshold must be between 0 and 1")
        if self.method not in {"GET", "POST"}:
            problems.append("method must be GET or POST")
        return problems
