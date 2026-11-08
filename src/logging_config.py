"""Structured logging with rotation and separate streams."""

from __future__ import annotations

import json
import logging
import logging.handlers
import os
import sys
from datetime import datetime, timezone


class JSONFormatter(logging.Formatter):
    """Structured JSON log formatter."""

    def format(self, record):
        entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        for key in ("url", "rule", "severity", "path", "status"):
            value = getattr(record, key, None)
            if value is not None:
                entry[key] = value
        if record.exc_info and record.exc_info[0]:
            entry["exception"] = self.formatException(record.exc_info)
        return json.dumps(entry, ensure_ascii=False)


class HumanFormatter(logging.Formatter):
    """Human-readable colored formatter for console output."""

    COLORS = {
        "DEBUG": "\033[36m",
        "INFO": "\033[32m",
        "WARNING": "\033[33m",
        "ERROR": "\033[31m",
        "CRITICAL": "\033[35m",
    }
    RESET = "\033[0m"

    def format(self, record):
        color = self.COLORS.get(record.levelname, "")
        timestamp = datetime.now().strftime("%H:%M:%S")
        return f"{color}[{timestamp}] {record.levelname}: {record.getMessage()}{self.RESET}"


def _rotating(path: str, max_bytes: int, backups: int, level: int) -> logging.Handler:
    handler = logging.handlers.RotatingFileHandler(
        path,
        maxBytes=max_bytes,
        backupCount=backups,
        encoding="utf-8",
    )
    handler.setLevel(level)
    handler.setFormatter(JSONFormatter())
    return handler


def setup_logging(
    log_dir: str = ".",
    verbose: bool = False,
    quiet: bool = False,
) -> logging.Logger:
    """Configure logging idempotently (safe to call more than once)."""
    os.makedirs(log_dir, exist_ok=True)

    root = logging.getLogger("secref")
    root.setLevel(logging.DEBUG)
    root.handlers.clear()

    if not quiet:
        console = logging.StreamHandler(sys.stdout)
        console.setLevel(logging.DEBUG if verbose else logging.INFO)
        console.setFormatter(HumanFormatter())
        root.addHandler(console)

    root.addHandler(_rotating(os.path.join(log_dir, "secref.log"), 10 * 1024 * 1024, 5, logging.DEBUG))
    root.addHandler(_rotating(os.path.join(log_dir, "secref_errors.log"), 5 * 1024 * 1024, 3, logging.ERROR))

    # Audit stream is separate and does not propagate to console/main logs.
    audit_logger = logging.getLogger("secref.audit")
    audit_logger.handlers.clear()
    audit_logger.setLevel(logging.INFO)
    audit_logger.propagate = False
    audit_logger.addHandler(
        _rotating(os.path.join(log_dir, "secref_audit.log"), 10 * 1024 * 1024, 5, logging.INFO)
    )

    return root
