"""Per-host request scheduling and adaptive throttling.

Global thread counts are a blunt instrument: a scan of one large host should
not hammer it at full speed, and a scan of many small hosts should not be
slowed to the same crawl rate.  :class:`HostRateLimiter` adds two independent
controls:

* ``per_host_delay`` — minimum seconds between request starts per host.
* ``per_host_concurrency`` — maximum in-flight requests per host (0 = no cap).

A 429 response can call :meth:`penalize`, which pushes that host's next allowed
request into the future without sleeping unrelated workers.
"""

from __future__ import annotations

import threading
import time
from contextlib import contextmanager
from typing import Dict, Iterator, Optional
from urllib.parse import urlparse


def host_of(url: str) -> str:
    """Return a normalized host key for a URL."""
    parsed = urlparse(url)
    return (parsed.netloc or parsed.hostname or "").lower()


class HostRateLimiter:
    """Thread-safe per-host delay, concurrency, and adaptive backoff."""

    def __init__(self, delay: float = 0.0, concurrency: int = 0) -> None:
        self.delay = max(0.0, float(delay))
        self.concurrency = max(0, int(concurrency))
        self._meta_lock = threading.Lock()
        self._host_locks: Dict[str, threading.Lock] = {}
        self._next_allowed: Dict[str, float] = {}
        self._semaphores: Dict[str, threading.Semaphore] = {}

    def _host_lock(self, host: str) -> threading.Lock:
        with self._meta_lock:
            return self._host_locks.setdefault(host, threading.Lock())

    def _semaphore(self, host: str) -> Optional[threading.Semaphore]:
        if self.concurrency <= 0:
            return None
        with self._meta_lock:
            return self._semaphores.setdefault(
                host, threading.Semaphore(self.concurrency)
            )

    def _wait(self, host: str) -> None:
        if not self.delay:
            return
        lock = self._host_lock(host)
        with lock:
            now = time.monotonic()
            target = self._next_allowed.get(host, 0.0)
            wait = max(0.0, target - now)
            if wait:
                time.sleep(wait)
            self._next_allowed[host] = time.monotonic() + self.delay

    def penalize(self, url: str, seconds: float) -> None:
        """Push the next allowed request for this host into the future."""
        seconds = max(0.0, min(float(seconds), 300.0))
        if not seconds:
            return
        host = host_of(url)
        with self._host_lock(host):
            self._next_allowed[host] = max(
                self._next_allowed.get(host, 0.0),
                time.monotonic() + seconds,
            )

    def next_delay(self, url: str) -> float:
        """Return seconds until this host is allowed (for observability/tests)."""
        host = host_of(url)
        with self._host_lock(host):
            return max(0.0, self._next_allowed.get(host, 0.0) - time.monotonic())

    @contextmanager
    def limit(self, url: str) -> Iterator[None]:
        """Acquire a host slot for one request and release it afterwards."""
        host = host_of(url)
        semaphore = self._semaphore(host)
        if semaphore is not None:
            semaphore.acquire()
        try:
            self._wait(host)
            yield
        finally:
            if semaphore is not None:
                semaphore.release()


__all__ = ["HostRateLimiter", "host_of"]
