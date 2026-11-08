"""Per-host rate limiter tests."""

import threading
import time

from src.ratelimit import HostRateLimiter, host_of


def test_host_of_normalizes():
    assert host_of("https://Example.COM:8443/a") == "example.com:8443"


def test_host_delay_serializes_starts():
    limiter = HostRateLimiter(delay=0.08)
    started = []
    with limiter.limit("https://example.com/a"):
        started.append(time.monotonic())
    with limiter.limit("https://example.com/b"):
        started.append(time.monotonic())
    assert started[1] - started[0] >= 0.05


def test_penalize_pushes_next_allowed():
    limiter = HostRateLimiter()
    limiter.penalize("https://example.com/a", 0.2)
    assert limiter.next_delay("https://example.com/b") > 0.1


def test_per_host_concurrency():
    limiter = HostRateLimiter(concurrency=1)
    first_entered = threading.Event()
    release_first = threading.Event()
    second_entered = threading.Event()

    def first():
        with limiter.limit("https://example.com/a"):
            first_entered.set()
            release_first.wait(timeout=2)

    def second():
        with limiter.limit("https://example.com/b"):
            second_entered.set()

    thread_one = threading.Thread(target=first)
    thread_two = threading.Thread(target=second)
    thread_one.start()
    assert first_entered.wait(timeout=1)
    thread_two.start()
    time.sleep(0.05)
    assert not second_entered.is_set()
    release_first.set()
    thread_one.join(timeout=2)
    thread_two.join(timeout=2)
    assert second_entered.is_set()
