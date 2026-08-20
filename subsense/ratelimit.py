"""Shared adaptive rate limiter: politeness ceiling + backoff + jitter + block detection.

Every source, DNS check, and prober acquires this limiter before making a network call. It is
the single place that enforces the global rate ceiling (architecture principle #2) — no plugin
should build its own semaphore/sleep logic.

Philosophy (per CLAUDE.md): avoid blocks by being polite, not by evading detection. On
sustained failures we slow down (adaptive backoff) rather than switching UA/proxy tricks to
push through.
"""

from __future__ import annotations

import asyncio
import random
import time

from subsense.config import RateLimitConfig


class RateLimiter:
    def __init__(self, config: RateLimitConfig):
        self.config = config
        self._semaphore = asyncio.Semaphore(config.max_concurrency)
        self._interval = 1.0 / config.requests_per_second if config.requests_per_second > 0 else 0.0
        self._lock = asyncio.Lock()
        self._next_slot: float = 0.0

        self._consecutive_failures = 0
        self._current_backoff = 0.0  # extra delay injected per-request while backing off

    @property
    def proxy(self) -> str | None:
        return self.config.proxy

    async def _wait_for_slot(self) -> None:
        """Simple token-interval scheduler: serializes callers onto a `_interval`-spaced timeline."""
        async with self._lock:
            now = time.monotonic()
            start = max(now, self._next_slot)
            self._next_slot = start + self._interval
            delay = start - now
        if delay > 0:
            await asyncio.sleep(delay)

    def _jitter(self) -> float:
        return random.uniform(0, self.config.jitter_seconds)

    async def acquire(self) -> None:
        await self._semaphore.acquire()
        await self._wait_for_slot()
        if self._current_backoff > 0:
            await asyncio.sleep(self._current_backoff + self._jitter())

    def release(self) -> None:
        self._semaphore.release()

    def record_success(self) -> None:
        self._consecutive_failures = 0
        self._current_backoff = 0.0

    def record_failure(self, retry_after: float | None = None) -> None:
        """Register a failed/blocked request. Escalates backoff; a `Retry-After` header
        (when `respect_retry_after` is set) takes precedence over the computed exponential value.
        """
        self._consecutive_failures += 1

        if retry_after is not None and self.config.respect_retry_after:
            self._current_backoff = min(retry_after, self.config.backoff_max_seconds)
            return

        if self._consecutive_failures >= self.config.block_detect_threshold:
            exponent = self._consecutive_failures - self.config.block_detect_threshold
            backoff = self.config.backoff_base_seconds * (2**exponent)
            self._current_backoff = min(backoff, self.config.backoff_max_seconds)

    def guard(self) -> "_RateLimitGuard":
        """Async context manager: `async with limiter.guard(): ...` acquires/releases + lets
        the caller report the outcome via `.success()` / `.failure(retry_after=...)`.
        """
        return _RateLimitGuard(self)


class _RateLimitGuard:
    def __init__(self, limiter: RateLimiter):
        self._limiter = limiter
        self._reported = False

    async def __aenter__(self) -> "_RateLimitGuard":
        await self._limiter.acquire()
        return self

    async def __aexit__(self, exc_type, exc, tb) -> bool:
        if not self._reported:
            if exc_type is None:
                self._limiter.record_success()
            else:
                self._limiter.record_failure()
        self._limiter.release()
        return False

    def success(self) -> None:
        self._reported = True
        self._limiter.record_success()

    def failure(self, retry_after: float | None = None) -> None:
        self._reported = True
        self._limiter.record_failure(retry_after=retry_after)
