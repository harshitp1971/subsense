import pytest

from subsense.config import RateLimitConfig
from subsense.ratelimit import RateLimiter


def test_success_resets_backoff():
    limiter = RateLimiter(RateLimitConfig(block_detect_threshold=3, backoff_base_seconds=1.0))
    for _ in range(5):
        limiter.record_failure()
    assert limiter._current_backoff > 0
    limiter.record_success()
    assert limiter._current_backoff == 0.0
    assert limiter._consecutive_failures == 0


def test_backoff_escalates_after_threshold():
    limiter = RateLimiter(
        RateLimitConfig(block_detect_threshold=3, backoff_base_seconds=1.0, backoff_max_seconds=100.0)
    )
    for _ in range(2):
        limiter.record_failure()
    assert limiter._current_backoff == 0.0  # under threshold, no backoff yet

    limiter.record_failure()  # 3rd failure hits the threshold
    first_backoff = limiter._current_backoff
    assert first_backoff > 0

    limiter.record_failure()  # 4th failure escalates further
    assert limiter._current_backoff > first_backoff


def test_backoff_capped_at_max():
    limiter = RateLimiter(
        RateLimitConfig(block_detect_threshold=1, backoff_base_seconds=10.0, backoff_max_seconds=15.0)
    )
    for _ in range(10):
        limiter.record_failure()
    assert limiter._current_backoff <= 15.0


def test_retry_after_takes_precedence():
    limiter = RateLimiter(RateLimitConfig(respect_retry_after=True, backoff_max_seconds=100.0))
    limiter.record_failure(retry_after=42.0)
    assert limiter._current_backoff == 42.0


@pytest.mark.asyncio
async def test_guard_reports_success_on_clean_exit():
    limiter = RateLimiter(RateLimitConfig(max_concurrency=5, requests_per_second=1000))
    limiter.record_failure()
    async with limiter.guard():
        pass
    assert limiter._consecutive_failures == 0


@pytest.mark.asyncio
async def test_guard_reports_failure_on_exception():
    limiter = RateLimiter(RateLimitConfig(max_concurrency=5, requests_per_second=1000))
    with pytest.raises(ValueError):
        async with limiter.guard():
            raise ValueError("boom")
    assert limiter._consecutive_failures == 1
