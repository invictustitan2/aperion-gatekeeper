"""Unit tests for rate limiter implementations."""

import time
import threading
import pytest

from aperion_gatekeeper.engines.rate_limiter import (
    InMemoryRateLimiter,
    NullRateLimiter,
    CompositeRateLimiter,
    RateLimitResult,
)


class TestInMemoryRateLimiter:
    """Tests for InMemoryRateLimiter."""

    def test_allows_requests_under_limit(self) -> None:
        """Requests under limit should be allowed."""
        limiter = InMemoryRateLimiter(limit=10, window_seconds=60, warning_threshold=1.0)

        for _ in range(10):
            info = limiter.check("test-key")
            assert info.is_allowed

    def test_denies_requests_over_limit(self) -> None:
        """Requests over limit should be denied."""
        limiter = InMemoryRateLimiter(limit=5, window_seconds=60)

        # Use up the limit
        for _ in range(5):
            limiter.check("test-key")

        # 6th request should be denied
        info = limiter.check("test-key")
        assert info.result == RateLimitResult.DENIED
        assert info.retry_after is not None
        assert info.retry_after > 0

    def test_warning_threshold(self) -> None:
        """Should return warning when approaching limit."""
        limiter = InMemoryRateLimiter(
            limit=10, window_seconds=60, warning_threshold=0.8
        )

        # Use 7 requests (70% - under threshold)
        for _ in range(7):
            info = limiter.check("test-key")

        assert info.result == RateLimitResult.ALLOWED

        # 8th request (80% - at threshold)
        info = limiter.check("test-key")
        assert info.result == RateLimitResult.WARNING

    def test_separate_keys_tracked_independently(self) -> None:
        """Different keys have separate limits."""
        limiter = InMemoryRateLimiter(limit=5, window_seconds=60)

        # Exhaust limit for key1
        for _ in range(6):
            limiter.check("key1")

        # key2 should still be allowed
        info = limiter.check("key2")
        assert info.is_allowed

    def test_reset_clears_key(self) -> None:
        """Reset should clear rate limit for key."""
        limiter = InMemoryRateLimiter(limit=5, window_seconds=60)

        # Exhaust limit
        for _ in range(6):
            limiter.check("test-key")

        # Should be denied
        info = limiter.check("test-key")
        assert info.result == RateLimitResult.DENIED

        # Reset
        assert limiter.reset("test-key")

        # Should be allowed again
        info = limiter.check("test-key")
        assert info.is_allowed

    def test_get_info_without_increment(self) -> None:
        """get_info should not increment counter."""
        limiter = InMemoryRateLimiter(limit=5, window_seconds=60)

        # Make 3 requests
        for _ in range(3):
            limiter.check("test-key")

        # get_info should show 3
        info = limiter.get_info("test-key")
        assert info is not None
        assert info.current_count == 3

        # Call get_info again - should still be 3
        info = limiter.get_info("test-key")
        assert info.current_count == 3

    def test_window_expiry(self) -> None:
        """Window should expire after window_seconds."""
        limiter = InMemoryRateLimiter(limit=5, window_seconds=1)

        # Exhaust limit
        for _ in range(6):
            limiter.check("test-key")

        info = limiter.check("test-key")
        assert info.result == RateLimitResult.DENIED

        # Wait for window to expire
        time.sleep(1.1)

        # Should be allowed again
        info = limiter.check("test-key")
        assert info.is_allowed

    def test_thread_safety(self) -> None:
        """Rate limiter should be thread-safe."""
        limiter = InMemoryRateLimiter(limit=1000, window_seconds=60)
        errors = []

        def make_requests():
            try:
                for _ in range(100):
                    limiter.check("test-key")
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=make_requests) for _ in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert len(errors) == 0

        # Should have tracked all requests
        info = limiter.get_info("test-key")
        assert info is not None
        assert info.current_count == 1000

    def test_tracked_keys_count(self) -> None:
        """tracked_keys should return number of tracked keys."""
        limiter = InMemoryRateLimiter(limit=100, window_seconds=60)

        assert limiter.tracked_keys == 0

        limiter.check("key1")
        limiter.check("key2")
        limiter.check("key3")

        assert limiter.tracked_keys == 3

    def test_cleanup_removes_expired_entries(self) -> None:
        """Expired entries should be cleaned up."""
        limiter = InMemoryRateLimiter(limit=100, window_seconds=1)

        limiter.check("key1")
        limiter.check("key2")

        assert limiter.tracked_keys == 2

        # Wait for entries to expire
        time.sleep(1.1)

        # Trigger cleanup via new request
        limiter.check("key3")

        # Old keys should be cleaned up
        assert limiter.tracked_keys == 1

    def test_rate_limit_info_properties(self) -> None:
        """RateLimitInfo properties should work correctly."""
        limiter = InMemoryRateLimiter(limit=10, window_seconds=60)

        for _ in range(5):
            limiter.check("test-key")

        info = limiter.get_info("test-key")
        assert info is not None
        assert info.usage_percent == 50.0
        assert info.remaining == 5


class TestNullRateLimiter:
    """Tests for NullRateLimiter."""

    def test_always_allows(self) -> None:
        """NullRateLimiter should always allow requests."""
        limiter = NullRateLimiter()

        for _ in range(1000):
            info = limiter.check("test-key")
            assert info.is_allowed

    def test_reset_returns_false(self) -> None:
        """Reset should return False (no-op)."""
        limiter = NullRateLimiter()
        assert limiter.reset("test-key") is False

    def test_get_info_returns_none(self) -> None:
        """get_info should return None."""
        limiter = NullRateLimiter()
        limiter.check("test-key")
        assert limiter.get_info("test-key") is None


class TestCompositeRateLimiter:
    """Tests for CompositeRateLimiter."""

    def test_allows_when_all_limiters_allow(self) -> None:
        """Should allow when all limiters allow."""
        limiter = CompositeRateLimiter([
            InMemoryRateLimiter(limit=10, window_seconds=60),
            InMemoryRateLimiter(limit=100, window_seconds=3600),
        ])

        info = limiter.check("test-key")
        assert info.is_allowed

    def test_denies_when_any_limiter_denies(self) -> None:
        """Should deny when ANY limiter denies."""
        burst_limiter = InMemoryRateLimiter(limit=5, window_seconds=60)
        sustained_limiter = InMemoryRateLimiter(limit=100, window_seconds=3600)

        limiter = CompositeRateLimiter([burst_limiter, sustained_limiter])

        # Exhaust burst limit
        for _ in range(6):
            limiter.check("test-key")

        info = limiter.check("test-key")
        assert info.result == RateLimitResult.DENIED

    def test_reset_resets_all(self) -> None:
        """Reset should reset all limiters."""
        limiter = CompositeRateLimiter([
            InMemoryRateLimiter(limit=10, window_seconds=60, warning_threshold=1.0),
            InMemoryRateLimiter(limit=100, window_seconds=3600, warning_threshold=1.0),
        ])

        # Make some requests
        for _ in range(5):
            limiter.check("test-key")

        # Reset
        assert limiter.reset("test-key")

        # Should be allowed again - count starts fresh
        info = limiter.check("test-key")
        assert info.is_allowed
        assert info.current_count == 1

    def test_warning_when_any_warning(self) -> None:
        """Should return warning if any limiter returns warning."""
        limiter = CompositeRateLimiter([
            InMemoryRateLimiter(limit=10, window_seconds=60, warning_threshold=0.5),
            InMemoryRateLimiter(limit=100, window_seconds=3600),
        ])

        # Use 5 requests (50% of first limiter - at threshold)
        for _ in range(5):
            limiter.check("test-key")

        info = limiter.check("test-key")
        assert info.result == RateLimitResult.WARNING


class TestRateLimiterProtocol:
    """Test that implementations satisfy the protocol."""

    def test_inmemory_satisfies_protocol(self) -> None:
        """InMemoryRateLimiter should satisfy RateLimiter protocol."""
        from aperion_gatekeeper.engines.rate_limiter import RateLimiter

        limiter = InMemoryRateLimiter()
        assert isinstance(limiter, RateLimiter)

    def test_null_satisfies_protocol(self) -> None:
        """NullRateLimiter should satisfy RateLimiter protocol."""
        from aperion_gatekeeper.engines.rate_limiter import RateLimiter

        limiter = NullRateLimiter()
        assert isinstance(limiter, RateLimiter)

    def test_composite_satisfies_protocol(self) -> None:
        """CompositeRateLimiter should satisfy RateLimiter protocol."""
        from aperion_gatekeeper.engines.rate_limiter import RateLimiter

        limiter = CompositeRateLimiter([InMemoryRateLimiter()])
        assert isinstance(limiter, RateLimiter)
