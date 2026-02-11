"""
Rate Limiting for Aperion Gatekeeper.

Provides sliding window rate limiting for abuse prevention.
Supports both in-memory (single-instance) and Redis (distributed) backends.

Zero-trust: Default deny when rate limit exceeded.
"""

from __future__ import annotations

import time
import threading
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Protocol, runtime_checkable


class RateLimitResult(Enum):
    """Result of a rate limit check."""

    ALLOWED = "allowed"
    DENIED = "denied"
    WARNING = "warning"  # Approaching limit


@dataclass
class RateLimitInfo:
    """Information about current rate limit state."""

    result: RateLimitResult
    current_count: int
    limit: int
    window_seconds: int
    remaining: int
    reset_at: float  # Unix timestamp when window resets
    retry_after: float | None = None  # Seconds until retry allowed (if denied)

    @property
    def is_allowed(self) -> bool:
        """Whether the request is allowed (includes warnings)."""
        return self.result != RateLimitResult.DENIED

    @property
    def usage_percent(self) -> float:
        """Percentage of limit used."""
        return (self.current_count / self.limit) * 100 if self.limit > 0 else 0


@runtime_checkable
class RateLimiter(Protocol):
    """
    Protocol for rate limiter implementations.

    All operations must be thread-safe.
    """

    def check(self, key: str) -> RateLimitInfo:
        """
        Check rate limit for a key and increment counter.

        Args:
            key: Rate limit key (e.g., IP address, principal ID)

        Returns:
            RateLimitInfo with current state
        """
        ...

    def reset(self, key: str) -> bool:
        """
        Reset rate limit for a key.

        Args:
            key: Rate limit key to reset

        Returns:
            True if key was reset
        """
        ...

    def get_info(self, key: str) -> RateLimitInfo | None:
        """
        Get current rate limit info without incrementing.

        Args:
            key: Rate limit key

        Returns:
            RateLimitInfo or None if key not tracked
        """
        ...


@dataclass
class SlidingWindowEntry:
    """Entry in sliding window rate limiter."""

    count: int
    window_start: float


class InMemoryRateLimiter:
    """
    In-memory sliding window rate limiter.

    Thread-safe implementation for single-instance deployments.

    Usage:
        limiter = InMemoryRateLimiter(limit=100, window_seconds=60)

        info = limiter.check("192.168.1.1")
        if not info.is_allowed:
            raise RateLimitExceeded(retry_after=info.retry_after)
    """

    def __init__(
        self,
        limit: int = 100,
        window_seconds: int = 60,
        warning_threshold: float = 0.8,
    ) -> None:
        """
        Initialize rate limiter.

        Args:
            limit: Maximum requests per window
            window_seconds: Window duration in seconds
            warning_threshold: Percentage (0-1) at which to return WARNING
        """
        self._limit = limit
        self._window = window_seconds
        self._warning_threshold = warning_threshold
        self._entries: dict[str, SlidingWindowEntry] = {}
        self._lock = threading.RLock()
        self._last_cleanup = time.time()
        self._cleanup_interval = max(window_seconds // 10, 1)

    def check(self, key: str) -> RateLimitInfo:
        """
        Check rate limit and increment counter.

        Uses sliding window algorithm:
        - Requests in current window are counted
        - Window slides forward with each request
        """
        now = time.time()

        with self._lock:
            self._maybe_cleanup(now)

            entry = self._entries.get(key)

            if entry is None or now - entry.window_start >= self._window:
                # New window
                entry = SlidingWindowEntry(count=1, window_start=now)
                self._entries[key] = entry
                return self._make_info(entry, now, RateLimitResult.ALLOWED)

            # Existing window - increment
            entry.count += 1

            if entry.count > self._limit:
                retry_after = entry.window_start + self._window - now
                return self._make_info(
                    entry, now, RateLimitResult.DENIED, retry_after=retry_after
                )

            if entry.count >= self._limit * self._warning_threshold:
                return self._make_info(entry, now, RateLimitResult.WARNING)

            return self._make_info(entry, now, RateLimitResult.ALLOWED)

    def reset(self, key: str) -> bool:
        """Reset rate limit for a key."""
        with self._lock:
            if key in self._entries:
                del self._entries[key]
                return True
            return False

    def get_info(self, key: str) -> RateLimitInfo | None:
        """Get current rate limit info without incrementing."""
        now = time.time()

        with self._lock:
            entry = self._entries.get(key)
            if entry is None:
                return None

            # Check if window expired
            if now - entry.window_start >= self._window:
                return None

            if entry.count > self._limit:
                retry_after = entry.window_start + self._window - now
                return self._make_info(
                    entry, now, RateLimitResult.DENIED, retry_after=retry_after
                )

            if entry.count >= self._limit * self._warning_threshold:
                return self._make_info(entry, now, RateLimitResult.WARNING)

            return self._make_info(entry, now, RateLimitResult.ALLOWED)

    def _make_info(
        self,
        entry: SlidingWindowEntry,
        now: float,
        result: RateLimitResult,
        retry_after: float | None = None,
    ) -> RateLimitInfo:
        """Create RateLimitInfo from entry."""
        remaining = max(0, self._limit - entry.count)
        reset_at = entry.window_start + self._window

        return RateLimitInfo(
            result=result,
            current_count=entry.count,
            limit=self._limit,
            window_seconds=self._window,
            remaining=remaining,
            reset_at=reset_at,
            retry_after=retry_after,
        )

    def _maybe_cleanup(self, now: float) -> None:
        """Clean up expired entries (must hold lock)."""
        if now - self._last_cleanup < self._cleanup_interval:
            return

        cutoff = now - self._window
        self._entries = {
            k: v for k, v in self._entries.items() if v.window_start > cutoff
        }
        self._last_cleanup = now

    @property
    def tracked_keys(self) -> int:
        """Number of currently tracked keys."""
        with self._lock:
            return len(self._entries)


class RedisRateLimiter:
    """
    Redis-backed sliding window rate limiter.

    Uses Redis sorted sets for distributed rate limiting.
    Suitable for multi-instance production deployments.

    Requires:
        pip install redis

    Usage:
        import redis
        from aperion_gatekeeper.engines.rate_limiter import RedisRateLimiter

        client = redis.Redis(host='localhost', port=6379, db=0)
        limiter = RedisRateLimiter(client, limit=100, window_seconds=60)

        info = limiter.check("user:123")
    """

    def __init__(
        self,
        redis_client: Any,  # redis.Redis
        limit: int = 100,
        window_seconds: int = 60,
        key_prefix: str = "gatekeeper:ratelimit:",
        warning_threshold: float = 0.8,
    ) -> None:
        """
        Initialize Redis rate limiter.

        Args:
            redis_client: Redis client instance
            limit: Maximum requests per window
            window_seconds: Window duration in seconds
            key_prefix: Redis key prefix
            warning_threshold: Percentage at which to return WARNING
        """
        self._redis = redis_client
        self._limit = limit
        self._window = window_seconds
        self._key_prefix = key_prefix
        self._warning_threshold = warning_threshold

    def check(self, key: str) -> RateLimitInfo:
        """
        Check rate limit using Redis sorted set.

        Uses sliding window with microsecond timestamps as scores.
        """
        now = time.time()
        redis_key = f"{self._key_prefix}{key}"
        window_start = now - self._window

        # Use pipeline for atomicity
        pipe = self._redis.pipeline()

        # Remove old entries outside window
        pipe.zremrangebyscore(redis_key, 0, window_start)

        # Add current request with timestamp as score
        pipe.zadd(redis_key, {str(now): now})

        # Count requests in window
        pipe.zcard(redis_key)

        # Set TTL to auto-cleanup
        pipe.expire(redis_key, self._window + 1)

        results = pipe.execute()
        current_count = results[2]

        remaining = max(0, self._limit - current_count)
        reset_at = now + self._window

        if current_count > self._limit:
            return RateLimitInfo(
                result=RateLimitResult.DENIED,
                current_count=current_count,
                limit=self._limit,
                window_seconds=self._window,
                remaining=0,
                reset_at=reset_at,
                retry_after=self._window,
            )

        if current_count >= self._limit * self._warning_threshold:
            result = RateLimitResult.WARNING
        else:
            result = RateLimitResult.ALLOWED

        return RateLimitInfo(
            result=result,
            current_count=current_count,
            limit=self._limit,
            window_seconds=self._window,
            remaining=remaining,
            reset_at=reset_at,
        )

    def reset(self, key: str) -> bool:
        """Reset rate limit for a key."""
        redis_key = f"{self._key_prefix}{key}"
        return self._redis.delete(redis_key) > 0

    def get_info(self, key: str) -> RateLimitInfo | None:
        """Get current rate limit info without incrementing."""
        now = time.time()
        redis_key = f"{self._key_prefix}{key}"
        window_start = now - self._window

        # Clean and count without adding
        pipe = self._redis.pipeline()
        pipe.zremrangebyscore(redis_key, 0, window_start)
        pipe.zcard(redis_key)
        results = pipe.execute()

        current_count = results[1]
        if current_count == 0:
            return None

        remaining = max(0, self._limit - current_count)
        reset_at = now + self._window

        if current_count > self._limit:
            result = RateLimitResult.DENIED
            retry_after = self._window
        elif current_count >= self._limit * self._warning_threshold:
            result = RateLimitResult.WARNING
            retry_after = None
        else:
            result = RateLimitResult.ALLOWED
            retry_after = None

        return RateLimitInfo(
            result=result,
            current_count=current_count,
            limit=self._limit,
            window_seconds=self._window,
            remaining=remaining,
            reset_at=reset_at,
            retry_after=retry_after,
        )


class NullRateLimiter:
    """
    No-op rate limiter that always allows requests.

    WARNING: Provides NO rate limiting.
    Only use for testing or when rate limiting is handled elsewhere.
    """

    def __init__(self, limit: int = 100, window_seconds: int = 60) -> None:
        self._limit = limit
        self._window = window_seconds

    def check(self, key: str) -> RateLimitInfo:
        """Always allows requests."""
        now = time.time()
        return RateLimitInfo(
            result=RateLimitResult.ALLOWED,
            current_count=0,
            limit=self._limit,
            window_seconds=self._window,
            remaining=self._limit,
            reset_at=now + self._window,
        )

    def reset(self, key: str) -> bool:
        """No-op reset."""
        return False

    def get_info(self, key: str) -> RateLimitInfo | None:
        """Always returns None."""
        return None


class CompositeRateLimiter:
    """
    Combines multiple rate limiters with different limits.

    Useful for implementing tiered rate limiting:
    - Per-second burst limit
    - Per-minute sustained limit
    - Per-hour daily limit

    Usage:
        limiter = CompositeRateLimiter([
            InMemoryRateLimiter(limit=10, window_seconds=1),   # 10/sec burst
            InMemoryRateLimiter(limit=100, window_seconds=60), # 100/min sustained
        ])

        info = limiter.check("user:123")
    """

    def __init__(self, limiters: list[RateLimiter]) -> None:
        """
        Initialize composite limiter.

        Args:
            limiters: List of rate limiters to check (all must pass)
        """
        self._limiters = limiters

    def check(self, key: str) -> RateLimitInfo:
        """
        Check all limiters - denied if ANY limiter denies.

        Returns the most restrictive result.
        """
        results = [limiter.check(key) for limiter in self._limiters]

        # Find most restrictive (denied > warning > allowed)
        denied = [r for r in results if r.result == RateLimitResult.DENIED]
        if denied:
            # Return the one with longest retry_after
            return max(denied, key=lambda r: r.retry_after or 0)

        warning = [r for r in results if r.result == RateLimitResult.WARNING]
        if warning:
            return warning[0]

        return results[0] if results else self._null_result()

    def reset(self, key: str) -> bool:
        """Reset all limiters for key."""
        return any(limiter.reset(key) for limiter in self._limiters)

    def get_info(self, key: str) -> RateLimitInfo | None:
        """Get info from most restrictive limiter."""
        for limiter in self._limiters:
            info = limiter.get_info(key)
            if info and info.result != RateLimitResult.ALLOWED:
                return info
        return None

    def _null_result(self) -> RateLimitInfo:
        return RateLimitInfo(
            result=RateLimitResult.ALLOWED,
            current_count=0,
            limit=0,
            window_seconds=0,
            remaining=0,
            reset_at=time.time(),
        )
