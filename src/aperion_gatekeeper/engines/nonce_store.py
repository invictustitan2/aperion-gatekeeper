"""
Nonce Storage Backends for Aperion Gatekeeper.

Provides pluggable nonce tracking for replay attack prevention.
Supports both in-memory (single-instance) and Redis (distributed) backends.

Zero-trust: Default deny. Nonces must be tracked for replay prevention.
"""

from __future__ import annotations

import time
import threading
from abc import ABC, abstractmethod
from typing import Any, Protocol, runtime_checkable


@runtime_checkable
class NonceStore(Protocol):
    """
    Protocol for nonce storage backends.

    Implementations must provide atomic nonce tracking for replay prevention.
    All operations must be thread-safe.
    """

    def is_replay(self, nonce: str, timestamp: float) -> bool:
        """
        Check if nonce has been used (replay attack) and record if new.

        This must be an atomic operation: check-and-set in one call.

        Args:
            nonce: Unique nonce value
            timestamp: Request timestamp for TTL calculation

        Returns:
            True if this is a replay (nonce was seen before)
        """
        ...

    def cleanup(self) -> int:
        """
        Clean up expired nonces.

        Returns:
            Number of nonces removed
        """
        ...

    @property
    def size(self) -> int:
        """Current number of tracked nonces."""
        ...


class InMemoryNonceStore:
    """
    In-memory nonce store for single-instance deployments.

    Thread-safe implementation using a lock and dict.
    Suitable for development and single-server production.

    WARNING: Does not work for distributed deployments.
    Use RedisNonceStore for multi-instance scenarios.
    """

    def __init__(self, window_seconds: int = 600) -> None:
        """
        Initialize in-memory nonce store.

        Args:
            window_seconds: How long to track nonces (default 10 minutes)
        """
        self._used: dict[str, float] = {}
        self._window = window_seconds
        # Cleanup every 1/10th of window or 60 seconds, whichever is smaller
        self._cleanup_interval = min(window_seconds // 10, 60) or 1
        self._last_cleanup = time.time()
        self._lock = threading.RLock()

    def is_replay(self, nonce: str, timestamp: float) -> bool:
        """
        Check if nonce has been used (replay attack).

        Thread-safe atomic check-and-set operation.

        Args:
            nonce: Nonce to check
            timestamp: Request timestamp

        Returns:
            True if this is a replay (nonce was used before)
        """
        with self._lock:
            self._maybe_cleanup()

            if nonce in self._used:
                return True

            self._used[nonce] = timestamp
            return False

    def cleanup(self) -> int:
        """Force cleanup of expired nonces."""
        with self._lock:
            now = time.time()
            cutoff = now - self._window
            before = len(self._used)
            self._used = {n: t for n, t in self._used.items() if t > cutoff}
            self._last_cleanup = now
            return before - len(self._used)

    def _maybe_cleanup(self) -> None:
        """Clean up old nonces periodically (must hold lock)."""
        now = time.time()
        if now - self._last_cleanup < self._cleanup_interval:
            return

        cutoff = now - self._window
        self._used = {n: t for n, t in self._used.items() if t > cutoff}
        self._last_cleanup = now

    @property
    def size(self) -> int:
        """Current number of tracked nonces."""
        with self._lock:
            return len(self._used)


class RedisNonceStore:
    """
    Redis-backed nonce store for distributed deployments.

    Uses Redis SETNX with TTL for atomic, distributed nonce tracking.
    Suitable for multi-instance production deployments.

    Requires:
        pip install redis

    Usage:
        import redis
        from aperion_gatekeeper.engines.nonce_store import RedisNonceStore

        client = redis.Redis(host='localhost', port=6379, db=0)
        store = RedisNonceStore(client, window_seconds=600)

        if store.is_replay(nonce, timestamp):
            # Reject request
            pass
    """

    def __init__(
        self,
        redis_client: Any,  # redis.Redis - type hint avoided for optional dependency
        window_seconds: int = 600,
        key_prefix: str = "gatekeeper:nonce:",
    ) -> None:
        """
        Initialize Redis nonce store.

        Args:
            redis_client: Redis client instance
            window_seconds: TTL for nonces (default 10 minutes)
            key_prefix: Redis key prefix for nonce keys
        """
        self._redis = redis_client
        self._window = window_seconds
        self._key_prefix = key_prefix

    def is_replay(self, nonce: str, timestamp: float) -> bool:
        """
        Check if nonce has been used (replay attack).

        Uses Redis SETNX for atomic check-and-set.

        Args:
            nonce: Nonce to check
            timestamp: Request timestamp (used for logging, TTL is fixed)

        Returns:
            True if this is a replay (nonce was used before)
        """
        key = f"{self._key_prefix}{nonce}"

        # SETNX returns True if key was set (new nonce), False if exists (replay)
        # SET with NX and EX (expire) in one atomic operation
        was_set = self._redis.set(key, str(timestamp), nx=True, ex=self._window)

        # was_set is True if key was NEW, False/None if it existed
        return not was_set

    def cleanup(self) -> int:
        """
        Cleanup is handled by Redis TTL - no-op.

        Returns:
            0 (Redis handles expiry automatically)
        """
        return 0

    @property
    def size(self) -> int:
        """
        Current number of tracked nonces.

        Note: This is approximate and may be slow for large datasets.
        """
        pattern = f"{self._key_prefix}*"
        count = 0
        cursor = 0
        while True:
            cursor, keys = self._redis.scan(cursor, match=pattern, count=1000)
            count += len(keys)
            if cursor == 0:
                break
        return count


class NullNonceStore:
    """
    No-op nonce store that never detects replays.

    WARNING: This provides NO replay protection.
    Only use for testing or when replay protection is handled elsewhere.
    """

    def is_replay(self, nonce: str, timestamp: float) -> bool:
        """Never detects replay - always returns False."""
        return False

    def cleanup(self) -> int:
        """No-op cleanup."""
        return 0

    @property
    def size(self) -> int:
        """Always returns 0."""
        return 0
