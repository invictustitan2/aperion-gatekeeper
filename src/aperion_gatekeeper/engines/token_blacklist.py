"""
Token Blacklist for Aperion Gatekeeper.

Provides revocation checking for tokens and sessions.
Supports both in-memory (single-instance) and Redis (distributed) backends.

Zero-trust: Revoked tokens are immediately invalid.
"""

from __future__ import annotations

import time
import threading
from dataclasses import dataclass
from typing import Any, Protocol, runtime_checkable


@dataclass
class BlacklistEntry:
    """Entry in the token blacklist."""

    token_hash: str
    revoked_at: float
    reason: str
    revoked_by: str | None = None
    expires_at: float | None = None  # When to auto-remove from blacklist


@runtime_checkable
class TokenBlacklist(Protocol):
    """
    Protocol for token blacklist implementations.

    All operations must be thread-safe.
    """

    def revoke(
        self,
        token_hash: str,
        reason: str,
        revoked_by: str | None = None,
        ttl_seconds: int | None = None,
    ) -> bool:
        """
        Revoke a token.

        Args:
            token_hash: Hash of the token to revoke
            reason: Reason for revocation
            revoked_by: Principal ID who revoked the token
            ttl_seconds: How long to keep in blacklist (None = forever)

        Returns:
            True if newly revoked, False if already revoked
        """
        ...

    def is_revoked(self, token_hash: str) -> bool:
        """
        Check if a token is revoked.

        Args:
            token_hash: Hash of the token to check

        Returns:
            True if revoked, False otherwise
        """
        ...

    def get_entry(self, token_hash: str) -> BlacklistEntry | None:
        """
        Get blacklist entry details.

        Args:
            token_hash: Hash of the token

        Returns:
            BlacklistEntry if revoked, None otherwise
        """
        ...

    def remove(self, token_hash: str) -> bool:
        """
        Remove a token from blacklist (un-revoke).

        Args:
            token_hash: Hash of the token

        Returns:
            True if removed, False if not found
        """
        ...

    def cleanup(self) -> int:
        """
        Remove expired entries from blacklist.

        Returns:
            Number of entries removed
        """
        ...


class InMemoryTokenBlacklist:
    """
    In-memory token blacklist.

    Thread-safe implementation for single-instance deployments.

    Usage:
        blacklist = InMemoryTokenBlacklist()
        blacklist.revoke(token_hash, reason="user_logout")

        if blacklist.is_revoked(token_hash):
            raise TokenRevokedException()
    """

    def __init__(self, auto_cleanup_interval: int = 60) -> None:
        """
        Initialize blacklist.

        Args:
            auto_cleanup_interval: Seconds between auto-cleanup (0 = disabled)
        """
        self._entries: dict[str, BlacklistEntry] = {}
        self._lock = threading.RLock()
        self._cleanup_interval = auto_cleanup_interval
        self._last_cleanup = time.time()

    def revoke(
        self,
        token_hash: str,
        reason: str,
        revoked_by: str | None = None,
        ttl_seconds: int | None = None,
    ) -> bool:
        """Revoke a token."""
        now = time.time()

        with self._lock:
            if token_hash in self._entries:
                return False

            expires_at = now + ttl_seconds if ttl_seconds else None

            self._entries[token_hash] = BlacklistEntry(
                token_hash=token_hash,
                revoked_at=now,
                reason=reason,
                revoked_by=revoked_by,
                expires_at=expires_at,
            )
            return True

    def is_revoked(self, token_hash: str) -> bool:
        """Check if token is revoked."""
        now = time.time()

        with self._lock:
            self._maybe_cleanup(now)

            entry = self._entries.get(token_hash)
            if entry is None:
                return False

            # Check if entry expired
            if entry.expires_at and entry.expires_at < now:
                del self._entries[token_hash]
                return False

            return True

    def get_entry(self, token_hash: str) -> BlacklistEntry | None:
        """Get blacklist entry details."""
        now = time.time()

        with self._lock:
            entry = self._entries.get(token_hash)
            if entry is None:
                return None

            if entry.expires_at and entry.expires_at < now:
                del self._entries[token_hash]
                return None

            return entry

    def remove(self, token_hash: str) -> bool:
        """Remove token from blacklist."""
        with self._lock:
            if token_hash in self._entries:
                del self._entries[token_hash]
                return True
            return False

    def cleanup(self) -> int:
        """Remove expired entries."""
        now = time.time()

        with self._lock:
            expired = [
                k
                for k, v in self._entries.items()
                if v.expires_at and v.expires_at < now
            ]
            for k in expired:
                del self._entries[k]
            return len(expired)

    def _maybe_cleanup(self, now: float) -> None:
        """Auto-cleanup on read (must hold lock)."""
        if self._cleanup_interval <= 0:
            return

        if now - self._last_cleanup < self._cleanup_interval:
            return

        self.cleanup()
        self._last_cleanup = now

    @property
    def size(self) -> int:
        """Number of entries in blacklist."""
        with self._lock:
            return len(self._entries)

    def revoke_all_for_principal(
        self,
        principal_id: str,
        token_hashes: list[str],
        reason: str,
        ttl_seconds: int | None = None,
    ) -> int:
        """
        Revoke all tokens for a principal.

        Args:
            principal_id: Principal whose tokens to revoke
            token_hashes: List of token hashes to revoke
            reason: Reason for revocation
            ttl_seconds: TTL for blacklist entries

        Returns:
            Number of newly revoked tokens
        """
        count = 0
        for token_hash in token_hashes:
            if self.revoke(token_hash, reason, revoked_by=principal_id, ttl_seconds=ttl_seconds):
                count += 1
        return count


class RedisTokenBlacklist:
    """
    Redis-backed token blacklist.

    Uses Redis SET with TTL for distributed revocation.
    Suitable for multi-instance production deployments.

    Usage:
        import redis
        client = redis.Redis(host='localhost', port=6379, db=0)
        blacklist = RedisTokenBlacklist(client)
    """

    def __init__(
        self,
        redis_client: Any,  # redis.Redis
        key_prefix: str = "gatekeeper:blacklist:",
        default_ttl: int = 86400,  # 24 hours
    ) -> None:
        """
        Initialize Redis blacklist.

        Args:
            redis_client: Redis client instance
            key_prefix: Redis key prefix
            default_ttl: Default TTL for entries (seconds)
        """
        self._redis = redis_client
        self._key_prefix = key_prefix
        self._default_ttl = default_ttl

    def revoke(
        self,
        token_hash: str,
        reason: str,
        revoked_by: str | None = None,
        ttl_seconds: int | None = None,
    ) -> bool:
        """Revoke a token."""
        key = f"{self._key_prefix}{token_hash}"
        ttl = ttl_seconds or self._default_ttl

        # Store entry as JSON
        import json

        entry = {
            "token_hash": token_hash,
            "revoked_at": time.time(),
            "reason": reason,
            "revoked_by": revoked_by,
        }

        # SETNX - only set if not exists
        result = self._redis.set(key, json.dumps(entry), nx=True, ex=ttl)
        return result is True

    def is_revoked(self, token_hash: str) -> bool:
        """Check if token is revoked."""
        key = f"{self._key_prefix}{token_hash}"
        return self._redis.exists(key) > 0

    def get_entry(self, token_hash: str) -> BlacklistEntry | None:
        """Get blacklist entry details."""
        import json

        key = f"{self._key_prefix}{token_hash}"
        data = self._redis.get(key)

        if data is None:
            return None

        entry_dict = json.loads(data)
        ttl = self._redis.ttl(key)
        expires_at = time.time() + ttl if ttl > 0 else None

        return BlacklistEntry(
            token_hash=entry_dict["token_hash"],
            revoked_at=entry_dict["revoked_at"],
            reason=entry_dict["reason"],
            revoked_by=entry_dict.get("revoked_by"),
            expires_at=expires_at,
        )

    def remove(self, token_hash: str) -> bool:
        """Remove token from blacklist."""
        key = f"{self._key_prefix}{token_hash}"
        return self._redis.delete(key) > 0

    def cleanup(self) -> int:
        """Redis auto-expires entries, no cleanup needed."""
        return 0


class NullTokenBlacklist:
    """
    No-op blacklist that never revokes.

    WARNING: Provides NO revocation.
    Only use for testing or when revocation is handled elsewhere.
    """

    def revoke(
        self,
        token_hash: str,
        reason: str,
        revoked_by: str | None = None,
        ttl_seconds: int | None = None,
    ) -> bool:
        """No-op revoke."""
        return True

    def is_revoked(self, token_hash: str) -> bool:
        """Never revoked."""
        return False

    def get_entry(self, token_hash: str) -> BlacklistEntry | None:
        """No entries."""
        return None

    def remove(self, token_hash: str) -> bool:
        """No-op remove."""
        return False

    def cleanup(self) -> int:
        """No cleanup needed."""
        return 0
