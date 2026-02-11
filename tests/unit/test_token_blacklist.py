"""Unit tests for token blacklist implementations."""

import time
import threading
import pytest

from aperion_gatekeeper.engines.token_blacklist import (
    InMemoryTokenBlacklist,
    NullTokenBlacklist,
    BlacklistEntry,
)


class TestInMemoryTokenBlacklist:
    """Tests for InMemoryTokenBlacklist."""

    def test_revoke_adds_to_blacklist(self) -> None:
        """Revoke should add token to blacklist."""
        blacklist = InMemoryTokenBlacklist()

        result = blacklist.revoke("token123", reason="user_logout")
        assert result is True
        assert blacklist.is_revoked("token123")

    def test_revoke_returns_false_for_duplicate(self) -> None:
        """Revoking same token twice returns False."""
        blacklist = InMemoryTokenBlacklist()

        assert blacklist.revoke("token123", reason="logout") is True
        assert blacklist.revoke("token123", reason="logout") is False

    def test_is_revoked_returns_false_for_unknown(self) -> None:
        """is_revoked returns False for unknown tokens."""
        blacklist = InMemoryTokenBlacklist()
        assert blacklist.is_revoked("unknown_token") is False

    def test_get_entry_returns_details(self) -> None:
        """get_entry should return full details."""
        blacklist = InMemoryTokenBlacklist()

        blacklist.revoke("token123", reason="security", revoked_by="admin")

        entry = blacklist.get_entry("token123")
        assert entry is not None
        assert entry.token_hash == "token123"
        assert entry.reason == "security"
        assert entry.revoked_by == "admin"
        assert entry.revoked_at > 0

    def test_remove_clears_revocation(self) -> None:
        """Remove should clear revocation."""
        blacklist = InMemoryTokenBlacklist()

        blacklist.revoke("token123", reason="test")
        assert blacklist.is_revoked("token123")

        assert blacklist.remove("token123") is True
        assert blacklist.is_revoked("token123") is False

    def test_remove_returns_false_for_unknown(self) -> None:
        """Remove returns False for unknown tokens."""
        blacklist = InMemoryTokenBlacklist()
        assert blacklist.remove("unknown") is False

    def test_ttl_expires_entry(self) -> None:
        """Entry should expire after TTL."""
        blacklist = InMemoryTokenBlacklist()

        blacklist.revoke("token123", reason="test", ttl_seconds=1)
        assert blacklist.is_revoked("token123")

        # Wait for expiry
        time.sleep(1.1)

        assert blacklist.is_revoked("token123") is False

    def test_cleanup_removes_expired(self) -> None:
        """Cleanup should remove expired entries."""
        blacklist = InMemoryTokenBlacklist()

        blacklist.revoke("token1", reason="test", ttl_seconds=1)
        blacklist.revoke("token2", reason="test")  # No TTL

        assert blacklist.size == 2

        time.sleep(1.1)

        removed = blacklist.cleanup()
        assert removed == 1
        assert blacklist.size == 1
        assert blacklist.is_revoked("token2")

    def test_thread_safety(self) -> None:
        """Blacklist should be thread-safe."""
        blacklist = InMemoryTokenBlacklist()
        errors = []

        def revoke_tokens(start: int):
            try:
                for i in range(100):
                    blacklist.revoke(f"token_{start}_{i}", reason="test")
            except Exception as e:
                errors.append(e)

        threads = [
            threading.Thread(target=revoke_tokens, args=(i,)) for i in range(10)
        ]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert len(errors) == 0
        assert blacklist.size == 1000

    def test_size_property(self) -> None:
        """Size property should return count."""
        blacklist = InMemoryTokenBlacklist()

        assert blacklist.size == 0

        blacklist.revoke("token1", reason="test")
        blacklist.revoke("token2", reason="test")

        assert blacklist.size == 2

    def test_revoke_all_for_principal(self) -> None:
        """Should revoke all tokens for a principal."""
        blacklist = InMemoryTokenBlacklist()

        tokens = ["token1", "token2", "token3"]
        count = blacklist.revoke_all_for_principal(
            principal_id="user123",
            token_hashes=tokens,
            reason="password_change",
        )

        assert count == 3
        for token in tokens:
            assert blacklist.is_revoked(token)
            entry = blacklist.get_entry(token)
            assert entry is not None
            assert entry.revoked_by == "user123"

    def test_get_entry_returns_none_for_expired(self) -> None:
        """get_entry should return None for expired tokens."""
        blacklist = InMemoryTokenBlacklist()

        blacklist.revoke("token123", reason="test", ttl_seconds=1)
        time.sleep(1.1)

        assert blacklist.get_entry("token123") is None


class TestNullTokenBlacklist:
    """Tests for NullTokenBlacklist."""

    def test_revoke_returns_true(self) -> None:
        """Revoke always returns True."""
        blacklist = NullTokenBlacklist()
        assert blacklist.revoke("token", reason="test") is True

    def test_is_revoked_always_false(self) -> None:
        """is_revoked always returns False."""
        blacklist = NullTokenBlacklist()
        blacklist.revoke("token", reason="test")
        assert blacklist.is_revoked("token") is False

    def test_get_entry_returns_none(self) -> None:
        """get_entry always returns None."""
        blacklist = NullTokenBlacklist()
        assert blacklist.get_entry("token") is None

    def test_remove_returns_false(self) -> None:
        """Remove always returns False."""
        blacklist = NullTokenBlacklist()
        assert blacklist.remove("token") is False

    def test_cleanup_returns_zero(self) -> None:
        """Cleanup always returns 0."""
        blacklist = NullTokenBlacklist()
        assert blacklist.cleanup() == 0


class TestBlacklistEntry:
    """Tests for BlacklistEntry dataclass."""

    def test_entry_creation(self) -> None:
        """BlacklistEntry should store all fields."""
        entry = BlacklistEntry(
            token_hash="abc123",
            revoked_at=time.time(),
            reason="stolen",
            revoked_by="admin",
            expires_at=time.time() + 3600,
        )

        assert entry.token_hash == "abc123"
        assert entry.reason == "stolen"
        assert entry.revoked_by == "admin"
        assert entry.expires_at is not None

    def test_entry_optional_fields(self) -> None:
        """Optional fields should default to None."""
        entry = BlacklistEntry(
            token_hash="abc123",
            revoked_at=time.time(),
            reason="test",
        )

        assert entry.revoked_by is None
        assert entry.expires_at is None


class TestTokenBlacklistProtocol:
    """Test that implementations satisfy the protocol."""

    def test_inmemory_satisfies_protocol(self) -> None:
        """InMemoryTokenBlacklist should satisfy TokenBlacklist protocol."""
        from aperion_gatekeeper.engines.token_blacklist import TokenBlacklist

        blacklist = InMemoryTokenBlacklist()
        assert isinstance(blacklist, TokenBlacklist)

    def test_null_satisfies_protocol(self) -> None:
        """NullTokenBlacklist should satisfy TokenBlacklist protocol."""
        from aperion_gatekeeper.engines.token_blacklist import TokenBlacklist

        blacklist = NullTokenBlacklist()
        assert isinstance(blacklist, TokenBlacklist)
