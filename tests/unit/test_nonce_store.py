"""
Tests for Nonce Store implementations.

Tests both InMemoryNonceStore and the NonceStore protocol.
RedisNonceStore tests require a Redis instance (integration tests).
"""

import time
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed

import pytest

from aperion_gatekeeper.engines.nonce_store import (
    InMemoryNonceStore,
    NonceStore,
    NullNonceStore,
)


class TestInMemoryNonceStore:
    """Tests for InMemoryNonceStore."""

    def test_new_nonce_not_replay(self) -> None:
        """New nonces should not be detected as replays."""
        store = InMemoryNonceStore(window_seconds=60)
        assert store.is_replay("nonce1", time.time()) is False
        assert store.is_replay("nonce2", time.time()) is False

    def test_same_nonce_is_replay(self) -> None:
        """Same nonce should be detected as replay."""
        store = InMemoryNonceStore(window_seconds=60)
        now = time.time()
        assert store.is_replay("nonce1", now) is False
        assert store.is_replay("nonce1", now) is True

    def test_nonce_cleanup_removes_old(self) -> None:
        """Expired nonces should be cleaned up."""
        store = InMemoryNonceStore(window_seconds=1)

        # Add a nonce
        store.is_replay("old_nonce", time.time())
        assert store.size == 1

        # Wait for expiry
        time.sleep(1.5)

        # Force cleanup
        removed = store.cleanup()
        assert removed == 1
        assert store.size == 0

    def test_cleanup_keeps_recent(self) -> None:
        """Recent nonces should not be cleaned up."""
        store = InMemoryNonceStore(window_seconds=60)

        store.is_replay("recent", time.time())
        removed = store.cleanup()

        assert removed == 0
        assert store.size == 1

    def test_automatic_cleanup_on_is_replay(self) -> None:
        """Cleanup should happen automatically during is_replay checks."""
        store = InMemoryNonceStore(window_seconds=1)
        store._cleanup_interval = 0  # Force cleanup every call

        # Add old nonce
        store.is_replay("old", time.time() - 2)
        assert store.size == 1

        # Next check should trigger cleanup
        time.sleep(0.1)
        store.is_replay("new", time.time())

        # Old nonce should be gone, new should remain
        assert store.size == 1

    def test_thread_safety(self) -> None:
        """Store should be thread-safe."""
        store = InMemoryNonceStore(window_seconds=60)

        errors: list[Exception] = []
        replays: list[bool] = []
        lock = threading.Lock()

        def worker(worker_id: int) -> None:
            try:
                for i in range(100):
                    nonce = f"worker_{worker_id}_nonce_{i}"
                    is_replay = store.is_replay(nonce, time.time())
                    with lock:
                        replays.append(is_replay)
            except Exception as e:
                with lock:
                    errors.append(e)

        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = [executor.submit(worker, i) for i in range(10)]
            for future in as_completed(futures):
                future.result()

        assert len(errors) == 0
        assert len(replays) == 1000
        # All should be unique (no false replay positives)
        assert not any(replays)

    def test_implements_protocol(self) -> None:
        """InMemoryNonceStore should implement NonceStore protocol."""
        store = InMemoryNonceStore()
        assert isinstance(store, NonceStore)


class TestNullNonceStore:
    """Tests for NullNonceStore."""

    def test_never_detects_replay(self) -> None:
        """NullNonceStore should never detect replays."""
        store = NullNonceStore()
        assert store.is_replay("nonce", time.time()) is False
        assert store.is_replay("nonce", time.time()) is False

    def test_size_always_zero(self) -> None:
        """Size should always be 0."""
        store = NullNonceStore()
        store.is_replay("nonce", time.time())
        assert store.size == 0

    def test_cleanup_noop(self) -> None:
        """Cleanup should do nothing."""
        store = NullNonceStore()
        assert store.cleanup() == 0


class TestNonceStoreProtocol:
    """Tests for NonceStore protocol compliance."""

    @pytest.mark.parametrize("store_factory", [
        lambda: InMemoryNonceStore(window_seconds=60),
        lambda: NullNonceStore(),
    ])
    def test_protocol_methods_exist(self, store_factory) -> None:
        """All protocol methods should exist and be callable."""
        store = store_factory()

        # Test is_replay
        result = store.is_replay("test", time.time())
        assert isinstance(result, bool)

        # Test cleanup
        removed = store.cleanup()
        assert isinstance(removed, int)

        # Test size
        size = store.size
        assert isinstance(size, int)
