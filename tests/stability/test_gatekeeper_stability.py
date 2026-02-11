"""
Phase 0 Stability Tests for Gatekeeper.

These tests validate:
- Memory stability under load (especially NonceTracker)
- No resource leaks with repeated auth attempts
- Concurrent authentication safety
- Long-running operation stability
- Key rotation doesn't cause memory leaks

Run with: pytest tests/stability/ -v --tb=short
"""

import gc
import os
import secrets
import time
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any

import pytest

from aperion_gatekeeper.core.credentials import KeyManager, KeyStatus
from aperion_gatekeeper.core.identity import Subject, User, Agent
from aperion_gatekeeper.engines.authentication import (
    AuthenticationEngine,
    AuthMethod,
    AuthResult,
    NonceTracker,
)


class TestNonceTrackerMemory:
    """Critical: NonceTracker memory leak tests."""

    def test_nonce_cleanup_works(self) -> None:
        """Verify old nonces are cleaned up."""
        tracker = NonceTracker(window_seconds=1)

        # Add some nonces
        for i in range(100):
            tracker.is_replay(f"nonce_{i}", time.time())

        initial_count = len(tracker._used)
        assert initial_count == 100

        # Wait for window to expire
        time.sleep(1.5)

        # Trigger cleanup by checking another nonce
        tracker._last_cleanup = 0  # Force cleanup
        tracker.is_replay("trigger", time.time())

        # Old nonces should be cleaned up
        final_count = len(tracker._used)
        assert final_count < 10, f"Expected cleanup, but still have {final_count} nonces"

    def test_nonce_memory_bounded_under_load(self) -> None:
        """Verify memory doesn't grow unbounded with many nonces."""
        tracker = NonceTracker(window_seconds=60)

        # Get baseline memory
        gc.collect()
        baseline = len(gc.get_objects())

        # Add 10,000 nonces
        now = time.time()
        for i in range(10000):
            tracker.is_replay(f"nonce_{i}", now)

        gc.collect()
        after_nonces = len(gc.get_objects())

        # Memory growth should be bounded
        growth = after_nonces - baseline
        # Each nonce is a string + dict entry, expect ~2 objects per nonce max
        assert growth < 25000, f"Memory grew by {growth} objects (expected < 25000)"

    def test_nonce_cleanup_under_continuous_load(self) -> None:
        """Verify cleanup works while continuously adding nonces."""
        tracker = NonceTracker(window_seconds=2)

        start = time.time()
        duration = 10  # 10 seconds

        nonces_added = 0
        max_size = 0

        while time.time() - start < duration:
            nonce = secrets.token_hex(8)
            tracker.is_replay(nonce, time.time())
            nonces_added += 1

            current_size = len(tracker._used)
            max_size = max(max_size, current_size)

            time.sleep(0.001)  # ~1000 nonces/sec

        print(f"\nNonces added: {nonces_added}")
        print(f"Max tracker size: {max_size}")
        print(f"Final size: {len(tracker._used)}")

        # With 2s window at 1000/s, max should be ~2000 + some buffer
        assert max_size < 5000, f"Tracker grew too large: {max_size}"


class TestAuthenticationEngineMemory:
    """Memory stability tests for AuthenticationEngine."""

    def _create_engine(self) -> AuthenticationEngine:
        """Create a fresh authentication engine."""
        km = KeyManager()
        km.add_hmac_key(os.urandom(32).hex(), key_id="test-key", status=KeyStatus.ACTIVE)
        return AuthenticationEngine(km, timestamp_skew=300, nonce_window=60)

    def test_repeated_auth_no_memory_leak(self) -> None:
        """Verify repeated authentication doesn't leak memory."""
        engine = self._create_engine()

        # Get baseline
        gc.collect()
        baseline = len(gc.get_objects())

        # Perform 10,000 authentications
        for i in range(10000):
            header = engine.create_hmac_header("GET", f"/api/{i}")
            result = engine.authenticate(header, method="GET", path=f"/api/{i}")
            assert result.success

        # Force cleanup
        gc.collect()
        final = len(gc.get_objects())

        growth = final - baseline
        # Auth results and subjects are transient, should not accumulate
        # Allow for NonceTracker storage (one entry per auth within window)
        assert growth < 15000, f"Memory grew by {growth} objects"

    def test_failed_auth_no_memory_leak(self) -> None:
        """Verify failed authentications don't leak memory."""
        engine = self._create_engine()

        gc.collect()
        baseline = len(gc.get_objects())

        # 10,000 failed authentications
        for i in range(10000):
            result = engine.authenticate(
                f"HMAC 0:bad_nonce_{i}:invalid_sig",
                method="GET",
                path="/api/test",
            )
            assert not result.success

        gc.collect()
        final = len(gc.get_objects())

        growth = final - baseline
        # Failed auths shouldn't store nonces
        assert growth < 1000, f"Failed auths leaked memory: {growth} objects"


class TestConcurrencyStability:
    """Thread-safety and concurrent access tests."""

    def _create_engine(self) -> AuthenticationEngine:
        """Create a fresh authentication engine."""
        km = KeyManager()
        km.add_hmac_key(os.urandom(32).hex(), key_id="test-key", status=KeyStatus.ACTIVE)
        return AuthenticationEngine(km, timestamp_skew=300, nonce_window=120)

    def test_concurrent_auth_thread_safe(self) -> None:
        """Verify concurrent authentications are thread-safe."""
        engine = self._create_engine()

        results: list[bool] = []
        errors: list[Exception] = []
        lock = threading.Lock()

        def authenticate_worker(worker_id: int) -> None:
            try:
                for i in range(100):
                    header = engine.create_hmac_header("GET", f"/api/{worker_id}/{i}")
                    result = engine.authenticate(
                        header, method="GET", path=f"/api/{worker_id}/{i}"
                    )
                    with lock:
                        results.append(result.success)
            except Exception as e:
                with lock:
                    errors.append(e)

        # Run 20 concurrent workers
        with ThreadPoolExecutor(max_workers=20) as executor:
            futures = [executor.submit(authenticate_worker, i) for i in range(20)]
            for future in as_completed(futures):
                future.result()

        assert len(errors) == 0, f"Errors during concurrent auth: {errors}"
        assert len(results) == 2000
        assert all(results), "Some authentications failed"

    def test_concurrent_nonce_tracking_safe(self) -> None:
        """Verify nonce tracker is thread-safe."""
        tracker = NonceTracker(window_seconds=60)

        replays: list[bool] = []
        lock = threading.Lock()

        def worker(worker_id: int) -> None:
            for i in range(100):
                nonce = f"worker_{worker_id}_nonce_{i}"
                is_replay = tracker.is_replay(nonce, time.time())
                with lock:
                    replays.append(is_replay)

        with ThreadPoolExecutor(max_workers=20) as executor:
            futures = [executor.submit(worker, i) for i in range(20)]
            for future in as_completed(futures):
                future.result()

        # All should be unique (no replays)
        assert len(replays) == 2000
        assert not any(replays), "Detected false replay positives"


class TestLoadStability:
    """High-load stress tests."""

    def _create_engine(self) -> AuthenticationEngine:
        """Create a fresh authentication engine."""
        km = KeyManager()
        km.add_hmac_key(os.urandom(32).hex(), key_id="test-key", status=KeyStatus.ACTIVE)
        return AuthenticationEngine(km, timestamp_skew=300, nonce_window=120)

    def test_high_throughput_hmac_auth(self) -> None:
        """Test HMAC authentication throughput."""
        engine = self._create_engine()

        # Warm up
        for i in range(100):
            header = engine.create_hmac_header("GET", f"/warmup/{i}")
            engine.authenticate(header, method="GET", path=f"/warmup/{i}")

        # Benchmark
        start = time.time()
        success_count = 0

        for i in range(10000):
            header = engine.create_hmac_header("GET", f"/api/{i}")
            result = engine.authenticate(header, method="GET", path=f"/api/{i}")
            if result.success:
                success_count += 1

        duration = time.time() - start

        print(f"\nHMAC Auth throughput: {10000 / duration:.0f} auths/sec")
        print(f"Success rate: {success_count / 10000 * 100:.1f}%")

        assert success_count == 10000
        assert duration < 30, f"Too slow: {duration}s for 10000 auths"

    def test_burst_authentication_stability(self) -> None:
        """Test handling of burst authentication requests."""
        engine = self._create_engine()

        # Pre-generate all headers
        headers = []
        for i in range(1000):
            header = engine.create_hmac_header("GET", f"/api/{i}")
            headers.append((header, f"/api/{i}"))

        # Process in rapid burst
        results: list[AuthResult] = []
        start = time.time()

        for header, path in headers:
            result = engine.authenticate(header, method="GET", path=path)
            results.append(result)

        duration = time.time() - start

        success = sum(1 for r in results if r.success)
        print(f"\nBurst: {1000 / duration:.0f} auths/sec")
        print(f"Success: {success}/1000")

        assert success == 1000


class TestKeyRotationStability:
    """Tests for key rotation stability."""

    def test_key_rotation_no_memory_leak(self) -> None:
        """Verify key rotation doesn't leak memory."""
        km = KeyManager()

        gc.collect()
        baseline = len(gc.get_objects())

        # Rotate keys many times
        for i in range(100):
            key_id = f"key_{i}"
            km.add_hmac_key(os.urandom(32).hex(), key_id=key_id, status=KeyStatus.ACTIVE)

            # Rotate old key to legacy using add_legacy_key pattern
            if i > 0:
                old_key_id = f"key_{i-1}"
                # Use add_hmac_key with LEGACY status (creates new key object)
                old_key = km._hmac_keys.get(old_key_id)
                if old_key:
                    km.add_hmac_key(old_key.hex_key, key_id=f"{old_key_id}_legacy", status=KeyStatus.LEGACY)
                    del km._hmac_keys[old_key_id]

            # Revoke very old keys using revoke_key API
            if i > 5:
                revoke_id = f"key_{i-5}_legacy"
                km.revoke_key(revoke_id)

        gc.collect()
        final = len(gc.get_objects())

        growth = final - baseline
        # Key objects should be bounded
        assert growth < 500, f"Key rotation leaked memory: {growth} objects"

    def test_concurrent_key_rotation_safe(self) -> None:
        """Verify concurrent key rotation is safe."""
        km = KeyManager()
        km.add_hmac_key(os.urandom(32).hex(), key_id="initial", status=KeyStatus.ACTIVE)

        engine = AuthenticationEngine(km, timestamp_skew=300, nonce_window=120)

        errors: list[Exception] = []
        auth_results: list[bool] = []
        lock = threading.Lock()

        def auth_worker() -> None:
            try:
                for i in range(100):
                    header = engine.create_hmac_header("GET", f"/api/{i}")
                    if header:
                        result = engine.authenticate(header, method="GET", path=f"/api/{i}")
                        with lock:
                            auth_results.append(result.success)
                    time.sleep(0.001)
            except Exception as e:
                with lock:
                    errors.append(e)

        def rotation_worker() -> None:
            try:
                for i in range(10):
                    key_id = f"rotated_key_{i}"
                    km.add_hmac_key(os.urandom(32).hex(), key_id=key_id, status=KeyStatus.ACTIVE)
                    time.sleep(0.01)
            except Exception as e:
                with lock:
                    errors.append(e)

        with ThreadPoolExecutor(max_workers=10) as executor:
            # 5 auth workers + 1 rotation worker
            futures = [executor.submit(auth_worker) for _ in range(5)]
            futures.append(executor.submit(rotation_worker))

            for future in as_completed(futures):
                future.result()

        assert len(errors) == 0, f"Errors: {errors}"
        # Some auths might fail during rotation, but most should succeed
        success_rate = sum(auth_results) / len(auth_results) if auth_results else 0
        assert success_rate > 0.9, f"Too many failures during rotation: {success_rate*100:.1f}%"


class TestLongRunning:
    """Extended stability tests."""

    @pytest.mark.slow
    def test_extended_operation_stability(self) -> None:
        """Test stability over extended operation (60 seconds)."""
        km = KeyManager()
        km.add_hmac_key(os.urandom(32).hex(), key_id="test", status=KeyStatus.ACTIVE)
        engine = AuthenticationEngine(km, timestamp_skew=300, nonce_window=60)

        start = time.time()
        duration = 60  # 60 seconds

        auth_count = 0
        success_count = 0
        error_count = 0

        while time.time() - start < duration:
            header = engine.create_hmac_header("GET", f"/api/{auth_count}")
            result = engine.authenticate(header, method="GET", path=f"/api/{auth_count}")

            auth_count += 1
            if result.success:
                success_count += 1
            else:
                error_count += 1

            time.sleep(0.01)  # ~100 auths/sec

        # Check nonce tracker size
        nonce_count = len(engine._nonce_tracker._used)

        print(f"\n60-second test results:")
        print(f"  Auths attempted: {auth_count}")
        print(f"  Successes: {success_count}")
        print(f"  Failures: {error_count}")
        print(f"  Rate: {auth_count / duration:.0f} auths/sec")
        print(f"  Nonce tracker size: {nonce_count}")

        # With 60s window at 100/s, expect ~6000 nonces max
        assert nonce_count < 10000, f"Nonce tracker grew too large: {nonce_count}"
        assert success_count == auth_count, f"Unexpected failures: {error_count}"

    @pytest.mark.slow
    def test_memory_stable_over_time(self) -> None:
        """Verify memory usage is stable over extended period."""
        km = KeyManager()
        km.add_hmac_key(os.urandom(32).hex(), key_id="test", status=KeyStatus.ACTIVE)
        engine = AuthenticationEngine(km, timestamp_skew=300, nonce_window=30)

        gc.collect()
        initial_objects = len(gc.get_objects())

        measurements: list[int] = []

        start = time.time()
        while time.time() - start < 60:
            # Do some work
            for _ in range(100):
                header = engine.create_hmac_header("GET", "/api/test")
                engine.authenticate(header, method="GET", path="/api/test")

            gc.collect()
            measurements.append(len(gc.get_objects()))
            time.sleep(0.5)

        # Check for memory growth trend
        first_quarter = sum(measurements[:len(measurements)//4]) // (len(measurements)//4)
        last_quarter = sum(measurements[-len(measurements)//4:]) // (len(measurements)//4)

        growth = last_quarter - first_quarter
        print(f"\nMemory trend over 60s:")
        print(f"  First quarter avg: {first_quarter}")
        print(f"  Last quarter avg: {last_quarter}")
        print(f"  Growth: {growth}")

        # Memory should be stable (allow some variance)
        assert growth < 5000, f"Memory growing over time: {growth} objects"
