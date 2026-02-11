#!/usr/bin/env python3
"""
24-Hour Stability Test Harness for Aperion Gatekeeper.

Runs continuous load testing with memory profiling to validate
production readiness.

Usage:
    # Quick validation (5 minutes)
    python stability_harness.py --duration 300

    # Full 24-hour test
    python stability_harness.py --duration 86400

    # With memory threshold
    python stability_harness.py --duration 3600 --max-memory-mb 500

Requirements:
    pip install psutil
"""

from __future__ import annotations

import argparse
import asyncio
import gc
import json
import os
import random
import string
import sys
import threading
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent / "src"))

from aperion_gatekeeper.core.credentials import KeyManager
from aperion_gatekeeper.core.identity import User
from aperion_gatekeeper.core.correlation import correlation_context, get_correlation_id
from aperion_gatekeeper.engines.authentication import AuthenticationEngine
from aperion_gatekeeper.engines.policy import PolicyEngine
from aperion_gatekeeper.engines.rate_limiter import InMemoryRateLimiter
from aperion_gatekeeper.engines.token_blacklist import InMemoryTokenBlacklist
from aperion_gatekeeper.engines.nonce_store import InMemoryNonceStore

try:
    import psutil
    HAS_PSUTIL = True
except ImportError:
    HAS_PSUTIL = False
    print("Warning: psutil not installed. Memory monitoring disabled.")
    print("Install with: pip install psutil")


@dataclass
class StabilityMetrics:
    """Metrics collected during stability test."""

    start_time: float = field(default_factory=time.time)
    end_time: float | None = None
    
    # Counters
    total_auth_attempts: int = 0
    successful_auths: int = 0
    failed_auths: int = 0
    policy_checks: int = 0
    rate_limit_hits: int = 0
    blacklist_checks: int = 0
    nonce_checks: int = 0
    
    # Errors
    exceptions: int = 0
    exception_types: dict[str, int] = field(default_factory=dict)
    
    # Memory (MB)
    initial_memory_mb: float = 0.0
    peak_memory_mb: float = 0.0
    final_memory_mb: float = 0.0
    memory_samples: list[tuple[float, float]] = field(default_factory=list)
    
    # Timing
    avg_auth_time_ms: float = 0.0
    max_auth_time_ms: float = 0.0
    auth_times: list[float] = field(default_factory=list)

    def to_dict(self) -> dict:
        """Convert to dict for JSON serialization."""
        d = asdict(self)
        # Don't include large lists in summary
        d.pop("memory_samples", None)
        d.pop("auth_times", None)
        d["duration_seconds"] = (self.end_time or time.time()) - self.start_time
        d["auth_per_second"] = self.total_auth_attempts / max(1, d["duration_seconds"])
        return d


class StabilityHarness:
    """
    24-hour stability test harness.

    Tests all major Gatekeeper components under continuous load:
    - Authentication (HMAC + Bearer)
    - Policy enforcement
    - Rate limiting
    - Token blacklist
    - Nonce tracking
    - Correlation ID propagation
    """

    def __init__(
        self,
        duration_seconds: int = 300,
        workers: int = 4,
        requests_per_second: int = 100,
        max_memory_mb: float | None = None,
        output_dir: Path | None = None,
    ) -> None:
        self.duration = duration_seconds
        self.workers = workers
        self.target_rps = requests_per_second
        self.max_memory_mb = max_memory_mb
        self.output_dir = output_dir or Path("stability_results")
        
        self.metrics = StabilityMetrics()
        self._running = False
        self._lock = threading.Lock()
        
        # Initialize components
        self._setup_components()

    def _setup_components(self) -> None:
        """Initialize all Gatekeeper components."""
        # Key manager with test keys
        self.key_manager = KeyManager()
        self.key_manager.add_hmac_key(
            "stability-test-secret-key-256bits!!",
            key_id="stability-test-key",
        )
        
        # Set up bearer token via env
        os.environ["TEST_BEARER_TOKEN"] = "stability-test-bearer-token"
        self.key_manager.load_bearer_from_env("TEST_BEARER_TOKEN", token_id="test-service")
        
        # Nonce store
        self.nonce_store = InMemoryNonceStore(window_seconds=300)
        
        # Auth engine
        self.auth_engine = AuthenticationEngine(
            key_manager=self.key_manager,
            nonce_store=self.nonce_store,
        )
        
        # Policy engine - use default role permissions
        self.policy_engine = PolicyEngine()
        
        # Rate limiter
        self.rate_limiter = InMemoryRateLimiter(
            limit=1000,
            window_seconds=60,
        )
        
        # Token blacklist
        self.blacklist = InMemoryTokenBlacklist()

    def _get_memory_mb(self) -> float:
        """Get current process memory in MB."""
        if not HAS_PSUTIL:
            return 0.0
        process = psutil.Process(os.getpid())
        return process.memory_info().rss / (1024 * 1024)

    def _record_exception(self, exc: Exception) -> None:
        """Record an exception."""
        with self._lock:
            self.metrics.exceptions += 1
            exc_type = type(exc).__name__
            self.metrics.exception_types[exc_type] = (
                self.metrics.exception_types.get(exc_type, 0) + 1
            )

    def _random_string(self, length: int = 16) -> str:
        """Generate random string."""
        return "".join(random.choices(string.ascii_letters + string.digits, k=length))

    async def _auth_worker(self, worker_id: int) -> None:
        """Worker that performs authentication operations."""
        delay = 1.0 / (self.target_rps / self.workers)
        
        while self._running:
            try:
                start = time.perf_counter()
                
                with correlation_context(f"worker-{worker_id}-{self._random_string(8)}"):
                    # Random operation type
                    op = random.choice(["bearer", "hmac", "policy", "rate", "blacklist"])
                    
                    if op == "bearer":
                        result = self.auth_engine.authenticate(
                            authorization="Bearer stability-test-bearer-token",
                            method="GET",
                            path="/api/test",
                        )
                        with self._lock:
                            self.metrics.total_auth_attempts += 1
                            if result.success:
                                self.metrics.successful_auths += 1
                            else:
                                self.metrics.failed_auths += 1
                    
                    elif op == "hmac":
                        # Invalid HMAC to test failure path
                        result = self.auth_engine.authenticate(
                            authorization=f"HMAC {int(time.time())}:{self._random_string()}:invalid",
                            method="POST",
                            path="/api/data",
                        )
                        with self._lock:
                            self.metrics.total_auth_attempts += 1
                            self.metrics.failed_auths += 1
                    
                    elif op == "policy":
                        user = User(
                            id=f"user-{worker_id}",
                            username=f"worker{worker_id}",
                            roles={"reader"},
                        )
                        self.policy_engine.enforce(user, "read", "/api/data")
                        with self._lock:
                            self.metrics.policy_checks += 1
                    
                    elif op == "rate":
                        info = self.rate_limiter.check(f"ip-{worker_id % 10}")
                        with self._lock:
                            if not info.is_allowed:
                                self.metrics.rate_limit_hits += 1
                    
                    elif op == "blacklist":
                        token = f"token-{self._random_string()}"
                        self.blacklist.revoke(token, reason="test", ttl_seconds=60)
                        self.blacklist.is_revoked(token)
                        with self._lock:
                            self.metrics.blacklist_checks += 1
                
                elapsed_ms = (time.perf_counter() - start) * 1000
                with self._lock:
                    self.metrics.auth_times.append(elapsed_ms)
                    if elapsed_ms > self.metrics.max_auth_time_ms:
                        self.metrics.max_auth_time_ms = elapsed_ms
                
                # Rate limit ourselves
                await asyncio.sleep(delay)
                
            except Exception as e:
                self._record_exception(e)

    async def _memory_monitor(self) -> None:
        """Monitor memory usage periodically."""
        if not HAS_PSUTIL:
            return
            
        self.metrics.initial_memory_mb = self._get_memory_mb()
        self.metrics.peak_memory_mb = self.metrics.initial_memory_mb
        
        while self._running:
            current = self._get_memory_mb()
            timestamp = time.time() - self.metrics.start_time
            
            with self._lock:
                self.metrics.memory_samples.append((timestamp, current))
                if current > self.metrics.peak_memory_mb:
                    self.metrics.peak_memory_mb = current
            
            # Check memory limit
            if self.max_memory_mb and current > self.max_memory_mb:
                print(f"\n❌ MEMORY LIMIT EXCEEDED: {current:.1f}MB > {self.max_memory_mb}MB")
                self._running = False
                return
            
            await asyncio.sleep(5)

    async def _progress_reporter(self) -> None:
        """Report progress periodically."""
        last_report = time.time()
        
        while self._running:
            await asyncio.sleep(10)
            
            elapsed = time.time() - self.metrics.start_time
            remaining = self.duration - elapsed
            
            with self._lock:
                total = self.metrics.total_auth_attempts
                rps = total / max(1, elapsed)
                mem = self._get_memory_mb()
            
            print(
                f"[{elapsed/60:.1f}m] "
                f"ops={total:,} "
                f"rps={rps:.0f} "
                f"mem={mem:.1f}MB "
                f"errors={self.metrics.exceptions} "
                f"remaining={remaining/60:.1f}m"
            )

    async def run(self) -> StabilityMetrics:
        """Run the stability test."""
        print(f"🚀 Starting {self.duration/3600:.1f}h stability test")
        print(f"   Workers: {self.workers}")
        print(f"   Target RPS: {self.target_rps}")
        if self.max_memory_mb:
            print(f"   Max Memory: {self.max_memory_mb}MB")
        print()
        
        self._running = True
        self.metrics.start_time = time.time()
        
        # Start workers
        workers = [
            asyncio.create_task(self._auth_worker(i))
            for i in range(self.workers)
        ]
        
        # Start monitors
        monitors = [
            asyncio.create_task(self._memory_monitor()),
            asyncio.create_task(self._progress_reporter()),
        ]
        
        # Run for duration
        try:
            await asyncio.sleep(self.duration)
        except asyncio.CancelledError:
            pass
        finally:
            self._running = False
            
            # Wait for workers to finish
            for task in workers + monitors:
                task.cancel()
                try:
                    await task
                except asyncio.CancelledError:
                    pass
        
        # Finalize metrics
        self.metrics.end_time = time.time()
        self.metrics.final_memory_mb = self._get_memory_mb()
        
        if self.metrics.auth_times:
            self.metrics.avg_auth_time_ms = (
                sum(self.metrics.auth_times) / len(self.metrics.auth_times)
            )
        
        # Force GC and check for leaks
        gc.collect()
        post_gc_memory = self._get_memory_mb()
        
        return self.metrics

    def save_results(self) -> Path:
        """Save results to file."""
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        result_file = self.output_dir / f"stability_{timestamp}.json"
        
        results = {
            "summary": self.metrics.to_dict(),
            "memory_samples": self.metrics.memory_samples[-1000:],  # Last 1000
            "config": {
                "duration_seconds": self.duration,
                "workers": self.workers,
                "target_rps": self.target_rps,
                "max_memory_mb": self.max_memory_mb,
            },
        }
        
        with open(result_file, "w") as f:
            json.dump(results, f, indent=2)
        
        return result_file

    def print_summary(self) -> bool:
        """Print test summary and return success status."""
        m = self.metrics
        duration = (m.end_time or time.time()) - m.start_time
        
        print("\n" + "=" * 60)
        print("STABILITY TEST RESULTS")
        print("=" * 60)
        
        print(f"\n⏱️  Duration: {duration/3600:.2f} hours ({duration:.0f}s)")
        print(f"📊 Total Operations: {m.total_auth_attempts:,}")
        print(f"⚡ Average RPS: {m.total_auth_attempts/duration:.1f}")
        
        print(f"\n🔐 Authentication:")
        print(f"   Successful: {m.successful_auths:,}")
        print(f"   Failed: {m.failed_auths:,}")
        print(f"   Avg Time: {m.avg_auth_time_ms:.2f}ms")
        print(f"   Max Time: {m.max_auth_time_ms:.2f}ms")
        
        print(f"\n🛡️  Security Components:")
        print(f"   Policy Checks: {m.policy_checks:,}")
        print(f"   Rate Limit Hits: {m.rate_limit_hits:,}")
        print(f"   Blacklist Checks: {m.blacklist_checks:,}")
        
        if HAS_PSUTIL:
            memory_growth = m.final_memory_mb - m.initial_memory_mb
            print(f"\n💾 Memory:")
            print(f"   Initial: {m.initial_memory_mb:.1f}MB")
            print(f"   Peak: {m.peak_memory_mb:.1f}MB")
            print(f"   Final: {m.final_memory_mb:.1f}MB")
            print(f"   Growth: {memory_growth:+.1f}MB")
        
        print(f"\n❌ Errors: {m.exceptions}")
        if m.exception_types:
            for exc_type, count in m.exception_types.items():
                print(f"   {exc_type}: {count}")
        
        # Determine pass/fail
        passed = True
        failures = []
        
        if m.exceptions > 0:
            passed = False
            failures.append(f"{m.exceptions} exceptions occurred")
        
        if HAS_PSUTIL and self.max_memory_mb:
            if m.peak_memory_mb > self.max_memory_mb:
                passed = False
                failures.append(f"Memory exceeded {self.max_memory_mb}MB")
        
        # Check for memory leak (>50% growth is suspicious)
        if HAS_PSUTIL and m.initial_memory_mb > 0:
            growth_pct = (m.final_memory_mb - m.initial_memory_mb) / m.initial_memory_mb
            if growth_pct > 0.5:
                passed = False
                failures.append(f"Possible memory leak: {growth_pct*100:.0f}% growth")
        
        print("\n" + "=" * 60)
        if passed:
            print("✅ STABILITY TEST PASSED")
        else:
            print("❌ STABILITY TEST FAILED")
            for f in failures:
                print(f"   - {f}")
        print("=" * 60)
        
        return passed


async def main() -> int:
    """Main entry point."""
    parser = argparse.ArgumentParser(description="Gatekeeper Stability Test")
    parser.add_argument(
        "--duration",
        type=int,
        default=300,
        help="Test duration in seconds (default: 300 = 5 min)",
    )
    parser.add_argument(
        "--workers",
        type=int,
        default=4,
        help="Number of worker tasks (default: 4)",
    )
    parser.add_argument(
        "--rps",
        type=int,
        default=100,
        help="Target requests per second (default: 100)",
    )
    parser.add_argument(
        "--max-memory-mb",
        type=float,
        default=None,
        help="Max memory threshold in MB (default: no limit)",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path("stability_results"),
        help="Output directory for results",
    )
    
    args = parser.parse_args()
    
    harness = StabilityHarness(
        duration_seconds=args.duration,
        workers=args.workers,
        requests_per_second=args.rps,
        max_memory_mb=args.max_memory_mb,
        output_dir=args.output_dir,
    )
    
    try:
        await harness.run()
    except KeyboardInterrupt:
        print("\n⚠️  Test interrupted by user")
        harness._running = False
    
    result_file = harness.save_results()
    print(f"\n📁 Results saved to: {result_file}")
    
    passed = harness.print_summary()
    return 0 if passed else 1


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
