# Distributed Nonce Tracking with Redis

> For preventing replay attacks in distributed deployments
> Last Updated: 2026-02-08

## Problem Statement

The current `NonceTracker` uses in-memory storage:

```python
class NonceTracker:
    def __init__(self):
        self._used: dict[str, float] = {}  # PROBLEM: Instance-local!
```

In a distributed deployment with multiple API servers, this allows replay attacks:

```
Attacker → Server A (nonce stored in A's memory)
Attacker → Server B (nonce NOT in B's memory) → REPLAY SUCCEEDS!
```

## Solution: Redis-Backed Nonce Tracker

### Implementation

```python
import redis
from typing import Protocol

class NonceStore(Protocol):
    """Protocol for nonce storage backends."""
    
    def mark_used(self, nonce: str, ttl_seconds: int) -> bool:
        """Mark nonce as used. Returns True if newly marked, False if already used."""
        ...
    
    def is_used(self, nonce: str) -> bool:
        """Check if nonce was already used."""
        ...


class RedisNonceStore:
    """Production-ready nonce tracking with Redis."""
    
    def __init__(
        self,
        redis_client: redis.Redis,
        *,
        key_prefix: str = "gatekeeper:nonce:",
    ):
        self._redis = redis_client
        self._prefix = key_prefix
    
    def _key(self, nonce: str) -> str:
        return f"{self._prefix}{nonce}"
    
    def mark_used(self, nonce: str, ttl_seconds: int) -> bool:
        """
        Atomically mark nonce as used.
        
        Uses SET with NX (only if not exists) and EX (expire).
        This is atomic and race-condition safe.
        
        Returns:
            True if nonce was newly marked (not a replay)
            False if nonce already existed (replay detected)
        """
        result = self._redis.set(
            self._key(nonce),
            "1",
            nx=True,  # Only set if not exists
            ex=ttl_seconds,  # Expire after TTL
        )
        return result is not None
    
    def is_used(self, nonce: str) -> bool:
        """Check if nonce was already used."""
        return self._redis.exists(self._key(nonce)) > 0


class InMemoryNonceStore:
    """In-memory nonce tracking for development/testing only."""
    
    def __init__(self):
        self._used: dict[str, float] = {}
        self._lock = threading.Lock()
    
    def mark_used(self, nonce: str, ttl_seconds: int) -> bool:
        with self._lock:
            if nonce in self._used:
                return False
            self._used[nonce] = time.time() + ttl_seconds
            self._cleanup()
            return True
    
    def is_used(self, nonce: str) -> bool:
        with self._lock:
            return nonce in self._used
    
    def _cleanup(self):
        now = time.time()
        self._used = {k: v for k, v in self._used.items() if v > now}
```

### Integration with AuthenticationEngine

```python
class AuthenticationEngine:
    def __init__(
        self,
        key_manager: KeyManager,
        *,
        nonce_store: NonceStore | None = None,  # NEW: Inject store
        timestamp_skew: int = 300,
    ):
        self._key_manager = key_manager
        self._nonce_store = nonce_store or InMemoryNonceStore()
        self._timestamp_skew = timestamp_skew
    
    def _check_replay(self, nonce: str, timestamp: int) -> bool:
        """Returns True if replay, False if OK."""
        ttl = self._timestamp_skew * 2  # Track for 2x skew window
        return not self._nonce_store.mark_used(nonce, ttl)
```

### Redis Configuration

```python
# Production configuration
import redis

redis_client = redis.Redis(
    host=os.environ.get("REDIS_HOST", "localhost"),
    port=int(os.environ.get("REDIS_PORT", 6379)),
    db=int(os.environ.get("REDIS_DB", 0)),
    password=os.environ.get("REDIS_PASSWORD"),
    decode_responses=True,
    socket_timeout=5,
    socket_connect_timeout=5,
    retry_on_timeout=True,
)

nonce_store = RedisNonceStore(redis_client)
auth_engine = AuthenticationEngine(key_manager, nonce_store=nonce_store)
```

## TTL Calculation

The nonce TTL should be **at least 2x the timestamp skew**:

| Timestamp Skew | Nonce TTL | Reason |
|----------------|-----------|--------|
| 300s (5 min) | 600s (10 min) | Cover both past and future skew |
| 60s (1 min) | 120s (2 min) | Tighter for high-security |

## Redis Memory Considerations

### Sizing:
- Each nonce key: ~50 bytes (prefix + nonce)
- At 1000 requests/second, 10-minute window: ~600,000 keys
- Memory: ~30MB

### Recommendations:
- Use Redis Cluster for high availability
- Set `maxmemory-policy allkeys-lru` as fallback
- Monitor key count: `redis-cli dbsize`

## Testing

```python
import pytest
from unittest.mock import MagicMock

def test_redis_nonce_replay_detection():
    """Verify nonce replay is detected across calls."""
    mock_redis = MagicMock()
    
    # First call: SET succeeds (returns True)
    mock_redis.set.return_value = True
    store = RedisNonceStore(mock_redis)
    
    assert store.mark_used("nonce123", 600) is True
    
    # Second call: SET fails (returns None - key exists)
    mock_redis.set.return_value = None
    
    assert store.mark_used("nonce123", 600) is False


@pytest.mark.integration
def test_redis_nonce_integration():
    """Integration test with real Redis."""
    redis_client = redis.Redis(host="localhost", port=6379)
    store = RedisNonceStore(redis_client, key_prefix="test:nonce:")
    
    # Unique nonce for this test
    nonce = f"test_{secrets.token_hex(8)}"
    
    assert store.mark_used(nonce, 10) is True
    assert store.mark_used(nonce, 10) is False  # Replay!
    
    # Cleanup
    redis_client.delete(f"test:nonce:{nonce}")
```

## Fallback Strategy

If Redis is unavailable:

```python
class FallbackNonceStore:
    """Falls back to in-memory if Redis fails."""
    
    def __init__(self, primary: RedisNonceStore, fallback: InMemoryNonceStore):
        self._primary = primary
        self._fallback = fallback
        self._using_fallback = False
    
    def mark_used(self, nonce: str, ttl: int) -> bool:
        if self._using_fallback:
            return self._fallback.mark_used(nonce, ttl)
        
        try:
            return self._primary.mark_used(nonce, ttl)
        except redis.RedisError:
            self._using_fallback = True
            logger.warning("Redis unavailable, using in-memory nonce tracking")
            return self._fallback.mark_used(nonce, ttl)
```

**⚠️ Security Note:** Fallback mode reduces security. Consider failing closed instead:

```python
def mark_used(self, nonce: str, ttl: int) -> bool:
    try:
        return self._primary.mark_used(nonce, ttl)
    except redis.RedisError:
        logger.error("Redis unavailable, rejecting all requests")
        return False  # Fail closed - treat as replay
```

## References

- [Redis SET documentation](https://redis.io/commands/set/)
- [Protecting API Requests with Nonce and Redis](https://dev.to/raselmahmuddev/protecting-api-requests-using-nonce-redis-and-time-based-validation-11nd)
- [HMAC + Timestamp + Nonce Pattern](https://thomasrones.com/technical/system-design/hmac-timestamp-nonce/)
