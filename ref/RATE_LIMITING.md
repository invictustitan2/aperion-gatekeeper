# Rate Limiting Implementation Guide

> Protecting Gatekeeper from brute-force and DoS attacks
> Last Updated: 2026-02-08

## Problem Statement

Without rate limiting, attackers can:
1. **Brute-force HMAC keys** - Try millions of signatures
2. **Credential stuff** - Test stolen credentials at scale
3. **DoS via auth failures** - Exhaust server resources with invalid requests

## Recommended Implementation

### Option 1: slowapi (FastAPI Native)

```python
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.middleware import SlowAPIMiddleware

# Create limiter
limiter = Limiter(
    key_func=get_remote_address,
    default_limits=["100/minute"],
    storage_uri="redis://localhost:6379",  # Distributed tracking
)

# Add to FastAPI
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
app.add_middleware(SlowAPIMiddleware)

# Apply to auth endpoints
@app.post("/auth/login")
@limiter.limit("5/minute")  # Strict for auth
async def login(request: Request, ...):
    ...
```

### Option 2: Redis-Based Custom Limiter

For tighter integration with Gatekeeper:

```python
import redis
from dataclasses import dataclass
from typing import Protocol

@dataclass
class RateLimitConfig:
    requests: int
    window_seconds: int
    
    @property
    def key_suffix(self) -> str:
        return f"{self.requests}_{self.window_seconds}"

class RateLimiter(Protocol):
    def is_allowed(self, key: str) -> bool:
        """Check if request is allowed."""
        ...
    
    def remaining(self, key: str) -> int:
        """Get remaining requests in window."""
        ...

class RedisRateLimiter:
    """Sliding window rate limiter using Redis."""
    
    def __init__(
        self,
        redis_client: redis.Redis,
        config: RateLimitConfig,
        key_prefix: str = "gatekeeper:ratelimit:",
    ):
        self._redis = redis_client
        self._config = config
        self._prefix = key_prefix
    
    def _key(self, identifier: str) -> str:
        return f"{self._prefix}{identifier}:{self._config.key_suffix}"
    
    def is_allowed(self, identifier: str) -> bool:
        """
        Check if request is allowed using sliding window.
        
        Uses Redis INCR with EXPIRE for atomic increment + TTL.
        """
        key = self._key(identifier)
        pipe = self._redis.pipeline()
        
        # Increment counter
        pipe.incr(key)
        # Set expiry (only on first request in window)
        pipe.expire(key, self._config.window_seconds)
        
        results = pipe.execute()
        current_count = results[0]
        
        return current_count <= self._config.requests
    
    def remaining(self, identifier: str) -> int:
        """Get remaining requests in current window."""
        key = self._key(identifier)
        current = self._redis.get(key)
        if current is None:
            return self._config.requests
        return max(0, self._config.requests - int(current))
    
    def reset_time(self, identifier: str) -> int | None:
        """Get seconds until rate limit resets."""
        key = self._key(identifier)
        return self._redis.ttl(key)
```

### Integration with AuthenticationEngine

```python
class AuthenticationEngine:
    def __init__(
        self,
        key_manager: KeyManager,
        *,
        rate_limiter: RateLimiter | None = None,
    ):
        self._key_manager = key_manager
        self._rate_limiter = rate_limiter
    
    def authenticate(
        self,
        authorization: str | None = None,
        *,
        method: str = "GET",
        path: str = "/",
        client_ip: str | None = None,
    ) -> AuthResult:
        # Rate limit check BEFORE any processing
        if self._rate_limiter and client_ip:
            if not self._rate_limiter.is_allowed(client_ip):
                return AuthResult(
                    success=False,
                    error_code=AuthErrorCode.RATE_LIMITED,
                    error_message="Too many authentication attempts",
                )
        
        # Continue with normal auth...
```

## Rate Limit Tiers

| Endpoint Category | Limit | Window | Rationale |
|-------------------|-------|--------|-----------|
| Auth endpoints | 5 | 1 min | Prevent brute-force |
| Token refresh | 10 | 1 min | Allow legitimate refreshes |
| API (authenticated) | 1000 | 1 min | Normal usage |
| API (unauthenticated) | 100 | 1 min | Prevent abuse |

## Response Headers

Include rate limit info in responses:

```python
from fastapi import Response

async def add_rate_limit_headers(
    response: Response,
    limiter: RateLimiter,
    identifier: str,
    config: RateLimitConfig,
):
    response.headers["X-RateLimit-Limit"] = str(config.requests)
    response.headers["X-RateLimit-Remaining"] = str(limiter.remaining(identifier))
    reset_time = limiter.reset_time(identifier)
    if reset_time:
        response.headers["X-RateLimit-Reset"] = str(reset_time)
```

## Handling Rate Limit Exceeded

```python
from fastapi import HTTPException

class RateLimitExceeded(HTTPException):
    def __init__(self, retry_after: int | None = None):
        headers = {}
        if retry_after:
            headers["Retry-After"] = str(retry_after)
        
        super().__init__(
            status_code=429,
            detail="Rate limit exceeded. Please slow down.",
            headers=headers,
        )
```

## Advanced: Per-Principal Rate Limiting

Limit by user, not just IP:

```python
class CompositeRateLimiter:
    """Rate limit by both IP and principal."""
    
    def __init__(
        self,
        ip_limiter: RateLimiter,
        principal_limiter: RateLimiter,
    ):
        self._ip_limiter = ip_limiter
        self._principal_limiter = principal_limiter
    
    def is_allowed(self, ip: str, principal_id: str | None = None) -> bool:
        # Check IP limit
        if not self._ip_limiter.is_allowed(ip):
            return False
        
        # Check principal limit (if authenticated)
        if principal_id:
            if not self._principal_limiter.is_allowed(principal_id):
                return False
        
        return True
```

## Testing

```python
import pytest
from unittest.mock import MagicMock

def test_rate_limiter_allows_within_limit():
    config = RateLimitConfig(requests=5, window_seconds=60)
    mock_redis = MagicMock()
    mock_redis.pipeline.return_value.execute.return_value = [1, True]
    
    limiter = RedisRateLimiter(mock_redis, config)
    
    assert limiter.is_allowed("test-ip") is True

def test_rate_limiter_blocks_over_limit():
    config = RateLimitConfig(requests=5, window_seconds=60)
    mock_redis = MagicMock()
    mock_redis.pipeline.return_value.execute.return_value = [6, True]
    
    limiter = RedisRateLimiter(mock_redis, config)
    
    assert limiter.is_allowed("test-ip") is False

@pytest.mark.integration
def test_rate_limiter_integration():
    """Test with real Redis."""
    redis_client = redis.Redis()
    config = RateLimitConfig(requests=3, window_seconds=10)
    limiter = RedisRateLimiter(redis_client, config, key_prefix="test:ratelimit:")
    
    test_key = f"test_{secrets.token_hex(4)}"
    
    # Should allow first 3
    assert limiter.is_allowed(test_key) is True
    assert limiter.is_allowed(test_key) is True
    assert limiter.is_allowed(test_key) is True
    
    # Should block 4th
    assert limiter.is_allowed(test_key) is False
    
    # Cleanup
    redis_client.delete(f"test:ratelimit:{test_key}:3_10")
```

## References

- [slowapi Documentation](https://github.com/laurentS/slowapi)
- [Redis Rate Limiting Patterns](https://redis.io/commands/incr/#pattern-rate-limiter)
- [OWASP: Blocking Brute Force Attacks](https://owasp.org/www-community/controls/Blocking_Brute_Force_Attacks)
