"""Authentication and Policy Engines."""

from aperion_gatekeeper.engines.authentication import AuthenticationEngine, AuthResult
from aperion_gatekeeper.engines.nonce_store import (
    InMemoryNonceStore,
    NonceStore,
    NullNonceStore,
    RedisNonceStore,
)
from aperion_gatekeeper.engines.policy import Permission, PolicyEngine, Role
from aperion_gatekeeper.engines.rate_limiter import (
    CompositeRateLimiter,
    InMemoryRateLimiter,
    NullRateLimiter,
    RateLimiter,
    RateLimitInfo,
    RateLimitResult,
    RedisRateLimiter,
)
from aperion_gatekeeper.engines.token_blacklist import (
    BlacklistEntry,
    InMemoryTokenBlacklist,
    NullTokenBlacklist,
    RedisTokenBlacklist,
    TokenBlacklist,
)

__all__ = [
    "AuthenticationEngine",
    "AuthResult",
    "PolicyEngine",
    "Role",
    "Permission",
    # Nonce stores
    "NonceStore",
    "InMemoryNonceStore",
    "RedisNonceStore",
    "NullNonceStore",
    # Rate limiting
    "RateLimiter",
    "RateLimitInfo",
    "RateLimitResult",
    "InMemoryRateLimiter",
    "RedisRateLimiter",
    "NullRateLimiter",
    "CompositeRateLimiter",
    # Token blacklist
    "TokenBlacklist",
    "BlacklistEntry",
    "InMemoryTokenBlacklist",
    "RedisTokenBlacklist",
    "NullTokenBlacklist",
]
