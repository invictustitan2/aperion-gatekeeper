"""
Aperion Gatekeeper - Unified Authentication & Authorization.

The Immune System of the Aperion Ecosystem.
Enforces Constitution B (Safety & Security) with zero-trust principles.
"""

from aperion_gatekeeper.core.identity import Agent, Subject, SubjectType, User
from aperion_gatekeeper.core.credentials import Credential, HMACKey, KeyManager, TokenCredential
from aperion_gatekeeper.core.correlation import (
    CorrelatedLogger,
    CorrelationHeaders,
    correlation_context,
    generate_correlation_id,
    get_correlation_id,
    get_or_create_correlation_id,
    get_trace_context,
    set_correlation_id,
)
from aperion_gatekeeper.engines.authentication import AuthenticationEngine, AuthResult
from aperion_gatekeeper.engines.policy import Permission, PolicyEngine, Role
from aperion_gatekeeper.engines.nonce_store import (
    InMemoryNonceStore,
    NonceStore,
    NullNonceStore,
    RedisNonceStore,
)
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

# Compatibility layer — provides the embedded stack.aperion.gatekeeper API
# so the monolith can depend on this standalone package.
# Non-conflicting symbols are exported directly; conflicting ones use aliases.
from aperion_gatekeeper.compat.models import (
    Principal,
    TokenInfo,
    AuthMethod,
    ROLE_PERMISSIONS,
    KeyValidationResult,
    PolicyDecision,
)
from aperion_gatekeeper.compat.models import (
    Role as CompatRole,
    Permission as CompatPermission,
    AuthResult as CompatAuthResult,
)
from aperion_gatekeeper.compat.tokens import TokenService, TokenStore
from aperion_gatekeeper.compat.tokens import NonceManager as CompatNonceManager
from aperion_gatekeeper.compat.keys import (
    KeyManager as CompatKeyManager,
    validate_security_keys,
)
from aperion_gatekeeper.compat.policies import (
    PolicyEngine as CompatPolicyEngine,
    require_admin,
    require_owner_or_admin,
)
from aperion_gatekeeper.compat.audit import SecurityAuditor
from aperion_gatekeeper.compat.middleware import (
    AuthenticatedPrincipal,
    GatekeeperMiddleware,
    configure_gatekeeper,
    get_auditor,
    get_policy_engine,
    get_token_service,
    require_action,
    require_auth,
    require_permission,
    require_role,
)

__version__ = "0.1.0"

__all__ = [
    # Identity
    "Subject",
    "SubjectType",
    "User",
    "Agent",
    # Credentials
    "Credential",
    "HMACKey",
    "TokenCredential",
    "KeyManager",
    # Authentication
    "AuthenticationEngine",
    "AuthResult",
    # Authorization
    "PolicyEngine",
    "Role",
    "Permission",
    # Correlation
    "correlation_context",
    "get_correlation_id",
    "set_correlation_id",
    "get_or_create_correlation_id",
    "generate_correlation_id",
    "get_trace_context",
    "CorrelationHeaders",
    "CorrelatedLogger",
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
    # Compat layer — embedded API surface
    "Principal",
    "TokenInfo",
    "AuthMethod",
    "ROLE_PERMISSIONS",
    "KeyValidationResult",
    "PolicyDecision",
    "CompatRole",
    "CompatPermission",
    "CompatAuthResult",
    "TokenService",
    "TokenStore",
    "CompatNonceManager",
    "CompatKeyManager",
    "validate_security_keys",
    "CompatPolicyEngine",
    "require_admin",
    "require_owner_or_admin",
    "SecurityAuditor",
    "AuthenticatedPrincipal",
    "GatekeeperMiddleware",
    "configure_gatekeeper",
    "get_auditor",
    "get_policy_engine",
    "get_token_service",
    "require_action",
    "require_auth",
    "require_permission",
    "require_role",
]
