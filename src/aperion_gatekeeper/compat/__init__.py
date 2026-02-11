"""
Gatekeeper Compatibility Layer.

Provides the exact API surface of the embedded stack.aperion.gatekeeper
module, allowing the monolith to depend on the standalone aperion-gatekeeper
package with zero consumer import changes.

Usage (standalone):
    from aperion_gatekeeper.compat import Principal, TokenService, PolicyEngine

Usage (monolith, via shim):
    from stack.aperion.gatekeeper import Principal, TokenService, PolicyEngine
"""

# Models
from .models import (
    AuthMethod,
    AuthResult,
    KeyValidationResult,
    Permission,
    PolicyDecision,
    Principal,
    Role,
    ROLE_PERMISSIONS,
    TokenInfo,
    check_resource_owner,
    has_permission,
)

# Services
from .tokens import TokenService, TokenStore, NonceManager
from .keys import (
    INSECURE_KEYS,
    INSECURE_PATTERNS,
    KeyManager,
    MIN_KEY_LENGTHS,
    enforce_key_validation,
    validate_security_keys,
)
from .policies import (
    PolicyEngine,
    ResourceOwnerChecker,
    require_admin,
    require_owner_or_admin,
)
from .audit import SecurityAuditor

# Middleware
from .middleware import (
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

__all__ = [
    # Models
    "AuthMethod",
    "AuthResult",
    "KeyValidationResult",
    "Permission",
    "PolicyDecision",
    "Principal",
    "Role",
    "ROLE_PERMISSIONS",
    "TokenInfo",
    "check_resource_owner",
    "has_permission",
    # Token service
    "TokenService",
    "TokenStore",
    "NonceManager",
    # Key management
    "KeyManager",
    "validate_security_keys",
    "enforce_key_validation",
    "INSECURE_PATTERNS",
    "INSECURE_KEYS",
    "MIN_KEY_LENGTHS",
    # Policy engine
    "PolicyEngine",
    "ResourceOwnerChecker",
    "require_admin",
    "require_owner_or_admin",
    # Audit
    "SecurityAuditor",
    # Middleware
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
