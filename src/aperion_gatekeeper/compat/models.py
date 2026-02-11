"""
Gatekeeper Core Models (Compatibility Layer).

Data models for the unified identity and access control system.
These models are the contract between Gatekeeper and all consuming services.

Ported from the embedded stack.aperion.gatekeeper.models module to allow
the monolith to depend on the standalone aperion-gatekeeper package.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class Role(str, Enum):
    """User roles in Aperion."""

    ADMIN = "admin"
    OPERATOR = "operator"
    USER = "user"
    READONLY = "readonly"
    SERVICE = "service"  # For service-to-service auth


class Permission(str, Enum):
    """Permission types for resource access."""

    READ = "read"
    WRITE = "write"
    DELETE = "delete"
    EXECUTE = "execute"
    ADMIN = "admin"


class AuthMethod(str, Enum):
    """Authentication method used."""

    BEARER = "bearer"
    HMAC = "hmac"
    API_KEY = "api_key"
    SERVICE = "service"


# Role permissions matrix - defines what each role can do
ROLE_PERMISSIONS: dict[Role, list[Permission]] = {
    Role.ADMIN: [
        Permission.READ,
        Permission.WRITE,
        Permission.DELETE,
        Permission.EXECUTE,
        Permission.ADMIN,
    ],
    Role.OPERATOR: [
        Permission.READ,
        Permission.WRITE,
        Permission.EXECUTE,
    ],
    Role.USER: [
        Permission.READ,
        Permission.WRITE,
    ],
    Role.READONLY: [
        Permission.READ,
    ],
    Role.SERVICE: [
        Permission.READ,
        Permission.WRITE,
        Permission.EXECUTE,
    ],
}


def has_permission(role: str | Role, permission: Permission) -> bool:
    """
    Check if a role has a specific permission.

    Args:
        role: User role (string or Role enum).
        permission: Required permission.

    Returns:
        True if role has permission.
    """
    try:
        role_enum = Role(role) if isinstance(role, str) else role
        return permission in ROLE_PERMISSIONS.get(role_enum, [])
    except ValueError:
        return False


def check_resource_owner(user_id: str, resource_user_id: str) -> bool:
    """
    Check if user owns a resource.

    Args:
        user_id: Current user ID.
        resource_user_id: Resource owner user ID.

    Returns:
        True if user owns resource.
    """
    return user_id == resource_user_id


@dataclass
class Principal:
    """
    Represents an authenticated identity (user, service, or system).

    This is the core identity object passed through the system after
    successful authentication.
    """

    user_id: str
    roles: list[Role] = field(default_factory=list)
    permissions: list[Permission] = field(default_factory=list)
    scopes: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)
    auth_method: AuthMethod = AuthMethod.BEARER

    def has_role(self, role: Role) -> bool:
        """Check if principal has a specific role."""
        return role in self.roles

    def has_permission(self, permission: Permission) -> bool:
        """Check if principal has a specific permission (direct or via role)."""
        if permission in self.permissions:
            return True
        for role in self.roles:
            if permission in ROLE_PERMISSIONS.get(role, []):
                return True
        return False

    def has_scope(self, scope: str) -> bool:
        """Check if principal has a specific scope."""
        return scope in self.scopes or "*" in self.scopes

    def to_dict(self) -> dict[str, Any]:
        """Serialize principal for logging/transport."""
        auth_method = self.auth_method
        if isinstance(auth_method, AuthMethod):
            auth_method = auth_method.value
        return {
            "user_id": self.user_id,
            "roles": [r.value for r in self.roles],
            "permissions": [p.value for p in self.permissions],
            "scopes": self.scopes,
            "auth_method": auth_method,
        }


@dataclass
class TokenInfo:
    """
    Information about an issued token.

    Returned when a token is successfully issued or validated.
    """

    token: str
    principal: Principal
    issued_at: int = field(default_factory=lambda: int(time.time()))
    expires_at: int = 0
    token_type: str = "Bearer"

    def __post_init__(self) -> None:
        """Set default expiry if not provided."""
        if self.expires_at == 0:
            self.expires_at = self.issued_at + 3600  # 1 hour default

    @property
    def is_expired(self) -> bool:
        """Check if token has expired."""
        return int(time.time()) > self.expires_at

    @property
    def ttl(self) -> int:
        """Remaining time-to-live in seconds."""
        remaining = self.expires_at - int(time.time())
        return max(0, remaining)


@dataclass
class AuthResult:
    """
    Result of an authentication attempt.

    Returned by TokenService.validate_token() and authenticate().
    """

    success: bool
    principal: Principal | None = None
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    auth_method: AuthMethod | None = None

    def to_dict(self) -> dict[str, Any]:
        """Serialize for logging/response."""
        return {
            "success": self.success,
            "principal": self.principal.to_dict() if self.principal else None,
            "errors": self.errors,
            "warnings": self.warnings,
            "auth_method": self.auth_method.value if self.auth_method else None,
        }


@dataclass
class PolicyDecision:
    """
    Result of a policy evaluation.

    Returned by PolicyEngine.can() to indicate whether an action is allowed.
    """

    allowed: bool
    reason: str = ""
    required_permissions: list[Permission] = field(default_factory=list)
    evaluated_at: int = field(default_factory=lambda: int(time.time()))

    def to_dict(self) -> dict[str, Any]:
        """Serialize for logging."""
        return {
            "allowed": self.allowed,
            "reason": self.reason,
            "required_permissions": [p.value for p in self.required_permissions],
        }


@dataclass
class KeyValidationResult:
    """Result of key validation check."""

    valid: bool
    warnings: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Serialize for logging."""
        return {
            "valid": self.valid,
            "warnings": self.warnings,
            "errors": self.errors,
        }
