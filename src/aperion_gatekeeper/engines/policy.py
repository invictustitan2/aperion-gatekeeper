"""
Policy Engine for Aperion Gatekeeper.

The "Can you do this?" logic - RBAC enforcement with default deny.
Evaluates subject permissions against resource policies.

Zero-trust: If no explicit rule grants access, deny.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable

from aperion_gatekeeper.core.identity import Subject


class Role(str, Enum):
    """Built-in roles for Aperion ecosystem."""

    ADMIN = "admin"
    USER = "user"
    READONLY = "readonly"
    AGENT = "agent"
    SERVICE = "service"
    SYSTEM = "system"


class Permission(str, Enum):
    """Permission types."""

    READ = "read"
    WRITE = "write"
    DELETE = "delete"
    EXECUTE = "execute"
    ADMIN = "admin"


# Default role-permission matrix
DEFAULT_ROLE_PERMISSIONS: dict[str, frozenset[Permission]] = {
    Role.ADMIN.value: frozenset(Permission),  # All permissions
    Role.USER.value: frozenset({Permission.READ, Permission.WRITE}),
    Role.READONLY.value: frozenset({Permission.READ}),
    Role.AGENT.value: frozenset({Permission.READ, Permission.EXECUTE}),
    Role.SERVICE.value: frozenset({Permission.READ, Permission.WRITE, Permission.EXECUTE}),
    Role.SYSTEM.value: frozenset(Permission),  # All permissions
}


@dataclass
class PolicyDecision:
    """
    Result of a policy evaluation.

    Contains the decision and reasoning for audit purposes.
    """

    allowed: bool
    reason: str
    policy_matched: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class ResourcePolicy:
    """
    Policy rule for a specific resource pattern.

    Defines what roles/subjects can perform what actions on matching resources.
    """

    resource_pattern: str  # Glob pattern, e.g., "/api/users/*"
    allowed_roles: frozenset[str]
    allowed_permissions: frozenset[Permission]
    deny_roles: frozenset[str] = field(default_factory=frozenset)
    conditions: list[Callable[[Subject, str], bool]] = field(default_factory=list)
    description: str = ""

    def matches_resource(self, resource: str) -> bool:
        """Check if resource matches this policy's pattern."""
        # Simple glob matching
        pattern = self.resource_pattern

        if pattern == "*":
            return True

        if pattern.endswith("*"):
            prefix = pattern[:-1]
            return resource.startswith(prefix)

        if pattern.startswith("*"):
            suffix = pattern[1:]
            return resource.endswith(suffix)

        return resource == pattern


class PolicyEngine:
    """
    RBAC Policy Enforcement Engine.

    Evaluates whether a subject can perform an action on a resource.
    Default behavior: DENY unless explicitly allowed.

    Usage:
        engine = PolicyEngine()

        # Add policies
        engine.add_policy(ResourcePolicy(
            resource_pattern="/api/admin/*",
            allowed_roles=frozenset({"admin"}),
            allowed_permissions=frozenset(Permission),
        ))

        # Enforce
        if engine.enforce(subject, "write", "/api/admin/users"):
            # Allow action
        else:
            # Deny action
    """

    def __init__(
        self,
        *,
        role_permissions: dict[str, frozenset[Permission]] | None = None,
        default_deny: bool = True,
    ) -> None:
        """
        Initialize policy engine.

        Args:
            role_permissions: Custom role-permission matrix (uses default if None)
            default_deny: Whether to deny if no policy matches (should be True)
        """
        self._role_permissions = role_permissions or DEFAULT_ROLE_PERMISSIONS.copy()
        self._default_deny = default_deny
        self._policies: list[ResourcePolicy] = []

    def add_policy(self, policy: ResourcePolicy) -> None:
        """
        Add a resource policy.

        Args:
            policy: Policy to add
        """
        self._policies.append(policy)

    def remove_policy(self, resource_pattern: str) -> bool:
        """
        Remove policies matching a resource pattern.

        Args:
            resource_pattern: Pattern to remove

        Returns:
            True if any policies were removed
        """
        original_count = len(self._policies)
        self._policies = [
            p for p in self._policies if p.resource_pattern != resource_pattern
        ]
        return len(self._policies) < original_count

    def enforce(
        self,
        subject: Subject,
        permission: str | Permission,
        resource: str,
    ) -> bool:
        """
        Enforce access control.

        The main entry point for authorization decisions.

        Args:
            subject: Authenticated subject attempting access
            permission: Required permission (e.g., "read", "write")
            resource: Resource being accessed (e.g., "/api/users/123")

        Returns:
            True if access is allowed, False otherwise
        """
        decision = self.evaluate(subject, permission, resource)
        return decision.allowed

    def evaluate(
        self,
        subject: Subject,
        permission: str | Permission,
        resource: str,
    ) -> PolicyDecision:
        """
        Evaluate policy with full decision details.

        Use this when you need the reason for the decision (e.g., for audit logging).

        Args:
            subject: Authenticated subject
            permission: Required permission
            resource: Resource being accessed

        Returns:
            PolicyDecision with allow/deny and reasoning
        """
        # Convert string permission to enum if needed
        if isinstance(permission, str):
            try:
                perm = Permission(permission)
            except ValueError:
                return PolicyDecision(
                    allowed=False,
                    reason=f"Unknown permission: {permission}",
                )
        else:
            perm = permission

        # Check authentication
        if not subject.is_authenticated:
            return PolicyDecision(
                allowed=False,
                reason="Subject is not authenticated",
            )

        # Check explicit resource policies first (most specific)
        for policy in self._policies:
            if not policy.matches_resource(resource):
                continue

            # Check deny list first (deny takes precedence)
            if subject.roles & policy.deny_roles:
                return PolicyDecision(
                    allowed=False,
                    reason=f"Role explicitly denied by policy: {policy.resource_pattern}",
                    policy_matched=policy.resource_pattern,
                )

            # Check if any subject role is allowed
            matching_roles = subject.roles & policy.allowed_roles

            if matching_roles and perm in policy.allowed_permissions:
                # Check additional conditions
                if policy.conditions:
                    for condition in policy.conditions:
                        if not condition(subject, resource):
                            return PolicyDecision(
                                allowed=False,
                                reason="Policy condition not satisfied",
                                policy_matched=policy.resource_pattern,
                            )

                return PolicyDecision(
                    allowed=True,
                    reason=f"Allowed by policy: {policy.resource_pattern}",
                    policy_matched=policy.resource_pattern,
                    metadata={"matching_roles": list(matching_roles)},
                )

        # Fall back to role-based permissions (less specific)
        for role in subject.roles:
            role_perms = self._role_permissions.get(role, frozenset())
            if perm in role_perms:
                return PolicyDecision(
                    allowed=True,
                    reason=f"Allowed by role permission: {role}",
                    metadata={"role": role},
                )

        # Default deny
        if self._default_deny:
            return PolicyDecision(
                allowed=False,
                reason="No matching policy and default deny is enabled",
            )

        return PolicyDecision(
            allowed=True,
            reason="No matching policy and default deny is disabled (INSECURE)",
        )

    def has_role_permission(self, role: str, permission: Permission) -> bool:
        """
        Check if a role has a specific permission.

        Args:
            role: Role name
            permission: Permission to check

        Returns:
            True if role has the permission
        """
        role_perms = self._role_permissions.get(role, frozenset())
        return permission in role_perms

    def grant_role_permission(self, role: str, permission: Permission) -> None:
        """
        Grant a permission to a role.

        Args:
            role: Role name
            permission: Permission to grant
        """
        current = self._role_permissions.get(role, frozenset())
        self._role_permissions[role] = current | {permission}

    def revoke_role_permission(self, role: str, permission: Permission) -> None:
        """
        Revoke a permission from a role.

        Args:
            role: Role name
            permission: Permission to revoke
        """
        current = self._role_permissions.get(role, frozenset())
        self._role_permissions[role] = current - {permission}

    def get_role_permissions(self, role: str) -> frozenset[Permission]:
        """
        Get all permissions for a role.

        Args:
            role: Role name

        Returns:
            Set of permissions
        """
        return self._role_permissions.get(role, frozenset())

    def list_policies(self) -> list[dict[str, Any]]:
        """
        List all policies (for debugging/admin).

        Returns:
            List of policy summaries
        """
        return [
            {
                "resource_pattern": p.resource_pattern,
                "allowed_roles": list(p.allowed_roles),
                "allowed_permissions": [perm.value for perm in p.allowed_permissions],
                "deny_roles": list(p.deny_roles),
                "description": p.description,
            }
            for p in self._policies
        ]
