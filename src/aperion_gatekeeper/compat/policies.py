"""
Policy Engine for The Gatekeeper (Compatibility Layer).

Centralized authorization logic using Role-Based Access Control (RBAC)
with support for resource-level policies.

Ported from the embedded stack.aperion.gatekeeper.policies module.
"""

from __future__ import annotations

from typing import Any, Callable

from .models import (
    Permission,
    PolicyDecision,
    Principal,
    Role,
    ROLE_PERMISSIONS,
)


# Type alias for resource ownership checker
ResourceOwnerChecker = Callable[[Principal, str], bool]


class PolicyEngine:
    """
    Centralized policy engine for authorization decisions.

    Evaluates whether a principal can perform an action on a resource
    based on roles, permissions, and resource-level policies.
    """

    def __init__(self) -> None:
        """Initialize policy engine."""
        self._resource_policies: dict[str, ResourceOwnerChecker] = {}
        self._action_permissions: dict[str, list[Permission]] = {
            # File operations
            "fs:read": [Permission.READ],
            "fs:write": [Permission.WRITE],
            "fs:delete": [Permission.DELETE],
            "fs:list": [Permission.READ],
            # Agent operations
            "agent:execute": [Permission.EXECUTE],
            "agent:list": [Permission.READ],
            "agent:create": [Permission.WRITE, Permission.ADMIN],
            "agent:delete": [Permission.DELETE, Permission.ADMIN],
            # Chat operations
            "chat:send": [Permission.EXECUTE],
            "chat:read": [Permission.READ],
            # Admin operations
            "admin:users": [Permission.ADMIN],
            "admin:config": [Permission.ADMIN],
            "admin:audit": [Permission.ADMIN],
            # State Gateway operations (The Cortex)
            "state:context": [Permission.READ],
            "state:vector": [Permission.READ],
            "state:database": [Permission.READ],
            "state:services": [Permission.READ],
            "state:admin": [Permission.ADMIN],
        }

    def register_action(
        self,
        action: str,
        required_permissions: list[Permission],
    ) -> None:
        """
        Register a custom action with its required permissions.

        Args:
            action: Action identifier (e.g., "custom:operation").
            required_permissions: Permissions required for this action.
        """
        self._action_permissions[action] = required_permissions

    def register_resource_policy(
        self,
        resource_type: str,
        checker: ResourceOwnerChecker,
    ) -> None:
        """
        Register a resource ownership checker.

        Args:
            resource_type: Resource type (e.g., "file", "agent").
            checker: Function that checks if principal owns resource.
        """
        self._resource_policies[resource_type] = checker

    def can(
        self,
        principal: Principal,
        action: str | Permission,
        resource: str | None = None,
    ) -> PolicyDecision:
        """
        Check if principal can perform action on resource.

        Args:
            principal: The authenticated identity.
            action: Action to perform (Permission enum or action string).
            resource: Optional resource identifier.

        Returns:
            PolicyDecision indicating if action is allowed.
        """
        # Handle Permission enum directly
        if isinstance(action, Permission):
            if principal.has_permission(action):
                return PolicyDecision(
                    allowed=True,
                    reason="Permission granted via role",
                    required_permissions=[action],
                )
            return PolicyDecision(
                allowed=False,
                reason=f"Missing permission: {action.value}",
                required_permissions=[action],
            )

        # Look up action requirements
        required = self._action_permissions.get(action)
        if not required:
            # Unknown action - deny by default
            return PolicyDecision(
                allowed=False,
                reason=f"Unknown action: {action}",
            )

        # Check if principal has any of the required permissions
        has_permission = any(principal.has_permission(p) for p in required)
        if not has_permission:
            return PolicyDecision(
                allowed=False,
                reason=f"Missing required permissions for {action}",
                required_permissions=required,
            )

        # Check resource-level policy if resource specified
        if resource:
            decision = self._check_resource_policy(principal, action, resource)
            if decision is not None:
                return decision

        return PolicyDecision(
            allowed=True,
            reason="Permission granted",
            required_permissions=required,
        )

    def _check_resource_policy(
        self,
        principal: Principal,
        action: str,
        resource: str,
    ) -> PolicyDecision | None:
        """
        Check resource-level policy.

        Returns PolicyDecision if resource policy applies, None otherwise.
        """
        # Extract resource type from action or resource path
        resource_type = action.split(":")[0] if ":" in action else None
        if not resource_type:
            return None

        checker = self._resource_policies.get(resource_type)
        if not checker:
            return None  # No resource policy, allow based on permissions

        if not checker(principal, resource):
            return PolicyDecision(
                allowed=False,
                reason=f"Access denied to resource: {resource}",
            )

        return None  # Resource check passed

    def get_permissions(self, principal: Principal) -> list[Permission]:
        """
        Get all effective permissions for a principal.

        Args:
            principal: The authenticated identity.

        Returns:
            List of all permissions (direct + role-based).
        """
        permissions = set(principal.permissions)
        for role in principal.roles:
            role_perms = ROLE_PERMISSIONS.get(role, [])
            permissions.update(role_perms)
        return list(permissions)

    def get_allowed_actions(self, principal: Principal) -> list[str]:
        """
        Get all actions a principal is allowed to perform.

        Args:
            principal: The authenticated identity.

        Returns:
            List of allowed action strings.
        """
        allowed = []
        for action, required in self._action_permissions.items():
            if any(principal.has_permission(p) for p in required):
                allowed.append(action)
        return allowed

    def get_stats(self) -> dict[str, Any]:
        """Get policy engine statistics."""
        return {
            "registered_actions": len(self._action_permissions),
            "resource_policies": len(self._resource_policies),
            "actions": list(self._action_permissions.keys()),
        }


# Convenience functions for common patterns


def require_admin(principal: Principal) -> PolicyDecision:
    """Check if principal has admin role."""
    if principal.has_role(Role.ADMIN):
        return PolicyDecision(allowed=True, reason="Admin access granted")
    return PolicyDecision(
        allowed=False,
        reason="Admin role required",
        required_permissions=[Permission.ADMIN],
    )


def require_owner_or_admin(
    principal: Principal,
    resource_owner_id: str,
) -> PolicyDecision:
    """Check if principal owns resource or is admin."""
    if principal.has_role(Role.ADMIN):
        return PolicyDecision(allowed=True, reason="Admin access granted")
    if principal.user_id == resource_owner_id:
        return PolicyDecision(allowed=True, reason="Owner access granted")
    return PolicyDecision(
        allowed=False,
        reason="Must be resource owner or admin",
    )
