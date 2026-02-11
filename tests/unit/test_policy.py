"""Unit tests for policy engine."""

import pytest

from aperion_gatekeeper.core.identity import Agent, User
from aperion_gatekeeper.engines.policy import (
    DEFAULT_ROLE_PERMISSIONS,
    Permission,
    PolicyEngine,
    ResourcePolicy,
    Role,
)


class TestPolicyEngine:
    """Tests for PolicyEngine."""

    @pytest.fixture
    def engine(self) -> PolicyEngine:
        """Create policy engine."""
        return PolicyEngine()

    @pytest.fixture
    def admin_user(self) -> User:
        """Create admin user."""
        return User(
            id="admin-1",
            username="admin",
            roles=frozenset({"admin"}),
        )

    @pytest.fixture
    def regular_user(self) -> User:
        """Create regular user."""
        return User(
            id="user-1",
            username="user",
            roles=frozenset({"user"}),
        )

    @pytest.fixture
    def readonly_user(self) -> User:
        """Create readonly user."""
        return User(
            id="readonly-1",
            username="viewer",
            roles=frozenset({"readonly"}),
        )

    def test_default_role_permissions(self) -> None:
        """Default role permissions are set correctly."""
        assert Permission.ADMIN in DEFAULT_ROLE_PERMISSIONS[Role.ADMIN.value]
        assert Permission.READ in DEFAULT_ROLE_PERMISSIONS[Role.USER.value]
        assert Permission.WRITE in DEFAULT_ROLE_PERMISSIONS[Role.USER.value]
        assert Permission.DELETE not in DEFAULT_ROLE_PERMISSIONS[Role.USER.value]
        assert Permission.READ in DEFAULT_ROLE_PERMISSIONS[Role.READONLY.value]
        assert Permission.WRITE not in DEFAULT_ROLE_PERMISSIONS[Role.READONLY.value]

    def test_admin_has_all_permissions(
        self, engine: PolicyEngine, admin_user: User
    ) -> None:
        """Admin role has all permissions."""
        assert engine.enforce(admin_user, "read", "/any/resource") is True
        assert engine.enforce(admin_user, "write", "/any/resource") is True
        assert engine.enforce(admin_user, "delete", "/any/resource") is True
        assert engine.enforce(admin_user, "admin", "/any/resource") is True

    def test_user_has_read_write(
        self, engine: PolicyEngine, regular_user: User
    ) -> None:
        """Regular user has read and write but not delete."""
        assert engine.enforce(regular_user, "read", "/data") is True
        assert engine.enforce(regular_user, "write", "/data") is True
        assert engine.enforce(regular_user, "delete", "/data") is False
        assert engine.enforce(regular_user, "admin", "/data") is False

    def test_readonly_only_reads(
        self, engine: PolicyEngine, readonly_user: User
    ) -> None:
        """Readonly user can only read."""
        assert engine.enforce(readonly_user, "read", "/data") is True
        assert engine.enforce(readonly_user, "write", "/data") is False
        assert engine.enforce(readonly_user, "delete", "/data") is False

    def test_unauthenticated_denied(self, engine: PolicyEngine) -> None:
        """Unauthenticated subjects are denied."""
        from aperion_gatekeeper.core.identity import ANONYMOUS

        assert engine.enforce(ANONYMOUS, "read", "/public") is False

    def test_unknown_permission_denied(
        self, engine: PolicyEngine, admin_user: User
    ) -> None:
        """Unknown permissions are denied."""
        assert engine.enforce(admin_user, "fly", "/anywhere") is False

    def test_resource_policy_allows(
        self, engine: PolicyEngine, regular_user: User
    ) -> None:
        """Resource policies can grant specific permissions."""
        # Add policy allowing delete for /user-data/*
        engine.add_policy(
            ResourcePolicy(
                resource_pattern="/user-data/*",
                allowed_roles=frozenset({"user"}),
                allowed_permissions=frozenset({Permission.DELETE}),
            )
        )

        # User can now delete their data
        assert engine.enforce(regular_user, "delete", "/user-data/123") is True
        # But not other resources
        assert engine.enforce(regular_user, "delete", "/other/123") is False

    def test_resource_policy_denies(
        self, engine: PolicyEngine, admin_user: User
    ) -> None:
        """Resource policies can explicitly deny roles."""
        # Add policy denying admin from /audit/*
        engine.add_policy(
            ResourcePolicy(
                resource_pattern="/audit/*",
                allowed_roles=frozenset({"system"}),
                allowed_permissions=frozenset(Permission),
                deny_roles=frozenset({"admin"}),
            )
        )

        # Admin is explicitly denied
        assert engine.enforce(admin_user, "read", "/audit/logs") is False

    def test_evaluate_returns_decision(
        self, engine: PolicyEngine, regular_user: User
    ) -> None:
        """Evaluate returns PolicyDecision with details."""
        decision = engine.evaluate(regular_user, "read", "/data")

        assert decision.allowed is True
        assert decision.reason is not None
        assert "role" in decision.reason.lower() or "allowed" in decision.reason.lower()

    def test_evaluate_denied_has_reason(
        self, engine: PolicyEngine, regular_user: User
    ) -> None:
        """Denied decisions have clear reasons."""
        decision = engine.evaluate(regular_user, "admin", "/system")

        assert decision.allowed is False
        assert decision.reason is not None

    def test_default_deny_is_true(self) -> None:
        """Default deny is enforced by default."""
        engine = PolicyEngine(default_deny=True)
        user_no_roles = User(
            id="norole", username="norole", roles=frozenset({"unknown_role"})
        )

        assert engine.enforce(user_no_roles, "read", "/anything") is False

    def test_grant_revoke_role_permission(self, engine: PolicyEngine) -> None:
        """Can grant and revoke role permissions."""
        # Readonly can't write by default
        assert engine.has_role_permission("readonly", Permission.WRITE) is False

        # Grant write
        engine.grant_role_permission("readonly", Permission.WRITE)
        assert engine.has_role_permission("readonly", Permission.WRITE) is True

        # Revoke write
        engine.revoke_role_permission("readonly", Permission.WRITE)
        assert engine.has_role_permission("readonly", Permission.WRITE) is False

    def test_remove_policy(self, engine: PolicyEngine) -> None:
        """Can remove policies."""
        engine.add_policy(
            ResourcePolicy(
                resource_pattern="/test/*",
                allowed_roles=frozenset({"user"}),
                allowed_permissions=frozenset({Permission.READ}),
            )
        )

        assert len(engine.list_policies()) == 1

        engine.remove_policy("/test/*")

        assert len(engine.list_policies()) == 0

    def test_list_policies(self, engine: PolicyEngine) -> None:
        """Can list all policies."""
        engine.add_policy(
            ResourcePolicy(
                resource_pattern="/api/*",
                allowed_roles=frozenset({"user", "admin"}),
                allowed_permissions=frozenset({Permission.READ}),
                description="API access",
            )
        )

        policies = engine.list_policies()

        assert len(policies) == 1
        assert policies[0]["resource_pattern"] == "/api/*"
        assert policies[0]["description"] == "API access"

    def test_agent_has_execute_permission(self, engine: PolicyEngine) -> None:
        """Agents have execute permission by default."""
        agent = Agent(
            id="agent-1",
            service_name="test-service",
            roles=frozenset({"agent"}),
        )

        assert engine.enforce(agent, "read", "/data") is True
        assert engine.enforce(agent, "execute", "/task") is True
        assert engine.enforce(agent, "write", "/data") is False

    def test_policy_conditions(
        self, engine: PolicyEngine, regular_user: User
    ) -> None:
        """Policy conditions are evaluated."""

        def is_owner(subject, resource):
            # Simple check: resource contains user ID
            return subject.principal_id in resource

        engine.add_policy(
            ResourcePolicy(
                resource_pattern="/users/*",
                allowed_roles=frozenset({"user"}),
                allowed_permissions=frozenset({Permission.DELETE}),
                conditions=[is_owner],
            )
        )

        # User can delete their own resource
        assert engine.enforce(regular_user, "delete", "/users/user-1/data") is True
        # But not others
        assert engine.enforce(regular_user, "delete", "/users/other/data") is False
