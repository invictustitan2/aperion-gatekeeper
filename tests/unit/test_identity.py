"""Unit tests for identity models."""

import pytest

from aperion_gatekeeper.core.identity import (
    ANONYMOUS,
    Agent,
    AnonymousSubject,
    Subject,
    SubjectType,
    User,
)


class TestUser:
    """Tests for User model."""

    def test_user_creation_with_defaults(self) -> None:
        """User can be created with minimal fields."""
        user = User(id="user-1", username="testuser")

        assert user.id == "user-1"
        assert user.username == "testuser"
        assert user.principal_id == "user-1"
        assert user.subject_type == SubjectType.USER
        assert user.is_authenticated is True
        assert "user" in user.roles

    def test_user_with_custom_roles(self) -> None:
        """User can have custom roles."""
        user = User(
            id="admin-1",
            username="admin",
            roles=frozenset({"admin", "user"}),
        )

        assert "admin" in user.roles
        assert "user" in user.roles

    def test_user_is_frozen(self) -> None:
        """User model is immutable."""
        user = User(id="user-1", username="testuser")

        with pytest.raises(Exception):  # Pydantic raises ValidationError
            user.id = "modified"

    def test_user_implements_subject_protocol(self) -> None:
        """User implements Subject protocol."""
        user = User(id="user-1", username="testuser")

        assert isinstance(user, Subject)


class TestAgent:
    """Tests for Agent model."""

    def test_agent_creation_with_defaults(self) -> None:
        """Agent can be created with minimal fields."""
        agent = Agent(id="agent-1", service_name="test-service")

        assert agent.id == "agent-1"
        assert agent.service_name == "test-service"
        assert agent.principal_id == "agent-1"
        assert agent.subject_type == SubjectType.AGENT
        assert agent.is_authenticated is True
        assert "agent" in agent.roles

    def test_agent_with_metadata(self) -> None:
        """Agent can have metadata."""
        agent = Agent(
            id="agent-1",
            service_name="test-service",
            version="1.0.0",
            metadata={"region": "us-west-1"},
        )

        assert agent.version == "1.0.0"
        assert agent.metadata["region"] == "us-west-1"

    def test_agent_implements_subject_protocol(self) -> None:
        """Agent implements Subject protocol."""
        agent = Agent(id="agent-1", service_name="test-service")

        assert isinstance(agent, Subject)


class TestAnonymousSubject:
    """Tests for AnonymousSubject."""

    def test_anonymous_properties(self) -> None:
        """Anonymous subject has correct properties."""
        anon = AnonymousSubject()

        assert anon.principal_id == "anonymous"
        assert anon.subject_type == SubjectType.USER
        assert anon.is_authenticated is False
        assert len(anon.roles) == 0

    def test_anonymous_singleton(self) -> None:
        """ANONYMOUS constant is available."""
        assert ANONYMOUS.principal_id == "anonymous"
        assert ANONYMOUS.is_authenticated is False

    def test_anonymous_implements_subject_protocol(self) -> None:
        """Anonymous implements Subject protocol."""
        assert isinstance(ANONYMOUS, Subject)
