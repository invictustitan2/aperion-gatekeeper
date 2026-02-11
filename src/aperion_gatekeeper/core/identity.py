"""
Unified Identity Models for Aperion Gatekeeper.

Defines the Subject protocol representing any authenticated principal
(human User or machine Agent) in the system.

Zero-trust: Every subject must be verified. No implicit trust.
"""

from __future__ import annotations

from datetime import UTC, datetime
from enum import Enum
from typing import Protocol, runtime_checkable

from pydantic import BaseModel, Field


class SubjectType(str, Enum):
    """Type of authenticated subject."""

    USER = "user"
    AGENT = "agent"
    SERVICE = "service"
    SYSTEM = "system"


@runtime_checkable
class Subject(Protocol):
    """
    Protocol defining any authenticated principal.

    Every subject in the system MUST implement this protocol.
    Used for both humans (User) and machines (Agent/Service).
    """

    @property
    def principal_id(self) -> str:
        """Unique identifier for this subject."""
        ...

    @property
    def subject_type(self) -> SubjectType:
        """Type of subject (user, agent, service, system)."""
        ...

    @property
    def roles(self) -> frozenset[str]:
        """Immutable set of roles assigned to this subject."""
        ...

    @property
    def is_authenticated(self) -> bool:
        """Whether this subject has been successfully authenticated."""
        ...


class User(BaseModel):
    """
    Human user identity.

    Represents an authenticated human user with assigned roles.
    """

    model_config = {"frozen": True}

    id: str = Field(..., description="Unique user identifier")
    username: str = Field(..., description="Human-readable username")
    email: str | None = Field(default=None, description="User email if available")
    roles: frozenset[str] = Field(
        default_factory=lambda: frozenset({"user"}),
        description="Assigned roles",
    )
    authenticated_at: datetime = Field(
        default_factory=lambda: datetime.now(UTC),
        description="When authentication occurred",
    )
    auth_method: str = Field(
        default="unknown",
        description="Method used for authentication (hmac, bearer, etc.)",
    )

    @property
    def principal_id(self) -> str:
        """User's principal ID is their unique ID."""
        return self.id

    @property
    def subject_type(self) -> SubjectType:
        """Users are of type USER."""
        return SubjectType.USER

    @property
    def is_authenticated(self) -> bool:
        """Users created via this model are always authenticated."""
        return True


class Agent(BaseModel):
    """
    Machine agent identity.

    Represents an authenticated machine/service agent with assigned roles.
    Agents may have additional metadata like service name and version.
    """

    model_config = {"frozen": True}

    id: str = Field(..., description="Unique agent identifier")
    service_name: str = Field(..., description="Name of the service/agent")
    version: str | None = Field(default=None, description="Agent version")
    roles: frozenset[str] = Field(
        default_factory=lambda: frozenset({"agent"}),
        description="Assigned roles",
    )
    authenticated_at: datetime = Field(
        default_factory=lambda: datetime.now(UTC),
        description="When authentication occurred",
    )
    auth_method: str = Field(
        default="hmac",
        description="Method used for authentication",
    )
    metadata: dict[str, str] = Field(
        default_factory=dict,
        description="Additional agent metadata",
    )

    @property
    def principal_id(self) -> str:
        """Agent's principal ID is their unique ID."""
        return self.id

    @property
    def subject_type(self) -> SubjectType:
        """Agents are of type AGENT."""
        return SubjectType.AGENT

    @property
    def is_authenticated(self) -> bool:
        """Agents created via this model are always authenticated."""
        return True


class AnonymousSubject:
    """
    Represents an unauthenticated/anonymous subject.

    Used as a sentinel for failed or missing authentication.
    Has no roles and is_authenticated is always False.
    """

    @property
    def principal_id(self) -> str:
        """Anonymous subjects have no ID."""
        return "anonymous"

    @property
    def subject_type(self) -> SubjectType:
        """Anonymous is treated as a user type."""
        return SubjectType.USER

    @property
    def roles(self) -> frozenset[str]:
        """Anonymous subjects have no roles."""
        return frozenset()

    @property
    def is_authenticated(self) -> bool:
        """Anonymous subjects are never authenticated."""
        return False


# Singleton for anonymous subject
ANONYMOUS = AnonymousSubject()
