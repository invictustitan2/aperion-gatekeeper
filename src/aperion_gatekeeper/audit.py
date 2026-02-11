"""
Structured Security Audit Logging for Aperion Gatekeeper.

All authentication and authorization events are logged in structured format.
Supports Constitution D3 compliance requirements.

Events are JSON-structured for easy parsing and analysis.
"""

from __future__ import annotations

import json
import logging
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any, TextIO

from aperion_gatekeeper.core.identity import Subject


class AuditEventType(str, Enum):
    """Types of security audit events."""

    AUTH_SUCCESS = "auth.success"
    AUTH_FAILURE = "auth.failure"
    AUTHZ_ALLOWED = "authz.allowed"
    AUTHZ_DENIED = "authz.denied"
    KEY_ROTATION = "key.rotation"
    KEY_REVOKED = "key.revoked"
    POLICY_CHANGE = "policy.change"
    SENSITIVE_OP = "sensitive.operation"


@dataclass
class AuditEvent:
    """
    Structured audit event.

    All fields are designed for compliance and forensic analysis.
    """

    event_type: AuditEventType
    timestamp: float = field(default_factory=time.time)
    principal_id: str | None = None
    action: str | None = None
    resource: str | None = None
    result: str = "unknown"
    ip_address: str | None = None
    correlation_id: str | None = None
    details: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        data = asdict(self)
        data["event_type"] = self.event_type.value
        data["timestamp_iso"] = datetime.fromtimestamp(self.timestamp).isoformat()
        return data

    def to_json(self) -> str:
        """Convert to JSON string."""
        return json.dumps(self.to_dict(), default=str)


class SecurityAuditor:
    """
    Security event auditor with structured logging.

    Logs all authentication and authorization events to:
    1. Python logging (configurable level)
    2. Optional JSONL file for compliance

    Usage:
        auditor = SecurityAuditor(log_path=Path("security_audit.jsonl"))

        # Log authentication success
        auditor.log_auth_success(
            subject=user,
            method="hmac",
            path="/api/data",
            ip_address="10.0.0.1",
        )

        # Log authorization denial
        auditor.log_authz_denied(
            subject=user,
            permission="delete",
            resource="/api/admin/users",
            reason="Role not allowed",
        )
    """

    def __init__(
        self,
        *,
        log_path: Path | None = None,
        log_level: int = logging.INFO,
        logger_name: str = "gatekeeper.audit",
    ) -> None:
        """
        Initialize security auditor.

        Args:
            log_path: Path to JSONL audit log file (optional)
            log_level: Python logging level
            logger_name: Name for the Python logger
        """
        self._logger = logging.getLogger(logger_name)
        self._logger.setLevel(log_level)
        self._log_path = log_path
        self._log_file: TextIO | None = None

        if log_path:
            log_path.parent.mkdir(parents=True, exist_ok=True)
            self._log_file = open(log_path, "a", encoding="utf-8")

    def close(self) -> None:
        """Close the audit log file."""
        if self._log_file:
            self._log_file.close()
            self._log_file = None

    def _emit(self, event: AuditEvent) -> str:
        """
        Emit an audit event.

        Args:
            event: Event to emit

        Returns:
            Event JSON for reference
        """
        json_line = event.to_json()

        # Log to Python logger
        self._logger.log(
            logging.WARNING if "denied" in event.result or "failure" in event.result else logging.INFO,
            json_line,
        )

        # Log to file
        if self._log_file:
            self._log_file.write(json_line + "\n")
            self._log_file.flush()

        return json_line

    def log_auth_success(
        self,
        subject: Subject,
        *,
        method: str,
        path: str,
        ip_address: str | None = None,
        correlation_id: str | None = None,
        details: dict[str, Any] | None = None,
    ) -> str:
        """
        Log successful authentication.

        Args:
            subject: Authenticated subject
            method: Auth method used (hmac, bearer, etc.)
            path: Request path
            ip_address: Client IP
            correlation_id: Request correlation ID
            details: Additional details

        Returns:
            Event JSON
        """
        event = AuditEvent(
            event_type=AuditEventType.AUTH_SUCCESS,
            principal_id=subject.principal_id,
            action=f"authenticate:{method}",
            resource=path,
            result="success",
            ip_address=ip_address,
            correlation_id=correlation_id,
            details={
                "method": method,
                "roles": list(subject.roles),
                **(details or {}),
            },
        )
        return self._emit(event)

    def log_auth_failure(
        self,
        *,
        reason: str,
        method: str,
        path: str,
        ip_address: str | None = None,
        correlation_id: str | None = None,
        details: dict[str, Any] | None = None,
    ) -> str:
        """
        Log failed authentication attempt.

        Args:
            reason: Failure reason
            method: Auth method attempted
            path: Request path
            ip_address: Client IP
            correlation_id: Request correlation ID
            details: Additional details

        Returns:
            Event JSON
        """
        event = AuditEvent(
            event_type=AuditEventType.AUTH_FAILURE,
            action=f"authenticate:{method}",
            resource=path,
            result="failure",
            ip_address=ip_address,
            correlation_id=correlation_id,
            details={
                "reason": reason,
                "method": method,
                **(details or {}),
            },
        )
        return self._emit(event)

    def log_authz_allowed(
        self,
        subject: Subject,
        *,
        permission: str,
        resource: str,
        policy: str | None = None,
        correlation_id: str | None = None,
    ) -> str:
        """
        Log authorization allowed.

        Args:
            subject: Subject granted access
            permission: Permission granted
            resource: Resource accessed
            policy: Policy that allowed access
            correlation_id: Request correlation ID

        Returns:
            Event JSON
        """
        event = AuditEvent(
            event_type=AuditEventType.AUTHZ_ALLOWED,
            principal_id=subject.principal_id,
            action=permission,
            resource=resource,
            result="allowed",
            correlation_id=correlation_id,
            details={
                "roles": list(subject.roles),
                "policy": policy,
            },
        )
        return self._emit(event)

    def log_authz_denied(
        self,
        subject: Subject,
        *,
        permission: str,
        resource: str,
        reason: str,
        correlation_id: str | None = None,
    ) -> str:
        """
        Log authorization denied.

        Args:
            subject: Subject denied access
            permission: Permission requested
            resource: Resource requested
            reason: Denial reason
            correlation_id: Request correlation ID

        Returns:
            Event JSON
        """
        event = AuditEvent(
            event_type=AuditEventType.AUTHZ_DENIED,
            principal_id=subject.principal_id,
            action=permission,
            resource=resource,
            result="denied",
            correlation_id=correlation_id,
            details={
                "roles": list(subject.roles),
                "reason": reason,
            },
        )
        return self._emit(event)

    def log_key_rotation(
        self,
        *,
        old_key_id: str,
        new_key_id: str,
        operator_id: str,
        correlation_id: str | None = None,
    ) -> str:
        """
        Log key rotation event.

        Args:
            old_key_id: ID of rotated key
            new_key_id: ID of new key
            operator_id: Who performed rotation
            correlation_id: Request correlation ID

        Returns:
            Event JSON
        """
        event = AuditEvent(
            event_type=AuditEventType.KEY_ROTATION,
            principal_id=operator_id,
            action="rotate_key",
            result="success",
            correlation_id=correlation_id,
            details={
                "old_key_id": old_key_id,
                "new_key_id": new_key_id,
            },
        )
        return self._emit(event)

    def log_sensitive_operation(
        self,
        subject: Subject,
        *,
        operation: str,
        resource: str,
        result: str,
        ip_address: str | None = None,
        correlation_id: str | None = None,
        details: dict[str, Any] | None = None,
    ) -> str:
        """
        Log sensitive operation (e.g., user creation, data deletion).

        Args:
            subject: Subject performing operation
            operation: Operation type
            resource: Affected resource
            result: Operation result
            ip_address: Client IP
            correlation_id: Request correlation ID
            details: Additional details

        Returns:
            Event JSON
        """
        event = AuditEvent(
            event_type=AuditEventType.SENSITIVE_OP,
            principal_id=subject.principal_id,
            action=operation,
            resource=resource,
            result=result,
            ip_address=ip_address,
            correlation_id=correlation_id,
            details={
                "roles": list(subject.roles),
                **(details or {}),
            },
        )
        return self._emit(event)
