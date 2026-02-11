"""
Security Audit Logging for The Gatekeeper (Compatibility Layer).

Emits structured audit events for authentication attempts and
sensitive operations via the Event Bus.

Ported from the embedded stack.aperion.gatekeeper.audit module.
The event_bus dependency is stubbed — the monolith's re-export shim
injects the real EventBus at runtime via the constructor parameter.
"""

from __future__ import annotations

import time
from typing import Any

from .models import AuthMethod, AuthResult, PolicyDecision, Principal


class _StubEventBus:
    """Minimal EventBus stub for when no real event bus is available."""

    def emit(self, event_type: str, payload: dict[str, Any], **kwargs: Any) -> str:
        return f"stub_{int(time.time())}"

    def get_stats(self) -> dict[str, Any]:
        return {"stub": True, "total_events_logged": 0, "audit_enabled": False, "subscriber_count": 0}


def _get_event_bus() -> Any:
    """
    Lazy import of EventBus to avoid circular imports.

    Tries standalone event_bus first, falls back to stub.
    """
    try:
        from event_bus import EventBus  # type: ignore[import-untyped]

        return EventBus(enable_audit=True)
    except ImportError:
        pass

    return _StubEventBus()


def require_event_bus(event_bus: Any, component: str = "unknown") -> Any:
    """Compatibility stub for foundation.event_bus.require_event_bus.

    In the standalone package context, this is a no-op — the monolith
    shim will inject the real require_event_bus when needed.
    """
    return event_bus


class SecurityAuditor:
    """
    Security audit logger using Event Bus for centralized tracking.

    All authentication attempts and authorization decisions are logged
    with full context for compliance and forensics.
    """

    # Event types emitted by the auditor
    EVENT_AUTH_SUCCESS = "gatekeeper.auth.success"
    EVENT_AUTH_FAILURE = "gatekeeper.auth.failure"
    EVENT_AUTHZ_ALLOWED = "gatekeeper.authz.allowed"
    EVENT_AUTHZ_DENIED = "gatekeeper.authz.denied"
    EVENT_TOKEN_ISSUED = "gatekeeper.token.issued"
    EVENT_TOKEN_REVOKED = "gatekeeper.token.revoked"
    EVENT_KEY_ROTATED = "gatekeeper.key.rotated"
    EVENT_SENSITIVE_OP = "gatekeeper.operation.sensitive"

    def __init__(self, event_bus: Any = None) -> None:
        """
        Initialize security auditor.

        Args:
            event_bus: EventBus instance. If None, creates default instance.
        """
        require_event_bus(event_bus, component="SecurityAuditor")
        self.event_bus = event_bus if event_bus is not None else _get_event_bus()

    def log_auth_attempt(
        self,
        result: AuthResult,
        method: str,
        path: str,
        ip_address: str | None = None,
        correlation_id: str | None = None,
    ) -> str:
        """
        Log an authentication attempt.

        Args:
            result: The authentication result.
            method: HTTP method.
            path: Request path.
            ip_address: Client IP address.
            correlation_id: Request correlation ID.

        Returns:
            Event ID from Event Bus.
        """
        event_type = (
            self.EVENT_AUTH_SUCCESS if result.success else self.EVENT_AUTH_FAILURE
        )

        payload = {
            "success": result.success,
            "auth_method": result.auth_method.value if result.auth_method else None,
            "user_id": result.principal.user_id if result.principal else None,
            "errors": result.errors,
            "warnings": result.warnings,
            "http_method": method,
            "path": path,
            "ip_address": ip_address,
            "timestamp": int(time.time()),
        }

        return self.event_bus.emit(
            event_type,
            payload,
            source="gatekeeper",
            correlation_id=correlation_id,
        )

    def log_authz_decision(
        self,
        principal: Principal,
        action: str,
        resource: str | None,
        decision: PolicyDecision,
        correlation_id: str | None = None,
    ) -> str:
        """
        Log an authorization decision.

        Args:
            principal: The authenticated identity.
            action: Action being authorized.
            resource: Resource being accessed.
            decision: The policy decision.
            correlation_id: Request correlation ID.

        Returns:
            Event ID from Event Bus.
        """
        event_type = (
            self.EVENT_AUTHZ_ALLOWED if decision.allowed else self.EVENT_AUTHZ_DENIED
        )

        payload = {
            "user_id": principal.user_id,
            "roles": [r.value for r in principal.roles],
            "action": action,
            "resource": resource,
            "allowed": decision.allowed,
            "reason": decision.reason,
            "required_permissions": [
                p.value for p in decision.required_permissions
            ],
            "timestamp": int(time.time()),
        }

        return self.event_bus.emit(
            event_type,
            payload,
            source="gatekeeper",
            correlation_id=correlation_id,
        )

    def log_token_issued(
        self,
        principal: Principal,
        token_id: str,
        scopes: list[str],
        ttl: int,
        correlation_id: str | None = None,
    ) -> str:
        """
        Log token issuance.

        Args:
            principal: The principal the token was issued to.
            token_id: Unique token identifier (NOT the token itself).
            scopes: Token scopes.
            ttl: Token time-to-live in seconds.
            correlation_id: Request correlation ID.

        Returns:
            Event ID from Event Bus.
        """
        payload = {
            "user_id": principal.user_id,
            "token_id": token_id[:8] + "..." if len(token_id) > 8 else token_id,
            "scopes": scopes,
            "ttl_seconds": ttl,
            "timestamp": int(time.time()),
        }

        return self.event_bus.emit(
            self.EVENT_TOKEN_ISSUED,
            payload,
            source="gatekeeper",
            correlation_id=correlation_id,
        )

    def log_token_revoked(
        self,
        token_id: str,
        reason: str,
        revoked_by: str | None = None,
        correlation_id: str | None = None,
    ) -> str:
        """
        Log token revocation.

        Args:
            token_id: The revoked token identifier.
            reason: Reason for revocation.
            revoked_by: User who revoked (if applicable).
            correlation_id: Request correlation ID.

        Returns:
            Event ID from Event Bus.
        """
        payload = {
            "token_id": token_id[:8] + "..." if len(token_id) > 8 else token_id,
            "reason": reason,
            "revoked_by": revoked_by,
            "timestamp": int(time.time()),
        }

        return self.event_bus.emit(
            self.EVENT_TOKEN_REVOKED,
            payload,
            source="gatekeeper",
            correlation_id=correlation_id,
        )

    def log_key_rotation(
        self,
        key_name: str,
        rotated_by: str,
        correlation_id: str | None = None,
    ) -> str:
        """
        Log key rotation event.

        Args:
            key_name: Name of the rotated key.
            rotated_by: User who performed rotation.
            correlation_id: Request correlation ID.

        Returns:
            Event ID from Event Bus.
        """
        payload = {
            "key_name": key_name,
            "rotated_by": rotated_by,
            "timestamp": int(time.time()),
        }

        return self.event_bus.emit(
            self.EVENT_KEY_ROTATED,
            payload,
            source="gatekeeper",
            correlation_id=correlation_id,
        )

    def log_sensitive_operation(
        self,
        operation: str,
        user_id: str,
        resource: str,
        result: str,
        action: str | None = None,
        details: dict[str, Any] | None = None,
        ip_address: str | None = None,
        correlation_id: str | None = None,
    ) -> str:
        """
        Log a sensitive operation (user creation, backup, etc.).

        Args:
            operation: Operation type.
            user_id: User performing the operation.
            resource: Affected resource.
            result: Operation result ("success" or "failure").
            action: Action taken (legacy compat, included in payload).
            details: Additional details.
            ip_address: Client IP address.
            correlation_id: Request correlation ID.

        Returns:
            Event ID from Event Bus.
        """
        payload: dict[str, Any] = {
            "operation": operation,
            "user_id": user_id,
            "resource": resource,
            "result": result,
            "details": details or {},
            "ip_address": ip_address,
            "timestamp": int(time.time()),
        }
        if action is not None:
            payload["action"] = action

        return self.event_bus.emit(
            self.EVENT_SENSITIVE_OP,
            payload,
            source="gatekeeper",
            correlation_id=correlation_id,
        )

    def get_stats(self) -> dict[str, Any]:
        """Get audit statistics from Event Bus."""
        stats = self.event_bus.get_stats()
        return {
            "total_events": stats.get("total_events_logged", 0),
            "audit_enabled": stats.get("audit_enabled", False),
            "event_bus_subscribers": stats.get("subscriber_count", 0),
        }

    # Legacy API methods (compat with stack.aperion.security.audit_logging)

    def log_auth_success(
        self,
        user_id: str,
        method: str,
        path: str,
        ip_address: str | None = None,
        correlation_id: str | None = None,
    ) -> str:
        """Legacy: log successful authentication."""
        payload = {
            "user_id": user_id,
            "method": method,
            "path": path,
            "ip_address": ip_address,
            "timestamp": int(time.time()),
            "result": "success",
        }
        return self.event_bus.emit(
            "security.auth_success",
            payload,
            source="security_auditor",
            correlation_id=correlation_id,
        )

    def log_auth_failure(
        self,
        reason: str,
        method: str,
        path: str,
        user_id: str | None = None,
        ip_address: str | None = None,
        correlation_id: str | None = None,
    ) -> str:
        """Legacy: log failed authentication attempt."""
        payload = {
            "reason": reason,
            "method": method,
            "path": path,
            "user_id": user_id,
            "ip_address": ip_address,
            "timestamp": int(time.time()),
            "result": "failure",
        }
        return self.event_bus.emit(
            "security.auth_failure",
            payload,
            source="security_auditor",
            correlation_id=correlation_id,
        )

    def get_audit_stats(self) -> dict[str, Any]:
        """Legacy: get audit statistics (alias for get_stats with old keys)."""
        stats = self.event_bus.get_stats()
        return {
            "total_events": stats.get("total_events_logged", 0),
            "audit_enabled": stats.get("audit_enabled", False),
            "audit_log_path": str(stats.get("log_file_size", "")),
        }
