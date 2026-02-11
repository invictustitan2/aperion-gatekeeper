"""
FastAPI Middleware for The Gatekeeper (Compatibility Layer).

Drop-in authentication and authorization middleware for FastAPI services.

Ported from the embedded stack.aperion.gatekeeper.middleware module.
"""

from __future__ import annotations

import logging
from typing import Annotated, Any, Callable

from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from .audit import SecurityAuditor
from .models import AuthResult, Permission, PolicyDecision, Principal, Role
from .policies import PolicyEngine
from .tokens import TokenService

logger = logging.getLogger(__name__)

# Shared instances - initialized on first use
_token_service: TokenService | None = None
_policy_engine: PolicyEngine | None = None
_auditor: SecurityAuditor | None = None


def get_token_service() -> TokenService:
    """Get or create the global TokenService instance."""
    global _token_service
    if _token_service is None:
        _token_service = TokenService()
    return _token_service


def get_policy_engine() -> PolicyEngine:
    """Get or create the global PolicyEngine instance."""
    global _policy_engine
    if _policy_engine is None:
        _policy_engine = PolicyEngine()
    return _policy_engine


def get_auditor() -> SecurityAuditor:
    """Get or create the global SecurityAuditor instance."""
    global _auditor
    if _auditor is None:
        _auditor = SecurityAuditor()
    return _auditor


def configure_gatekeeper(
    token_service: TokenService | None = None,
    policy_engine: PolicyEngine | None = None,
    auditor: SecurityAuditor | None = None,
) -> None:
    """
    Configure global Gatekeeper instances.

    Call this at application startup to inject custom instances.

    Args:
        token_service: Custom TokenService instance.
        policy_engine: Custom PolicyEngine instance.
        auditor: Custom SecurityAuditor instance.
    """
    global _token_service, _policy_engine, _auditor
    if token_service:
        _token_service = token_service
    if policy_engine:
        _policy_engine = policy_engine
    if auditor:
        _auditor = auditor


# HTTP Bearer security scheme
security = HTTPBearer(auto_error=False)


async def _extract_auth_header(request: Request) -> str | None:
    """Extract Authorization header from request."""
    return request.headers.get("Authorization")


async def require_auth(
    request: Request,
    credentials: HTTPAuthorizationCredentials | None = Depends(security),
) -> Principal:
    """
    FastAPI dependency that requires authentication.

    Validates Bearer token or HMAC header and returns the authenticated
    principal. Raises 401 if authentication fails.

    Usage:
        @app.get("/protected")
        async def protected(principal: Principal = Depends(require_auth)):
            return {"user": principal.user_id}
    """
    token_service = get_token_service()
    auditor = get_auditor()

    # Get full auth header for HMAC support
    auth_header = await _extract_auth_header(request)
    if not auth_header:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authorization header required",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # Authenticate
    result = token_service.authenticate(
        auth_header,
        method=request.method,
        path=str(request.url.path),
    )

    # Get correlation ID for audit trail
    correlation_id = request.headers.get("X-Correlation-ID")

    # Audit the attempt
    auditor.log_auth_attempt(
        result,
        method=request.method,
        path=str(request.url.path),
        ip_address=request.client.host if request.client else None,
        correlation_id=correlation_id,
    )

    if not result.success:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=result.errors[0] if result.errors else "Authentication failed",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # Store principal in request state for downstream use
    request.state.principal = result.principal
    return result.principal


def require_permission(permission: Permission) -> Callable:
    """
    Create a dependency that requires a specific permission.

    Usage:
        @app.post("/write")
        async def write_data(
            principal: Principal = Depends(require_auth),
            _: None = Depends(require_permission(Permission.WRITE)),
        ):
            ...
    """

    async def check_permission(
        request: Request,
        principal: Principal = Depends(require_auth),
    ) -> None:
        engine = get_policy_engine()
        auditor = get_auditor()

        decision = engine.can(principal, permission)

        # Audit the decision
        correlation_id = request.headers.get("X-Correlation-ID")
        auditor.log_authz_decision(
            principal,
            action=permission.value,
            resource=str(request.url.path),
            decision=decision,
            correlation_id=correlation_id,
        )

        if not decision.allowed:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=decision.reason,
            )

    return check_permission


def require_role(*roles: Role) -> Callable:
    """
    Create a dependency that requires one of the specified roles.

    Usage:
        @app.delete("/admin/users/{id}")
        async def delete_user(
            principal: Principal = Depends(require_auth),
            _: None = Depends(require_role(Role.ADMIN)),
        ):
            ...
    """

    async def check_role(
        request: Request,
        principal: Principal = Depends(require_auth),
    ) -> None:
        if not any(principal.has_role(role) for role in roles):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Required role: {[r.value for r in roles]}",
            )

    return check_role


def require_action(action: str) -> Callable:
    """
    Create a dependency that requires authorization for a specific action.

    Uses the PolicyEngine's action registry.

    Usage:
        @app.post("/agents/execute")
        async def execute_agent(
            principal: Principal = Depends(require_auth),
            _: None = Depends(require_action("agent:execute")),
        ):
            ...
    """

    async def check_action(
        request: Request,
        principal: Principal = Depends(require_auth),
    ) -> None:
        engine = get_policy_engine()
        auditor = get_auditor()

        # Get resource from path
        resource = str(request.url.path)
        decision = engine.can(principal, action, resource)

        # Audit the decision
        correlation_id = request.headers.get("X-Correlation-ID")
        auditor.log_authz_decision(
            principal,
            action=action,
            resource=resource,
            decision=decision,
            correlation_id=correlation_id,
        )

        if not decision.allowed:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=decision.reason,
            )

    return check_action


# Type aliases for cleaner endpoint signatures
AuthenticatedPrincipal = Annotated[Principal, Depends(require_auth)]


class GatekeeperMiddleware:
    """
    ASGI middleware for optional authentication on all routes.

    Unlike the require_auth dependency, this middleware allows
    unauthenticated requests to pass through with a None principal.
    Use for routes that have optional authentication.
    """

    def __init__(self, app: Any) -> None:
        """Initialize middleware."""
        self.app = app
        self.token_service = get_token_service()

    async def __call__(self, scope: dict, receive: Callable, send: Callable) -> None:
        """Process request."""
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        # Try to authenticate but don't fail
        headers = dict(scope.get("headers", []))
        auth_header = headers.get(b"authorization", b"").decode()

        principal = None
        if auth_header:
            result = self.token_service.authenticate(
                auth_header,
                method=scope.get("method", "GET"),
                path=scope.get("path", "/"),
            )
            if result.success:
                principal = result.principal

        # Store in scope for access in route handlers
        scope["principal"] = principal
        await self.app(scope, receive, send)
