"""
FastAPI Integration for Aperion Gatekeeper.

Provides drop-in dependencies for authentication and authorization.
Use these to secure FastAPI endpoints.

Usage:
    from aperion_gatekeeper.middleware.fastapi import get_current_subject, require_permission

    @app.get("/api/data")
    async def get_data(subject: Subject = Depends(get_current_subject)):
        # subject is authenticated
        return {"user": subject.principal_id}

    @app.delete("/api/data/{id}")
    async def delete_data(
        id: str,
        subject: Subject = Depends(require_permission("delete"))
    ):
        # subject has delete permission
        ...
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Annotated, Callable

from fastapi import Depends, Header, HTTPException, Request, Response, status
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint

from aperion_gatekeeper.core.correlation import (
    CorrelationHeaders,
    correlation_context,
    get_correlation_id,
    get_or_create_correlation_id,
)
from aperion_gatekeeper.core.credentials import KeyManager
from aperion_gatekeeper.core.identity import ANONYMOUS, Subject
from aperion_gatekeeper.engines.authentication import AuthenticationEngine, AuthResult
from aperion_gatekeeper.engines.policy import Permission, PolicyEngine


@dataclass
class GatekeeperConfig:
    """
    Configuration for Gatekeeper FastAPI integration.

    Set up once at app startup and use the dependencies.
    """

    key_manager: KeyManager = field(default_factory=KeyManager)
    policy_engine: PolicyEngine = field(default_factory=PolicyEngine)
    auth_engine: AuthenticationEngine | None = None

    # Configuration
    require_auth: bool = True  # If False, allows anonymous (dev mode)
    log_failures: bool = True  # Log authentication failures

    def __post_init__(self) -> None:
        """Initialize auth engine if not provided."""
        if self.auth_engine is None:
            self.auth_engine = AuthenticationEngine(self.key_manager)


# Global config - set at app startup
_config: GatekeeperConfig | None = None


def configure_gatekeeper(config: GatekeeperConfig) -> None:
    """
    Configure Gatekeeper for the application.

    Call this at FastAPI app startup:

        from aperion_gatekeeper.middleware.fastapi import configure_gatekeeper, GatekeeperConfig
        from aperion_gatekeeper.core.credentials import KeyManager

        key_manager = KeyManager()
        key_manager.load_hmac_from_env("APERION_HMAC_KEY")

        configure_gatekeeper(GatekeeperConfig(key_manager=key_manager))

    Args:
        config: Gatekeeper configuration
    """
    global _config
    _config = config


def get_config() -> GatekeeperConfig:
    """Get current configuration or create default."""
    global _config
    if _config is None:
        _config = GatekeeperConfig()
    return _config


async def get_current_subject(
    request: Request,
    authorization: Annotated[str | None, Header()] = None,
) -> Subject:
    """
    FastAPI dependency to get the authenticated subject.

    Checks both Bearer and HMAC headers based on configuration.

    Usage:
        @app.get("/api/resource")
        async def get_resource(subject: Subject = Depends(get_current_subject)):
            ...

    Args:
        request: FastAPI request
        authorization: Authorization header

    Returns:
        Authenticated Subject

    Raises:
        HTTPException: 401 if authentication required but failed
    """
    config = get_config()

    if not config.auth_engine:
        if config.require_auth:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Authentication engine not configured",
            )
        return ANONYMOUS

    # Authenticate
    result: AuthResult = config.auth_engine.authenticate(
        authorization=authorization,
        method=request.method,
        path=str(request.url.path),
        client_ip=request.client.host if request.client else None,
    )

    if result.success:
        # Store subject in request state for other middleware
        request.state.subject = result.subject
        return result.subject

    # Authentication failed
    if config.require_auth:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=result.error_message or "Authentication required",
            headers={"WWW-Authenticate": "Bearer, HMAC"},
        )

    # Dev mode: allow anonymous
    request.state.subject = ANONYMOUS
    return ANONYMOUS


def require_authenticated(
    subject: Annotated[Subject, Depends(get_current_subject)],
) -> Subject:
    """
    Dependency that requires authenticated subject.

    Stricter than get_current_subject - always requires authentication.

    Usage:
        @app.get("/api/secure")
        async def secure_endpoint(subject: Subject = Depends(require_authenticated)):
            ...
    """
    if not subject.is_authenticated:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required",
            headers={"WWW-Authenticate": "Bearer, HMAC"},
        )
    return subject


def require_permission(permission: str | Permission) -> Callable[..., Subject]:
    """
    Factory for permission-checking dependency.

    Usage:
        @app.delete("/api/resource/{id}")
        async def delete_resource(
            id: str,
            subject: Subject = Depends(require_permission("delete"))
        ):
            ...

    Args:
        permission: Required permission

    Returns:
        Dependency function
    """

    async def check_permission(
        request: Request,
        subject: Annotated[Subject, Depends(require_authenticated)],
    ) -> Subject:
        config = get_config()

        # Get resource from path
        resource = str(request.url.path)

        # Check permission
        if not config.policy_engine.enforce(subject, permission, resource):
            decision = config.policy_engine.evaluate(subject, permission, resource)
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Permission denied: {decision.reason}",
            )

        return subject

    return check_permission


def require_role(*roles: str) -> Callable[..., Subject]:
    """
    Factory for role-checking dependency.

    Usage:
        @app.get("/api/admin/users")
        async def list_users(
            subject: Subject = Depends(require_role("admin"))
        ):
            ...

    Args:
        roles: Required roles (any match)

    Returns:
        Dependency function
    """
    required_roles = frozenset(roles)

    async def check_role(
        subject: Annotated[Subject, Depends(require_authenticated)],
    ) -> Subject:
        if not (subject.roles & required_roles):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Required roles: {list(required_roles)}",
            )
        return subject

    return check_role


class CorrelationMiddleware(BaseHTTPMiddleware):
    """
    Middleware that propagates correlation IDs through requests.

    Extracts correlation ID from incoming headers (X-Correlation-ID, X-Request-ID)
    or generates a new one. The ID is available via get_correlation_id() throughout
    the request lifecycle and is added to the response headers.

    Usage:
        from fastapi import FastAPI
        from aperion_gatekeeper.middleware.fastapi import CorrelationMiddleware

        app = FastAPI()
        app.add_middleware(CorrelationMiddleware)

        @app.get("/")
        async def root():
            from aperion_gatekeeper.core.correlation import get_correlation_id
            return {"correlation_id": get_correlation_id()}
    """

    async def dispatch(
        self,
        request: Request,
        call_next: RequestResponseEndpoint,
    ) -> Response:
        """Process request with correlation context."""
        # Extract correlation ID from headers
        headers = dict(request.headers)
        correlation_id = CorrelationHeaders.extract_from_headers(headers)

        # Use correlation context for the entire request
        with correlation_context(
            correlation_id=correlation_id,
            method=request.method,
            path=str(request.url.path),
            client_ip=request.client.host if request.client else None,
        ) as cid:
            # Store in request state for other middleware/handlers
            request.state.correlation_id = cid

            # Process request
            response = await call_next(request)

            # Add correlation ID to response headers
            response.headers[CorrelationHeaders.CORRELATION_ID] = cid

            return response


async def get_correlation_id_dependency(request: Request) -> str:
    """
    FastAPI dependency to get current correlation ID.

    Usage:
        @app.get("/api/resource")
        async def get_resource(correlation_id: str = Depends(get_correlation_id_dependency)):
            logger.info("Processing", extra={"correlation_id": correlation_id})
    """
    # Try request state first (set by middleware)
    if hasattr(request.state, "correlation_id"):
        return request.state.correlation_id

    # Fall back to header extraction or generation
    return get_or_create_correlation_id()
