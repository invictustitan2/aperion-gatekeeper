"""
Authentication Engine for Aperion Gatekeeper.

The "Who are you?" logic - routes between HMAC and Bearer authentication.
Produces verified Subject identities or fails closed.

Zero-trust: No authentication = no access. Default deny.
"""

from __future__ import annotations

import os
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from aperion_gatekeeper.core.credentials import KeyManager
from aperion_gatekeeper.core.identity import ANONYMOUS, Agent, Subject, User
from aperion_gatekeeper.engines.nonce_store import InMemoryNonceStore, NonceStore


class AuthMethod(str, Enum):
    """Supported authentication methods."""

    HMAC = "hmac"
    BEARER = "bearer"
    NONE = "none"


class AuthErrorCode(str, Enum):
    """Authentication error codes."""

    MISSING_HEADER = "missing_header"
    INVALID_FORMAT = "invalid_format"
    INVALID_SIGNATURE = "invalid_signature"
    EXPIRED_TIMESTAMP = "expired_timestamp"
    FUTURE_TIMESTAMP = "future_timestamp"
    REPLAY_DETECTED = "replay_detected"
    INVALID_TOKEN = "invalid_token"
    NO_KEYS_CONFIGURED = "no_keys_configured"
    UNKNOWN_METHOD = "unknown_method"


@dataclass
class AuthResult:
    """
    Result of an authentication attempt.

    Contains either a verified Subject or error details.
    """

    success: bool
    subject: Subject = field(default_factory=lambda: ANONYMOUS)
    method: AuthMethod = AuthMethod.NONE
    error_code: AuthErrorCode | None = None
    error_message: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def is_authenticated(self) -> bool:
        """Convenience check for successful authentication."""
        return self.success and self.subject.is_authenticated


class NonceTracker:
    """
    Tracks used nonces for replay attack prevention.

    DEPRECATED: Use InMemoryNonceStore or RedisNonceStore instead.
    Kept for backwards compatibility.
    """

    def __init__(self, window_seconds: int = 600) -> None:
        """
        Initialize nonce tracker.

        Args:
            window_seconds: How long to track nonces (default 10 minutes)
        """
        self._store = InMemoryNonceStore(window_seconds)

    def is_replay(self, nonce: str, timestamp: float) -> bool:
        """Check if nonce has been used (replay attack)."""
        return self._store.is_replay(nonce, timestamp)

    def _maybe_cleanup(self) -> None:
        """Clean up old nonces periodically."""
        self._store.cleanup()

    @property
    def _used(self) -> dict[str, float]:
        """Access internal store for backwards compatibility with tests."""
        return self._store._used


class AuthenticationEngine:
    """
    Central authentication engine.

    Routes between HMAC and Bearer authentication based on request headers.
    Produces verified Subject identities or fails closed.

    Supports pluggable nonce storage for distributed deployments:
    - InMemoryNonceStore (default): Single-instance, development
    - RedisNonceStore: Multi-instance, production

    Usage:
        engine = AuthenticationEngine(key_manager)

        # Authenticate a request
        result = engine.authenticate(
            authorization="HMAC 1234567890:abc123:sig...",
            method="GET",
            path="/api/data",
        )

        if result.success:
            subject = result.subject
            # Proceed with authorized subject
        else:
            # Handle authentication failure
            log_failure(result.error_code, result.error_message)

    Distributed Usage:
        import redis
        from aperion_gatekeeper.engines.nonce_store import RedisNonceStore

        redis_client = redis.Redis(host='localhost', port=6379)
        nonce_store = RedisNonceStore(redis_client, window_seconds=600)
        engine = AuthenticationEngine(key_manager, nonce_store=nonce_store)
    """

    def __init__(
        self,
        key_manager: KeyManager,
        *,
        timestamp_skew: int = 300,
        nonce_window: int = 600,
        nonce_store: NonceStore | None = None,
    ) -> None:
        """
        Initialize authentication engine.

        Args:
            key_manager: Key manager with loaded credentials
            timestamp_skew: Allowed timestamp skew in seconds (default 5 min)
            nonce_window: Nonce tracking window in seconds (default 10 min)
            nonce_store: Optional pluggable nonce store (defaults to InMemoryNonceStore)
        """
        self._key_manager = key_manager
        self._timestamp_skew = timestamp_skew

        # Use injected store or default to in-memory
        if nonce_store is not None:
            self._nonce_store = nonce_store
            # Keep _nonce_tracker for backwards compatibility
            self._nonce_tracker = NonceTracker(nonce_window)
            self._nonce_tracker._store = nonce_store  # type: ignore[assignment]
        else:
            self._nonce_tracker = NonceTracker(nonce_window)
            self._nonce_store = self._nonce_tracker._store

    def authenticate(
        self,
        authorization: str | None = None,
        *,
        method: str = "GET",
        path: str = "/",
        client_ip: str | None = None,
    ) -> AuthResult:
        """
        Authenticate a request.

        Automatically detects HMAC vs Bearer based on header format.

        Args:
            authorization: Authorization header value
            method: HTTP method
            path: Request path
            client_ip: Client IP for logging

        Returns:
            AuthResult with success status and Subject or error
        """
        if not authorization:
            return AuthResult(
                success=False,
                error_code=AuthErrorCode.MISSING_HEADER,
                error_message="Authorization header required",
            )

        # Route based on header format
        if authorization.startswith("HMAC "):
            return self._authenticate_hmac(authorization, method, path)
        elif authorization.startswith("Bearer "):
            return self._authenticate_bearer(authorization)
        else:
            return AuthResult(
                success=False,
                error_code=AuthErrorCode.INVALID_FORMAT,
                error_message="Unknown authorization format. Expected 'HMAC' or 'Bearer'",
            )

    def _authenticate_hmac(
        self,
        header: str,
        method: str,
        path: str,
    ) -> AuthResult:
        """Authenticate using HMAC signature."""
        # Check keys are configured
        if not self._key_manager.valid_hmac_keys:
            return AuthResult(
                success=False,
                method=AuthMethod.HMAC,
                error_code=AuthErrorCode.NO_KEYS_CONFIGURED,
                error_message="No HMAC keys configured",
            )

        # Parse header: HMAC <timestamp>:<nonce>:<signature>
        try:
            payload = header[5:]  # Remove "HMAC "
            parts = payload.split(":")
            if len(parts) != 3:
                return AuthResult(
                    success=False,
                    method=AuthMethod.HMAC,
                    error_code=AuthErrorCode.INVALID_FORMAT,
                    error_message="Invalid HMAC header format. Expected 'HMAC <ts>:<nonce>:<sig>'",
                )

            timestamp_str, nonce, signature = parts
            timestamp = int(timestamp_str)
        except (ValueError, IndexError) as e:
            return AuthResult(
                success=False,
                method=AuthMethod.HMAC,
                error_code=AuthErrorCode.INVALID_FORMAT,
                error_message=f"Failed to parse HMAC header: {e}",
            )

        # Validate timestamp
        now = int(time.time())
        time_diff = now - timestamp

        if time_diff > self._timestamp_skew:
            return AuthResult(
                success=False,
                method=AuthMethod.HMAC,
                error_code=AuthErrorCode.EXPIRED_TIMESTAMP,
                error_message=f"Timestamp expired ({time_diff}s old, max {self._timestamp_skew}s)",
            )

        if time_diff < -self._timestamp_skew:
            return AuthResult(
                success=False,
                method=AuthMethod.HMAC,
                error_code=AuthErrorCode.FUTURE_TIMESTAMP,
                error_message=f"Timestamp is {-time_diff}s in the future",
            )

        # Check for replay attack
        if self._nonce_tracker.is_replay(nonce, timestamp):
            return AuthResult(
                success=False,
                method=AuthMethod.HMAC,
                error_code=AuthErrorCode.REPLAY_DETECTED,
                error_message="Replay attack detected: nonce already used",
            )

        # Verify signature
        message = f"{timestamp}:{nonce}:{method}:{path}"
        if not self._key_manager.verify_hmac(message, signature):
            return AuthResult(
                success=False,
                method=AuthMethod.HMAC,
                error_code=AuthErrorCode.INVALID_SIGNATURE,
                error_message="HMAC signature verification failed",
            )

        # Success! Create authenticated agent
        agent = Agent(
            id=f"agent_{nonce[:8]}",
            service_name="hmac_authenticated",
            roles=frozenset({"agent", "authenticated"}),
            auth_method="hmac",
            metadata={
                "timestamp": str(timestamp),
                "nonce": nonce,
            },
        )

        return AuthResult(
            success=True,
            subject=agent,
            method=AuthMethod.HMAC,
            metadata={"timestamp": timestamp, "nonce": nonce},
        )

    def _authenticate_bearer(self, header: str) -> AuthResult:
        """Authenticate using Bearer token."""
        try:
            token = header.split(" ", 1)[1]
        except IndexError:
            return AuthResult(
                success=False,
                method=AuthMethod.BEARER,
                error_code=AuthErrorCode.INVALID_FORMAT,
                error_message="Empty Bearer token",
            )

        if not token:
            return AuthResult(
                success=False,
                method=AuthMethod.BEARER,
                error_code=AuthErrorCode.INVALID_TOKEN,
                error_message="Bearer token is empty",
            )

        # Verify token
        credential = self._key_manager.verify_bearer(token)
        if not credential:
            return AuthResult(
                success=False,
                method=AuthMethod.BEARER,
                error_code=AuthErrorCode.INVALID_TOKEN,
                error_message="Invalid or expired bearer token",
            )

        # Success! Create authenticated user
        user = User(
            id=f"user_{credential.token_id}",
            username=credential.token_id,
            roles=frozenset({"user", "authenticated"}),
            auth_method="bearer",
        )

        return AuthResult(
            success=True,
            subject=user,
            method=AuthMethod.BEARER,
            metadata={"token_id": credential.token_id},
        )

    def create_hmac_header(
        self,
        method: str,
        path: str,
        *,
        timestamp: int | None = None,
        nonce: str | None = None,
    ) -> str | None:
        """
        Create an HMAC Authorization header.

        Convenience method for clients/tests.

        Args:
            method: HTTP method
            path: Request path
            timestamp: Optional timestamp (defaults to now)
            nonce: Optional nonce (defaults to random)

        Returns:
            Authorization header value, or None if no active key
        """
        if not self._key_manager.active_hmac_key:
            return None

        if timestamp is None:
            timestamp = int(time.time())

        if nonce is None:
            nonce = os.urandom(8).hex()

        message = f"{timestamp}:{nonce}:{method}:{path}"
        signature = self._key_manager.sign_hmac(message)

        if not signature:
            return None

        return f"HMAC {timestamp}:{nonce}:{signature}"
