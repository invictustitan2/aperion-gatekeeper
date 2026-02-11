"""
Token Service for The Gatekeeper (Compatibility Layer).

Centralized token issuance, validation, and revocation.
Supports both Bearer tokens and HMAC authentication.

Ported from the embedded stack.aperion.gatekeeper.tokens module.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import secrets
import time
import warnings
from typing import Any

from .models import (
    AuthMethod,
    AuthResult,
    Permission,
    Principal,
    Role,
    TokenInfo,
)


class TokenStore:
    """
    In-memory token store with expiry tracking.

    In production, replace with Redis or similar distributed cache.
    """

    def __init__(self) -> None:
        """Initialize token store."""
        self._tokens: dict[str, TokenInfo] = {}
        self._revoked: set[str] = set()

    def store(self, token_info: TokenInfo) -> None:
        """Store a token."""
        self._tokens[token_info.token] = token_info

    def get(self, token: str) -> TokenInfo | None:
        """Retrieve token info."""
        if token in self._revoked:
            return None
        info = self._tokens.get(token)
        if info and info.is_expired:
            self._tokens.pop(token, None)
            return None
        return info

    def revoke(self, token: str) -> bool:
        """Revoke a token."""
        if token in self._tokens:
            self._tokens.pop(token, None)
            self._revoked.add(token)
            return True
        return False

    def is_revoked(self, token: str) -> bool:
        """Check if token is revoked."""
        return token in self._revoked

    def cleanup_expired(self) -> int:
        """Remove expired tokens. Returns count removed."""
        now = int(time.time())
        expired = [t for t, info in self._tokens.items() if info.expires_at < now]
        for t in expired:
            self._tokens.pop(t, None)
        return len(expired)


class NonceManager:
    """
    Manages nonces for HMAC replay attack prevention.

    Tracks used nonces within a time window to prevent replay attacks.
    """

    def __init__(self, cleanup_interval: int = 3600) -> None:
        """Initialize nonce manager."""
        self._used_nonces: dict[str, int] = {}  # nonce -> timestamp
        self.cleanup_interval = cleanup_interval
        self._last_cleanup = time.time()

    def generate(self) -> str:
        """Generate a new unique nonce."""
        return secrets.token_hex(16)

    def is_duplicate(self, nonce: str) -> bool:
        """Check if nonce has been used."""
        self._maybe_cleanup()
        return nonce in self._used_nonces

    def mark_used(self, nonce: str) -> None:
        """Mark nonce as used."""
        self._used_nonces[nonce] = int(time.time())

    def _maybe_cleanup(self) -> None:
        """Clean up old nonces periodically."""
        now = time.time()
        if now - self._last_cleanup > self.cleanup_interval:
            cutoff = int(now) - self.cleanup_interval
            self._used_nonces = {
                n: ts for n, ts in self._used_nonces.items() if ts > cutoff
            }
            self._last_cleanup = now


class TokenService:
    """
    Centralized token service for The Gatekeeper.

    Handles:
    - Bearer token issuance and validation
    - HMAC signature generation and verification
    - Token revocation
    - Nonce/replay protection
    """

    # Default HMAC key (hex-encoded) - INSECURE, for testing only
    _DEFAULT_KEY = "746573742d686d61632d6b6579"

    def __init__(
        self,
        hmac_key: str | None = None,
        token_ttl: int = 3600,
        timestamp_skew: int = 300,
    ) -> None:
        """
        Initialize token service.

        Args:
            hmac_key: HMAC key for signature operations. Falls back to
                      APERION_HMAC_KEY env var, then default (with warning).
            token_ttl: Default token TTL in seconds.
            timestamp_skew: Allowed timestamp skew for HMAC validation.
        """
        env_key = os.environ.get("APERION_HMAC_KEY")
        self.hmac_key = hmac_key or env_key or self._DEFAULT_KEY

        if self.hmac_key == self._DEFAULT_KEY:
            warnings.warn(
                "Using default HMAC key! Set APERION_HMAC_KEY for production.",
                UserWarning,
                stacklevel=2,
            )

        self.token_ttl = token_ttl
        self.timestamp_skew = timestamp_skew
        self._store = TokenStore()
        self._nonces = NonceManager()

    # -------------------------------------------------------------------------
    # Bearer Token Operations
    # -------------------------------------------------------------------------

    def issue_token(
        self,
        principal: Principal,
        scopes: list[str] | None = None,
        ttl: int | None = None,
    ) -> TokenInfo:
        """
        Issue a new Bearer token for a principal.

        Args:
            principal: The authenticated identity.
            scopes: Optional scopes to restrict token access.
            ttl: Token time-to-live in seconds.

        Returns:
            TokenInfo with the issued token.
        """
        token = secrets.token_urlsafe(32)
        now = int(time.time())
        expires_at = now + (ttl or self.token_ttl)

        if scopes:
            principal.scopes = scopes

        token_info = TokenInfo(
            token=token,
            principal=principal,
            issued_at=now,
            expires_at=expires_at,
            token_type="Bearer",
        )

        self._store.store(token_info)
        return token_info

    def validate_token(self, token: str) -> AuthResult:
        """
        Validate a Bearer token.

        Args:
            token: The token string to validate.

        Returns:
            AuthResult with success status and principal if valid.
        """
        if not token:
            return AuthResult(
                success=False,
                errors=["Token is required"],
                auth_method=AuthMethod.BEARER,
            )

        if self._store.is_revoked(token):
            return AuthResult(
                success=False,
                errors=["Token has been revoked"],
                auth_method=AuthMethod.BEARER,
            )

        token_info = self._store.get(token)
        if not token_info:
            return AuthResult(
                success=False,
                errors=["Invalid or expired token"],
                auth_method=AuthMethod.BEARER,
            )

        return AuthResult(
            success=True,
            principal=token_info.principal,
            auth_method=AuthMethod.BEARER,
        )

    def revoke_token(self, token: str) -> bool:
        """
        Revoke a token.

        Args:
            token: The token to revoke.

        Returns:
            True if token was revoked, False if not found.
        """
        return self._store.revoke(token)

    # -------------------------------------------------------------------------
    # HMAC Authentication
    # -------------------------------------------------------------------------

    def generate_hmac_signature(
        self,
        timestamp: int,
        nonce: str,
        method: str,
        path: str,
    ) -> str:
        """
        Generate HMAC signature for a request.

        Args:
            timestamp: Unix timestamp.
            nonce: Unique nonce for replay protection.
            method: HTTP method.
            path: Request path.

        Returns:
            Hex-encoded HMAC-SHA256 signature.
        """
        message = f"{timestamp}:{nonce}:{method}:{path}"
        key_bytes = bytes.fromhex(self.hmac_key)
        signature = hmac.new(
            key_bytes, message.encode("utf-8"), hashlib.sha256
        ).hexdigest()
        return signature

    def create_hmac_header(
        self,
        method: str,
        path: str,
        timestamp: int | None = None,
        nonce: str | None = None,
    ) -> str:
        """
        Create an HMAC authorization header.

        Args:
            method: HTTP method.
            path: Request path.
            timestamp: Optional timestamp (defaults to now).
            nonce: Optional nonce (defaults to generated).

        Returns:
            Authorization header value: "HMAC timestamp:nonce:signature"
        """
        if timestamp is None:
            timestamp = int(time.time())
        if nonce is None:
            nonce = self._nonces.generate()

        signature = self.generate_hmac_signature(timestamp, nonce, method, path)
        return f"HMAC {timestamp}:{nonce}:{signature}"

    def validate_hmac(
        self,
        auth_header: str,
        method: str,
        path: str,
    ) -> AuthResult:
        """
        Validate an HMAC authorization header.

        Args:
            auth_header: The Authorization header value.
            method: HTTP method.
            path: Request path.

        Returns:
            AuthResult with success status.
        """
        # Parse header
        if not auth_header or not auth_header.startswith("HMAC "):
            return AuthResult(
                success=False,
                errors=["Invalid HMAC header format"],
                auth_method=AuthMethod.HMAC,
            )

        try:
            parts = auth_header[5:].split(":")
            if len(parts) != 3:
                return AuthResult(
                    success=False,
                    errors=["Invalid HMAC header format"],
                    auth_method=AuthMethod.HMAC,
                )

            timestamp_str, nonce, signature = parts
            timestamp = int(timestamp_str)
        except (ValueError, IndexError):
            return AuthResult(
                success=False,
                errors=["Malformed HMAC header"],
                auth_method=AuthMethod.HMAC,
            )

        # Validate timestamp
        now = int(time.time())
        time_diff = abs(now - timestamp)
        if time_diff > self.timestamp_skew:
            if timestamp > now:
                return AuthResult(
                    success=False,
                    errors=["Timestamp is too far in the future"],
                    auth_method=AuthMethod.HMAC,
                )
            return AuthResult(
                success=False,
                errors=["Timestamp is expired"],
                auth_method=AuthMethod.HMAC,
            )

        # Check replay
        if self._nonces.is_duplicate(nonce):
            return AuthResult(
                success=False,
                errors=["Replay attack detected"],
                auth_method=AuthMethod.HMAC,
            )

        # Verify signature
        expected = self.generate_hmac_signature(timestamp, nonce, method, path)
        if not hmac.compare_digest(signature, expected):
            return AuthResult(
                success=False,
                errors=["Invalid signature"],
                auth_method=AuthMethod.HMAC,
            )

        # Mark nonce as used
        self._nonces.mark_used(nonce)

        # Create principal for HMAC-authenticated request
        principal = Principal(
            user_id="hmac_authenticated",
            roles=[Role.SERVICE],
            permissions=[Permission.READ, Permission.WRITE, Permission.EXECUTE],
            auth_method=AuthMethod.HMAC,
        )

        return AuthResult(
            success=True,
            principal=principal,
            auth_method=AuthMethod.HMAC,
        )

    # -------------------------------------------------------------------------
    # Unified Authentication
    # -------------------------------------------------------------------------

    def authenticate(
        self,
        auth_header: str,
        method: str = "GET",
        path: str = "/",
    ) -> AuthResult:
        """
        Authenticate a request using the appropriate method.

        Automatically detects Bearer vs HMAC based on header prefix.

        Args:
            auth_header: The Authorization header value.
            method: HTTP method (for HMAC).
            path: Request path (for HMAC).

        Returns:
            AuthResult with success status and principal.
        """
        if not auth_header:
            return AuthResult(
                success=False,
                errors=["Authorization header required"],
            )

        if auth_header.startswith("Bearer "):
            token = auth_header[7:]
            return self.validate_token(token)

        if auth_header.startswith("HMAC "):
            return self.validate_hmac(auth_header, method, path)

        return AuthResult(
            success=False,
            errors=["Unsupported authentication method"],
        )

    # -------------------------------------------------------------------------
    # Utilities
    # -------------------------------------------------------------------------

    def get_stats(self) -> dict[str, Any]:
        """Get token service statistics."""
        return {
            "active_tokens": len(self._store._tokens),
            "revoked_tokens": len(self._store._revoked),
            "used_nonces": len(self._nonces._used_nonces),
            "default_ttl": self.token_ttl,
            "timestamp_skew": self.timestamp_skew,
        }
