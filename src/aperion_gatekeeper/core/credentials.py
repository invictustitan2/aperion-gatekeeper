"""
Credential Management for Aperion Gatekeeper.

Handles secure key storage, rotation, and credential validation.
Supports loading from environment variables per Constitution B1.

Zero-trust: Default deny. Keys must be explicitly provided.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import secrets
import warnings
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import Enum
from typing import Protocol, runtime_checkable


class CredentialType(str, Enum):
    """Type of credential."""

    HMAC_KEY = "hmac_key"
    BEARER_TOKEN = "bearer_token"
    API_KEY = "api_key"


class KeyStatus(str, Enum):
    """Status of a key in the keyring."""

    ACTIVE = "active"  # Primary key for signing
    LEGACY = "legacy"  # Valid for verification only (rotation support)
    REVOKED = "revoked"  # No longer valid


@runtime_checkable
class Credential(Protocol):
    """Protocol for any credential type."""

    @property
    def credential_type(self) -> CredentialType:
        """Type of this credential."""
        ...

    @property
    def is_valid(self) -> bool:
        """Whether this credential is currently valid."""
        ...


@dataclass(frozen=True)
class HMACKey:
    """
    HMAC signing key with rotation support.

    Keys support multiple states to allow zero-downtime rotation:
    - ACTIVE: Used for signing new requests
    - LEGACY: Valid for verification only (clients may still use old key)
    - REVOKED: No longer valid
    """

    key_id: str
    key_bytes: bytes
    status: KeyStatus = KeyStatus.ACTIVE
    created_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    expires_at: datetime | None = None

    @property
    def credential_type(self) -> CredentialType:
        """HMAC keys are of type HMAC_KEY."""
        return CredentialType.HMAC_KEY

    @property
    def is_valid(self) -> bool:
        """Key is valid if not revoked and not expired."""
        if self.status == KeyStatus.REVOKED:
            return False
        if self.expires_at and datetime.utcnow() > self.expires_at:
            return False
        return True

    @property
    def hex_key(self) -> str:
        """Return hex-encoded key for signing operations."""
        return self.key_bytes.hex()

    def sign(self, message: str) -> str:
        """
        Sign a message with this key.

        Args:
            message: Message to sign

        Returns:
            Hex-encoded signature
        """
        return hmac.new(
            self.key_bytes,
            message.encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()

    def verify(self, message: str, signature: str) -> bool:
        """
        Verify a signature against a message.

        Args:
            message: Original message
            signature: Hex-encoded signature to verify

        Returns:
            True if signature is valid
        """
        expected = self.sign(message)
        return hmac.compare_digest(expected, signature)


@dataclass(frozen=True)
class TokenCredential:
    """
    Bearer token credential.

    Simple token for API authentication. Supports environment variable loading.
    """

    token: str
    token_id: str = ""
    created_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    expires_at: datetime | None = None

    def __post_init__(self) -> None:
        """Generate token_id if not provided."""
        if not self.token_id:
            # Use object.__setattr__ since frozen=True
            object.__setattr__(self, "token_id", f"token_{secrets.token_hex(4)}")

    @property
    def credential_type(self) -> CredentialType:
        """Bearer tokens are of type BEARER_TOKEN."""
        return CredentialType.BEARER_TOKEN

    @property
    def is_valid(self) -> bool:
        """Token is valid if not empty and not expired."""
        if not self.token:
            return False
        if self.expires_at and datetime.now(UTC) > self.expires_at:
            return False
        return True

    def matches(self, candidate: str) -> bool:
        """
        Securely compare candidate token to stored token.

        Args:
            candidate: Token to compare

        Returns:
            True if tokens match
        """
        return hmac.compare_digest(self.token, candidate)


class KeyManager:
    """
    Secure key management with rotation support.

    The Keyring: Manages multiple keys to support zero-downtime rotation.
    Keys can be loaded from environment variables per Constitution B1.

    Usage:
        manager = KeyManager()
        manager.load_from_env("APERION_HMAC_KEY")  # Load primary key
        manager.add_legacy_key(old_key)  # Add legacy key for rotation

        # Signing uses active key
        sig = manager.sign_hmac(message)

        # Verification tries all valid keys
        if manager.verify_hmac(message, sig):
            ...
    """

    # Known insecure default keys - will warn if used
    _INSECURE_DEFAULTS = frozenset(
        {
            "746573742d686d61632d6b6579",  # "test-hmac-key" in hex
            "test-hmac-key",
            "development-key",
            "changeme",
        }
    )

    def __init__(self) -> None:
        """Initialize empty key manager."""
        self._hmac_keys: dict[str, HMACKey] = {}
        self._bearer_tokens: dict[str, TokenCredential] = {}
        self._active_hmac_key_id: str | None = None

    def load_hmac_from_env(
        self,
        env_var: str = "APERION_HMAC_KEY",
        *,
        key_id: str | None = None,
        make_active: bool = True,
    ) -> bool:
        """
        Load HMAC key from environment variable.

        Args:
            env_var: Environment variable name
            key_id: Optional key ID (defaults to env var name)
            make_active: Whether to make this the active signing key

        Returns:
            True if key was loaded successfully
        """
        key_value = os.environ.get(env_var)
        if not key_value:
            return False

        # Warn about insecure defaults
        if key_value in self._INSECURE_DEFAULTS:
            warnings.warn(
                f"Insecure default key loaded from {env_var}! "
                "This is NOT safe for production. Set a secure key.",
                UserWarning,
                stacklevel=2,
            )

        return self.add_hmac_key(
            key_value=key_value,
            key_id=key_id or env_var,
            make_active=make_active,
        )

    def add_hmac_key(
        self,
        key_value: str,
        *,
        key_id: str | None = None,
        status: KeyStatus = KeyStatus.ACTIVE,
        make_active: bool = True,
    ) -> bool:
        """
        Add an HMAC key to the keyring.

        Args:
            key_value: Key value (hex-encoded or raw string)
            key_id: Optional key ID
            status: Key status
            make_active: Whether to make this the active signing key

        Returns:
            True if key was added successfully
        """
        # Try to interpret as hex first, fall back to raw encoding
        try:
            key_bytes = bytes.fromhex(key_value)
        except ValueError:
            key_bytes = key_value.encode("utf-8")

        if not key_id:
            key_id = f"hmac_{secrets.token_hex(4)}"

        key = HMACKey(
            key_id=key_id,
            key_bytes=key_bytes,
            status=status,
        )

        self._hmac_keys[key_id] = key

        if make_active and status == KeyStatus.ACTIVE:
            self._active_hmac_key_id = key_id

        return True

    def add_legacy_key(self, key_value: str, *, key_id: str | None = None) -> bool:
        """
        Add a legacy HMAC key (verification only).

        Useful during key rotation to accept signatures from clients
        that haven't yet updated to the new key.

        Args:
            key_value: Key value
            key_id: Optional key ID

        Returns:
            True if key was added
        """
        return self.add_hmac_key(
            key_value=key_value,
            key_id=key_id,
            status=KeyStatus.LEGACY,
            make_active=False,
        )

    def revoke_key(self, key_id: str) -> bool:
        """
        Revoke a key by ID.

        Args:
            key_id: Key to revoke

        Returns:
            True if key was revoked
        """
        if key_id not in self._hmac_keys:
            return False

        old_key = self._hmac_keys[key_id]
        self._hmac_keys[key_id] = HMACKey(
            key_id=old_key.key_id,
            key_bytes=old_key.key_bytes,
            status=KeyStatus.REVOKED,
            created_at=old_key.created_at,
            expires_at=old_key.expires_at,
        )

        if self._active_hmac_key_id == key_id:
            self._active_hmac_key_id = None

        return True

    def load_bearer_from_env(
        self,
        env_var: str = "FSAL_TOKEN",
        *,
        token_id: str | None = None,
    ) -> bool:
        """
        Load bearer token from environment variable.

        Args:
            env_var: Environment variable name
            token_id: Optional token ID

        Returns:
            True if token was loaded
        """
        token_value = os.environ.get(env_var)
        if not token_value:
            return False

        token = TokenCredential(
            token=token_value,
            token_id=token_id or env_var,
        )

        self._bearer_tokens[token.token_id] = token
        return True

    @property
    def active_hmac_key(self) -> HMACKey | None:
        """Get the active HMAC signing key."""
        if not self._active_hmac_key_id:
            return None
        return self._hmac_keys.get(self._active_hmac_key_id)

    @property
    def valid_hmac_keys(self) -> list[HMACKey]:
        """Get all valid (non-revoked) HMAC keys for verification."""
        return [k for k in self._hmac_keys.values() if k.is_valid]

    def sign_hmac(self, message: str) -> str | None:
        """
        Sign a message with the active HMAC key.

        Args:
            message: Message to sign

        Returns:
            Hex-encoded signature, or None if no active key
        """
        key = self.active_hmac_key
        if not key:
            return None
        return key.sign(message)

    def verify_hmac(self, message: str, signature: str) -> bool:
        """
        Verify HMAC signature against all valid keys.

        Tries all valid keys (active and legacy) for verification.
        This supports zero-downtime key rotation.

        Args:
            message: Original message
            signature: Signature to verify

        Returns:
            True if signature matches any valid key
        """
        for key in self.valid_hmac_keys:
            if key.verify(message, signature):
                return True
        return False

    def verify_bearer(self, token: str) -> TokenCredential | None:
        """
        Verify a bearer token.

        Args:
            token: Token to verify

        Returns:
            Matching TokenCredential if valid, None otherwise
        """
        for cred in self._bearer_tokens.values():
            if cred.is_valid and cred.matches(token):
                return cred
        return None

    def has_keys(self) -> bool:
        """Check if any keys are loaded."""
        return bool(self._hmac_keys) or bool(self._bearer_tokens)

    def get_key_info(self) -> dict[str, list[dict[str, str]]]:
        """
        Get non-sensitive info about loaded keys.

        Returns:
            Dict with key metadata (no secrets)
        """
        return {
            "hmac_keys": [
                {
                    "key_id": k.key_id,
                    "status": k.status.value,
                    "is_active": k.key_id == self._active_hmac_key_id,
                }
                for k in self._hmac_keys.values()
            ],
            "bearer_tokens": [
                {
                    "token_id": t.token_id,
                    "is_valid": t.is_valid,
                }
                for t in self._bearer_tokens.values()
            ],
        }
