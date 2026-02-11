"""
Key Management for The Gatekeeper (Compatibility Layer).

Centralized key validation, rotation support, and security checks.
Ensures production deployments use secure keys.

Ported from the embedded stack.aperion.gatekeeper.keys module.
"""

from __future__ import annotations

import os
import sys
import warnings
from typing import Any

from .models import KeyValidationResult


# Known insecure default keys that must not be used in production
INSECURE_PATTERNS: dict[str, list[str]] = {
    "APERION_HMAC_KEY": [
        "746573742d686d61632d6b6579",  # hex of "test-hmac-key"
        "test-hmac-key",
        "aperion-default-key-replace-in-prod",
    ],
    "FSAL_TOKEN": [
        "test-token",
        "development-token",
        "default-fsal-token",
        "aperion-fsal-default",
        "dev-token",
    ],
    "GATEKEEPER_SECRET": [
        "gatekeeper-default",
        "test-secret",
    ],
    "GENERIC": [
        "test",
        "development",
        "dev",
        "localhost",
        "changeme",
        "secret",
        "password",
        "demo",
        "example",
        "placeholder",
    ],
}

# Minimum recommended key lengths
MIN_KEY_LENGTHS: dict[str, int] = {
    "APERION_HMAC_KEY": 32,  # 256 bits hex = 64 chars, but 32 is acceptable
    "FSAL_TOKEN": 16,
    "GATEKEEPER_SECRET": 32,
}


class KeyManager:
    """
    Centralized key management for The Gatekeeper.

    Handles:
    - Key validation on startup
    - Detection of insecure defaults
    - Key rotation with grace periods
    - Secure key generation guidance
    """

    def __init__(self) -> None:
        """Initialize key manager."""
        self._active_keys: dict[str, str] = {}
        self._previous_keys: dict[str, str] = {}  # For rotation grace period
        self._rotation_timestamps: dict[str, int] = {}

    def validate_key(
        self,
        key: str | None,
        key_name: str,
    ) -> KeyValidationResult:
        """
        Validate a single key against known insecure patterns.

        Args:
            key: The key value to validate.
            key_name: Name of the key/env var (for error messages).

        Returns:
            KeyValidationResult with validation status.
        """
        result = KeyValidationResult(valid=True)

        if not key or key.strip() == "":
            result.warnings.append(
                f"{key_name} is not set - using insecure defaults"
            )
            return result

        # Check against known insecure keys
        key_specific = INSECURE_PATTERNS.get(key_name, [])
        all_insecure = key_specific + INSECURE_PATTERNS["GENERIC"]

        lower_key = key.lower()
        for insecure in all_insecure:
            if lower_key == insecure or insecure in lower_key:
                result.valid = False
                result.errors.append(
                    f'{key_name} contains insecure pattern: "{insecure}". '
                    f"Generate secure keys with: openssl rand -base64 32"
                )
                return result

        # Check minimum length
        min_length = MIN_KEY_LENGTHS.get(key_name, 24)
        if len(key) < min_length:
            result.warnings.append(
                f"{key_name} is shorter than recommended ({min_length}+ chars). "
                f"Consider generating a stronger key."
            )

        return result

    def validate_all_keys(self) -> KeyValidationResult:
        """
        Validate all security keys used by Gatekeeper.

        Checks environment variables for all known keys.

        Returns:
            KeyValidationResult with overall validation status.
        """
        is_production = (
            os.environ.get("ENV") == "production"
            or os.environ.get("NODE_ENV") == "production"
            or os.environ.get("APERION_ENV") == "production"
        )

        combined = KeyValidationResult(valid=True)

        # Validate each known key
        keys_to_check = ["APERION_HMAC_KEY", "FSAL_TOKEN", "GATEKEEPER_SECRET"]
        for key_name in keys_to_check:
            result = self.validate_key(os.environ.get(key_name), key_name)
            combined.warnings.extend(result.warnings)
            combined.errors.extend(result.errors)
            combined.valid = combined.valid and result.valid

        # In production, warnings become errors
        if is_production:
            if combined.warnings:
                combined.valid = False
                combined.errors.append(
                    "Production requires all security keys to be explicitly set. "
                    "See warnings above."
                )

        return combined

    def enforce_validation(self) -> None:
        """
        Fail-fast if keys are invalid.

        Call at application startup to ensure secure keys before
        accepting requests.

        Raises:
            RuntimeError: If validation fails.
        """
        result = self.validate_all_keys()
        self.log_validation(result)

        if not result.valid:
            msg = (
                "[GATEKEEPER] Startup blocked due to insecure keys. "
                "Set secure environment variables."
            )
            print(msg, file=sys.stderr)
            raise RuntimeError(msg)

    def log_validation(self, result: KeyValidationResult) -> None:
        """Log validation results."""
        if result.warnings:
            for warning in result.warnings:
                warnings.warn(f"[GATEKEEPER] {warning}", UserWarning, stacklevel=3)

        if result.errors:
            for error in result.errors:
                print(f"[GATEKEEPER ERROR] {error}", file=sys.stderr)

        if result.valid and not result.warnings:
            print("[GATEKEEPER] All security keys validated successfully")

    def set_key(self, key_name: str, value: str) -> None:
        """
        Set or update a key (for rotation).

        The previous key is preserved for a grace period to allow
        in-flight requests to complete.

        Args:
            key_name: Name of the key.
            value: New key value.
        """
        import time

        if key_name in self._active_keys:
            self._previous_keys[key_name] = self._active_keys[key_name]
            self._rotation_timestamps[key_name] = int(time.time())

        self._active_keys[key_name] = value

    def get_key(self, key_name: str) -> str | None:
        """Get current active key."""
        return self._active_keys.get(key_name)

    def validate_with_rotation(
        self,
        key_name: str,
        provided_key: str,
        grace_period: int = 300,
    ) -> bool:
        """
        Validate a key, allowing previous key during grace period.

        Args:
            key_name: Name of the key.
            provided_key: Key to validate.
            grace_period: Seconds to accept previous key after rotation.

        Returns:
            True if key matches current or recent previous key.
        """
        import time

        # Check active key
        active = self._active_keys.get(key_name)
        if active and provided_key == active:
            return True

        # Check previous key during grace period
        previous = self._previous_keys.get(key_name)
        timestamp = self._rotation_timestamps.get(key_name, 0)
        if previous and provided_key == previous:
            if int(time.time()) - timestamp <= grace_period:
                return True

        return False

    def get_stats(self) -> dict[str, Any]:
        """Get key manager statistics."""
        return {
            "active_keys": list(self._active_keys.keys()),
            "keys_with_previous": list(self._previous_keys.keys()),
            "rotation_timestamps": self._rotation_timestamps.copy(),
        }


# Convenience function for quick validation
def validate_security_keys() -> KeyValidationResult:
    """Validate all security keys. Convenience wrapper."""
    manager = KeyManager()
    return manager.validate_all_keys()


def enforce_key_validation() -> None:
    """Fail-fast if keys are invalid. Convenience wrapper."""
    manager = KeyManager()
    manager.enforce_validation()


# Alias for backward compat with security/key_validation.py
INSECURE_KEYS = INSECURE_PATTERNS
