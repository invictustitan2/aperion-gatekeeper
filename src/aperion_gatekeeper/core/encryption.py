"""
Centralized Cryptographic Utilities for Aperion Gatekeeper.

Wraps the cryptography library with secure defaults.
All crypto operations should go through this module.

Principles:
- Use proven algorithms (AES-GCM, SHA-256, Argon2)
- Fail-closed on any error
- No custom crypto implementations
"""

from __future__ import annotations

import hashlib
import hmac
import os
import secrets
from dataclasses import dataclass
from typing import Final

# Constants
NONCE_SIZE: Final[int] = 16
HMAC_ALGORITHM: Final[str] = "sha256"
MIN_KEY_LENGTH: Final[int] = 16


@dataclass(frozen=True)
class SecureBytes:
    """
    Wrapper for sensitive byte data.

    Prevents accidental logging/printing of secrets.
    """

    _data: bytes

    def __repr__(self) -> str:
        """Hide data in repr."""
        return f"SecureBytes(len={len(self._data)})"

    def __str__(self) -> str:
        """Hide data in str."""
        return "<SecureBytes>"

    def reveal(self) -> bytes:
        """Explicitly reveal the data when needed."""
        return self._data

    def reveal_hex(self) -> str:
        """Reveal as hex string."""
        return self._data.hex()


def generate_nonce(size: int = NONCE_SIZE) -> str:
    """
    Generate a cryptographically secure nonce.

    Args:
        size: Number of random bytes

    Returns:
        Hex-encoded nonce
    """
    return secrets.token_hex(size)


def generate_key(size: int = 32) -> SecureBytes:
    """
    Generate a cryptographically secure random key.

    Args:
        size: Key size in bytes (default 32 = 256 bits)

    Returns:
        SecureBytes containing the key
    """
    if size < MIN_KEY_LENGTH:
        raise ValueError(f"Key size must be at least {MIN_KEY_LENGTH} bytes")
    return SecureBytes(os.urandom(size))


def compute_hmac(key: bytes, message: bytes) -> str:
    """
    Compute HMAC-SHA256 of a message.

    Args:
        key: Secret key
        message: Message to sign

    Returns:
        Hex-encoded HMAC
    """
    return hmac.new(key, message, hashlib.sha256).hexdigest()


def verify_hmac_constant_time(key: bytes, message: bytes, signature: str) -> bool:
    """
    Verify HMAC signature using constant-time comparison.

    Args:
        key: Secret key
        message: Original message
        signature: Hex-encoded signature to verify

    Returns:
        True if signature is valid
    """
    expected = compute_hmac(key, message)
    return hmac.compare_digest(expected, signature)


def secure_hash(data: bytes) -> str:
    """
    Compute SHA-256 hash of data.

    Args:
        data: Data to hash

    Returns:
        Hex-encoded hash
    """
    return hashlib.sha256(data).hexdigest()


def constant_time_compare(a: str, b: str) -> bool:
    """
    Compare two strings in constant time.

    Prevents timing attacks on secret comparison.

    Args:
        a: First string
        b: Second string

    Returns:
        True if strings are equal
    """
    return hmac.compare_digest(a.encode(), b.encode())
