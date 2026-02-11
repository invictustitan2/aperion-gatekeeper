"""Unit tests for credentials and key management."""

import os
from unittest import mock

import pytest

from aperion_gatekeeper.core.credentials import (
    HMACKey,
    KeyManager,
    KeyStatus,
    TokenCredential,
)


class TestHMACKey:
    """Tests for HMACKey."""

    def test_hmac_key_creation(self) -> None:
        """HMAC key can be created."""
        key = HMACKey(
            key_id="test-key",
            key_bytes=b"secret-key-bytes",
        )

        assert key.key_id == "test-key"
        assert key.status == KeyStatus.ACTIVE
        assert key.is_valid is True

    def test_hmac_key_sign_verify(self) -> None:
        """HMAC key can sign and verify messages."""
        key = HMACKey(
            key_id="test-key",
            key_bytes=b"secret-key-bytes",
        )

        message = "test-message"
        signature = key.sign(message)

        assert key.verify(message, signature) is True
        assert key.verify("wrong-message", signature) is False
        assert key.verify(message, "wrong-signature") is False

    def test_revoked_key_is_invalid(self) -> None:
        """Revoked keys are not valid."""
        key = HMACKey(
            key_id="test-key",
            key_bytes=b"secret",
            status=KeyStatus.REVOKED,
        )

        assert key.is_valid is False

    def test_legacy_key_is_valid(self) -> None:
        """Legacy keys are still valid for verification."""
        key = HMACKey(
            key_id="test-key",
            key_bytes=b"secret",
            status=KeyStatus.LEGACY,
        )

        assert key.is_valid is True


class TestTokenCredential:
    """Tests for TokenCredential."""

    def test_token_creation(self) -> None:
        """Token can be created."""
        token = TokenCredential(token="my-secret-token")

        assert token.token == "my-secret-token"
        assert token.is_valid is True

    def test_token_matches(self) -> None:
        """Token matching uses constant-time comparison."""
        token = TokenCredential(token="my-secret-token")

        assert token.matches("my-secret-token") is True
        assert token.matches("wrong-token") is False

    def test_empty_token_invalid(self) -> None:
        """Empty tokens are invalid."""
        token = TokenCredential(token="")

        assert token.is_valid is False


class TestKeyManager:
    """Tests for KeyManager."""

    def test_empty_manager(self) -> None:
        """Empty manager has no keys."""
        manager = KeyManager()

        assert manager.has_keys() is False
        assert manager.active_hmac_key is None
        assert manager.valid_hmac_keys == []

    def test_add_hmac_key(self) -> None:
        """Can add HMAC keys."""
        manager = KeyManager()

        result = manager.add_hmac_key("746573742d6b6579", key_id="test")

        assert result is True
        assert manager.has_keys() is True
        assert manager.active_hmac_key is not None
        assert manager.active_hmac_key.key_id == "test"

    def test_add_legacy_key(self) -> None:
        """Can add legacy keys for rotation."""
        manager = KeyManager()
        manager.add_hmac_key("new-key", key_id="new")
        manager.add_legacy_key("old-key", key_id="old")

        # Active key is still the first one
        assert manager.active_hmac_key.key_id == "new"

        # Both keys are valid for verification
        assert len(manager.valid_hmac_keys) == 2

    def test_sign_and_verify_hmac(self) -> None:
        """Can sign and verify with key manager."""
        manager = KeyManager()
        manager.add_hmac_key("my-secret-key", key_id="test")

        message = "test-message"
        signature = manager.sign_hmac(message)

        assert signature is not None
        assert manager.verify_hmac(message, signature) is True
        assert manager.verify_hmac("wrong", signature) is False

    def test_verify_with_legacy_key(self) -> None:
        """Verification works with legacy keys (rotation support)."""
        manager = KeyManager()

        # Add current key
        manager.add_hmac_key("new-key", key_id="new")

        # Add legacy key and sign with it directly
        legacy_key = HMACKey(key_id="legacy", key_bytes=b"old-key")
        manager._hmac_keys["legacy"] = legacy_key

        # Sign with legacy key
        legacy_signature = legacy_key.sign("test-message")

        # Manager should verify using legacy key
        assert manager.verify_hmac("test-message", legacy_signature) is True

    def test_revoke_key(self) -> None:
        """Can revoke keys."""
        manager = KeyManager()
        manager.add_hmac_key("secret", key_id="test")

        assert manager.active_hmac_key is not None

        manager.revoke_key("test")

        assert manager.active_hmac_key is None
        assert len(manager.valid_hmac_keys) == 0

    def test_load_from_env(self) -> None:
        """Can load keys from environment variables."""
        manager = KeyManager()

        with mock.patch.dict(os.environ, {"TEST_KEY": "env-secret-key"}):
            result = manager.load_hmac_from_env("TEST_KEY")

        assert result is True
        assert manager.has_keys() is True

    def test_load_missing_env_returns_false(self) -> None:
        """Loading from missing env var returns False."""
        manager = KeyManager()

        with mock.patch.dict(os.environ, {}, clear=True):
            result = manager.load_hmac_from_env("NONEXISTENT_KEY")

        assert result is False
        assert manager.has_keys() is False

    def test_insecure_default_warning(self) -> None:
        """Warning is raised for insecure default keys."""
        manager = KeyManager()

        with pytest.warns(UserWarning, match="Insecure default key"):
            with mock.patch.dict(os.environ, {"TEST": "746573742d686d61632d6b6579"}):
                manager.load_hmac_from_env("TEST")

    def test_bearer_token_management(self) -> None:
        """Can manage bearer tokens."""
        manager = KeyManager()

        with mock.patch.dict(os.environ, {"FSAL_TOKEN": "my-bearer-token"}):
            result = manager.load_bearer_from_env("FSAL_TOKEN")

        assert result is True

        # Verify token
        cred = manager.verify_bearer("my-bearer-token")
        assert cred is not None
        assert cred.token_id == "FSAL_TOKEN"

        # Wrong token returns None
        assert manager.verify_bearer("wrong-token") is None

    def test_get_key_info_no_secrets(self) -> None:
        """Key info doesn't expose secrets."""
        manager = KeyManager()
        manager.add_hmac_key("secret-key-here", key_id="test")

        info = manager.get_key_info()

        assert "hmac_keys" in info
        assert len(info["hmac_keys"]) == 1
        assert info["hmac_keys"][0]["key_id"] == "test"
        # Verify no secrets in output
        assert "secret" not in str(info).lower()
