"""Unit tests for authentication engine."""

import time

import pytest

from aperion_gatekeeper.core.credentials import KeyManager
from aperion_gatekeeper.engines.authentication import (
    AuthenticationEngine,
    AuthErrorCode,
    AuthMethod,
)


class TestAuthenticationEngine:
    """Tests for AuthenticationEngine."""

    @pytest.fixture
    def key_manager(self) -> KeyManager:
        """Create a key manager with test keys."""
        km = KeyManager()
        km.add_hmac_key("test-hmac-secret-key", key_id="test-hmac")
        return km

    @pytest.fixture
    def engine(self, key_manager: KeyManager) -> AuthenticationEngine:
        """Create authentication engine."""
        return AuthenticationEngine(key_manager)

    def test_missing_header_fails(self, engine: AuthenticationEngine) -> None:
        """Missing authorization header fails."""
        result = engine.authenticate(None)

        assert result.success is False
        assert result.error_code == AuthErrorCode.MISSING_HEADER

    def test_unknown_format_fails(self, engine: AuthenticationEngine) -> None:
        """Unknown auth format fails."""
        result = engine.authenticate("Basic dXNlcjpwYXNz")

        assert result.success is False
        assert result.error_code == AuthErrorCode.INVALID_FORMAT

    def test_hmac_authentication_success(self, engine: AuthenticationEngine) -> None:
        """Valid HMAC header authenticates successfully."""
        # Create valid header
        header = engine.create_hmac_header("GET", "/api/test")
        assert header is not None

        result = engine.authenticate(header, method="GET", path="/api/test")

        assert result.success is True
        assert result.method == AuthMethod.HMAC
        assert result.subject.is_authenticated is True

    def test_hmac_invalid_signature_fails(self, engine: AuthenticationEngine) -> None:
        """Invalid HMAC signature fails."""
        timestamp = int(time.time())
        header = f"HMAC {timestamp}:nonce123:invalidsignature"

        result = engine.authenticate(header, method="GET", path="/api/test")

        assert result.success is False
        assert result.error_code == AuthErrorCode.INVALID_SIGNATURE

    def test_hmac_expired_timestamp_fails(self, engine: AuthenticationEngine) -> None:
        """Expired timestamp fails."""
        old_timestamp = int(time.time()) - 600  # 10 minutes ago
        header = f"HMAC {old_timestamp}:nonce123:anysig"

        result = engine.authenticate(header, method="GET", path="/api/test")

        assert result.success is False
        assert result.error_code == AuthErrorCode.EXPIRED_TIMESTAMP

    def test_hmac_future_timestamp_fails(self, engine: AuthenticationEngine) -> None:
        """Future timestamp fails."""
        future_timestamp = int(time.time()) + 600  # 10 minutes in future
        header = f"HMAC {future_timestamp}:nonce123:anysig"

        result = engine.authenticate(header, method="GET", path="/api/test")

        assert result.success is False
        assert result.error_code == AuthErrorCode.FUTURE_TIMESTAMP

    def test_hmac_replay_detection(self, engine: AuthenticationEngine) -> None:
        """Replay attacks are detected."""
        # Create and use valid header
        header = engine.create_hmac_header("GET", "/api/test")
        assert header is not None

        # First request succeeds
        result1 = engine.authenticate(header, method="GET", path="/api/test")
        assert result1.success is True

        # Same header (replay) fails
        result2 = engine.authenticate(header, method="GET", path="/api/test")
        assert result2.success is False
        assert result2.error_code == AuthErrorCode.REPLAY_DETECTED

    def test_hmac_malformed_header_fails(self, engine: AuthenticationEngine) -> None:
        """Malformed HMAC header fails."""
        result = engine.authenticate("HMAC invalid-format")

        assert result.success is False
        assert result.error_code == AuthErrorCode.INVALID_FORMAT

    def test_bearer_authentication_success(self) -> None:
        """Valid Bearer token authenticates successfully."""
        km = KeyManager()
        km._bearer_tokens["test"] = km._bearer_tokens.get("test") or None

        # Add token manually
        from aperion_gatekeeper.core.credentials import TokenCredential

        km._bearer_tokens["test"] = TokenCredential(
            token="valid-token-123", token_id="test"
        )

        engine = AuthenticationEngine(km)
        result = engine.authenticate("Bearer valid-token-123")

        assert result.success is True
        assert result.method == AuthMethod.BEARER
        assert result.subject.is_authenticated is True

    def test_bearer_invalid_token_fails(self, key_manager: KeyManager) -> None:
        """Invalid Bearer token fails."""
        engine = AuthenticationEngine(key_manager)
        result = engine.authenticate("Bearer wrong-token")

        assert result.success is False
        assert result.error_code == AuthErrorCode.INVALID_TOKEN

    def test_bearer_empty_token_fails(self, engine: AuthenticationEngine) -> None:
        """Empty Bearer token fails."""
        result = engine.authenticate("Bearer ")

        assert result.success is False

    def test_no_keys_configured_fails(self) -> None:
        """Authentication fails when no keys configured."""
        empty_manager = KeyManager()
        engine = AuthenticationEngine(empty_manager)

        result = engine.authenticate(f"HMAC {int(time.time())}:nonce:sig")

        assert result.success is False
        assert result.error_code == AuthErrorCode.NO_KEYS_CONFIGURED

    def test_create_hmac_header(self, engine: AuthenticationEngine) -> None:
        """Can create valid HMAC headers."""
        header = engine.create_hmac_header("POST", "/api/data")

        assert header is not None
        assert header.startswith("HMAC ")
        parts = header[5:].split(":")
        assert len(parts) == 3
