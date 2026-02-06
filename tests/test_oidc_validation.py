"""Tests for OIDC token validation."""

import base64
import json
from datetime import UTC, datetime, timedelta


# Create a mock JWT token for testing (unsigned)
def _create_test_jwt(
    payload: dict,
    header: dict | None = None,
) -> str:
    """Create a test JWT token (without valid signature)."""
    if header is None:
        header = {"alg": "RS256", "typ": "JWT"}

    def b64_encode(data: dict) -> str:
        json_bytes = json.dumps(data).encode()
        return base64.urlsafe_b64encode(json_bytes).decode().rstrip("=")

    header_b64 = b64_encode(header)
    payload_b64 = b64_encode(payload)
    # Fake signature
    signature_b64 = "fake_signature_for_testing"

    return f"{header_b64}.{payload_b64}.{signature_b64}"


class TestTokenValidationResult:
    """Tests for TokenValidationResult."""

    def test_to_dict_and_from_dict(self) -> None:
        """Test serialization roundtrip."""
        from authtest.core.oidc.validation import (
            TokenValidationResult,
            ValidationCheck,
            ValidationStatus,
        )

        result = TokenValidationResult(
            is_valid=True,
            signature_valid=True,
            claims_valid=True,
            checks=[
                ValidationCheck(
                    name="Test Check",
                    description="A test check",
                    status=ValidationStatus.VALID,
                    expected="expected",
                    actual="actual",
                    message="Test message",
                )
            ],
            warnings=["Test warning"],
        )

        data = result.to_dict()
        restored = TokenValidationResult.from_dict(data)

        assert restored.is_valid == result.is_valid
        assert restored.signature_valid == result.signature_valid
        assert restored.claims_valid == result.claims_valid
        assert len(restored.checks) == 1
        assert restored.checks[0].name == "Test Check"
        assert restored.checks[0].status == ValidationStatus.VALID
        assert restored.warnings == ["Test warning"]


class TestTokenValidator:
    """Tests for TokenValidator."""

    def test_validate_claims_valid_token(self) -> None:
        """Test validation of a token with valid claims."""
        from authtest.core.oidc.validation import TokenValidator, ValidationStatus

        now = datetime.now(UTC)
        payload = {
            "iss": "https://example.com",
            "sub": "user123",
            "aud": "my-client",
            "exp": int((now + timedelta(hours=1)).timestamp()),
            "iat": int(now.timestamp()),
            "nonce": "test-nonce",
        }
        token = _create_test_jwt(payload)

        validator = TokenValidator(
            issuer="https://example.com",
            audience="my-client",
        )
        result = validator.validate_token(token, nonce="test-nonce", validate_signature=False)

        # Find specific checks
        checks_by_name = {c.name: c for c in result.checks}

        assert checks_by_name["Issuer (iss)"].status == ValidationStatus.VALID
        assert checks_by_name["Audience (aud)"].status == ValidationStatus.VALID
        assert checks_by_name["Expiration (exp)"].status == ValidationStatus.VALID
        assert checks_by_name["Nonce"].status == ValidationStatus.VALID

    def test_validate_claims_expired_token(self) -> None:
        """Test validation of an expired token."""
        from authtest.core.oidc.validation import TokenValidator, ValidationStatus

        now = datetime.now(UTC)
        payload = {
            "iss": "https://example.com",
            "sub": "user123",
            "aud": "my-client",
            "exp": int((now - timedelta(hours=1)).timestamp()),  # Expired
            "iat": int((now - timedelta(hours=2)).timestamp()),
        }
        token = _create_test_jwt(payload)

        validator = TokenValidator(
            issuer="https://example.com",
            audience="my-client",
        )
        result = validator.validate_token(token, validate_signature=False)

        checks_by_name = {c.name: c for c in result.checks}
        assert checks_by_name["Expiration (exp)"].status == ValidationStatus.INVALID

    def test_validate_claims_issuer_mismatch(self) -> None:
        """Test validation with issuer mismatch."""
        from authtest.core.oidc.validation import TokenValidator, ValidationStatus

        now = datetime.now(UTC)
        payload = {
            "iss": "https://wrong-issuer.com",
            "sub": "user123",
            "aud": "my-client",
            "exp": int((now + timedelta(hours=1)).timestamp()),
        }
        token = _create_test_jwt(payload)

        validator = TokenValidator(
            issuer="https://example.com",
            audience="my-client",
        )
        result = validator.validate_token(token, validate_signature=False)

        checks_by_name = {c.name: c for c in result.checks}
        assert checks_by_name["Issuer (iss)"].status == ValidationStatus.INVALID

    def test_validate_claims_audience_mismatch(self) -> None:
        """Test validation with audience mismatch."""
        from authtest.core.oidc.validation import TokenValidator, ValidationStatus

        now = datetime.now(UTC)
        payload = {
            "iss": "https://example.com",
            "sub": "user123",
            "aud": "wrong-client",
            "exp": int((now + timedelta(hours=1)).timestamp()),
        }
        token = _create_test_jwt(payload)

        validator = TokenValidator(
            issuer="https://example.com",
            audience="my-client",
        )
        result = validator.validate_token(token, validate_signature=False)

        checks_by_name = {c.name: c for c in result.checks}
        assert checks_by_name["Audience (aud)"].status == ValidationStatus.INVALID

    def test_validate_claims_audience_list(self) -> None:
        """Test validation with audience as a list."""
        from authtest.core.oidc.validation import TokenValidator, ValidationStatus

        now = datetime.now(UTC)
        payload = {
            "iss": "https://example.com",
            "sub": "user123",
            "aud": ["my-client", "other-client"],
            "exp": int((now + timedelta(hours=1)).timestamp()),
        }
        token = _create_test_jwt(payload)

        validator = TokenValidator(
            issuer="https://example.com",
            audience="my-client",
        )
        result = validator.validate_token(token, validate_signature=False)

        checks_by_name = {c.name: c for c in result.checks}
        assert checks_by_name["Audience (aud)"].status == ValidationStatus.VALID

    def test_validate_claims_nonce_mismatch(self) -> None:
        """Test validation with nonce mismatch."""
        from authtest.core.oidc.validation import TokenValidator, ValidationStatus

        now = datetime.now(UTC)
        payload = {
            "iss": "https://example.com",
            "sub": "user123",
            "aud": "my-client",
            "exp": int((now + timedelta(hours=1)).timestamp()),
            "nonce": "wrong-nonce",
        }
        token = _create_test_jwt(payload)

        validator = TokenValidator(
            issuer="https://example.com",
            audience="my-client",
        )
        result = validator.validate_token(token, nonce="expected-nonce", validate_signature=False)

        checks_by_name = {c.name: c for c in result.checks}
        assert checks_by_name["Nonce"].status == ValidationStatus.INVALID

    def test_validate_insecure_algorithm(self) -> None:
        """Test validation warns about insecure algorithm."""
        from authtest.core.oidc.validation import TokenValidator, ValidationStatus

        now = datetime.now(UTC)
        payload = {
            "iss": "https://example.com",
            "sub": "user123",
            "exp": int((now + timedelta(hours=1)).timestamp()),
        }
        # Token with 'none' algorithm
        token = _create_test_jwt(payload, header={"alg": "none", "typ": "JWT"})

        validator = TokenValidator()
        result = validator.validate_token(token, validate_signature=False)

        checks_by_name = {c.name: c for c in result.checks}
        assert checks_by_name["Algorithm"].status == ValidationStatus.WARNING
        assert any("none" in w.lower() for w in result.warnings)

    def test_validate_nbf_future(self) -> None:
        """Test validation of token not yet valid."""
        from authtest.core.oidc.validation import TokenValidator, ValidationStatus

        now = datetime.now(UTC)
        payload = {
            "iss": "https://example.com",
            "sub": "user123",
            "exp": int((now + timedelta(hours=1)).timestamp()),
            "nbf": int((now + timedelta(hours=1)).timestamp()),  # Not valid yet
        }
        token = _create_test_jwt(payload)

        validator = TokenValidator(clock_skew_seconds=0)
        result = validator.validate_token(token, validate_signature=False)

        checks_by_name = {c.name: c for c in result.checks}
        assert checks_by_name["Not Before (nbf)"].status == ValidationStatus.INVALID


class TestValidateIdToken:
    """Tests for the validate_id_token convenience function."""

    def test_validate_id_token_basic(self) -> None:
        """Test the convenience function."""
        from authtest.core.oidc.validation import validate_id_token

        now = datetime.now(UTC)
        payload = {
            "iss": "https://example.com",
            "sub": "user123",
            "aud": "my-client",
            "exp": int((now + timedelta(hours=1)).timestamp()),
            "nonce": "test-nonce",
        }
        token = _create_test_jwt(payload)

        result = validate_id_token(
            token,
            issuer="https://example.com",
            audience="my-client",
            nonce="test-nonce",
        )

        assert result.claims_valid is True
