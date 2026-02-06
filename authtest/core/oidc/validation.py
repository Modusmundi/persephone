"""JWT token validation for OIDC.

Provides signature validation against IdP JWKS and standard claim validation
for OIDC ID tokens and access tokens.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

import httpx
import jwt
from jwt import PyJWKClient, PyJWKClientError


class ValidationStatus(StrEnum):
    """Status of a validation check."""

    VALID = "valid"
    INVALID = "invalid"
    SKIPPED = "skipped"
    WARNING = "warning"


@dataclass
class ValidationCheck:
    """Result of a single validation check."""

    name: str
    description: str
    status: ValidationStatus
    expected: str | None = None
    actual: str | None = None
    message: str = ""


@dataclass
class TokenValidationResult:
    """Complete validation result for a JWT token."""

    is_valid: bool = False
    signature_valid: bool | None = None  # None if not checked
    claims_valid: bool = False

    # Individual checks
    checks: list[ValidationCheck] = field(default_factory=list)

    # Overall messages
    error: str | None = None
    warnings: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for storage/serialization."""
        return {
            "is_valid": self.is_valid,
            "signature_valid": self.signature_valid,
            "claims_valid": self.claims_valid,
            "checks": [
                {
                    "name": c.name,
                    "description": c.description,
                    "status": c.status.value,
                    "expected": c.expected,
                    "actual": c.actual,
                    "message": c.message,
                }
                for c in self.checks
            ],
            "error": self.error,
            "warnings": self.warnings,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> TokenValidationResult:
        """Reconstruct from dictionary."""
        result = cls(
            is_valid=data.get("is_valid", False),
            signature_valid=data.get("signature_valid"),
            claims_valid=data.get("claims_valid", False),
            error=data.get("error"),
            warnings=data.get("warnings", []),
        )
        for check_data in data.get("checks", []):
            result.checks.append(
                ValidationCheck(
                    name=check_data["name"],
                    description=check_data["description"],
                    status=ValidationStatus(check_data["status"]),
                    expected=check_data.get("expected"),
                    actual=check_data.get("actual"),
                    message=check_data.get("message", ""),
                )
            )
        return result


class JWKSManager:
    """Manages fetching and caching JWKS from IdPs."""

    def __init__(self, jwks_uri: str, timeout: float = 10.0) -> None:
        """Initialize JWKS manager.

        Args:
            jwks_uri: URI to fetch JWKS from.
            timeout: HTTP timeout in seconds.
        """
        self.jwks_uri = jwks_uri
        self.timeout = timeout
        self._jwks_client: PyJWKClient | None = None

    def get_signing_key(self, token: str) -> Any:
        """Get the signing key for a token from JWKS.

        Args:
            token: JWT token string.

        Returns:
            Signing key for the token.

        Raises:
            PyJWKClientError: If key cannot be found.
        """
        if not self._jwks_client:
            self._jwks_client = PyJWKClient(self.jwks_uri, timeout=self.timeout)
        return self._jwks_client.get_signing_key_from_jwt(token)

    def fetch_jwks(self) -> dict[str, Any]:
        """Fetch the raw JWKS document.

        Returns:
            JWKS document as dictionary.
        """
        try:
            response = httpx.get(self.jwks_uri, timeout=self.timeout, verify=False)
            if response.status_code == 200:
                result: dict[str, Any] = response.json()
                return result
        except Exception:
            pass
        return {}


class TokenValidator:
    """Validates JWT tokens against IdP configuration."""

    def __init__(
        self,
        jwks_uri: str | None = None,
        issuer: str | None = None,
        audience: str | None = None,
        clock_skew_seconds: int = 120,
    ) -> None:
        """Initialize the token validator.

        Args:
            jwks_uri: URI to fetch JWKS for signature verification.
            issuer: Expected issuer (iss claim).
            audience: Expected audience (aud claim) - typically the client_id.
            clock_skew_seconds: Allowed clock skew for time-based validation.
        """
        self.jwks_uri = jwks_uri
        self.issuer = issuer
        self.audience = audience
        self.clock_skew_seconds = clock_skew_seconds
        self._jwks_manager: JWKSManager | None = None

    @property
    def jwks_manager(self) -> JWKSManager | None:
        """Get or create JWKS manager."""
        if self.jwks_uri and not self._jwks_manager:
            self._jwks_manager = JWKSManager(self.jwks_uri)
        return self._jwks_manager

    def validate_token(
        self,
        token: str,
        nonce: str | None = None,
        validate_signature: bool = True,
    ) -> TokenValidationResult:
        """Validate a JWT token.

        Args:
            token: JWT token string.
            nonce: Expected nonce value (for ID tokens).
            validate_signature: Whether to validate signature against JWKS.

        Returns:
            TokenValidationResult with all validation checks.
        """
        result = TokenValidationResult()

        # First, decode without verification to get claims
        try:
            unverified_header = jwt.get_unverified_header(token)
            unverified_payload = jwt.decode(token, options={"verify_signature": False})
        except jwt.exceptions.DecodeError as e:
            result.error = f"Invalid JWT format: {e}"
            return result

        # Add algorithm check
        alg = unverified_header.get("alg", "")
        alg_check = ValidationCheck(
            name="Algorithm",
            description="Signing algorithm",
            status=ValidationStatus.VALID if alg in _SECURE_ALGORITHMS else ValidationStatus.WARNING,
            actual=alg,
            message=_get_algorithm_message(alg),
        )
        result.checks.append(alg_check)
        if alg == "none":
            result.warnings.append("Token has no signature (alg=none). This is insecure.")
        elif alg not in _SECURE_ALGORITHMS:
            result.warnings.append(f"Algorithm '{alg}' may not be secure.")

        # Validate signature if requested and JWKS is available
        if validate_signature:
            sig_result = self._validate_signature(token)
            result.checks.append(sig_result)
            result.signature_valid = sig_result.status == ValidationStatus.VALID
        else:
            result.checks.append(
                ValidationCheck(
                    name="Signature",
                    description="Token signature verification",
                    status=ValidationStatus.SKIPPED,
                    message="Signature validation skipped (no JWKS URI or validation disabled)",
                )
            )

        # Validate standard claims
        claim_checks = self._validate_claims(unverified_payload, nonce)
        result.checks.extend(claim_checks)

        # Determine overall claims validity
        claim_statuses = [c.status for c in claim_checks]
        result.claims_valid = all(s in (ValidationStatus.VALID, ValidationStatus.SKIPPED) for s in claim_statuses)

        # Overall validity
        result.is_valid = (result.signature_valid is not False) and result.claims_valid

        return result

    def _validate_signature(self, token: str) -> ValidationCheck:
        """Validate token signature against JWKS.

        Args:
            token: JWT token string.

        Returns:
            ValidationCheck for signature.
        """
        if not self.jwks_uri:
            return ValidationCheck(
                name="Signature",
                description="Token signature verification",
                status=ValidationStatus.SKIPPED,
                message="No JWKS URI configured for signature validation",
            )

        try:
            # Get the signing key from JWKS
            manager = self.jwks_manager
            if not manager:
                return ValidationCheck(
                    name="Signature",
                    description="Token signature verification",
                    status=ValidationStatus.SKIPPED,
                    message="Could not initialize JWKS client",
                )

            signing_key = manager.get_signing_key(token)

            # Decode with signature verification
            # Note: We only verify the signature here, claims are validated separately
            jwt.decode(
                token,
                signing_key.key,
                algorithms=list(_SECURE_ALGORITHMS),
                options={
                    "verify_exp": False,
                    "verify_nbf": False,
                    "verify_iat": False,
                    "verify_aud": False,
                    "verify_iss": False,
                },
            )

            return ValidationCheck(
                name="Signature",
                description="Token signature verification",
                status=ValidationStatus.VALID,
                message=f"Signature verified using key '{signing_key.key_id or 'unknown'}'",
            )

        except PyJWKClientError as e:
            return ValidationCheck(
                name="Signature",
                description="Token signature verification",
                status=ValidationStatus.INVALID,
                message=f"Could not find matching key in JWKS: {e}",
            )
        except jwt.exceptions.InvalidSignatureError:
            return ValidationCheck(
                name="Signature",
                description="Token signature verification",
                status=ValidationStatus.INVALID,
                message="Signature verification failed - token may have been tampered with",
            )
        except jwt.exceptions.DecodeError as e:
            return ValidationCheck(
                name="Signature",
                description="Token signature verification",
                status=ValidationStatus.INVALID,
                message=f"Could not decode token for signature validation: {e}",
            )
        except Exception as e:
            return ValidationCheck(
                name="Signature",
                description="Token signature verification",
                status=ValidationStatus.INVALID,
                message=f"Unexpected error during signature validation: {e}",
            )

    def _validate_claims(
        self,
        payload: dict[str, Any],
        nonce: str | None = None,
    ) -> list[ValidationCheck]:
        """Validate standard JWT/OIDC claims.

        Args:
            payload: Decoded JWT payload.
            nonce: Expected nonce for ID tokens.

        Returns:
            List of ValidationCheck results.
        """
        checks = []
        now = datetime.now(UTC).timestamp()

        # Issuer (iss)
        iss = payload.get("iss")
        if self.issuer:
            checks.append(
                ValidationCheck(
                    name="Issuer (iss)",
                    description="Token issuer matches expected IdP",
                    status=ValidationStatus.VALID if iss == self.issuer else ValidationStatus.INVALID,
                    expected=self.issuer,
                    actual=str(iss) if iss else "(not present)",
                    message="Issuer matches" if iss == self.issuer else "Issuer mismatch",
                )
            )
        elif iss:
            checks.append(
                ValidationCheck(
                    name="Issuer (iss)",
                    description="Token issuer",
                    status=ValidationStatus.VALID,
                    actual=str(iss),
                    message="Issuer present (no expected value configured)",
                )
            )
        else:
            checks.append(
                ValidationCheck(
                    name="Issuer (iss)",
                    description="Token issuer",
                    status=ValidationStatus.WARNING,
                    message="Issuer claim not present",
                )
            )

        # Audience (aud)
        aud = payload.get("aud")
        if self.audience:
            aud_valid = False
            if isinstance(aud, list):
                aud_valid = self.audience in aud
                aud_str = ", ".join(aud)
            else:
                aud_valid = aud == self.audience
                aud_str = str(aud) if aud else "(not present)"

            checks.append(
                ValidationCheck(
                    name="Audience (aud)",
                    description="Token audience includes expected client",
                    status=ValidationStatus.VALID if aud_valid else ValidationStatus.INVALID,
                    expected=self.audience,
                    actual=aud_str,
                    message="Audience matches" if aud_valid else "Audience mismatch",
                )
            )
        elif aud:
            aud_str = ", ".join(aud) if isinstance(aud, list) else str(aud)
            checks.append(
                ValidationCheck(
                    name="Audience (aud)",
                    description="Token audience",
                    status=ValidationStatus.VALID,
                    actual=aud_str,
                    message="Audience present (no expected value configured)",
                )
            )

        # Expiration (exp)
        exp = payload.get("exp")
        if exp:
            exp_dt = datetime.fromtimestamp(exp, tz=UTC)
            is_expired = now > exp + self.clock_skew_seconds
            checks.append(
                ValidationCheck(
                    name="Expiration (exp)",
                    description="Token has not expired",
                    status=ValidationStatus.INVALID if is_expired else ValidationStatus.VALID,
                    actual=exp_dt.isoformat(),
                    message="Token has expired" if is_expired else "Token is not expired",
                )
            )
        else:
            checks.append(
                ValidationCheck(
                    name="Expiration (exp)",
                    description="Token expiration time",
                    status=ValidationStatus.WARNING,
                    message="Expiration claim not present - token never expires",
                )
            )

        # Not Before (nbf)
        nbf = payload.get("nbf")
        if nbf:
            nbf_dt = datetime.fromtimestamp(nbf, tz=UTC)
            is_not_yet_valid = now < nbf - self.clock_skew_seconds
            checks.append(
                ValidationCheck(
                    name="Not Before (nbf)",
                    description="Token is valid for current time",
                    status=ValidationStatus.INVALID if is_not_yet_valid else ValidationStatus.VALID,
                    actual=nbf_dt.isoformat(),
                    message="Token not yet valid" if is_not_yet_valid else "Token is valid for current time",
                )
            )

        # Issued At (iat)
        iat = payload.get("iat")
        if iat:
            iat_dt = datetime.fromtimestamp(iat, tz=UTC)
            is_future = now < iat - self.clock_skew_seconds
            checks.append(
                ValidationCheck(
                    name="Issued At (iat)",
                    description="Token issue time is not in future",
                    status=ValidationStatus.INVALID if is_future else ValidationStatus.VALID,
                    actual=iat_dt.isoformat(),
                    message="Token issued in the future (clock skew?)" if is_future else "Issue time is valid",
                )
            )

        # Subject (sub)
        sub = payload.get("sub")
        if sub:
            checks.append(
                ValidationCheck(
                    name="Subject (sub)",
                    description="Token contains subject identifier",
                    status=ValidationStatus.VALID,
                    actual=str(sub),
                    message="Subject claim present",
                )
            )

        # Nonce (for ID tokens)
        token_nonce = payload.get("nonce")
        if nonce:
            checks.append(
                ValidationCheck(
                    name="Nonce",
                    description="Nonce matches request",
                    status=ValidationStatus.VALID if token_nonce == nonce else ValidationStatus.INVALID,
                    expected=nonce,
                    actual=str(token_nonce) if token_nonce else "(not present)",
                    message="Nonce matches" if token_nonce == nonce else "Nonce mismatch or missing",
                )
            )

        return checks


# Secure algorithms (asymmetric only - symmetric algs require shared secret)
_SECURE_ALGORITHMS = frozenset(
    {
        "RS256",
        "RS384",
        "RS512",  # RSA
        "ES256",
        "ES384",
        "ES512",  # ECDSA
        "PS256",
        "PS384",
        "PS512",  # RSA-PSS
        "EdDSA",  # Edwards-curve
    }
)


def _get_algorithm_message(alg: str) -> str:
    """Get a human-readable message about the algorithm.

    Args:
        alg: Algorithm identifier.

    Returns:
        Description of the algorithm.
    """
    messages = {
        "RS256": "RSA signature with SHA-256 (recommended)",
        "RS384": "RSA signature with SHA-384",
        "RS512": "RSA signature with SHA-512",
        "ES256": "ECDSA with P-256 curve and SHA-256 (recommended)",
        "ES384": "ECDSA with P-384 curve and SHA-384",
        "ES512": "ECDSA with P-521 curve and SHA-512",
        "PS256": "RSA-PSS with SHA-256",
        "PS384": "RSA-PSS with SHA-384",
        "PS512": "RSA-PSS with SHA-512",
        "EdDSA": "Edwards-curve Digital Signature Algorithm",
        "HS256": "HMAC with SHA-256 (symmetric - not recommended for OIDC)",
        "HS384": "HMAC with SHA-384 (symmetric - not recommended for OIDC)",
        "HS512": "HMAC with SHA-512 (symmetric - not recommended for OIDC)",
        "none": "No signature (INSECURE)",
    }
    return messages.get(alg, f"Unknown algorithm: {alg}")


def validate_id_token(
    token: str,
    jwks_uri: str | None = None,
    issuer: str | None = None,
    audience: str | None = None,
    nonce: str | None = None,
    clock_skew_seconds: int = 120,
) -> TokenValidationResult:
    """Convenience function to validate an ID token.

    Args:
        token: JWT token string.
        jwks_uri: URI to fetch JWKS for signature verification.
        issuer: Expected issuer (iss claim).
        audience: Expected audience (aud claim).
        nonce: Expected nonce value.
        clock_skew_seconds: Allowed clock skew for time-based validation.

    Returns:
        TokenValidationResult with all validation checks.
    """
    validator = TokenValidator(
        jwks_uri=jwks_uri,
        issuer=issuer,
        audience=audience,
        clock_skew_seconds=clock_skew_seconds,
    )
    return validator.validate_token(token, nonce=nonce)
