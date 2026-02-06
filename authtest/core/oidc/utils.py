"""OIDC utility functions.

Provides utilities for decoding and inspecting JWT tokens,
including ID tokens and access tokens.
"""

from __future__ import annotations

import base64
import json
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any


@dataclass
class DecodedToken:
    """Represents a decoded JWT token."""

    header: dict[str, Any] = field(default_factory=dict)
    payload: dict[str, Any] = field(default_factory=dict)
    signature: str = ""

    # Decoded information
    is_valid_format: bool = True
    error: str | None = None

    # Common claims
    issuer: str | None = None
    subject: str | None = None
    audience: str | list[str] | None = None
    expiration: datetime | None = None
    issued_at: datetime | None = None
    not_before: datetime | None = None
    jwt_id: str | None = None
    nonce: str | None = None

    @property
    def is_expired(self) -> bool:
        """Check if the token is expired."""
        if self.expiration is None:
            return False
        return datetime.now(UTC) > self.expiration

    @property
    def algorithm(self) -> str | None:
        """Get the signing algorithm from the header."""
        return self.header.get("alg")

    @property
    def key_id(self) -> str | None:
        """Get the key ID from the header."""
        return self.header.get("kid")


def decode_jwt(token: str) -> DecodedToken:
    """Decode a JWT token without verification.

    This decodes the token for inspection purposes only.
    It does NOT verify the signature.

    Args:
        token: JWT token string.

    Returns:
        DecodedToken with header and payload.
    """
    try:
        parts = token.split(".")
        if len(parts) != 3:
            return DecodedToken(
                is_valid_format=False,
                error=f"Invalid JWT format: expected 3 parts, got {len(parts)}",
            )

        # Decode header
        header = _decode_base64url(parts[0])

        # Decode payload
        payload = _decode_base64url(parts[1])

        # Extract common claims
        decoded = DecodedToken(
            header=header,
            payload=payload,
            signature=parts[2],
            is_valid_format=True,
            issuer=payload.get("iss"),
            subject=payload.get("sub"),
            audience=payload.get("aud"),
            jwt_id=payload.get("jti"),
            nonce=payload.get("nonce"),
        )

        # Parse timestamps
        if "exp" in payload:
            decoded.expiration = datetime.fromtimestamp(payload["exp"], tz=UTC)
        if "iat" in payload:
            decoded.issued_at = datetime.fromtimestamp(payload["iat"], tz=UTC)
        if "nbf" in payload:
            decoded.not_before = datetime.fromtimestamp(payload["nbf"], tz=UTC)

        return decoded

    except Exception as e:
        return DecodedToken(
            is_valid_format=False,
            error=f"Failed to decode JWT: {e}",
        )


def _decode_base64url(data: str) -> dict[str, Any]:
    """Decode base64url-encoded JSON data.

    Args:
        data: Base64url-encoded string.

    Returns:
        Decoded JSON as dictionary.
    """
    # Add padding if needed
    padding = 4 - len(data) % 4
    if padding != 4:
        data += "=" * padding

    # Decode from base64url
    decoded_bytes = base64.urlsafe_b64decode(data)
    result: dict[str, Any] = json.loads(decoded_bytes)
    return result


def format_token_claims(payload: dict[str, Any]) -> list[tuple[str, str, str]]:
    """Format token claims for display.

    Args:
        payload: JWT payload dictionary.

    Returns:
        List of (claim_name, claim_value, description) tuples.
    """
    claims = []

    # Standard OIDC claims with descriptions
    claim_descriptions = {
        "iss": "Issuer",
        "sub": "Subject (User ID)",
        "aud": "Audience",
        "exp": "Expiration Time",
        "iat": "Issued At",
        "nbf": "Not Before",
        "jti": "JWT ID",
        "nonce": "Nonce",
        "auth_time": "Authentication Time",
        "acr": "Authentication Context Class",
        "amr": "Authentication Methods",
        "azp": "Authorized Party",
        "at_hash": "Access Token Hash",
        "c_hash": "Code Hash",
        "name": "Full Name",
        "given_name": "Given Name",
        "family_name": "Family Name",
        "middle_name": "Middle Name",
        "nickname": "Nickname",
        "preferred_username": "Preferred Username",
        "profile": "Profile URL",
        "picture": "Picture URL",
        "website": "Website URL",
        "email": "Email Address",
        "email_verified": "Email Verified",
        "gender": "Gender",
        "birthdate": "Birthdate",
        "zoneinfo": "Time Zone",
        "locale": "Locale",
        "phone_number": "Phone Number",
        "phone_number_verified": "Phone Verified",
        "address": "Address",
        "updated_at": "Updated At",
    }

    for key, value in payload.items():
        description = claim_descriptions.get(key, "Custom Claim")

        # Format timestamp values
        if key in ("exp", "iat", "nbf", "auth_time", "updated_at") and isinstance(value, (int, float)):
            try:
                dt = datetime.fromtimestamp(value, tz=UTC)
                formatted_value = f"{value} ({dt.isoformat()})"
            except Exception:
                formatted_value = str(value)
        elif isinstance(value, dict):
            formatted_value = json.dumps(value, indent=2)
        elif isinstance(value, list):
            formatted_value = ", ".join(str(v) for v in value)
        else:
            formatted_value = str(value)

        claims.append((key, formatted_value, description))

    return claims


def get_token_type_description(header: dict[str, Any]) -> str:
    """Get a description of the token type based on header.

    Args:
        header: JWT header dictionary.

    Returns:
        Human-readable token type description.
    """
    typ = header.get("typ", "JWT").upper()
    alg = header.get("alg", "unknown")

    if typ == "JWT":
        return f"JSON Web Token (signed with {alg})"
    elif typ == "AT+JWT":
        return f"Access Token JWT (signed with {alg})"
    else:
        return f"{typ} Token (signed with {alg})"


def get_algorithm_description(alg: str) -> str:
    """Get a description of the JWT signing algorithm.

    Args:
        alg: Algorithm identifier (e.g., "RS256").

    Returns:
        Human-readable algorithm description.
    """
    algorithms = {
        "HS256": "HMAC using SHA-256",
        "HS384": "HMAC using SHA-384",
        "HS512": "HMAC using SHA-512",
        "RS256": "RSA using SHA-256",
        "RS384": "RSA using SHA-384",
        "RS512": "RSA using SHA-512",
        "ES256": "ECDSA using P-256 and SHA-256",
        "ES384": "ECDSA using P-384 and SHA-384",
        "ES512": "ECDSA using P-521 and SHA-512",
        "PS256": "RSA-PSS using SHA-256",
        "PS384": "RSA-PSS using SHA-384",
        "PS512": "RSA-PSS using SHA-512",
        "EdDSA": "Edwards-curve DSA",
        "none": "No signature (INSECURE)",
    }
    return algorithms.get(alg, f"Unknown algorithm: {alg}")
