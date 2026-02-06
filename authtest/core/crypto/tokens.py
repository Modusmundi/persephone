"""Token manipulation utilities for security testing.

This module provides tools to modify and re-sign JWT tokens and SAML assertions
for testing how applications handle manipulated security tokens.

WARNING: These tools are intended for authorized security testing only.
Manipulated tokens are clearly labeled and should never be used maliciously.
"""

from __future__ import annotations

import base64
import hashlib
import json
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from typing import Any

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa


class ManipulationType(StrEnum):
    """Type of manipulation applied to a token."""

    CLAIM_MODIFIED = "claim_modified"
    CLAIM_ADDED = "claim_added"
    CLAIM_REMOVED = "claim_removed"
    HEADER_MODIFIED = "header_modified"
    ALGORITHM_CHANGED = "algorithm_changed"
    SIGNATURE_STRIPPED = "signature_stripped"
    CUSTOM_SIGNED = "custom_signed"


@dataclass
class TokenManipulation:
    """Record of a manipulation applied to a token."""

    type: ManipulationType
    description: str
    original_value: str | None = None
    new_value: str | None = None


@dataclass
class ManipulatedToken:
    """Result of token manipulation."""

    original_token: str
    manipulated_token: str
    manipulations: list[TokenManipulation] = field(default_factory=list)
    header: dict[str, Any] = field(default_factory=dict)
    payload: dict[str, Any] = field(default_factory=dict)
    signed_with: str | None = None  # Description of signing key used

    # Warning label
    warning: str = "MANIPULATED TOKEN - FOR SECURITY TESTING ONLY"

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "original_token": self.original_token,
            "manipulated_token": self.manipulated_token,
            "manipulations": [
                {
                    "type": m.type.value,
                    "description": m.description,
                    "original_value": m.original_value,
                    "new_value": m.new_value,
                }
                for m in self.manipulations
            ],
            "header": self.header,
            "payload": self.payload,
            "signed_with": self.signed_with,
            "warning": self.warning,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ManipulatedToken:
        """Reconstruct from dictionary."""
        result = cls(
            original_token=data.get("original_token", ""),
            manipulated_token=data.get("manipulated_token", ""),
            header=data.get("header", {}),
            payload=data.get("payload", {}),
            signed_with=data.get("signed_with"),
            warning=data.get("warning", ""),
        )
        for m_data in data.get("manipulations", []):
            result.manipulations.append(
                TokenManipulation(
                    type=ManipulationType(m_data["type"]),
                    description=m_data["description"],
                    original_value=m_data.get("original_value"),
                    new_value=m_data.get("new_value"),
                )
            )
        return result


class JWTManipulator:
    """Manipulates JWT tokens for security testing.

    This class allows modifying JWT claims, headers, and re-signing tokens
    with custom keys for testing how applications validate tokens.
    """

    def __init__(self, token: str) -> None:
        """Initialize with a JWT token to manipulate.

        Args:
            token: JWT token string.

        Raises:
            ValueError: If token format is invalid.
        """
        self.original_token = token
        self._decode_token()

    def _decode_token(self) -> None:
        """Decode the token into header and payload."""
        parts = self.original_token.split(".")
        if len(parts) != 3:
            raise ValueError(f"Invalid JWT format: expected 3 parts, got {len(parts)}")

        self.header = self._decode_base64url_json(parts[0])
        self.payload = self._decode_base64url_json(parts[1])
        self.original_signature = parts[2]
        self.manipulations: list[TokenManipulation] = []

    @staticmethod
    def _decode_base64url_json(data: str) -> dict[str, Any]:
        """Decode base64url-encoded JSON."""
        # Add padding if needed
        padding_needed = 4 - len(data) % 4
        if padding_needed != 4:
            data += "=" * padding_needed

        decoded = base64.urlsafe_b64decode(data)
        result: dict[str, Any] = json.loads(decoded)
        return result

    @staticmethod
    def _encode_base64url(data: bytes) -> str:
        """Encode bytes to base64url without padding."""
        return base64.urlsafe_b64encode(data).rstrip(b"=").decode("utf-8")

    def modify_claim(
        self,
        claim: str,
        new_value: Any,
        *,
        add_if_missing: bool = False,
    ) -> JWTManipulator:
        """Modify a claim in the token payload.

        Args:
            claim: Name of the claim to modify.
            new_value: New value for the claim.
            add_if_missing: If True, add the claim if it doesn't exist.

        Returns:
            Self for chaining.

        Raises:
            KeyError: If claim doesn't exist and add_if_missing is False.
        """
        if claim not in self.payload:
            if not add_if_missing:
                raise KeyError(f"Claim '{claim}' not found in token")
            self.manipulations.append(
                TokenManipulation(
                    type=ManipulationType.CLAIM_ADDED,
                    description=f"Added claim '{claim}'",
                    original_value=None,
                    new_value=json.dumps(new_value) if not isinstance(new_value, str) else new_value,
                )
            )
        else:
            original = self.payload[claim]
            self.manipulations.append(
                TokenManipulation(
                    type=ManipulationType.CLAIM_MODIFIED,
                    description=f"Modified claim '{claim}'",
                    original_value=json.dumps(original) if not isinstance(original, str) else str(original),
                    new_value=json.dumps(new_value) if not isinstance(new_value, str) else str(new_value),
                )
            )

        self.payload[claim] = new_value
        return self

    def remove_claim(self, claim: str) -> JWTManipulator:
        """Remove a claim from the token payload.

        Args:
            claim: Name of the claim to remove.

        Returns:
            Self for chaining.

        Raises:
            KeyError: If claim doesn't exist.
        """
        if claim not in self.payload:
            raise KeyError(f"Claim '{claim}' not found in token")

        original = self.payload.pop(claim)
        self.manipulations.append(
            TokenManipulation(
                type=ManipulationType.CLAIM_REMOVED,
                description=f"Removed claim '{claim}'",
                original_value=json.dumps(original) if not isinstance(original, str) else str(original),
                new_value=None,
            )
        )
        return self

    def modify_header(self, key: str, new_value: Any) -> JWTManipulator:
        """Modify a header field.

        Args:
            key: Header key to modify.
            new_value: New value for the header field.

        Returns:
            Self for chaining.
        """
        original = self.header.get(key)
        self.header[key] = new_value
        self.manipulations.append(
            TokenManipulation(
                type=ManipulationType.HEADER_MODIFIED,
                description=f"Modified header '{key}'",
                original_value=str(original) if original is not None else None,
                new_value=str(new_value),
            )
        )
        return self

    def extend_expiration(self, hours: int = 24) -> JWTManipulator:
        """Extend the token expiration time.

        Args:
            hours: Number of hours to extend the expiration.

        Returns:
            Self for chaining.
        """
        new_exp = int((datetime.now(UTC) + timedelta(hours=hours)).timestamp())
        return self.modify_claim("exp", new_exp, add_if_missing=True)

    def change_subject(self, new_subject: str) -> JWTManipulator:
        """Change the subject claim.

        Args:
            new_subject: New subject identifier.

        Returns:
            Self for chaining.
        """
        return self.modify_claim("sub", new_subject, add_if_missing=True)

    def change_issuer(self, new_issuer: str) -> JWTManipulator:
        """Change the issuer claim.

        Args:
            new_issuer: New issuer URL.

        Returns:
            Self for chaining.
        """
        return self.modify_claim("iss", new_issuer, add_if_missing=True)

    def change_audience(self, new_audience: str | list[str]) -> JWTManipulator:
        """Change the audience claim.

        Args:
            new_audience: New audience (client_id) or list of audiences.

        Returns:
            Self for chaining.
        """
        return self.modify_claim("aud", new_audience, add_if_missing=True)

    def add_role(self, role: str, claim: str = "roles") -> JWTManipulator:
        """Add a role to the roles claim.

        Args:
            role: Role to add.
            claim: Name of the roles claim (default: "roles").

        Returns:
            Self for chaining.
        """
        current_roles = self.payload.get(claim, [])
        if not isinstance(current_roles, list):
            current_roles = [current_roles]

        if role not in current_roles:
            current_roles.append(role)
            return self.modify_claim(claim, current_roles, add_if_missing=True)

        return self

    def set_admin(self, admin_claim: str = "admin", value: bool = True) -> JWTManipulator:
        """Set an admin claim.

        Args:
            admin_claim: Name of the admin claim.
            value: Value to set (default: True).

        Returns:
            Self for chaining.
        """
        return self.modify_claim(admin_claim, value, add_if_missing=True)

    def strip_signature(self) -> ManipulatedToken:
        """Create token with no signature (alg=none attack).

        This tests if applications properly validate token signatures.

        Returns:
            ManipulatedToken with signature stripped.
        """
        original_alg = self.header.get("alg")
        self.header["alg"] = "none"

        self.manipulations.append(
            TokenManipulation(
                type=ManipulationType.ALGORITHM_CHANGED,
                description="Changed algorithm to 'none' (signature stripped)",
                original_value=original_alg,
                new_value="none",
            )
        )
        self.manipulations.append(
            TokenManipulation(
                type=ManipulationType.SIGNATURE_STRIPPED,
                description="Removed signature from token",
            )
        )

        # Encode without signature
        header_b64 = self._encode_base64url(json.dumps(self.header).encode())
        payload_b64 = self._encode_base64url(json.dumps(self.payload).encode())

        return ManipulatedToken(
            original_token=self.original_token,
            manipulated_token=f"{header_b64}.{payload_b64}.",
            manipulations=self.manipulations.copy(),
            header=self.header.copy(),
            payload=self.payload.copy(),
            signed_with="none (unsigned)",
        )

    def sign_with_rsa_key(
        self,
        private_key: rsa.RSAPrivateKey,
        algorithm: str = "RS256",
        key_description: str = "Custom RSA key",
    ) -> ManipulatedToken:
        """Re-sign the token with an RSA private key.

        Args:
            private_key: RSA private key for signing.
            algorithm: JWT algorithm (RS256, RS384, RS512).
            key_description: Description of the key for labeling.

        Returns:
            ManipulatedToken signed with the provided key.
        """
        original_alg = self.header.get("alg")
        if original_alg != algorithm:
            self.header["alg"] = algorithm
            self.manipulations.append(
                TokenManipulation(
                    type=ManipulationType.ALGORITHM_CHANGED,
                    description=f"Changed algorithm to '{algorithm}'",
                    original_value=original_alg,
                    new_value=algorithm,
                )
            )

        self.manipulations.append(
            TokenManipulation(
                type=ManipulationType.CUSTOM_SIGNED,
                description=f"Re-signed with {key_description}",
            )
        )

        # Use PyJWT for signing
        token = jwt.encode(
            self.payload,
            private_key,
            algorithm=algorithm,
            headers={k: v for k, v in self.header.items() if k not in ("alg", "typ")},
        )

        return ManipulatedToken(
            original_token=self.original_token,
            manipulated_token=token,
            manipulations=self.manipulations.copy(),
            header=self.header.copy(),
            payload=self.payload.copy(),
            signed_with=key_description,
        )

    def sign_with_ec_key(
        self,
        private_key: ec.EllipticCurvePrivateKey,
        algorithm: str = "ES256",
        key_description: str = "Custom EC key",
    ) -> ManipulatedToken:
        """Re-sign the token with an EC private key.

        Args:
            private_key: EC private key for signing.
            algorithm: JWT algorithm (ES256, ES384, ES512).
            key_description: Description of the key for labeling.

        Returns:
            ManipulatedToken signed with the provided key.
        """
        original_alg = self.header.get("alg")
        if original_alg != algorithm:
            self.header["alg"] = algorithm
            self.manipulations.append(
                TokenManipulation(
                    type=ManipulationType.ALGORITHM_CHANGED,
                    description=f"Changed algorithm to '{algorithm}'",
                    original_value=original_alg,
                    new_value=algorithm,
                )
            )

        self.manipulations.append(
            TokenManipulation(
                type=ManipulationType.CUSTOM_SIGNED,
                description=f"Re-signed with {key_description}",
            )
        )

        # Use PyJWT for signing
        token = jwt.encode(
            self.payload,
            private_key,
            algorithm=algorithm,
            headers={k: v for k, v in self.header.items() if k not in ("alg", "typ")},
        )

        return ManipulatedToken(
            original_token=self.original_token,
            manipulated_token=token,
            manipulations=self.manipulations.copy(),
            header=self.header.copy(),
            payload=self.payload.copy(),
            signed_with=key_description,
        )

    def sign_with_hs_secret(
        self,
        secret: str,
        algorithm: str = "HS256",
        key_description: str = "Custom HMAC secret",
    ) -> ManipulatedToken:
        """Re-sign the token with an HMAC secret.

        This can test for algorithm confusion attacks where an RSA public key
        is used as an HMAC secret.

        Args:
            secret: Secret for HMAC signing.
            algorithm: JWT algorithm (HS256, HS384, HS512).
            key_description: Description of the key for labeling.

        Returns:
            ManipulatedToken signed with the provided secret.
        """
        original_alg = self.header.get("alg")
        if original_alg != algorithm:
            self.header["alg"] = algorithm
            self.manipulations.append(
                TokenManipulation(
                    type=ManipulationType.ALGORITHM_CHANGED,
                    description=f"Changed algorithm to '{algorithm}' (possible algorithm confusion attack)",
                    original_value=original_alg,
                    new_value=algorithm,
                )
            )

        self.manipulations.append(
            TokenManipulation(
                type=ManipulationType.CUSTOM_SIGNED,
                description=f"Re-signed with {key_description}",
            )
        )

        # Use PyJWT for signing
        token = jwt.encode(
            self.payload,
            secret,
            algorithm=algorithm,
            headers={k: v for k, v in self.header.items() if k not in ("alg", "typ")},
        )

        return ManipulatedToken(
            original_token=self.original_token,
            manipulated_token=token,
            manipulations=self.manipulations.copy(),
            header=self.header.copy(),
            payload=self.payload.copy(),
            signed_with=key_description,
        )

    def build_unsigned(self) -> ManipulatedToken:
        """Build manipulated token without changing the signature.

        NOTE: This creates an INVALID token since the payload doesn't match
        the signature. Use this to test if applications validate signatures.

        Returns:
            ManipulatedToken with original signature (invalid).
        """
        header_b64 = self._encode_base64url(json.dumps(self.header).encode())
        payload_b64 = self._encode_base64url(json.dumps(self.payload).encode())

        return ManipulatedToken(
            original_token=self.original_token,
            manipulated_token=f"{header_b64}.{payload_b64}.{self.original_signature}",
            manipulations=self.manipulations.copy(),
            header=self.header.copy(),
            payload=self.payload.copy(),
            signed_with="Original signature (INVALID - payload modified)",
        )


def create_jwt_from_scratch(
    claims: dict[str, Any],
    private_key: rsa.RSAPrivateKey | ec.EllipticCurvePrivateKey | str,
    algorithm: str = "RS256",
    additional_headers: dict[str, Any] | None = None,
) -> str:
    """Create a new JWT token from scratch.

    Args:
        claims: Payload claims for the token.
        private_key: Key for signing (RSA, EC, or string for HMAC).
        algorithm: Signing algorithm.
        additional_headers: Additional header fields.

    Returns:
        Signed JWT token string.
    """
    headers = additional_headers or {}
    return jwt.encode(claims, private_key, algorithm=algorithm, headers=headers)


def decode_jwt_parts(token: str) -> tuple[dict[str, Any], dict[str, Any], str]:
    """Decode a JWT token into its parts without verification.

    Args:
        token: JWT token string.

    Returns:
        Tuple of (header, payload, signature).

    Raises:
        ValueError: If token format is invalid.
    """
    parts = token.split(".")
    if len(parts) != 3:
        raise ValueError(f"Invalid JWT format: expected 3 parts, got {len(parts)}")

    def decode_part(part: str) -> dict[str, Any]:
        pad_len = 4 - len(part) % 4
        if pad_len != 4:
            part += "=" * pad_len
        decoded = base64.urlsafe_b64decode(part)
        result: dict[str, Any] = json.loads(decoded)
        return result

    return decode_part(parts[0]), decode_part(parts[1]), parts[2]


def generate_signing_key_pair(
    algorithm: str = "RS256",
    key_size: int = 2048,
) -> tuple[Any, Any, str]:
    """Generate a key pair for signing JWTs.

    Args:
        algorithm: JWT algorithm (RS256, ES256, etc.).
        key_size: Key size for RSA keys.

    Returns:
        Tuple of (private_key, public_key, key_id).

    Raises:
        ValueError: If algorithm is not supported.
    """
    # Generate key ID from current timestamp
    key_id = hashlib.sha256(datetime.now(UTC).isoformat().encode()).hexdigest()[:16]

    if algorithm.startswith("RS") or algorithm.startswith("PS"):
        # RSA key
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=key_size,
        )
        public_key = private_key.public_key()
        return private_key, public_key, f"authtest-rsa-{key_id}"

    elif algorithm.startswith("ES"):
        # EC key
        if algorithm == "ES256":
            curve = ec.SECP256R1()
        elif algorithm == "ES384":
            curve = ec.SECP384R1()
        elif algorithm == "ES512":
            curve = ec.SECP521R1()
        else:
            raise ValueError(f"Unsupported EC algorithm: {algorithm}")

        private_key = ec.generate_private_key(curve)
        public_key = private_key.public_key()
        return private_key, public_key, f"authtest-ec-{key_id}"

    else:
        raise ValueError(f"Unsupported algorithm for key generation: {algorithm}")


def get_public_key_jwk(
    public_key: rsa.RSAPublicKey | ec.EllipticCurvePublicKey,
    key_id: str,
    algorithm: str = "RS256",
) -> dict[str, Any]:
    """Get the public key in JWK format.

    Args:
        public_key: Public key to convert.
        key_id: Key ID for the JWK.
        algorithm: Algorithm this key is used with.

    Returns:
        JWK dictionary.
    """
    from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePublicKey
    from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey

    if isinstance(public_key, RSAPublicKey):
        numbers = public_key.public_numbers()
        # Convert to base64url
        n = base64.urlsafe_b64encode(
            numbers.n.to_bytes((numbers.n.bit_length() + 7) // 8, "big")
        ).rstrip(b"=").decode()
        e = base64.urlsafe_b64encode(
            numbers.e.to_bytes((numbers.e.bit_length() + 7) // 8, "big")
        ).rstrip(b"=").decode()

        return {
            "kty": "RSA",
            "kid": key_id,
            "alg": algorithm,
            "use": "sig",
            "n": n,
            "e": e,
        }

    elif isinstance(public_key, EllipticCurvePublicKey):
        numbers = public_key.public_numbers()
        curve_name = public_key.curve.name

        # Map curve names
        curve_map = {
            "secp256r1": "P-256",
            "secp384r1": "P-384",
            "secp521r1": "P-521",
        }
        crv = curve_map.get(curve_name, curve_name)

        # Calculate byte length for the curve
        byte_len = (numbers.x.bit_length() + 7) // 8
        if crv == "P-256":
            byte_len = 32
        elif crv == "P-384":
            byte_len = 48
        elif crv == "P-521":
            byte_len = 66

        x = base64.urlsafe_b64encode(
            numbers.x.to_bytes(byte_len, "big")
        ).rstrip(b"=").decode()
        y = base64.urlsafe_b64encode(
            numbers.y.to_bytes(byte_len, "big")
        ).rstrip(b"=").decode()

        return {
            "kty": "EC",
            "kid": key_id,
            "alg": algorithm,
            "use": "sig",
            "crv": crv,
            "x": x,
            "y": y,
        }

    else:
        raise ValueError(f"Unsupported key type: {type(public_key)}")


def get_private_key_pem(
    private_key: rsa.RSAPrivateKey | ec.EllipticCurvePrivateKey,
) -> str:
    """Get the private key in PEM format.

    Args:
        private_key: Private key to convert.

    Returns:
        PEM-encoded private key string.
    """
    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("utf-8")


def get_public_key_pem(
    public_key: rsa.RSAPublicKey | ec.EllipticCurvePublicKey,
) -> str:
    """Get the public key in PEM format.

    Args:
        public_key: Public key to convert.

    Returns:
        PEM-encoded public key string.
    """
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("utf-8")
