"""OIDC client implementation.

Provides a client for interacting with OIDC/OAuth2 providers,
supporting the Authorization Code flow with optional PKCE.
"""

from __future__ import annotations

import base64
import hashlib
import secrets
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any
from urllib.parse import urlencode

import httpx

from authtest.core.logging import LoggingClient, ProtocolLogger, get_protocol_logger


def generate_code_verifier(length: int = 64) -> str:
    """Generate a PKCE code verifier.

    The code verifier is a high-entropy cryptographic random string
    between 43 and 128 characters, using unreserved URI characters.

    Args:
        length: Length of the verifier (43-128, default 64).

    Returns:
        URL-safe base64-encoded random string.
    """
    # Clamp length to valid range per RFC 7636
    length = max(43, min(128, length))
    # Generate random bytes and encode as URL-safe base64
    # We need enough bytes to get the desired length after encoding
    num_bytes = (length * 3) // 4 + 1
    random_bytes = secrets.token_bytes(num_bytes)
    verifier = base64.urlsafe_b64encode(random_bytes).decode("ascii")
    # Strip padding and truncate to exact length
    return verifier.rstrip("=")[:length]


def generate_code_challenge(code_verifier: str, method: str = "S256") -> str:
    """Generate a PKCE code challenge from a code verifier.

    Args:
        code_verifier: The code verifier string.
        method: Challenge method - "S256" (recommended) or "plain".

    Returns:
        The code challenge string.

    Raises:
        ValueError: If method is not supported.
    """
    if method == "plain":
        return code_verifier
    elif method == "S256":
        # SHA256 hash the verifier, then base64url encode
        digest = hashlib.sha256(code_verifier.encode("ascii")).digest()
        challenge = base64.urlsafe_b64encode(digest).decode("ascii")
        # Remove padding
        return challenge.rstrip("=")
    else:
        raise ValueError(f"Unsupported code_challenge_method: {method}")


if TYPE_CHECKING:
    from authtest.storage.models import IdPProvider


@dataclass
class OIDCClientConfig:
    """Configuration for an OIDC client."""

    client_id: str
    client_secret: str | None = None
    redirect_uri: str = ""
    scopes: list[str] = field(default_factory=lambda: ["openid", "profile", "email"])

    # IdP endpoints
    authorization_endpoint: str = ""
    token_endpoint: str = ""
    userinfo_endpoint: str = ""
    jwks_uri: str = ""
    issuer: str = ""

    # Optional endpoints
    end_session_endpoint: str | None = None

    @classmethod
    def from_idp(
        cls,
        idp: IdPProvider,
        client_id: str,
        client_secret: str | None = None,
        redirect_uri: str = "",
        scopes: list[str] | None = None,
    ) -> OIDCClientConfig:
        """Create client config from an IdP provider.

        Args:
            idp: IdP provider with OIDC endpoints.
            client_id: OAuth2 client ID.
            client_secret: OAuth2 client secret (for confidential clients).
            redirect_uri: Callback URI for authorization code flow.
            scopes: OAuth2 scopes to request.

        Returns:
            Configured OIDCClientConfig.
        """
        default_scopes = ["openid", "profile", "email"]
        if idp.settings and "default_scopes" in idp.settings:
            default_scopes = idp.settings["default_scopes"]

        return cls(
            client_id=client_id,
            client_secret=client_secret,
            redirect_uri=redirect_uri,
            scopes=scopes or default_scopes,
            authorization_endpoint=idp.authorization_endpoint or "",
            token_endpoint=idp.token_endpoint or "",
            userinfo_endpoint=idp.userinfo_endpoint or "",
            jwks_uri=idp.jwks_uri or "",
            issuer=idp.issuer or "",
            end_session_endpoint=idp.settings.get("logout_endpoint") if idp.settings else None,
        )


@dataclass
class AuthorizationRequest:
    """Represents an OAuth2 authorization request."""

    authorization_url: str
    state: str
    nonce: str
    code_verifier: str | None = None  # For PKCE
    code_challenge: str | None = None  # For PKCE
    code_challenge_method: str | None = None  # For PKCE (S256 or plain)


@dataclass
class TokenResponse:
    """Represents an OAuth2 token response."""

    access_token: str
    token_type: str
    expires_in: int | None = None
    refresh_token: str | None = None
    id_token: str | None = None
    scope: str | None = None

    # Raw response for debugging
    raw_response: dict[str, Any] = field(default_factory=dict)

    # Error information
    error: str | None = None
    error_description: str | None = None

    @property
    def is_success(self) -> bool:
        """Check if the token response is successful."""
        return self.error is None and bool(self.access_token)


@dataclass
class UserInfoResponse:
    """Represents an OIDC userinfo response."""

    sub: str | None = None
    name: str | None = None
    email: str | None = None
    email_verified: bool | None = None
    preferred_username: str | None = None
    given_name: str | None = None
    family_name: str | None = None
    picture: str | None = None

    # All claims
    claims: dict[str, Any] = field(default_factory=dict)

    # Error information
    error: str | None = None
    error_description: str | None = None

    @property
    def is_success(self) -> bool:
        """Check if the userinfo response is successful."""
        return self.error is None and bool(self.sub)


class OIDCClient:
    """Client for OIDC/OAuth2 interactions.

    Supports the Authorization Code flow for testing OIDC implementations.
    """

    def __init__(
        self,
        config: OIDCClientConfig,
        protocol_logger: ProtocolLogger | None = None,
    ) -> None:
        """Initialize the OIDC client.

        Args:
            config: Client configuration with endpoints and credentials.
            protocol_logger: Optional protocol logger for HTTP traffic capture.
        """
        self.config = config
        self._protocol_logger = protocol_logger or get_protocol_logger()
        self._http_client: LoggingClient | None = None

    @property
    def http_client(self) -> LoggingClient:
        """Get or create HTTP client with logging."""
        if self._http_client is None:
            self._http_client = LoggingClient(
                protocol_logger=self._protocol_logger,
                timeout=30.0,
                verify=False,  # For testing with self-signed certs
            )
        return self._http_client

    @property
    def protocol_logger(self) -> ProtocolLogger:
        """Get the protocol logger."""
        return self._protocol_logger

    def close(self) -> None:
        """Close the HTTP client."""
        if self._http_client is not None:
            self._http_client.close()
            self._http_client = None

    def create_authorization_request(
        self,
        state: str | None = None,
        nonce: str | None = None,
        prompt: str | None = None,
        login_hint: str | None = None,
        use_pkce: bool = False,
        code_challenge_method: str = "S256",
        additional_params: dict[str, str] | None = None,
    ) -> AuthorizationRequest:
        """Create an authorization request URL.

        Args:
            state: OAuth2 state parameter (generated if not provided).
            nonce: OIDC nonce parameter (generated if not provided).
            prompt: OIDC prompt parameter (none, login, consent, select_account).
            login_hint: OIDC login_hint parameter.
            use_pkce: Whether to use PKCE (Proof Key for Code Exchange).
            code_challenge_method: PKCE method - "S256" (recommended) or "plain".
            additional_params: Additional query parameters.

        Returns:
            AuthorizationRequest with URL and state parameters.
        """
        state = state or secrets.token_urlsafe(32)
        nonce = nonce or secrets.token_urlsafe(32)

        params: dict[str, str] = {
            "response_type": "code",
            "client_id": self.config.client_id,
            "redirect_uri": self.config.redirect_uri,
            "scope": " ".join(self.config.scopes),
            "state": state,
            "nonce": nonce,
        }

        # Generate PKCE parameters if enabled
        code_verifier: str | None = None
        code_challenge: str | None = None
        if use_pkce:
            code_verifier = generate_code_verifier()
            code_challenge = generate_code_challenge(code_verifier, code_challenge_method)
            params["code_challenge"] = code_challenge
            params["code_challenge_method"] = code_challenge_method

        if prompt:
            params["prompt"] = prompt

        if login_hint:
            params["login_hint"] = login_hint

        if additional_params:
            params.update(additional_params)

        authorization_url = f"{self.config.authorization_endpoint}?{urlencode(params)}"

        return AuthorizationRequest(
            authorization_url=authorization_url,
            state=state,
            nonce=nonce,
            code_verifier=code_verifier,
            code_challenge=code_challenge,
            code_challenge_method=code_challenge_method if use_pkce else None,
        )

    def exchange_code(
        self,
        code: str,
        code_verifier: str | None = None,
    ) -> TokenResponse:
        """Exchange an authorization code for tokens.

        Args:
            code: Authorization code from the callback.
            code_verifier: PKCE code verifier (for public clients).

        Returns:
            TokenResponse with access token, id token, etc.
        """
        data: dict[str, str] = {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": self.config.redirect_uri,
            "client_id": self.config.client_id,
        }

        if self.config.client_secret:
            data["client_secret"] = self.config.client_secret

        if code_verifier:
            data["code_verifier"] = code_verifier

        try:
            response = self.http_client.post(
                self.config.token_endpoint,
                data=data,
                headers={"Accept": "application/json"},
            )

            response_data = response.json()

            if response.status_code != 200:
                return TokenResponse(
                    access_token="",
                    token_type="",
                    error=response_data.get("error", "token_error"),
                    error_description=response_data.get(
                        "error_description",
                        f"Token request failed with status {response.status_code}",
                    ),
                    raw_response=response_data,
                )

            return TokenResponse(
                access_token=response_data.get("access_token", ""),
                token_type=response_data.get("token_type", "Bearer"),
                expires_in=response_data.get("expires_in"),
                refresh_token=response_data.get("refresh_token"),
                id_token=response_data.get("id_token"),
                scope=response_data.get("scope"),
                raw_response=response_data,
            )

        except httpx.HTTPError as e:
            return TokenResponse(
                access_token="",
                token_type="",
                error="http_error",
                error_description=f"HTTP error during token exchange: {e}",
            )
        except Exception as e:
            return TokenResponse(
                access_token="",
                token_type="",
                error="unexpected_error",
                error_description=f"Unexpected error during token exchange: {e}",
            )

    def get_userinfo(self, access_token: str) -> UserInfoResponse:
        """Fetch user information from the userinfo endpoint.

        Args:
            access_token: Bearer token for authorization.

        Returns:
            UserInfoResponse with user claims.
        """
        if not self.config.userinfo_endpoint:
            return UserInfoResponse(
                error="no_endpoint",
                error_description="UserInfo endpoint not configured",
            )

        try:
            response = self.http_client.get(
                self.config.userinfo_endpoint,
                headers={
                    "Authorization": f"Bearer {access_token}",
                    "Accept": "application/json",
                },
            )

            if response.status_code != 200:
                try:
                    error_data = response.json()
                    return UserInfoResponse(
                        error=error_data.get("error", "userinfo_error"),
                        error_description=error_data.get(
                            "error_description",
                            f"UserInfo request failed with status {response.status_code}",
                        ),
                    )
                except Exception:
                    return UserInfoResponse(
                        error="userinfo_error",
                        error_description=f"UserInfo request failed with status {response.status_code}",
                    )

            claims = response.json()

            return UserInfoResponse(
                sub=claims.get("sub"),
                name=claims.get("name"),
                email=claims.get("email"),
                email_verified=claims.get("email_verified"),
                preferred_username=claims.get("preferred_username"),
                given_name=claims.get("given_name"),
                family_name=claims.get("family_name"),
                picture=claims.get("picture"),
                claims=claims,
            )

        except httpx.HTTPError as e:
            return UserInfoResponse(
                error="http_error",
                error_description=f"HTTP error fetching userinfo: {e}",
            )
        except Exception as e:
            return UserInfoResponse(
                error="unexpected_error",
                error_description=f"Unexpected error fetching userinfo: {e}",
            )

    def fetch_jwks(self) -> dict[str, Any]:
        """Fetch the JWKS (JSON Web Key Set) from the IdP.

        Returns:
            JWKS document with keys, or empty dict on error.
        """
        if not self.config.jwks_uri:
            return {}

        try:
            response = self.http_client.get(self.config.jwks_uri)
            if response.status_code == 200:
                result: dict[str, Any] = response.json()
                return result
        except Exception:
            pass

        return {}

    def client_credentials_grant(
        self,
        scopes: list[str] | None = None,
        additional_params: dict[str, str] | None = None,
    ) -> TokenResponse:
        """Execute the Client Credentials grant to obtain an access token.

        This is a machine-to-machine flow that does not involve user interaction.
        The client authenticates using its client_id and client_secret.

        Args:
            scopes: Scopes to request (defaults to client config scopes minus 'openid').
            additional_params: Additional parameters to include in the request.

        Returns:
            TokenResponse with access token and metadata.
        """
        # Client credentials flow requires client_secret
        if not self.config.client_secret:
            return TokenResponse(
                access_token="",
                token_type="",
                error="invalid_client",
                error_description="Client credentials flow requires a client_secret",
            )

        # Use provided scopes or default scopes (without 'openid' which is for user auth)
        request_scopes = scopes
        if request_scopes is None:
            request_scopes = [s for s in self.config.scopes if s != "openid"]

        data: dict[str, str] = {
            "grant_type": "client_credentials",
            "client_id": self.config.client_id,
            "client_secret": self.config.client_secret,
        }

        if request_scopes:
            data["scope"] = " ".join(request_scopes)

        if additional_params:
            data.update(additional_params)

        try:
            response = self.http_client.post(
                self.config.token_endpoint,
                data=data,
                headers={"Accept": "application/json"},
            )

            response_data = response.json()

            if response.status_code != 200:
                return TokenResponse(
                    access_token="",
                    token_type="",
                    error=response_data.get("error", "token_error"),
                    error_description=response_data.get(
                        "error_description",
                        f"Token request failed with status {response.status_code}",
                    ),
                    raw_response=response_data,
                )

            return TokenResponse(
                access_token=response_data.get("access_token", ""),
                token_type=response_data.get("token_type", "Bearer"),
                expires_in=response_data.get("expires_in"),
                refresh_token=response_data.get("refresh_token"),
                id_token=response_data.get("id_token"),  # Usually not returned for client_credentials
                scope=response_data.get("scope"),
                raw_response=response_data,
            )

        except httpx.HTTPError as e:
            return TokenResponse(
                access_token="",
                token_type="",
                error="http_error",
                error_description=f"HTTP error during token request: {e}",
            )
        except Exception as e:
            return TokenResponse(
                access_token="",
                token_type="",
                error="unexpected_error",
                error_description=f"Unexpected error during token request: {e}",
            )
