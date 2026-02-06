"""OIDC authentication flow handlers.

Handles OIDC/OAuth2 flow orchestration, including:
- Authorization Code flow
- Token exchange
- Token validation and display
- Result recording
"""

from __future__ import annotations

import secrets
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from typing import TYPE_CHECKING, Any

from authtest.core.logging import ProtocolLog, ProtocolLogger, get_protocol_logger
from authtest.core.oidc.client import (
    AuthorizationRequest,
    OIDCClient,
    OIDCClientConfig,
    TokenResponse,
    UserInfoResponse,
)
from authtest.core.oidc.utils import DecodedToken, decode_jwt
from authtest.core.oidc.validation import TokenValidationResult, TokenValidator

if TYPE_CHECKING:
    from authtest.storage.database import Database
    from authtest.storage.models import IdPProvider


class OIDCFlowStatus(StrEnum):
    """Status of an OIDC flow test."""

    PENDING = "pending"
    PREFLIGHT = "preflight"
    INITIATED = "initiated"
    WAITING_CALLBACK = "waiting_callback"
    EXCHANGING = "exchanging"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class TestOutcome(StrEnum):
    """Outcome of a test."""

    PASSED = "passed"
    FAILED = "failed"
    ERROR = "error"


@dataclass
class PreflightCheck:
    """Result of a single preflight check."""

    name: str
    description: str
    passed: bool
    details: str = ""


@dataclass
class PreflightResult:
    """Result of all preflight checks."""

    checks: list[PreflightCheck] = field(default_factory=list)
    all_passed: bool = False
    warnings: list[str] = field(default_factory=list)


@dataclass
class OIDCFlowState:
    """Maintains state for an in-progress OIDC flow.

    This state is stored in the Flask session to track the flow
    across the authorization redirect.
    """

    flow_id: str
    idp_id: int
    idp_name: str
    status: OIDCFlowStatus
    grant_type: str = "authorization_code"

    # Client configuration
    client_id: str = ""
    redirect_uri: str = ""
    scopes: list[str] = field(default_factory=list)

    # Authorization request state
    state: str | None = None
    nonce: str | None = None
    code_verifier: str | None = None  # For PKCE
    code_challenge: str | None = None  # For PKCE
    code_challenge_method: str | None = None  # For PKCE (S256 or plain)

    # Timing
    started_at: datetime | None = None
    completed_at: datetime | None = None

    # Preflight
    preflight: PreflightResult | None = None

    # Response data
    authorization_code: str | None = None
    token_response: TokenResponse | None = None
    userinfo_response: UserInfoResponse | None = None
    id_token_decoded: DecodedToken | None = None
    access_token_decoded: DecodedToken | None = None

    # Token validation results
    id_token_validation: TokenValidationResult | None = None
    access_token_validation: TokenValidationResult | None = None

    # Error handling
    error: str | None = None
    error_description: str | None = None

    # Options
    options: dict[str, Any] = field(default_factory=dict)

    # Protocol logging (not serialized to session, used for results)
    protocol_log: ProtocolLog | None = None

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for session storage."""
        return {
            "flow_id": self.flow_id,
            "idp_id": self.idp_id,
            "idp_name": self.idp_name,
            "status": self.status,
            "grant_type": self.grant_type,
            "client_id": self.client_id,
            "redirect_uri": self.redirect_uri,
            "scopes": self.scopes,
            "state": self.state,
            "nonce": self.nonce,
            "code_verifier": self.code_verifier,
            "code_challenge": self.code_challenge,
            "code_challenge_method": self.code_challenge_method,
            "started_at": self.started_at.isoformat() if self.started_at else None,
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
            "preflight": _preflight_to_dict(self.preflight) if self.preflight else None,
            "authorization_code": self.authorization_code,
            "token_response": _token_response_to_dict(self.token_response) if self.token_response else None,
            "userinfo_response": _userinfo_to_dict(self.userinfo_response) if self.userinfo_response else None,
            "id_token_decoded": _decoded_token_to_dict(self.id_token_decoded) if self.id_token_decoded else None,
            "access_token_decoded": _decoded_token_to_dict(self.access_token_decoded)
            if self.access_token_decoded
            else None,
            "id_token_validation": self.id_token_validation.to_dict() if self.id_token_validation else None,
            "access_token_validation": self.access_token_validation.to_dict()
            if self.access_token_validation
            else None,
            "error": self.error,
            "error_description": self.error_description,
            "options": self.options,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> OIDCFlowState:
        """Reconstruct from dictionary."""
        state = cls(
            flow_id=data["flow_id"],
            idp_id=data["idp_id"],
            idp_name=data["idp_name"],
            status=OIDCFlowStatus(data["status"]),
            grant_type=data.get("grant_type", "authorization_code"),
            client_id=data.get("client_id", ""),
            redirect_uri=data.get("redirect_uri", ""),
            scopes=data.get("scopes", []),
            state=data.get("state"),
            nonce=data.get("nonce"),
            code_verifier=data.get("code_verifier"),
            code_challenge=data.get("code_challenge"),
            code_challenge_method=data.get("code_challenge_method"),
            started_at=datetime.fromisoformat(data["started_at"]) if data.get("started_at") else None,
            completed_at=datetime.fromisoformat(data["completed_at"]) if data.get("completed_at") else None,
            preflight=_dict_to_preflight(data["preflight"]) if data.get("preflight") else None,
            authorization_code=data.get("authorization_code"),
            error=data.get("error"),
            error_description=data.get("error_description"),
            options=data.get("options", {}),
        )

        # Reconstruct token response if present
        if data.get("token_response"):
            state.token_response = _dict_to_token_response(data["token_response"])

        # Reconstruct userinfo response if present
        if data.get("userinfo_response"):
            state.userinfo_response = _dict_to_userinfo(data["userinfo_response"])

        # Reconstruct decoded tokens if present
        if data.get("id_token_decoded"):
            state.id_token_decoded = _dict_to_decoded_token(data["id_token_decoded"])
        if data.get("access_token_decoded"):
            state.access_token_decoded = _dict_to_decoded_token(data["access_token_decoded"])

        # Reconstruct validation results if present
        if data.get("id_token_validation"):
            state.id_token_validation = TokenValidationResult.from_dict(data["id_token_validation"])
        if data.get("access_token_validation"):
            state.access_token_validation = TokenValidationResult.from_dict(data["access_token_validation"])

        return state


def _preflight_to_dict(preflight: PreflightResult) -> dict[str, Any]:
    """Convert PreflightResult to dict."""
    return {
        "all_passed": preflight.all_passed,
        "warnings": preflight.warnings,
        "checks": [
            {
                "name": c.name,
                "description": c.description,
                "passed": c.passed,
                "details": c.details,
            }
            for c in preflight.checks
        ],
    }


def _dict_to_preflight(data: dict[str, Any]) -> PreflightResult:
    """Reconstruct PreflightResult from dict."""
    checks = [
        PreflightCheck(
            name=c["name"],
            description=c["description"],
            passed=c["passed"],
            details=c.get("details", ""),
        )
        for c in data.get("checks", [])
    ]
    return PreflightResult(
        checks=checks,
        all_passed=data.get("all_passed", False),
        warnings=data.get("warnings", []),
    )


def _token_response_to_dict(token: TokenResponse) -> dict[str, Any]:
    """Convert TokenResponse to dict."""
    return {
        "access_token": token.access_token,
        "token_type": token.token_type,
        "expires_in": token.expires_in,
        "refresh_token": token.refresh_token,
        "id_token": token.id_token,
        "scope": token.scope,
        "raw_response": token.raw_response,
        "error": token.error,
        "error_description": token.error_description,
    }


def _dict_to_token_response(data: dict[str, Any]) -> TokenResponse:
    """Reconstruct TokenResponse from dict."""
    return TokenResponse(
        access_token=data.get("access_token", ""),
        token_type=data.get("token_type", ""),
        expires_in=data.get("expires_in"),
        refresh_token=data.get("refresh_token"),
        id_token=data.get("id_token"),
        scope=data.get("scope"),
        raw_response=data.get("raw_response", {}),
        error=data.get("error"),
        error_description=data.get("error_description"),
    )


def _userinfo_to_dict(userinfo: UserInfoResponse) -> dict[str, Any]:
    """Convert UserInfoResponse to dict."""
    return {
        "sub": userinfo.sub,
        "name": userinfo.name,
        "email": userinfo.email,
        "email_verified": userinfo.email_verified,
        "preferred_username": userinfo.preferred_username,
        "given_name": userinfo.given_name,
        "family_name": userinfo.family_name,
        "picture": userinfo.picture,
        "claims": userinfo.claims,
        "error": userinfo.error,
        "error_description": userinfo.error_description,
    }


def _dict_to_userinfo(data: dict[str, Any]) -> UserInfoResponse:
    """Reconstruct UserInfoResponse from dict."""
    return UserInfoResponse(
        sub=data.get("sub"),
        name=data.get("name"),
        email=data.get("email"),
        email_verified=data.get("email_verified"),
        preferred_username=data.get("preferred_username"),
        given_name=data.get("given_name"),
        family_name=data.get("family_name"),
        picture=data.get("picture"),
        claims=data.get("claims", {}),
        error=data.get("error"),
        error_description=data.get("error_description"),
    )


def _decoded_token_to_dict(decoded: DecodedToken) -> dict[str, Any]:
    """Convert DecodedToken to dict."""
    return {
        "header": decoded.header,
        "payload": decoded.payload,
        "signature": decoded.signature,
        "is_valid_format": decoded.is_valid_format,
        "error": decoded.error,
        "issuer": decoded.issuer,
        "subject": decoded.subject,
        "audience": decoded.audience,
        "expiration": decoded.expiration.isoformat() if decoded.expiration else None,
        "issued_at": decoded.issued_at.isoformat() if decoded.issued_at else None,
        "not_before": decoded.not_before.isoformat() if decoded.not_before else None,
        "jwt_id": decoded.jwt_id,
        "nonce": decoded.nonce,
    }


def _dict_to_decoded_token(data: dict[str, Any]) -> DecodedToken:
    """Reconstruct DecodedToken from dict."""
    decoded = DecodedToken(
        header=data.get("header", {}),
        payload=data.get("payload", {}),
        signature=data.get("signature", ""),
        is_valid_format=data.get("is_valid_format", False),
        error=data.get("error"),
        issuer=data.get("issuer"),
        subject=data.get("subject"),
        audience=data.get("audience"),
        jwt_id=data.get("jwt_id"),
        nonce=data.get("nonce"),
    )
    if data.get("expiration"):
        decoded.expiration = datetime.fromisoformat(data["expiration"])
    if data.get("issued_at"):
        decoded.issued_at = datetime.fromisoformat(data["issued_at"])
    if data.get("not_before"):
        decoded.not_before = datetime.fromisoformat(data["not_before"])
    return decoded


@dataclass
class OIDCFlowResult:
    """Result of an OIDC flow test."""

    flow_state: OIDCFlowState
    outcome: TestOutcome
    duration_ms: int | None = None
    summary: str = ""


class AuthorizationCodeFlow:
    """Orchestrates the OIDC Authorization Code flow.

    This flow follows these steps:
    1. Run pre-flight checks
    2. Create authorization request
    3. Redirect user to IdP
    4. Handle callback with authorization code
    5. Exchange code for tokens
    6. Decode and display tokens
    7. Optionally fetch userinfo
    8. Record test result
    """

    def __init__(
        self,
        idp: IdPProvider,
        db: Database,
        client_id: str,
        client_secret: str | None = None,
        base_url: str = "https://localhost:8443",
        scopes: list[str] | None = None,
        protocol_logger: ProtocolLogger | None = None,
    ) -> None:
        """Initialize the flow handler.

        Args:
            idp: Identity Provider configuration.
            db: Database instance for recording results.
            client_id: OAuth2 client ID.
            client_secret: OAuth2 client secret (optional for public clients).
            base_url: Base URL of this application.
            scopes: Scopes to request (defaults to IdP defaults).
            protocol_logger: Optional protocol logger for HTTP traffic capture.
        """
        self.idp = idp
        self.db = db
        self.base_url = base_url.rstrip("/")
        self.client_id = client_id
        self.client_secret = client_secret
        self.scopes = scopes
        self.protocol_logger = protocol_logger or get_protocol_logger()

        # Build redirect URI
        self.redirect_uri = f"{self.base_url}/oidc/callback"

        # Create client config
        self.client_config = OIDCClientConfig.from_idp(
            idp=idp,
            client_id=client_id,
            client_secret=client_secret,
            redirect_uri=self.redirect_uri,
            scopes=scopes,
        )
        self.client = OIDCClient(self.client_config, protocol_logger=self.protocol_logger)

    def start_flow(
        self,
        prompt: str | None = None,
        login_hint: str | None = None,
    ) -> OIDCFlowState:
        """Start a new Authorization Code flow.

        Args:
            prompt: OIDC prompt parameter.
            login_hint: OIDC login_hint parameter.

        Returns:
            OIDCFlowState with preflight results.
        """
        flow_id = f"oidc_flow_{secrets.token_hex(16)}"

        # Start protocol logging for this flow
        protocol_log = self.protocol_logger.start_flow(flow_id, "oidc_authorization_code")

        # Run pre-flight checks
        preflight = self._run_preflight_checks()

        state = OIDCFlowState(
            flow_id=flow_id,
            idp_id=self.idp.id,
            idp_name=self.idp.name,
            status=OIDCFlowStatus.PREFLIGHT,
            grant_type="authorization_code",
            client_id=self.client_id,
            redirect_uri=self.redirect_uri,
            scopes=self.client_config.scopes,
            started_at=datetime.now(UTC),
            preflight=preflight,
            options={
                "prompt": prompt,
                "login_hint": login_hint,
            },
            protocol_log=protocol_log,
        )

        return state

    def _run_preflight_checks(self) -> PreflightResult:
        """Run pre-flight checks for the Authorization Code flow."""
        checks = []
        warnings = []

        # Check authorization endpoint
        auth_check = PreflightCheck(
            name="Authorization Endpoint",
            description="IdP authorization endpoint is configured",
            passed=bool(self.client_config.authorization_endpoint),
            details=self.client_config.authorization_endpoint or "Not configured",
        )
        checks.append(auth_check)

        # Check token endpoint
        token_check = PreflightCheck(
            name="Token Endpoint",
            description="IdP token endpoint is configured",
            passed=bool(self.client_config.token_endpoint),
            details=self.client_config.token_endpoint or "Not configured",
        )
        checks.append(token_check)

        # Check client ID
        client_check = PreflightCheck(
            name="Client ID",
            description="OAuth2 client ID is configured",
            passed=bool(self.client_id),
            details=self.client_id if self.client_id else "Not configured",
        )
        checks.append(client_check)

        # Check redirect URI
        redirect_check = PreflightCheck(
            name="Redirect URI",
            description="Redirect URI is configured",
            passed=bool(self.redirect_uri),
            details=self.redirect_uri,
        )
        checks.append(redirect_check)

        # Check for client secret (confidential client)
        if not self.client_secret:
            warnings.append("No client secret configured. This is only valid for public clients using PKCE.")

        # Check userinfo endpoint (optional)
        if not self.client_config.userinfo_endpoint:
            warnings.append("UserInfo endpoint not configured. User claims will only be available from ID token.")

        # Check JWKS URI (optional but recommended)
        if not self.client_config.jwks_uri:
            warnings.append("JWKS URI not configured. Token signature verification will not be available.")

        all_passed = all(c.passed for c in checks)

        return PreflightResult(
            checks=checks,
            all_passed=all_passed,
            warnings=warnings,
        )

    def create_authorization_request(self, state: OIDCFlowState) -> tuple[OIDCFlowState, str]:
        """Create the authorization request URL.

        Args:
            state: Current flow state.

        Returns:
            Tuple of (updated state, authorization URL).

        Raises:
            ValueError: If flow is in wrong state.
        """
        if state.status != OIDCFlowStatus.PREFLIGHT:
            raise ValueError(f"Cannot create authorization request from state: {state.status}")

        if state.preflight and not state.preflight.all_passed:
            state.status = OIDCFlowStatus.FAILED
            state.error = "Pre-flight checks failed"
            return state, ""

        # Get PKCE options from state
        use_pkce = state.options.get("use_pkce", False)
        code_challenge_method = state.options.get("code_challenge_method", "S256")

        # Create authorization request
        auth_request: AuthorizationRequest = self.client.create_authorization_request(
            prompt=state.options.get("prompt"),
            login_hint=state.options.get("login_hint"),
            use_pkce=use_pkce,
            code_challenge_method=code_challenge_method,
        )

        # Update state
        state.status = OIDCFlowStatus.INITIATED
        state.state = auth_request.state
        state.nonce = auth_request.nonce
        state.code_verifier = auth_request.code_verifier
        state.code_challenge = auth_request.code_challenge
        state.code_challenge_method = auth_request.code_challenge_method

        return state, auth_request.authorization_url

    def process_callback(
        self,
        state: OIDCFlowState,
        code: str | None = None,
        error: str | None = None,
        error_description: str | None = None,
        returned_state: str | None = None,
    ) -> OIDCFlowState:
        """Process the authorization callback.

        Args:
            state: Current flow state.
            code: Authorization code (on success).
            error: Error code (on failure).
            error_description: Error description (on failure).
            returned_state: State parameter returned by IdP.

        Returns:
            Updated flow state.
        """
        state.completed_at = datetime.now(UTC)

        # Verify state parameter
        if returned_state and returned_state != state.state:
            state.status = OIDCFlowStatus.FAILED
            state.error = "state_mismatch"
            state.error_description = f"State parameter mismatch. Expected: {state.state}, Got: {returned_state}"
            return state

        # Handle error response
        if error:
            state.status = OIDCFlowStatus.FAILED
            state.error = error
            state.error_description = error_description
            return state

        # Handle missing code
        if not code:
            state.status = OIDCFlowStatus.FAILED
            state.error = "missing_code"
            state.error_description = "No authorization code received"
            return state

        state.authorization_code = code
        state.status = OIDCFlowStatus.EXCHANGING

        # Exchange code for tokens
        token_response = self.client.exchange_code(
            code=code,
            code_verifier=state.code_verifier,
        )
        state.token_response = token_response

        if not token_response.is_success:
            state.status = OIDCFlowStatus.FAILED
            state.error = token_response.error
            state.error_description = token_response.error_description
            return state

        # Decode ID token if present
        if token_response.id_token:
            state.id_token_decoded = decode_jwt(token_response.id_token)

            # Validate ID token (signature + claims)
            validator = TokenValidator(
                jwks_uri=self.client_config.jwks_uri,
                issuer=self.client_config.issuer,
                audience=self.client_id,
            )
            state.id_token_validation = validator.validate_token(
                token_response.id_token,
                nonce=state.nonce,
            )

            # Check nonce from validation result or decoded token
            if state.nonce and state.id_token_decoded.nonce != state.nonce:
                state.status = OIDCFlowStatus.FAILED
                state.error = "nonce_mismatch"
                state.error_description = (
                    f"Nonce mismatch in ID token. Expected: {state.nonce}, Got: {state.id_token_decoded.nonce}"
                )
                return state

        # Try to decode access token (may not be JWT)
        if token_response.access_token:
            decoded = decode_jwt(token_response.access_token)
            if decoded.is_valid_format:
                state.access_token_decoded = decoded
                # Validate access token signature (claims may differ from ID token)
                validator = TokenValidator(
                    jwks_uri=self.client_config.jwks_uri,
                    issuer=self.client_config.issuer,
                    # audience for access tokens may differ from client_id
                )
                state.access_token_validation = validator.validate_token(
                    token_response.access_token,
                    validate_signature=True,
                )

        # Fetch userinfo if endpoint is configured
        if self.client_config.userinfo_endpoint and token_response.access_token:
            userinfo = self.client.get_userinfo(token_response.access_token)
            state.userinfo_response = userinfo

        state.status = OIDCFlowStatus.COMPLETED

        # End protocol logging
        state.protocol_log = self.protocol_logger.end_flow()

        return state

    def record_result(self, state: OIDCFlowState) -> int:
        """Record the test result to the database.

        Args:
            state: Completed flow state.

        Returns:
            ID of the created TestResult record.
        """
        from authtest.storage.models import TestResult

        # Calculate duration
        duration_ms = None
        if state.started_at and state.completed_at:
            duration = state.completed_at - state.started_at
            duration_ms = int(duration.total_seconds() * 1000)

        # Determine outcome
        if state.status == OIDCFlowStatus.COMPLETED:
            outcome = TestOutcome.PASSED
        elif state.status == OIDCFlowStatus.FAILED:
            outcome = TestOutcome.FAILED
        else:
            outcome = TestOutcome.ERROR

        # Build request data
        request_data = {
            "flow_type": state.grant_type,
            "client_id": state.client_id,
            "redirect_uri": state.redirect_uri,
            "scopes": state.scopes,
            "state": state.state,
            "nonce": state.nonce,
            "options": state.options,
        }

        # Add PKCE info if used
        if state.code_verifier:
            request_data["pkce"] = {
                "used": True,
                "code_challenge_method": state.code_challenge_method,
            }

        # Build response data
        response_data: dict[str, Any] = {}
        if state.token_response:
            response_data["token_response"] = _token_response_to_dict(state.token_response)
        if state.id_token_decoded:
            response_data["id_token_decoded"] = _decoded_token_to_dict(state.id_token_decoded)
        if state.access_token_decoded:
            response_data["access_token_decoded"] = _decoded_token_to_dict(state.access_token_decoded)
        if state.id_token_validation:
            response_data["id_token_validation"] = state.id_token_validation.to_dict()
        if state.access_token_validation:
            response_data["access_token_validation"] = state.access_token_validation.to_dict()
        if state.userinfo_response:
            response_data["userinfo"] = _userinfo_to_dict(state.userinfo_response)

        # Include protocol log (without sensitive data)
        if state.protocol_log:
            response_data["protocol_log"] = state.protocol_log.to_dict(include_sensitive=False)

        # Determine test name based on PKCE usage
        test_name = "Authorization Code Flow"
        if state.code_verifier:
            test_name = f"Authorization Code Flow + PKCE ({state.code_challenge_method or 'S256'})"

        result = TestResult(
            idp_provider_id=state.idp_id,
            test_name=test_name,
            test_type="oidc",
            status=outcome.value,
            error_message=state.error_description or state.error,
            started_at=state.started_at or datetime.now(UTC),
            completed_at=state.completed_at,
            duration_ms=duration_ms,
            request_data=request_data,
            response_data=response_data,
        )

        session = self.db.get_session()
        try:
            session.add(result)
            session.commit()
            result_id = result.id
        finally:
            session.close()

        return result_id

    def get_flow_result(self, state: OIDCFlowState) -> OIDCFlowResult:
        """Get the final result of the flow.

        Args:
            state: Completed flow state.

        Returns:
            OIDCFlowResult with outcome summary.
        """
        duration_ms = None
        if state.started_at and state.completed_at:
            duration = state.completed_at - state.started_at
            duration_ms = int(duration.total_seconds() * 1000)

        if state.status == OIDCFlowStatus.COMPLETED:
            outcome = TestOutcome.PASSED

            # Build summary
            if state.id_token_decoded and state.id_token_decoded.subject:
                summary = f"Authenticated as: {state.id_token_decoded.subject}"
            elif state.userinfo_response and state.userinfo_response.sub:
                summary = f"Authenticated as: {state.userinfo_response.sub}"
            else:
                summary = "Authentication successful"

            # Add email if available
            email = None
            if state.userinfo_response and state.userinfo_response.email:
                email = state.userinfo_response.email
            elif state.id_token_decoded and state.id_token_decoded.payload.get("email"):
                email = state.id_token_decoded.payload["email"]

            if email:
                summary += f" ({email})"

        elif state.status == OIDCFlowStatus.FAILED:
            outcome = TestOutcome.FAILED
            summary = state.error_description or state.error or "Authentication failed"
        else:
            outcome = TestOutcome.ERROR
            summary = state.error or f"Flow ended in unexpected state: {state.status}"

        return OIDCFlowResult(
            flow_state=state,
            outcome=outcome,
            duration_ms=duration_ms,
            summary=summary,
        )


class ImplicitFlow:
    """Orchestrates the OIDC Implicit flow (LEGACY - NOT RECOMMENDED).

    WARNING: The Implicit flow is considered insecure and should NOT be used
    for new applications. It exposes tokens in the URL fragment which can be
    leaked through browser history, referrer headers, and logging.

    This flow is provided for testing legacy implementations only.

    Flow steps:
    1. Run pre-flight checks
    2. Create authorization request with response_type=token or id_token
    3. Redirect user to IdP
    4. IdP returns tokens directly in URL fragment (no code exchange)
    5. Client-side JavaScript extracts tokens from fragment
    6. Decode and display tokens
    7. Record test result
    """

    def __init__(
        self,
        idp: IdPProvider,
        db: Database,
        client_id: str,
        base_url: str = "https://localhost:8443",
        scopes: list[str] | None = None,
        protocol_logger: ProtocolLogger | None = None,
    ) -> None:
        """Initialize the flow handler.

        Args:
            idp: Identity Provider configuration.
            db: Database instance for recording results.
            client_id: OAuth2 client ID.
            base_url: Base URL of this application.
            scopes: Scopes to request (defaults to IdP defaults).
            protocol_logger: Optional protocol logger for HTTP traffic capture.
        """
        self.idp = idp
        self.db = db
        self.base_url = base_url.rstrip("/")
        self.client_id = client_id
        self.scopes = scopes
        self.protocol_logger = protocol_logger or get_protocol_logger()

        # Build redirect URI - uses a special callback for implicit flow
        self.redirect_uri = f"{self.base_url}/oidc/implicit/callback"

        # Create client config (no client_secret needed for implicit flow)
        self.client_config = OIDCClientConfig.from_idp(
            idp=idp,
            client_id=client_id,
            redirect_uri=self.redirect_uri,
            scopes=scopes,
        )
        self.client = OIDCClient(self.client_config, protocol_logger=self.protocol_logger)

    def start_flow(
        self,
        response_type: str = "id_token token",
        prompt: str | None = None,
        login_hint: str | None = None,
    ) -> OIDCFlowState:
        """Start a new Implicit flow.

        Args:
            response_type: OIDC response type (token, id_token, or id_token token).
            prompt: OIDC prompt parameter.
            login_hint: OIDC login_hint parameter.

        Returns:
            OIDCFlowState with preflight results.
        """
        flow_id = f"oidc_implicit_flow_{secrets.token_hex(16)}"

        # Start protocol logging for this flow
        protocol_log = self.protocol_logger.start_flow(flow_id, "oidc_implicit")

        # Run pre-flight checks
        preflight = self._run_preflight_checks()

        state = OIDCFlowState(
            flow_id=flow_id,
            idp_id=self.idp.id,
            idp_name=self.idp.name,
            status=OIDCFlowStatus.PREFLIGHT,
            grant_type="implicit",
            client_id=self.client_id,
            redirect_uri=self.redirect_uri,
            scopes=self.client_config.scopes,
            started_at=datetime.now(UTC),
            preflight=preflight,
            options={
                "response_type": response_type,
                "prompt": prompt,
                "login_hint": login_hint,
            },
            protocol_log=protocol_log,
        )

        return state

    def _run_preflight_checks(self) -> PreflightResult:
        """Run pre-flight checks for the Implicit flow."""
        checks = []
        warnings = []

        # Check authorization endpoint
        auth_check = PreflightCheck(
            name="Authorization Endpoint",
            description="IdP authorization endpoint is configured",
            passed=bool(self.client_config.authorization_endpoint),
            details=self.client_config.authorization_endpoint or "Not configured",
        )
        checks.append(auth_check)

        # Check client ID
        client_check = PreflightCheck(
            name="Client ID",
            description="OAuth2 client ID is configured",
            passed=bool(self.client_id),
            details=self.client_id if self.client_id else "Not configured",
        )
        checks.append(client_check)

        # Check redirect URI
        redirect_check = PreflightCheck(
            name="Redirect URI",
            description="Redirect URI is configured",
            passed=bool(self.redirect_uri),
            details=self.redirect_uri,
        )
        checks.append(redirect_check)

        # Security warning - always show
        warnings.append(
            "SECURITY WARNING: The Implicit flow is deprecated and insecure. "
            "Tokens are exposed in the URL fragment and can leak via browser history, "
            "referrer headers, and server logs. Use Authorization Code + PKCE instead."
        )

        # Check JWKS URI (optional but recommended)
        if not self.client_config.jwks_uri:
            warnings.append("JWKS URI not configured. Token signature verification will not be available.")

        all_passed = all(c.passed for c in checks)

        return PreflightResult(
            checks=checks,
            all_passed=all_passed,
            warnings=warnings,
        )

    def create_authorization_request(self, state: OIDCFlowState) -> tuple[OIDCFlowState, str]:
        """Create the authorization request URL for implicit flow.

        Args:
            state: Current flow state.

        Returns:
            Tuple of (updated state, authorization URL).

        Raises:
            ValueError: If flow is in wrong state.
        """
        if state.status != OIDCFlowStatus.PREFLIGHT:
            raise ValueError(f"Cannot create authorization request from state: {state.status}")

        if state.preflight and not state.preflight.all_passed:
            state.status = OIDCFlowStatus.FAILED
            state.error = "Pre-flight checks failed"
            return state, ""

        # Get response_type from options (token, id_token, or id_token token)
        response_type = state.options.get("response_type", "id_token token")

        # Generate state and nonce
        oauth_state = secrets.token_urlsafe(32)
        nonce = secrets.token_urlsafe(32)

        # Build authorization URL with implicit flow parameters
        from urllib.parse import urlencode

        params: dict[str, str] = {
            "response_type": response_type,
            "client_id": self.client_id,
            "redirect_uri": self.redirect_uri,
            "scope": " ".join(self.client_config.scopes),
            "state": oauth_state,
            "nonce": nonce,
        }

        if state.options.get("prompt"):
            params["prompt"] = state.options["prompt"]

        if state.options.get("login_hint"):
            params["login_hint"] = state.options["login_hint"]

        authorization_url = f"{self.client_config.authorization_endpoint}?{urlencode(params)}"

        # Update state
        state.status = OIDCFlowStatus.INITIATED
        state.state = oauth_state
        state.nonce = nonce

        return state, authorization_url

    def process_fragment_response(
        self,
        state: OIDCFlowState,
        access_token: str | None = None,
        id_token: str | None = None,
        token_type: str | None = None,
        expires_in: int | None = None,
        scope: str | None = None,
        error: str | None = None,
        error_description: str | None = None,
        returned_state: str | None = None,
    ) -> OIDCFlowState:
        """Process the tokens received in the URL fragment.

        This is called after client-side JavaScript extracts tokens from
        the URL fragment and sends them to the server.

        Args:
            state: Current flow state.
            access_token: Access token from fragment.
            id_token: ID token from fragment.
            token_type: Token type (usually Bearer).
            expires_in: Token expiration in seconds.
            scope: Granted scopes.
            error: Error code (on failure).
            error_description: Error description (on failure).
            returned_state: State parameter returned by IdP.

        Returns:
            Updated flow state.
        """
        state.completed_at = datetime.now(UTC)

        # Verify state parameter
        if returned_state and returned_state != state.state:
            state.status = OIDCFlowStatus.FAILED
            state.error = "state_mismatch"
            state.error_description = f"State parameter mismatch. Expected: {state.state}, Got: {returned_state}"
            return state

        # Handle error response
        if error:
            state.status = OIDCFlowStatus.FAILED
            state.error = error
            state.error_description = error_description
            return state

        # Build a token response from fragment parameters
        token_response = TokenResponse(
            access_token=access_token or "",
            token_type=token_type or "Bearer",
            expires_in=expires_in,
            id_token=id_token,
            scope=scope,
            raw_response={
                "access_token": access_token,
                "id_token": id_token,
                "token_type": token_type,
                "expires_in": expires_in,
                "scope": scope,
            },
        )
        state.token_response = token_response

        # Check if we got at least one token
        if not access_token and not id_token:
            state.status = OIDCFlowStatus.FAILED
            state.error = "missing_tokens"
            state.error_description = "No tokens received in the response"
            return state

        # Decode ID token if present
        if id_token:
            state.id_token_decoded = decode_jwt(id_token)

            # Validate ID token (signature + claims)
            validator = TokenValidator(
                jwks_uri=self.client_config.jwks_uri,
                issuer=self.client_config.issuer,
                audience=self.client_id,
            )
            state.id_token_validation = validator.validate_token(
                id_token,
                nonce=state.nonce,
            )

            # Check nonce
            if state.nonce and state.id_token_decoded.nonce != state.nonce:
                state.status = OIDCFlowStatus.FAILED
                state.error = "nonce_mismatch"
                state.error_description = (
                    f"Nonce mismatch in ID token. Expected: {state.nonce}, Got: {state.id_token_decoded.nonce}"
                )
                return state

        # Try to decode access token (may not be JWT)
        if access_token:
            decoded = decode_jwt(access_token)
            if decoded.is_valid_format:
                state.access_token_decoded = decoded
                # Validate access token signature
                validator = TokenValidator(
                    jwks_uri=self.client_config.jwks_uri,
                    issuer=self.client_config.issuer,
                )
                state.access_token_validation = validator.validate_token(
                    access_token,
                    validate_signature=True,
                )

        state.status = OIDCFlowStatus.COMPLETED

        # End protocol logging
        state.protocol_log = self.protocol_logger.end_flow()

        return state

    def record_result(self, state: OIDCFlowState) -> int:
        """Record the test result to the database.

        Args:
            state: Completed flow state.

        Returns:
            ID of the created TestResult record.
        """
        from authtest.storage.models import TestResult

        # Calculate duration
        duration_ms = None
        if state.started_at and state.completed_at:
            duration = state.completed_at - state.started_at
            duration_ms = int(duration.total_seconds() * 1000)

        # Determine outcome
        if state.status == OIDCFlowStatus.COMPLETED:
            outcome = TestOutcome.PASSED
        elif state.status == OIDCFlowStatus.FAILED:
            outcome = TestOutcome.FAILED
        else:
            outcome = TestOutcome.ERROR

        # Build request data
        request_data = {
            "flow_type": state.grant_type,
            "response_type": state.options.get("response_type", "id_token token"),
            "client_id": state.client_id,
            "redirect_uri": state.redirect_uri,
            "scopes": state.scopes,
            "state": state.state,
            "nonce": state.nonce,
            "options": state.options,
        }

        # Build response data
        response_data: dict[str, Any] = {}
        if state.token_response:
            response_data["token_response"] = _token_response_to_dict(state.token_response)
        if state.id_token_decoded:
            response_data["id_token_decoded"] = _decoded_token_to_dict(state.id_token_decoded)
        if state.access_token_decoded:
            response_data["access_token_decoded"] = _decoded_token_to_dict(state.access_token_decoded)
        if state.id_token_validation:
            response_data["id_token_validation"] = state.id_token_validation.to_dict()
        if state.access_token_validation:
            response_data["access_token_validation"] = state.access_token_validation.to_dict()

        # Include protocol log (without sensitive data)
        if state.protocol_log:
            response_data["protocol_log"] = state.protocol_log.to_dict(include_sensitive=False)

        # Determine test name based on response_type
        response_type = state.options.get("response_type", "id_token token")
        test_name = f"Implicit Flow ({response_type})"

        result = TestResult(
            idp_provider_id=state.idp_id,
            test_name=test_name,
            test_type="oidc",
            status=outcome.value,
            error_message=state.error_description or state.error,
            started_at=state.started_at or datetime.now(UTC),
            completed_at=state.completed_at,
            duration_ms=duration_ms,
            request_data=request_data,
            response_data=response_data,
        )

        session = self.db.get_session()
        try:
            session.add(result)
            session.commit()
            result_id = result.id
        finally:
            session.close()

        return result_id

    def get_flow_result(self, state: OIDCFlowState) -> OIDCFlowResult:
        """Get the final result of the flow.

        Args:
            state: Completed flow state.

        Returns:
            OIDCFlowResult with outcome summary.
        """
        duration_ms = None
        if state.started_at and state.completed_at:
            duration = state.completed_at - state.started_at
            duration_ms = int(duration.total_seconds() * 1000)

        if state.status == OIDCFlowStatus.COMPLETED:
            outcome = TestOutcome.PASSED

            # Build summary
            if state.id_token_decoded and state.id_token_decoded.subject:
                summary = f"Authenticated as: {state.id_token_decoded.subject}"
            else:
                summary = "Tokens received successfully"

            # Add email if available
            if state.id_token_decoded and state.id_token_decoded.payload.get("email"):
                summary += f" ({state.id_token_decoded.payload['email']})"

        elif state.status == OIDCFlowStatus.FAILED:
            outcome = TestOutcome.FAILED
            summary = state.error_description or state.error or "Authentication failed"
        else:
            outcome = TestOutcome.ERROR
            summary = state.error or f"Flow ended in unexpected state: {state.status}"

        return OIDCFlowResult(
            flow_state=state,
            outcome=outcome,
            duration_ms=duration_ms,
            summary=summary,
        )


class ClientCredentialsFlow:
    """Orchestrates the OIDC Client Credentials flow.

    This is a machine-to-machine flow that:
    1. Runs pre-flight checks
    2. Authenticates using client_id and client_secret
    3. Retrieves access token directly (no user interaction)
    4. Decodes and validates the token
    5. Records test result
    """

    def __init__(
        self,
        idp: IdPProvider,
        db: Database,
        client_id: str,
        client_secret: str,
        scopes: list[str] | None = None,
        protocol_logger: ProtocolLogger | None = None,
    ) -> None:
        """Initialize the flow handler.

        Args:
            idp: Identity Provider configuration.
            db: Database instance for recording results.
            client_id: OAuth2 client ID.
            client_secret: OAuth2 client secret (required for this flow).
            scopes: Scopes to request (defaults to IdP defaults minus 'openid').
            protocol_logger: Optional protocol logger for HTTP traffic capture.
        """
        self.idp = idp
        self.db = db
        self.client_id = client_id
        self.client_secret = client_secret
        self.scopes = scopes
        self.protocol_logger = protocol_logger or get_protocol_logger()

        # Create client config
        self.client_config = OIDCClientConfig.from_idp(
            idp=idp,
            client_id=client_id,
            client_secret=client_secret,
            scopes=scopes,
        )
        self.client = OIDCClient(self.client_config, protocol_logger=self.protocol_logger)

    def start_flow(self) -> OIDCFlowState:
        """Start a new Client Credentials flow.

        Returns:
            OIDCFlowState with preflight results.
        """
        flow_id = f"oidc_cc_flow_{secrets.token_hex(16)}"

        # Start protocol logging for this flow
        protocol_log = self.protocol_logger.start_flow(flow_id, "oidc_client_credentials")

        # Run pre-flight checks
        preflight = self._run_preflight_checks()

        state = OIDCFlowState(
            flow_id=flow_id,
            idp_id=self.idp.id,
            idp_name=self.idp.name,
            status=OIDCFlowStatus.PREFLIGHT,
            grant_type="client_credentials",
            client_id=self.client_id,
            scopes=self.scopes or [s for s in self.client_config.scopes if s != "openid"],
            started_at=datetime.now(UTC),
            preflight=preflight,
            protocol_log=protocol_log,
        )

        return state

    def _run_preflight_checks(self) -> PreflightResult:
        """Run pre-flight checks for the Client Credentials flow."""
        checks = []
        warnings = []

        # Check token endpoint
        token_check = PreflightCheck(
            name="Token Endpoint",
            description="IdP token endpoint is configured",
            passed=bool(self.client_config.token_endpoint),
            details=self.client_config.token_endpoint or "Not configured",
        )
        checks.append(token_check)

        # Check client ID
        client_check = PreflightCheck(
            name="Client ID",
            description="OAuth2 client ID is configured",
            passed=bool(self.client_id),
            details=self.client_id if self.client_id else "Not configured",
        )
        checks.append(client_check)

        # Check client secret (required for this flow)
        secret_check = PreflightCheck(
            name="Client Secret",
            description="OAuth2 client secret is configured (required for client credentials)",
            passed=bool(self.client_secret),
            details="Configured" if self.client_secret else "Not configured",
        )
        checks.append(secret_check)

        # Check JWKS URI (optional but recommended)
        if not self.client_config.jwks_uri:
            warnings.append("JWKS URI not configured. Token signature verification will not be available.")

        all_passed = all(c.passed for c in checks)

        return PreflightResult(
            checks=checks,
            all_passed=all_passed,
            warnings=warnings,
        )

    def execute_flow(
        self,
        state: OIDCFlowState,
        scopes: list[str] | None = None,
    ) -> OIDCFlowState:
        """Execute the Client Credentials flow.

        Args:
            state: Current flow state.
            scopes: Optional override for scopes to request.

        Returns:
            Updated flow state with token response.
        """
        if state.status != OIDCFlowStatus.PREFLIGHT:
            state.status = OIDCFlowStatus.FAILED
            state.error = "invalid_state"
            state.error_description = f"Cannot execute flow from state: {state.status}"
            return state

        if state.preflight and not state.preflight.all_passed:
            state.status = OIDCFlowStatus.FAILED
            state.error = "preflight_failed"
            state.error_description = "Pre-flight checks failed"
            return state

        state.status = OIDCFlowStatus.EXCHANGING

        # Execute client credentials grant
        request_scopes = scopes or state.scopes
        token_response = self.client.client_credentials_grant(scopes=request_scopes)
        state.token_response = token_response
        state.completed_at = datetime.now(UTC)

        if not token_response.is_success:
            state.status = OIDCFlowStatus.FAILED
            state.error = token_response.error
            state.error_description = token_response.error_description
            return state

        # Try to decode access token (may or may not be JWT)
        if token_response.access_token:
            decoded = decode_jwt(token_response.access_token)
            if decoded.is_valid_format:
                state.access_token_decoded = decoded
                # Validate access token signature
                validator = TokenValidator(
                    jwks_uri=self.client_config.jwks_uri,
                    issuer=self.client_config.issuer,
                )
                state.access_token_validation = validator.validate_token(
                    token_response.access_token,
                    validate_signature=True,
                )

        state.status = OIDCFlowStatus.COMPLETED

        # End protocol logging
        state.protocol_log = self.protocol_logger.end_flow()

        return state

    def record_result(self, state: OIDCFlowState) -> int:
        """Record the test result to the database.

        Args:
            state: Completed flow state.

        Returns:
            ID of the created TestResult record.
        """
        from authtest.storage.models import TestResult

        # Calculate duration
        duration_ms = None
        if state.started_at and state.completed_at:
            duration = state.completed_at - state.started_at
            duration_ms = int(duration.total_seconds() * 1000)

        # Determine outcome
        if state.status == OIDCFlowStatus.COMPLETED:
            outcome = TestOutcome.PASSED
        elif state.status == OIDCFlowStatus.FAILED:
            outcome = TestOutcome.FAILED
        else:
            outcome = TestOutcome.ERROR

        # Build request data
        request_data = {
            "flow_type": state.grant_type,
            "client_id": state.client_id,
            "scopes": state.scopes,
        }

        # Build response data
        response_data: dict[str, Any] = {}
        if state.token_response:
            response_data["token_response"] = _token_response_to_dict(state.token_response)
        if state.access_token_decoded:
            response_data["access_token_decoded"] = _decoded_token_to_dict(state.access_token_decoded)
        if state.access_token_validation:
            response_data["access_token_validation"] = state.access_token_validation.to_dict()

        # Include protocol log (without sensitive data)
        if state.protocol_log:
            response_data["protocol_log"] = state.protocol_log.to_dict(include_sensitive=False)

        result = TestResult(
            idp_provider_id=state.idp_id,
            test_name="Client Credentials Flow",
            test_type="oidc",
            status=outcome.value,
            error_message=state.error_description or state.error,
            started_at=state.started_at or datetime.now(UTC),
            completed_at=state.completed_at,
            duration_ms=duration_ms,
            request_data=request_data,
            response_data=response_data,
        )

        session = self.db.get_session()
        try:
            session.add(result)
            session.commit()
            result_id = result.id
        finally:
            session.close()

        return result_id

    def get_flow_result(self, state: OIDCFlowState) -> OIDCFlowResult:
        """Get the final result of the flow.

        Args:
            state: Completed flow state.

        Returns:
            OIDCFlowResult with outcome summary.
        """
        duration_ms = None
        if state.started_at and state.completed_at:
            duration = state.completed_at - state.started_at
            duration_ms = int(duration.total_seconds() * 1000)

        if state.status == OIDCFlowStatus.COMPLETED:
            outcome = TestOutcome.PASSED

            # Build summary
            if state.access_token_decoded and state.access_token_decoded.subject:
                summary = f"Token issued for client: {state.access_token_decoded.subject}"
            else:
                summary = "Access token obtained successfully"

            # Add scope info if available
            if state.token_response and state.token_response.scope:
                summary += f" (scopes: {state.token_response.scope})"

        elif state.status == OIDCFlowStatus.FAILED:
            outcome = TestOutcome.FAILED
            summary = state.error_description or state.error or "Token request failed"
        else:
            outcome = TestOutcome.ERROR
            summary = state.error or f"Flow ended in unexpected state: {state.status}"

        return OIDCFlowResult(
            flow_state=state,
            outcome=outcome,
            duration_ms=duration_ms,
            summary=summary,
        )
