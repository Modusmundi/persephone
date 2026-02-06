"""SAML Single Logout (SLO) implementation.

Handles both SP-initiated and IdP-initiated logout flows:
- LogoutRequest generation and validation
- LogoutResponse generation and validation
- Session cleanup coordination
"""

from __future__ import annotations

import base64
import secrets
import zlib
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from typing import TYPE_CHECKING, Any
from urllib.parse import parse_qs, urlencode, urlparse
from xml.etree import ElementTree

if TYPE_CHECKING:
    from authtest.core.saml.signature import SignatureValidationResult
    from authtest.storage.models import IdPProvider


# SAML namespace
SAML_NS = {
    "samlp": "urn:oasis:names:tc:SAML:2.0:protocol",
    "saml": "urn:oasis:names:tc:SAML:2.0:assertion",
    "ds": "http://www.w3.org/2000/09/xmldsig#",
}


class LogoutStatus(StrEnum):
    """SAML Logout status codes."""

    SUCCESS = "urn:oasis:names:tc:SAML:2.0:status:Success"
    REQUESTER = "urn:oasis:names:tc:SAML:2.0:status:Requester"
    RESPONDER = "urn:oasis:names:tc:SAML:2.0:status:Responder"
    PARTIAL_LOGOUT = "urn:oasis:names:tc:SAML:2.0:status:PartialLogout"
    UNKNOWN_PRINCIPAL = "urn:oasis:names:tc:SAML:2.0:status:UnknownPrincipal"


LOGOUT_STATUS_DESCRIPTIONS = {
    LogoutStatus.SUCCESS: "The logout request was processed successfully",
    LogoutStatus.REQUESTER: "The request was invalid or could not be processed",
    LogoutStatus.RESPONDER: "The IdP encountered an error processing the request",
    LogoutStatus.PARTIAL_LOGOUT: "The user was logged out from some but not all sessions",
    LogoutStatus.UNKNOWN_PRINCIPAL: "The principal specified in the request was not recognized",
}


def get_logout_status_description(status_code: str) -> str:
    """Get a human-readable description for a logout status code."""
    for status in LogoutStatus:
        if status.value == status_code:
            return LOGOUT_STATUS_DESCRIPTIONS.get(status, status_code)
    return status_code


@dataclass
class SAMLLogoutRequest:
    """Represents a SAML LogoutRequest message.

    Used for both SP-initiated (we generate) and IdP-initiated (we receive) logout.
    """

    id: str
    issue_instant: str
    issuer: str
    destination: str
    name_id: str
    name_id_format: str = "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified"
    session_index: str | None = None
    reason: str | None = None
    not_on_or_after: str | None = None

    def to_xml(self) -> str:
        """Generate the LogoutRequest XML."""
        session_index_elem = ""
        if self.session_index:
            session_index_elem = f'\n    <samlp:SessionIndex>{self.session_index}</samlp:SessionIndex>'

        reason_attr = ""
        if self.reason:
            reason_attr = f' Reason="{self.reason}"'

        not_on_or_after_attr = ""
        if self.not_on_or_after:
            not_on_or_after_attr = f' NotOnOrAfter="{self.not_on_or_after}"'

        return f"""<?xml version="1.0" encoding="UTF-8"?>
<samlp:LogoutRequest
    xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
    xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
    ID="{self.id}"
    Version="2.0"
    IssueInstant="{self.issue_instant}"
    Destination="{self.destination}"{reason_attr}{not_on_or_after_attr}>
    <saml:Issuer>{self.issuer}</saml:Issuer>
    <saml:NameID Format="{self.name_id_format}">{self.name_id}</saml:NameID>{session_index_elem}
</samlp:LogoutRequest>"""

    def encode_redirect(self) -> str:
        """Encode request for HTTP-Redirect binding (deflate + base64)."""
        xml_bytes = self.to_xml().encode("utf-8")
        # Deflate compression (raw deflate, no zlib header)
        compressed = zlib.compress(xml_bytes)[2:-4]
        return base64.b64encode(compressed).decode("utf-8")

    def encode_post(self) -> str:
        """Encode request for HTTP-POST binding (base64 only)."""
        xml_bytes = self.to_xml().encode("utf-8")
        return base64.b64encode(xml_bytes).decode("utf-8")

    @classmethod
    def parse(cls, encoded_request: str, is_redirect: bool = False) -> SAMLLogoutRequest:
        """Parse an encoded SAML LogoutRequest.

        Args:
            encoded_request: Base64-encoded (and optionally deflated) LogoutRequest.
            is_redirect: True if from HTTP-Redirect binding (deflated), False for POST.

        Returns:
            Parsed SAMLLogoutRequest object.

        Raises:
            ValueError: If the request cannot be parsed.
        """
        try:
            decoded = base64.b64decode(encoded_request)
            if is_redirect:
                # Decompress deflated content
                decoded = zlib.decompress(decoded, -15)
            xml_str = decoded.decode("utf-8")
        except Exception as e:
            raise ValueError(f"Failed to decode LogoutRequest: {e}") from e

        try:
            root = ElementTree.fromstring(xml_str)
        except ElementTree.ParseError as e:
            raise ValueError(f"Failed to parse LogoutRequest XML: {e}") from e

        # Extract attributes
        request_id = root.get("ID", "")
        issue_instant = root.get("IssueInstant", "")
        destination = root.get("Destination", "")
        reason = root.get("Reason")
        not_on_or_after = root.get("NotOnOrAfter")

        # Extract issuer
        issuer_elem = root.find("saml:Issuer", SAML_NS)
        issuer = issuer_elem.text if issuer_elem is not None and issuer_elem.text else ""

        # Extract NameID
        nameid_elem = root.find("saml:NameID", SAML_NS)
        name_id = nameid_elem.text if nameid_elem is not None and nameid_elem.text else ""
        name_id_format = (
            nameid_elem.get("Format", "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified")
            if nameid_elem is not None
            else "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified"
        )

        # Extract SessionIndex (optional)
        session_index_elem = root.find("samlp:SessionIndex", SAML_NS)
        session_index = (
            session_index_elem.text if session_index_elem is not None and session_index_elem.text else None
        )

        return cls(
            id=request_id,
            issue_instant=issue_instant,
            issuer=issuer,
            destination=destination,
            name_id=name_id,
            name_id_format=name_id_format,
            session_index=session_index,
            reason=reason,
            not_on_or_after=not_on_or_after,
        )


@dataclass
class SAMLLogoutResponse:
    """Represents a parsed SAML LogoutResponse message."""

    raw_xml: str
    response_id: str
    in_response_to: str | None
    issue_instant: str | None
    issuer: str | None
    destination: str | None
    status_code: str | None
    status_message: str | None
    is_success: bool = False
    validation_errors: list[str] = field(default_factory=list)
    signature_validation: SignatureValidationResult | None = None

    @property
    def status_description(self) -> str:
        """Get human-readable description of the status code."""
        if self.status_code:
            return get_logout_status_description(self.status_code)
        return "Unknown status"

    @classmethod
    def parse(cls, encoded_response: str, is_redirect: bool = False) -> SAMLLogoutResponse:
        """Parse an encoded SAML LogoutResponse.

        Args:
            encoded_response: Base64-encoded (and optionally deflated) LogoutResponse.
            is_redirect: True if from HTTP-Redirect binding (deflated), False for POST.

        Returns:
            Parsed SAMLLogoutResponse object.
        """
        try:
            decoded = base64.b64decode(encoded_response)
            if is_redirect:
                # Decompress deflated content
                decoded = zlib.decompress(decoded, -15)
            xml_str = decoded.decode("utf-8")
        except Exception as e:
            return cls(
                raw_xml="",
                response_id="",
                in_response_to=None,
                issue_instant=None,
                issuer=None,
                destination=None,
                status_code=None,
                status_message=None,
                validation_errors=[f"Failed to decode response: {e}"],
            )

        try:
            root = ElementTree.fromstring(xml_str)
        except ElementTree.ParseError as e:
            return cls(
                raw_xml=xml_str,
                response_id="",
                in_response_to=None,
                issue_instant=None,
                issuer=None,
                destination=None,
                status_code=None,
                status_message=None,
                validation_errors=[f"Failed to parse XML: {e}"],
            )

        # Extract response attributes
        response_id = root.get("ID", "")
        in_response_to = root.get("InResponseTo")
        issue_instant = root.get("IssueInstant")
        destination = root.get("Destination")

        # Extract issuer
        issuer_elem = root.find("saml:Issuer", SAML_NS)
        issuer = issuer_elem.text if issuer_elem is not None else None

        # Extract status
        status_elem = root.find("samlp:Status/samlp:StatusCode", SAML_NS)
        status_code = status_elem.get("Value") if status_elem is not None else None

        status_msg_elem = root.find("samlp:Status/samlp:StatusMessage", SAML_NS)
        status_message = status_msg_elem.text if status_msg_elem is not None else None

        is_success = status_code == LogoutStatus.SUCCESS.value

        return cls(
            raw_xml=xml_str,
            response_id=response_id,
            in_response_to=in_response_to,
            issue_instant=issue_instant,
            issuer=issuer,
            destination=destination,
            status_code=status_code,
            status_message=status_message,
            is_success=is_success,
        )

    @classmethod
    def create(
        cls,
        request_id: str,
        issuer: str,
        destination: str,
        status_code: str = LogoutStatus.SUCCESS.value,
        status_message: str | None = None,
    ) -> SAMLLogoutResponse:
        """Create a new LogoutResponse.

        Args:
            request_id: The ID of the LogoutRequest this responds to.
            issuer: The entity ID of the responder (SP).
            destination: The IdP's SLO endpoint URL.
            status_code: The logout status code.
            status_message: Optional status message.

        Returns:
            SAMLLogoutResponse ready to be encoded and sent.
        """
        response_id = f"_authtest_slo_resp_{secrets.token_hex(16)}"
        issue_instant = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")

        status_msg_elem = ""
        if status_message:
            status_msg_elem = f"\n        <samlp:StatusMessage>{status_message}</samlp:StatusMessage>"

        raw_xml = f"""<?xml version="1.0" encoding="UTF-8"?>
<samlp:LogoutResponse
    xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
    xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
    ID="{response_id}"
    Version="2.0"
    IssueInstant="{issue_instant}"
    Destination="{destination}"
    InResponseTo="{request_id}">
    <saml:Issuer>{issuer}</saml:Issuer>
    <samlp:Status>
        <samlp:StatusCode Value="{status_code}"/>{status_msg_elem}
    </samlp:Status>
</samlp:LogoutResponse>"""

        return cls(
            raw_xml=raw_xml,
            response_id=response_id,
            in_response_to=request_id,
            issue_instant=issue_instant,
            issuer=issuer,
            destination=destination,
            status_code=status_code,
            status_message=status_message,
            is_success=status_code == LogoutStatus.SUCCESS.value,
        )

    def encode_redirect(self) -> str:
        """Encode response for HTTP-Redirect binding (deflate + base64)."""
        xml_bytes = self.raw_xml.encode("utf-8")
        compressed = zlib.compress(xml_bytes)[2:-4]
        return base64.b64encode(compressed).decode("utf-8")

    def encode_post(self) -> str:
        """Encode response for HTTP-POST binding (base64 only)."""
        xml_bytes = self.raw_xml.encode("utf-8")
        return base64.b64encode(xml_bytes).decode("utf-8")


@dataclass
class LogoutSessionInfo:
    """Information about the session being logged out.

    This tracks what we know about the user's session for logout validation.
    """

    name_id: str
    name_id_format: str
    session_index: str | None = None
    idp_entity_id: str | None = None
    authenticated_at: datetime | None = None


class SAMLLogoutHandler:
    """Handles SAML Single Logout operations.

    Supports both SP-initiated logout (we send LogoutRequest) and
    IdP-initiated logout (we receive LogoutRequest).
    """

    def __init__(
        self,
        idp: IdPProvider,
        base_url: str = "https://localhost:8443",
    ) -> None:
        """Initialize the logout handler.

        Args:
            idp: Identity Provider configuration.
            base_url: Base URL of this application.
        """
        self.idp = idp
        self.base_url = base_url.rstrip("/")

    @property
    def sp_entity_id(self) -> str:
        """Get the SP entity ID."""
        return f"{self.base_url}/saml/metadata"

    @property
    def slo_url(self) -> str:
        """Get the SP's SLO endpoint URL."""
        return f"{self.base_url}/saml/slo"

    @property
    def idp_slo_url(self) -> str | None:
        """Get the IdP's SLO endpoint URL."""
        return self.idp.slo_url

    def create_logout_request(
        self,
        session_info: LogoutSessionInfo,
        reason: str | None = None,
    ) -> SAMLLogoutRequest:
        """Create a LogoutRequest for SP-initiated logout.

        Args:
            session_info: Information about the session to logout.
            reason: Optional logout reason (user, admin, timeout).

        Returns:
            SAMLLogoutRequest ready to be encoded and sent.

        Raises:
            ValueError: If IdP SLO URL is not configured.
        """
        if not self.idp_slo_url:
            raise ValueError("IdP SLO URL not configured")

        request_id = f"_authtest_slo_{secrets.token_hex(16)}"
        issue_instant = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")

        return SAMLLogoutRequest(
            id=request_id,
            issue_instant=issue_instant,
            issuer=self.sp_entity_id,
            destination=self.idp_slo_url,
            name_id=session_info.name_id,
            name_id_format=session_info.name_id_format,
            session_index=session_info.session_index,
            reason=reason,
        )

    def build_logout_redirect_url(
        self,
        request: SAMLLogoutRequest,
        relay_state: str | None = None,
    ) -> str:
        """Build the SLO redirect URL with encoded LogoutRequest.

        Args:
            request: The SAMLLogoutRequest to encode.
            relay_state: Optional RelayState to preserve.

        Returns:
            Complete URL to redirect the user to.
        """
        if not self.idp_slo_url:
            raise ValueError("IdP SLO URL not configured")

        encoded_request = request.encode_redirect()

        params: dict[str, str] = {"SAMLRequest": encoded_request}
        if relay_state:
            params["RelayState"] = relay_state

        parsed = urlparse(self.idp_slo_url)
        existing_params = parse_qs(parsed.query)
        for key, values in existing_params.items():
            if key not in params:
                params[key] = values[0]

        query_string = urlencode(params)
        return f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{query_string}"

    def process_logout_response(
        self,
        encoded_response: str,
        expected_request_id: str | None = None,
        is_redirect: bool = False,
    ) -> SAMLLogoutResponse:
        """Process a LogoutResponse from the IdP.

        Args:
            encoded_response: Base64-encoded LogoutResponse.
            expected_request_id: The ID of our LogoutRequest (for InResponseTo validation).
            is_redirect: True if from HTTP-Redirect binding.

        Returns:
            Parsed and validated SAMLLogoutResponse.
        """
        from authtest.core.saml.signature import SignatureStatus, validate_signature

        response = SAMLLogoutResponse.parse(encoded_response, is_redirect=is_redirect)

        # Validate signature if we have certificate
        if response.raw_xml and self.idp.x509_cert:
            sig_result = validate_signature(response.raw_xml, self.idp.x509_cert)
            response.signature_validation = sig_result

            if sig_result.status == SignatureStatus.INVALID:
                response.validation_errors.append(
                    f"Signature validation failed: {sig_result.message}"
                )
            elif sig_result.status == SignatureStatus.ERROR:
                response.validation_errors.append(
                    f"Signature validation error: {sig_result.message}"
                )

        # Validate InResponseTo
        if (
            expected_request_id
            and response.in_response_to
            and response.in_response_to != expected_request_id
        ):
            response.validation_errors.append(
                f"InResponseTo ({response.in_response_to}) does not match "
                f"expected request ID ({expected_request_id})"
            )

        # Validate issuer
        if response.issuer and response.issuer != self.idp.entity_id:
            response.validation_errors.append(
                f"Response issuer ({response.issuer}) does not match "
                f"configured IdP entity ID ({self.idp.entity_id})"
            )

        return response

    def process_logout_request(
        self,
        encoded_request: str,
        is_redirect: bool = False,
    ) -> tuple[SAMLLogoutRequest, list[str]]:
        """Process a LogoutRequest from the IdP (IdP-initiated logout).

        Args:
            encoded_request: Base64-encoded LogoutRequest.
            is_redirect: True if from HTTP-Redirect binding.

        Returns:
            Tuple of (parsed LogoutRequest, list of validation errors).
        """
        from authtest.core.saml.signature import SignatureStatus, validate_signature

        validation_errors: list[str] = []

        try:
            request = SAMLLogoutRequest.parse(encoded_request, is_redirect=is_redirect)
        except ValueError as e:
            # Return a minimal request object with the error
            return SAMLLogoutRequest(
                id="",
                issue_instant="",
                issuer="",
                destination="",
                name_id="",
            ), [str(e)]

        # Validate signature if we have certificate
        if self.idp.x509_cert:
            xml_bytes = base64.b64decode(encoded_request)
            if is_redirect:
                xml_bytes = zlib.decompress(xml_bytes, -15)
            xml_str = xml_bytes.decode("utf-8")

            sig_result = validate_signature(xml_str, self.idp.x509_cert)
            if sig_result.status == SignatureStatus.INVALID:
                validation_errors.append(
                    f"Signature validation failed: {sig_result.message}"
                )
            elif sig_result.status == SignatureStatus.ERROR:
                validation_errors.append(
                    f"Signature validation error: {sig_result.message}"
                )

        # Validate issuer
        if request.issuer and request.issuer != self.idp.entity_id:
            validation_errors.append(
                f"Request issuer ({request.issuer}) does not match "
                f"configured IdP entity ID ({self.idp.entity_id})"
            )

        # Validate destination (should be our SLO endpoint)
        if request.destination and request.destination != self.slo_url:
            # Allow if destination matches without trailing slash difference
            normalized_dest = request.destination.rstrip("/")
            normalized_slo = self.slo_url.rstrip("/")
            if normalized_dest != normalized_slo:
                validation_errors.append(
                    f"Request destination ({request.destination}) does not match "
                    f"SP SLO URL ({self.slo_url})"
                )

        return request, validation_errors

    def create_logout_response(
        self,
        request_id: str,
        status_code: str = LogoutStatus.SUCCESS.value,
        status_message: str | None = None,
    ) -> SAMLLogoutResponse:
        """Create a LogoutResponse to send back to the IdP.

        Args:
            request_id: The ID of the received LogoutRequest.
            status_code: The logout status code.
            status_message: Optional status message.

        Returns:
            SAMLLogoutResponse ready to be encoded and sent.

        Raises:
            ValueError: If IdP SLO URL is not configured.
        """
        if not self.idp_slo_url:
            raise ValueError("IdP SLO URL not configured")

        return SAMLLogoutResponse.create(
            request_id=request_id,
            issuer=self.sp_entity_id,
            destination=self.idp_slo_url,
            status_code=status_code,
            status_message=status_message,
        )

    def build_response_redirect_url(
        self,
        response: SAMLLogoutResponse,
        relay_state: str | None = None,
    ) -> str:
        """Build the redirect URL for sending a LogoutResponse.

        Args:
            response: The SAMLLogoutResponse to encode.
            relay_state: Optional RelayState to preserve.

        Returns:
            Complete URL to redirect to.
        """
        if not self.idp_slo_url:
            raise ValueError("IdP SLO URL not configured")

        encoded_response = response.encode_redirect()

        params: dict[str, str] = {"SAMLResponse": encoded_response}
        if relay_state:
            params["RelayState"] = relay_state

        parsed = urlparse(self.idp_slo_url)
        existing_params = parse_qs(parsed.query)
        for key, values in existing_params.items():
            if key not in params:
                params[key] = values[0]

        query_string = urlencode(params)
        return f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{query_string}"


@dataclass
class LogoutValidationCheck:
    """Represents a single logout validation check."""

    name: str
    description: str
    passed: bool
    expected: str | None = None
    actual: str | None = None
    details: str = ""


@dataclass
class LogoutValidationResult:
    """Result of logout validation."""

    checks: list[LogoutValidationCheck] = field(default_factory=list)
    session_terminated: bool = False
    all_passed: bool = False
    warnings: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for storage."""
        return {
            "checks": [
                {
                    "name": c.name,
                    "description": c.description,
                    "passed": c.passed,
                    "expected": c.expected,
                    "actual": c.actual,
                    "details": c.details,
                }
                for c in self.checks
            ],
            "session_terminated": self.session_terminated,
            "all_passed": self.all_passed,
            "warnings": self.warnings,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> LogoutValidationResult:
        """Reconstruct from dictionary."""
        checks = [
            LogoutValidationCheck(
                name=c["name"],
                description=c["description"],
                passed=c["passed"],
                expected=c.get("expected"),
                actual=c.get("actual"),
                details=c.get("details", ""),
            )
            for c in data.get("checks", [])
        ]
        return cls(
            checks=checks,
            session_terminated=data.get("session_terminated", False),
            all_passed=data.get("all_passed", False),
            warnings=data.get("warnings", []),
        )


def validate_logout_response(
    response: SAMLLogoutResponse,
    expected_request_id: str | None = None,
    expected_issuer: str | None = None,
) -> LogoutValidationResult:
    """Perform comprehensive validation of a LogoutResponse.

    Args:
        response: The LogoutResponse to validate.
        expected_request_id: Expected InResponseTo value.
        expected_issuer: Expected issuer (IdP entity ID).

    Returns:
        LogoutValidationResult with all validation checks.
    """
    checks: list[LogoutValidationCheck] = []
    warnings: list[str] = []

    # Check 1: Status code
    status_check = LogoutValidationCheck(
        name="Status Code",
        description="LogoutResponse indicates successful logout",
        passed=response.is_success,
        expected=LogoutStatus.SUCCESS.value,
        actual=response.status_code,
        details=response.status_description if not response.is_success else "",
    )
    checks.append(status_check)

    # Check 2: InResponseTo matches
    if expected_request_id:
        in_response_check = LogoutValidationCheck(
            name="InResponseTo",
            description="Response references the correct LogoutRequest",
            passed=response.in_response_to == expected_request_id,
            expected=expected_request_id,
            actual=response.in_response_to,
        )
        checks.append(in_response_check)

    # Check 3: Issuer matches
    if expected_issuer:
        issuer_check = LogoutValidationCheck(
            name="Issuer",
            description="Response is from the expected IdP",
            passed=response.issuer == expected_issuer,
            expected=expected_issuer,
            actual=response.issuer,
        )
        checks.append(issuer_check)

    # Check 4: Response ID present
    id_check = LogoutValidationCheck(
        name="Response ID",
        description="Response has a valid ID",
        passed=bool(response.response_id),
        actual=response.response_id or "Missing",
    )
    checks.append(id_check)

    # Check 5: Issue instant present
    instant_check = LogoutValidationCheck(
        name="Issue Instant",
        description="Response has a timestamp",
        passed=bool(response.issue_instant),
        actual=response.issue_instant or "Missing",
    )
    checks.append(instant_check)

    # Check 6: Signature (if present)
    if response.signature_validation:
        from authtest.core.saml.signature import SignatureStatus

        sig_valid = response.signature_validation.status == SignatureStatus.VALID
        sig_check = LogoutValidationCheck(
            name="Signature",
            description="Response signature is valid",
            passed=sig_valid,
            details=response.signature_validation.message,
        )
        checks.append(sig_check)

        if response.signature_validation.status == SignatureStatus.MISSING:
            warnings.append("LogoutResponse is not signed - signature validation skipped")

    # Check for any validation errors already found
    if response.validation_errors:
        for error in response.validation_errors:
            checks.append(
                LogoutValidationCheck(
                    name="Validation",
                    description="Response passed validation",
                    passed=False,
                    details=error,
                )
            )

    all_passed = all(c.passed for c in checks)

    # Session terminated if status is success and all checks pass
    session_terminated = response.is_success and all_passed

    return LogoutValidationResult(
        checks=checks,
        session_terminated=session_terminated,
        all_passed=all_passed,
        warnings=warnings,
    )
