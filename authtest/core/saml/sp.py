"""SAML Service Provider implementation.

Uses python3-saml (OneLogin) for SAML protocol handling.
"""

from __future__ import annotations

import base64
import zlib
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any
from urllib.parse import parse_qs, urlencode, urlparse
from xml.etree import ElementTree

if TYPE_CHECKING:
    from authtest.storage.models import ClientConfig, IdPProvider


# SAML namespace
SAML_NS = {
    "samlp": "urn:oasis:names:tc:SAML:2.0:protocol",
    "saml": "urn:oasis:names:tc:SAML:2.0:assertion",
    "ds": "http://www.w3.org/2000/09/xmldsig#",
}


@dataclass
class SAMLRequest:
    """Represents a SAML AuthnRequest."""

    id: str
    issue_instant: str
    issuer: str
    destination: str
    acs_url: str
    name_id_policy_format: str = "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified"
    authn_context_class_ref: str | None = None
    force_authn: bool = False
    is_passive: bool = False

    def to_xml(self) -> str:
        """Generate the AuthnRequest XML."""
        force_authn_attr = ' ForceAuthn="true"' if self.force_authn else ""
        is_passive_attr = ' IsPassive="true"' if self.is_passive else ""

        authn_context = ""
        if self.authn_context_class_ref:
            authn_context = f"""
    <samlp:RequestedAuthnContext Comparison="exact">
        <saml:AuthnContextClassRef>{self.authn_context_class_ref}</saml:AuthnContextClassRef>
    </samlp:RequestedAuthnContext>"""

        return f"""<?xml version="1.0" encoding="UTF-8"?>
<samlp:AuthnRequest
    xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
    xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
    ID="{self.id}"
    Version="2.0"
    IssueInstant="{self.issue_instant}"
    Destination="{self.destination}"
    AssertionConsumerServiceURL="{self.acs_url}"
    ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"{force_authn_attr}{is_passive_attr}>
    <saml:Issuer>{self.issuer}</saml:Issuer>
    <samlp:NameIDPolicy Format="{self.name_id_policy_format}" AllowCreate="true"/>{authn_context}
</samlp:AuthnRequest>"""

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


@dataclass
class SAMLResponse:
    """Represents a parsed SAML Response."""

    raw_xml: str
    response_id: str
    in_response_to: str | None
    issue_instant: str | None
    issuer: str | None
    status_code: str | None
    status_message: str | None
    assertions: list[SAMLAssertion] = field(default_factory=list)
    is_success: bool = False
    validation_errors: list[str] = field(default_factory=list)

    @classmethod
    def parse(cls, encoded_response: str) -> SAMLResponse:
        """Parse a base64-encoded SAML Response.

        Args:
            encoded_response: Base64-encoded SAML Response from POST binding.

        Returns:
            Parsed SAMLResponse object.
        """
        try:
            xml_bytes = base64.b64decode(encoded_response)
            xml_str = xml_bytes.decode("utf-8")
        except Exception as e:
            return cls(
                raw_xml="",
                response_id="",
                in_response_to=None,
                issue_instant=None,
                issuer=None,
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
                status_code=None,
                status_message=None,
                validation_errors=[f"Failed to parse XML: {e}"],
            )

        # Extract response attributes
        response_id = root.get("ID", "")
        in_response_to = root.get("InResponseTo")
        issue_instant = root.get("IssueInstant")

        # Extract issuer
        issuer_elem = root.find("saml:Issuer", SAML_NS)
        issuer = issuer_elem.text if issuer_elem is not None else None

        # Extract status
        status_elem = root.find("samlp:Status/samlp:StatusCode", SAML_NS)
        status_code = status_elem.get("Value") if status_elem is not None else None

        status_msg_elem = root.find("samlp:Status/samlp:StatusMessage", SAML_NS)
        status_message = status_msg_elem.text if status_msg_elem is not None else None

        is_success = status_code == "urn:oasis:names:tc:SAML:2.0:status:Success"

        # Parse assertions
        assertions = []
        for assertion_elem in root.findall("saml:Assertion", SAML_NS):
            assertion = SAMLAssertion.from_element(assertion_elem)
            assertions.append(assertion)

        return cls(
            raw_xml=xml_str,
            response_id=response_id,
            in_response_to=in_response_to,
            issue_instant=issue_instant,
            issuer=issuer,
            status_code=status_code,
            status_message=status_message,
            assertions=assertions,
            is_success=is_success,
        )


@dataclass
class SAMLAssertion:
    """Represents a SAML Assertion."""

    assertion_id: str
    issuer: str | None
    subject_name_id: str | None
    subject_name_id_format: str | None
    conditions_not_before: str | None
    conditions_not_on_or_after: str | None
    audience_restrictions: list[str] = field(default_factory=list)
    authn_instant: str | None = None
    authn_context_class_ref: str | None = None
    session_index: str | None = None
    attributes: dict[str, list[str]] = field(default_factory=dict)

    @classmethod
    def from_element(cls, elem: ElementTree.Element) -> SAMLAssertion:
        """Parse an Assertion XML element."""
        assertion_id = elem.get("ID", "")

        # Issuer
        issuer_elem = elem.find("saml:Issuer", SAML_NS)
        issuer = issuer_elem.text if issuer_elem is not None else None

        # Subject
        subject_elem = elem.find("saml:Subject/saml:NameID", SAML_NS)
        subject_name_id = subject_elem.text if subject_elem is not None else None
        subject_name_id_format = (
            subject_elem.get("Format") if subject_elem is not None else None
        )

        # Conditions
        conditions_elem = elem.find("saml:Conditions", SAML_NS)
        conditions_not_before = None
        conditions_not_on_or_after = None
        audience_restrictions: list[str] = []

        if conditions_elem is not None:
            conditions_not_before = conditions_elem.get("NotBefore")
            conditions_not_on_or_after = conditions_elem.get("NotOnOrAfter")

            for audience_elem in conditions_elem.findall(
                "saml:AudienceRestriction/saml:Audience", SAML_NS
            ):
                if audience_elem.text:
                    audience_restrictions.append(audience_elem.text)

        # AuthnStatement
        authn_stmt = elem.find("saml:AuthnStatement", SAML_NS)
        authn_instant = None
        session_index = None
        authn_context_class_ref = None

        if authn_stmt is not None:
            authn_instant = authn_stmt.get("AuthnInstant")
            session_index = authn_stmt.get("SessionIndex")

            context_elem = authn_stmt.find(
                "saml:AuthnContext/saml:AuthnContextClassRef", SAML_NS
            )
            if context_elem is not None:
                authn_context_class_ref = context_elem.text

        # Attributes
        attributes: dict[str, list[str]] = {}
        for attr_elem in elem.findall(
            "saml:AttributeStatement/saml:Attribute", SAML_NS
        ):
            attr_name = attr_elem.get("Name", "")
            values: list[str] = []
            for value_elem in attr_elem.findall("saml:AttributeValue", SAML_NS):
                if value_elem.text:
                    values.append(value_elem.text)
            if attr_name:
                attributes[attr_name] = values

        return cls(
            assertion_id=assertion_id,
            issuer=issuer,
            subject_name_id=subject_name_id,
            subject_name_id_format=subject_name_id_format,
            conditions_not_before=conditions_not_before,
            conditions_not_on_or_after=conditions_not_on_or_after,
            audience_restrictions=audience_restrictions,
            authn_instant=authn_instant,
            authn_context_class_ref=authn_context_class_ref,
            session_index=session_index,
            attributes=attributes,
        )


@dataclass
class PreflightCheck:
    """Represents a pre-flight checklist item."""

    name: str
    description: str
    passed: bool
    details: str = ""


@dataclass
class PreflightResult:
    """Result of pre-flight checks."""

    checks: list[PreflightCheck]
    all_passed: bool
    warnings: list[str] = field(default_factory=list)


class SAMLServiceProvider:
    """SAML Service Provider for authentication testing.

    This class handles:
    - Generating AuthnRequests for SP-Initiated SSO
    - Processing SAML Responses
    - Running pre-flight checks
    """

    def __init__(
        self,
        idp: IdPProvider,
        client_config: ClientConfig | None = None,
        base_url: str = "https://localhost:8443",
    ) -> None:
        """Initialize the SAML Service Provider.

        Args:
            idp: The Identity Provider configuration.
            client_config: Optional client/SP configuration. If not provided,
                defaults will be used based on the IdP settings.
            base_url: Base URL of this application for callbacks.
        """
        self.idp = idp
        self.client_config = client_config
        self.base_url = base_url.rstrip("/")

    @property
    def sp_entity_id(self) -> str:
        """Get the SP entity ID."""
        if self.client_config and self.client_config.sp_entity_id:
            return self.client_config.sp_entity_id
        return f"{self.base_url}/saml/metadata"

    @property
    def acs_url(self) -> str:
        """Get the Assertion Consumer Service URL."""
        if self.client_config and self.client_config.acs_url:
            return self.client_config.acs_url
        return f"{self.base_url}/saml/acs"

    @property
    def idp_sso_url(self) -> str | None:
        """Get the IdP SSO URL."""
        return self.idp.sso_url

    def run_preflight_checks(self) -> PreflightResult:
        """Run pre-flight checks before initiating SSO.

        Returns:
            PreflightResult with status of all checks.
        """
        checks: list[PreflightCheck] = []
        warnings: list[str] = []

        # Check 1: IdP SSO URL configured
        sso_url_check = PreflightCheck(
            name="IdP SSO URL",
            description="Identity Provider SSO endpoint is configured",
            passed=bool(self.idp.sso_url),
            details=self.idp.sso_url or "Not configured",
        )
        checks.append(sso_url_check)

        # Check 2: IdP Entity ID configured
        entity_id_check = PreflightCheck(
            name="IdP Entity ID",
            description="Identity Provider Entity ID is configured",
            passed=bool(self.idp.entity_id),
            details=self.idp.entity_id or "Not configured",
        )
        checks.append(entity_id_check)

        # Check 3: SP Entity ID valid
        sp_entity_check = PreflightCheck(
            name="SP Entity ID",
            description="Service Provider Entity ID is valid",
            passed=bool(self.sp_entity_id),
            details=self.sp_entity_id,
        )
        checks.append(sp_entity_check)

        # Check 4: ACS URL valid and HTTPS
        acs_is_https = self.acs_url.startswith("https://")
        acs_check = PreflightCheck(
            name="ACS URL",
            description="Assertion Consumer Service URL uses HTTPS",
            passed=acs_is_https,
            details=self.acs_url,
        )
        checks.append(acs_check)

        if not acs_is_https:
            warnings.append(
                "ACS URL does not use HTTPS. Most IdPs require HTTPS for security."
            )

        # Check 5: IdP certificate (optional but recommended)
        has_cert = bool(self.idp.x509_cert)
        cert_check = PreflightCheck(
            name="IdP Certificate",
            description="IdP signing certificate is configured (for signature validation)",
            passed=has_cert,
            details="Configured" if has_cert else "Not configured (signatures won't be validated)",
        )
        checks.append(cert_check)

        if not has_cert:
            warnings.append(
                "IdP certificate not configured. SAML Response signatures cannot be validated."
            )

        all_passed = all(c.passed for c in checks if c.name in ["IdP SSO URL", "IdP Entity ID"])

        return PreflightResult(
            checks=checks,
            all_passed=all_passed,
            warnings=warnings,
        )

    def create_authn_request(
        self,
        force_authn: bool = False,
        is_passive: bool = False,
        authn_context: str | None = None,
    ) -> SAMLRequest:
        """Create an AuthnRequest for SP-Initiated SSO.

        Args:
            force_authn: Request fresh authentication even if user has existing session.
            is_passive: Request passive authentication (no user interaction).
            authn_context: Requested authentication context class.

        Returns:
            SAMLRequest object ready to be encoded and sent.
        """
        import secrets

        # Generate unique request ID
        request_id = f"_authtest_{secrets.token_hex(16)}"

        # Get current timestamp in ISO format
        issue_instant = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")

        return SAMLRequest(
            id=request_id,
            issue_instant=issue_instant,
            issuer=self.sp_entity_id,
            destination=self.idp_sso_url or "",
            acs_url=self.acs_url,
            force_authn=force_authn,
            is_passive=is_passive,
            authn_context_class_ref=authn_context,
        )

    def build_sso_redirect_url(
        self,
        request: SAMLRequest,
        relay_state: str | None = None,
    ) -> str:
        """Build the SSO redirect URL with encoded AuthnRequest.

        Args:
            request: The SAMLRequest to encode.
            relay_state: Optional RelayState to preserve across the SSO flow.

        Returns:
            Complete URL to redirect the user to.
        """
        if not self.idp_sso_url:
            raise ValueError("IdP SSO URL not configured")

        # Encode request for HTTP-Redirect binding
        encoded_request = request.encode_redirect()

        # Build query parameters
        params: dict[str, str] = {"SAMLRequest": encoded_request}
        if relay_state:
            params["RelayState"] = relay_state

        # Construct final URL
        parsed = urlparse(self.idp_sso_url)
        existing_params = parse_qs(parsed.query)
        # Merge existing params
        for key, values in existing_params.items():
            if key not in params:
                params[key] = values[0]

        query_string = urlencode(params)
        return f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{query_string}"

    def build_sso_post_form(
        self,
        request: SAMLRequest,
        relay_state: str | None = None,
    ) -> dict[str, Any]:
        """Build data for HTTP-POST binding form.

        Args:
            request: The SAMLRequest to encode.
            relay_state: Optional RelayState to preserve across the SSO flow.

        Returns:
            Dictionary with 'action' URL and 'fields' for form inputs.
        """
        if not self.idp_sso_url:
            raise ValueError("IdP SSO URL not configured")

        encoded_request = request.encode_post()

        fields = {"SAMLRequest": encoded_request}
        if relay_state:
            fields["RelayState"] = relay_state

        return {
            "action": self.idp_sso_url,
            "fields": fields,
        }

    def process_response(self, saml_response: str) -> SAMLResponse:
        """Process a SAML Response from the IdP.

        Args:
            saml_response: Base64-encoded SAML Response from POST.

        Returns:
            Parsed SAMLResponse with validation results.
        """
        response = SAMLResponse.parse(saml_response)

        # Basic validation
        if not response.is_success:
            response.validation_errors.append(
                f"SAML Response status is not Success: {response.status_code}"
            )

        if response.issuer and response.issuer != self.idp.entity_id:
            response.validation_errors.append(
                f"Response issuer ({response.issuer}) does not match "
                f"configured IdP entity ID ({self.idp.entity_id})"
            )

        # Validate assertions
        for assertion in response.assertions:
            # Check audience restriction
            if (
                assertion.audience_restrictions
                and self.sp_entity_id not in assertion.audience_restrictions
            ):
                response.validation_errors.append(
                    f"SP Entity ID ({self.sp_entity_id}) not in "
                    f"audience restrictions ({assertion.audience_restrictions})"
                )

            # Check time conditions
            now = datetime.now(UTC)

            if assertion.conditions_not_before:
                try:
                    not_before = datetime.fromisoformat(
                        assertion.conditions_not_before.replace("Z", "+00:00")
                    )
                    if now < not_before:
                        response.validation_errors.append(
                            f"Assertion not valid yet (NotBefore: {assertion.conditions_not_before})"
                        )
                except ValueError:
                    pass

            if assertion.conditions_not_on_or_after:
                try:
                    not_after = datetime.fromisoformat(
                        assertion.conditions_not_on_or_after.replace("Z", "+00:00")
                    )
                    if now >= not_after:
                        response.validation_errors.append(
                            f"Assertion has expired (NotOnOrAfter: {assertion.conditions_not_on_or_after})"
                        )
                except ValueError:
                    pass

        return response
