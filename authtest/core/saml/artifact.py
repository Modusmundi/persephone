"""SAML Artifact binding implementation.

Provides artifact resolution for SAML HTTP-Artifact binding.
The artifact binding uses a two-step process:
1. IdP sends a small artifact reference instead of the full assertion
2. SP resolves the artifact via a back-channel SOAP request to get the assertion

This binding is useful for:
- Avoiding URL length limits (artifacts are small, fixed-size)
- Enhanced security (assertion travels over back-channel)
- Testing artifact resolution endpoints
"""

from __future__ import annotations

import base64
import secrets
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import TYPE_CHECKING
from xml.etree import ElementTree

import httpx

if TYPE_CHECKING:
    from authtest.storage.models import IdPProvider

# SAML namespaces
SAML_NS = {
    "samlp": "urn:oasis:names:tc:SAML:2.0:protocol",
    "saml": "urn:oasis:names:tc:SAML:2.0:assertion",
    "soap": "http://schemas.xmlsoap.org/soap/envelope/",
}

# Artifact binding URI
ARTIFACT_BINDING = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Artifact"


@dataclass
class SAMLArtifact:
    """Represents a SAML Artifact.

    SAML 2.0 artifacts have the structure:
    - TypeCode (2 bytes): Identifies the artifact type (0x0004 for HTTP-Artifact)
    - EndpointIndex (2 bytes): Index of the resolution endpoint
    - SourceID (20 bytes): SHA-1 hash of the issuer's entity ID
    - MessageHandle (20 bytes): Unique identifier for the artifact

    Total: 44 bytes, Base64-encoded to ~60 characters
    """

    raw_artifact: str  # Base64-encoded artifact
    type_code: int | None = None
    endpoint_index: int | None = None
    source_id: bytes | None = None
    message_handle: bytes | None = None

    @classmethod
    def parse(cls, artifact_b64: str) -> SAMLArtifact:
        """Parse a base64-encoded SAML artifact.

        Args:
            artifact_b64: Base64-encoded artifact string.

        Returns:
            Parsed SAMLArtifact object.
        """
        try:
            artifact_bytes = base64.b64decode(artifact_b64)
        except Exception:
            return cls(raw_artifact=artifact_b64)

        if len(artifact_bytes) != 44:
            return cls(raw_artifact=artifact_b64)

        type_code = int.from_bytes(artifact_bytes[0:2], "big")
        endpoint_index = int.from_bytes(artifact_bytes[2:4], "big")
        source_id = artifact_bytes[4:24]
        message_handle = artifact_bytes[24:44]

        return cls(
            raw_artifact=artifact_b64,
            type_code=type_code,
            endpoint_index=endpoint_index,
            source_id=source_id,
            message_handle=message_handle,
        )

    @property
    def is_valid_format(self) -> bool:
        """Check if the artifact has valid SAML 2.0 format."""
        return self.type_code == 0x0004 and self.source_id is not None


@dataclass
class ArtifactResolveRequest:
    """SAML ArtifactResolve request message.

    Sent via SOAP to the IdP's Artifact Resolution Service (ARS).
    """

    id: str
    issue_instant: str
    issuer: str
    destination: str
    artifact: str

    def to_soap_xml(self) -> str:
        """Generate the SOAP envelope with ArtifactResolve request."""
        return f"""<?xml version="1.0" encoding="UTF-8"?>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
    <soap:Body>
        <samlp:ArtifactResolve
            xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
            xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
            ID="{self.id}"
            Version="2.0"
            IssueInstant="{self.issue_instant}"
            Destination="{self.destination}">
            <saml:Issuer>{self.issuer}</saml:Issuer>
            <samlp:Artifact>{self.artifact}</samlp:Artifact>
        </samlp:ArtifactResolve>
    </soap:Body>
</soap:Envelope>"""


@dataclass
class ArtifactResolveResponse:
    """Parsed SAML ArtifactResponse from IdP."""

    raw_xml: str
    response_id: str
    in_response_to: str | None
    issue_instant: str | None
    issuer: str | None
    status_code: str | None
    status_message: str | None
    saml_response_xml: str | None = None  # The embedded SAML Response
    is_success: bool = False
    validation_errors: list[str] = field(default_factory=list)

    @classmethod
    def parse(cls, soap_response: str) -> ArtifactResolveResponse:
        """Parse a SOAP envelope containing ArtifactResponse.

        Args:
            soap_response: SOAP XML response from the IdP.

        Returns:
            Parsed ArtifactResolveResponse object.
        """
        try:
            root = ElementTree.fromstring(soap_response)
        except ElementTree.ParseError as e:
            return cls(
                raw_xml=soap_response,
                response_id="",
                in_response_to=None,
                issue_instant=None,
                issuer=None,
                status_code=None,
                status_message=None,
                validation_errors=[f"Failed to parse SOAP response: {e}"],
            )

        # Find the ArtifactResponse in the SOAP body
        # Handle both namespaced and non-namespaced elements
        artifact_response = None
        for ns_prefix in ["samlp:", "{urn:oasis:names:tc:SAML:2.0:protocol}"]:
            artifact_response = root.find(
                f".//{ns_prefix}ArtifactResponse",
                SAML_NS if ns_prefix == "samlp:" else None,
            )
            if artifact_response is not None:
                break

        # Try with explicit namespace
        if artifact_response is None:
            artifact_response = root.find(
                ".//{urn:oasis:names:tc:SAML:2.0:protocol}ArtifactResponse"
            )

        if artifact_response is None:
            return cls(
                raw_xml=soap_response,
                response_id="",
                in_response_to=None,
                issue_instant=None,
                issuer=None,
                status_code=None,
                status_message=None,
                validation_errors=["No ArtifactResponse found in SOAP envelope"],
            )

        # Extract ArtifactResponse attributes
        response_id = artifact_response.get("ID", "")
        in_response_to = artifact_response.get("InResponseTo")
        issue_instant = artifact_response.get("IssueInstant")

        # Extract Issuer
        issuer_elem = artifact_response.find(
            "{urn:oasis:names:tc:SAML:2.0:assertion}Issuer"
        )
        issuer = issuer_elem.text if issuer_elem is not None else None

        # Extract Status
        status_elem = artifact_response.find(
            "{urn:oasis:names:tc:SAML:2.0:protocol}Status/"
            "{urn:oasis:names:tc:SAML:2.0:protocol}StatusCode"
        )
        status_code = status_elem.get("Value") if status_elem is not None else None

        status_msg_elem = artifact_response.find(
            "{urn:oasis:names:tc:SAML:2.0:protocol}Status/"
            "{urn:oasis:names:tc:SAML:2.0:protocol}StatusMessage"
        )
        status_message = status_msg_elem.text if status_msg_elem is not None else None

        is_success = status_code == "urn:oasis:names:tc:SAML:2.0:status:Success"

        # Extract the embedded SAML Response
        saml_response_elem = artifact_response.find(
            "{urn:oasis:names:tc:SAML:2.0:protocol}Response"
        )
        saml_response_xml = None
        if saml_response_elem is not None:
            saml_response_xml = ElementTree.tostring(
                saml_response_elem, encoding="unicode"
            )

        return cls(
            raw_xml=soap_response,
            response_id=response_id,
            in_response_to=in_response_to,
            issue_instant=issue_instant,
            issuer=issuer,
            status_code=status_code,
            status_message=status_message,
            saml_response_xml=saml_response_xml,
            is_success=is_success,
        )


class ArtifactResolver:
    """Resolves SAML artifacts via back-channel SOAP request.

    The artifact resolution process:
    1. Receive artifact from IdP (via redirect or POST)
    2. Build ArtifactResolve SOAP request
    3. Send to IdP's Artifact Resolution Service
    4. Parse ArtifactResponse containing the actual SAML assertion
    """

    def __init__(
        self,
        idp: IdPProvider,
        sp_entity_id: str,
        timeout: float = 30.0,
    ) -> None:
        """Initialize the artifact resolver.

        Args:
            idp: Identity Provider configuration.
            sp_entity_id: Service Provider entity ID (issuer).
            timeout: HTTP timeout for artifact resolution in seconds.
        """
        self.idp = idp
        self.sp_entity_id = sp_entity_id
        self.timeout = timeout

    @property
    def artifact_resolution_url(self) -> str | None:
        """Get the IdP's Artifact Resolution Service URL.

        This URL is typically found in the IdP metadata under
        ArtifactResolutionService with SOAP binding.
        """
        # Check if stored in settings
        if self.idp.settings and "artifact_resolution_url" in self.idp.settings:
            url = self.idp.settings["artifact_resolution_url"]
            return str(url) if url else None

        # Default: try to derive from SSO URL (common pattern)
        # Some IdPs use /ARS or /artifact path
        return None

    def create_resolve_request(self, artifact: str) -> ArtifactResolveRequest:
        """Create an ArtifactResolve request.

        Args:
            artifact: The base64-encoded SAML artifact to resolve.

        Returns:
            ArtifactResolveRequest ready to send.
        """
        request_id = f"_artifact_{secrets.token_hex(16)}"
        issue_instant = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")

        return ArtifactResolveRequest(
            id=request_id,
            issue_instant=issue_instant,
            issuer=self.sp_entity_id,
            destination=self.artifact_resolution_url or "",
            artifact=artifact,
        )

    def resolve(
        self,
        artifact: str,
        resolution_url: str | None = None,
    ) -> tuple[ArtifactResolveResponse, dict[str, str]]:
        """Resolve an artifact by sending ArtifactResolve to the IdP.

        Args:
            artifact: The base64-encoded SAML artifact.
            resolution_url: Override URL for artifact resolution service.

        Returns:
            Tuple of (ArtifactResolveResponse, trace_dict) where trace_dict
            contains debugging information about the resolution.

        Raises:
            ValueError: If no artifact resolution URL is configured.
        """
        trace: dict[str, str] = {}

        # Determine resolution URL
        url = resolution_url or self.artifact_resolution_url
        if not url:
            raise ValueError(
                "No Artifact Resolution Service URL configured. "
                "Set 'artifact_resolution_url' in IdP settings or provide resolution_url parameter."
            )

        trace["resolution_url"] = url

        # Parse and validate the artifact
        parsed_artifact = SAMLArtifact.parse(artifact)
        trace["artifact_valid_format"] = str(parsed_artifact.is_valid_format)
        if parsed_artifact.endpoint_index is not None:
            trace["artifact_endpoint_index"] = str(parsed_artifact.endpoint_index)

        # Create the request
        request = self.create_resolve_request(artifact)
        soap_request = request.to_soap_xml()
        trace["request_id"] = request.id
        trace["request_xml"] = soap_request

        # Send the SOAP request
        try:
            response = httpx.post(
                url,
                content=soap_request.encode("utf-8"),
                headers={
                    "Content-Type": "text/xml; charset=utf-8",
                    "SOAPAction": "http://www.oasis-open.org/committees/security",
                },
                timeout=self.timeout,
                verify=True,  # Verify SSL certificates
            )
            trace["http_status"] = str(response.status_code)
            trace["response_headers"] = str(dict(response.headers))

            if response.status_code != 200:
                return ArtifactResolveResponse(
                    raw_xml=response.text,
                    response_id="",
                    in_response_to=None,
                    issue_instant=None,
                    issuer=None,
                    status_code=None,
                    status_message=None,
                    validation_errors=[
                        f"HTTP error {response.status_code}: {response.text[:500]}"
                    ],
                ), trace

            # Parse the SOAP response
            artifact_response = ArtifactResolveResponse.parse(response.text)
            trace["response_xml"] = response.text

            # Validate InResponseTo matches our request
            if artifact_response.in_response_to != request.id:
                artifact_response.validation_errors.append(
                    f"InResponseTo mismatch: expected {request.id}, "
                    f"got {artifact_response.in_response_to}"
                )

            return artifact_response, trace

        except httpx.TimeoutException:
            return ArtifactResolveResponse(
                raw_xml="",
                response_id="",
                in_response_to=None,
                issue_instant=None,
                issuer=None,
                status_code=None,
                status_message=None,
                validation_errors=[
                    f"Timeout connecting to Artifact Resolution Service at {url}"
                ],
            ), trace
        except httpx.RequestError as e:
            return ArtifactResolveResponse(
                raw_xml="",
                response_id="",
                in_response_to=None,
                issue_instant=None,
                issuer=None,
                status_code=None,
                status_message=None,
                validation_errors=[f"Failed to connect to Artifact Resolution Service: {e}"],
            ), trace
