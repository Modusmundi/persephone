"""SAML authentication flow handlers.

Handles the SP-Initiated SSO flow orchestration, including:
- Pre-flight checks
- AuthnRequest generation
- Response processing
- Result recording
"""

from __future__ import annotations

import secrets
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from typing import TYPE_CHECKING, Any

from authtest.core.saml.sp import (
    BINDING_HTTP_ARTIFACT,
    PreflightResult,
    SAMLResponse,
    SAMLServiceProvider,
)

if TYPE_CHECKING:
    from authtest.storage.database import Database
    from authtest.storage.models import IdPProvider


class FlowStatus(StrEnum):
    """Status of a SAML flow test."""

    PENDING = "pending"
    PREFLIGHT = "preflight"
    INITIATED = "initiated"
    WAITING_RESPONSE = "waiting_response"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class TestOutcome(StrEnum):
    """Outcome of a test."""

    PASSED = "passed"
    FAILED = "failed"
    ERROR = "error"


@dataclass
class FlowState:
    """Maintains state for an in-progress SAML flow.

    This state is stored in the Flask session to track the flow
    across the SSO redirect.
    """

    flow_id: str
    idp_id: int
    idp_name: str
    status: FlowStatus
    request_id: str | None = None
    request_xml: str | None = None
    started_at: datetime | None = None
    completed_at: datetime | None = None
    preflight: PreflightResult | None = None
    response: SAMLResponse | None = None
    error: str | None = None
    options: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for session storage."""
        return {
            "flow_id": self.flow_id,
            "idp_id": self.idp_id,
            "idp_name": self.idp_name,
            "status": self.status,
            "request_id": self.request_id,
            "request_xml": self.request_xml,
            "started_at": self.started_at.isoformat() if self.started_at else None,
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
            "preflight": _preflight_to_dict(self.preflight) if self.preflight else None,
            "response": _response_to_dict(self.response) if self.response else None,
            "error": self.error,
            "options": self.options,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> FlowState:
        """Reconstruct from dictionary."""
        return cls(
            flow_id=data["flow_id"],
            idp_id=data["idp_id"],
            idp_name=data["idp_name"],
            status=FlowStatus(data["status"]),
            request_id=data.get("request_id"),
            request_xml=data.get("request_xml"),
            started_at=datetime.fromisoformat(data["started_at"]) if data.get("started_at") else None,
            completed_at=datetime.fromisoformat(data["completed_at"]) if data.get("completed_at") else None,
            preflight=_dict_to_preflight(data["preflight"]) if data.get("preflight") else None,
            response=None,  # Response is too large for session, stored separately
            error=data.get("error"),
            options=data.get("options", {}),
        )


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
    from authtest.core.saml.sp import PreflightCheck, PreflightResult

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


def _signature_validation_to_dict(sig_result: Any) -> dict[str, Any] | None:
    """Convert SignatureValidationResult to dict for storage."""
    if sig_result is None:
        return None

    return {
        "status": sig_result.status.value,
        "message": sig_result.message,
        "signatures": [
            {
                "location": s.location.value,
                "signature_algorithm": s.signature_algorithm,
                "signature_algorithm_name": s.signature_algorithm_name,
                "digest_algorithm": s.digest_algorithm,
                "digest_algorithm_name": s.digest_algorithm_name,
                "canonicalization_method": s.canonicalization_method,
                "canonicalization_method_name": s.canonicalization_method_name,
                "reference_uri": s.reference_uri,
                "certificate_embedded": s.certificate_embedded,
            }
            for s in sig_result.signatures
        ],
        "trace": sig_result.trace,
        "warnings": sig_result.warnings,
    }


def _response_to_dict(response: SAMLResponse) -> dict[str, Any]:
    """Convert SAMLResponse to dict for storage."""
    return {
        "response_id": response.response_id,
        "in_response_to": response.in_response_to,
        "issue_instant": response.issue_instant,
        "issuer": response.issuer,
        "status_code": response.status_code,
        "status_message": response.status_message,
        "is_success": response.is_success,
        "validation_errors": response.validation_errors,
        "signature_validation": _signature_validation_to_dict(response.signature_validation),
        "assertions": [
            {
                "assertion_id": a.assertion_id,
                "issuer": a.issuer,
                "subject_name_id": a.subject_name_id,
                "subject_name_id_format": a.subject_name_id_format,
                "authn_instant": a.authn_instant,
                "authn_context_class_ref": a.authn_context_class_ref,
                "session_index": a.session_index,
                "attributes": a.attributes,
            }
            for a in response.assertions
        ],
    }


@dataclass
class FlowResult:
    """Result of a SAML SSO test."""

    flow_state: FlowState
    outcome: TestOutcome
    duration_ms: int | None = None
    summary: str = ""


# Alias for backwards compatibility
SPInitiatedFlowResult = FlowResult


class SPInitiatedFlow:
    """Orchestrates the SP-Initiated SSO flow.

    This flow follows these steps:
    1. Run pre-flight checks
    2. Generate AuthnRequest
    3. Redirect user to IdP
    4. Process SAML Response callback
    5. Record test result
    """

    def __init__(
        self,
        idp: IdPProvider,
        db: Database,
        base_url: str = "https://localhost:8443",
    ) -> None:
        """Initialize the flow handler.

        Args:
            idp: Identity Provider configuration.
            db: Database instance for recording results.
            base_url: Base URL of this application.
        """
        self.idp = idp
        self.db = db
        self.base_url = base_url
        self.sp = SAMLServiceProvider(idp, base_url=base_url)

    def start_flow(
        self,
        force_authn: bool = False,
        is_passive: bool = False,
        authn_context: str | None = None,
    ) -> FlowState:
        """Start a new SP-Initiated SSO flow.

        Args:
            force_authn: Request fresh authentication.
            is_passive: Request passive (non-interactive) authentication.
            authn_context: Requested authentication context.

        Returns:
            FlowState with preflight results.
        """
        flow_id = f"flow_{secrets.token_hex(16)}"

        # Run pre-flight checks
        preflight = self.sp.run_preflight_checks()

        state = FlowState(
            flow_id=flow_id,
            idp_id=self.idp.id,
            idp_name=self.idp.name,
            status=FlowStatus.PREFLIGHT,
            started_at=datetime.now(UTC),
            preflight=preflight,
            options={
                "force_authn": force_authn,
                "is_passive": is_passive,
                "authn_context": authn_context,
            },
        )

        return state

    def initiate_sso(self, state: FlowState) -> tuple[FlowState, str]:
        """Initiate the SSO redirect after preflight passes.

        Args:
            state: Current flow state.

        Returns:
            Tuple of (updated state, redirect URL).

        Raises:
            ValueError: If preflight checks failed or flow is in wrong state.
        """
        if state.status != FlowStatus.PREFLIGHT:
            raise ValueError(f"Cannot initiate SSO from state: {state.status}")

        if state.preflight and not state.preflight.all_passed:
            state.status = FlowStatus.FAILED
            state.error = "Pre-flight checks failed"
            return state, ""

        # Create AuthnRequest
        request = self.sp.create_authn_request(
            force_authn=state.options.get("force_authn", False),
            is_passive=state.options.get("is_passive", False),
            authn_context=state.options.get("authn_context"),
        )

        # Build redirect URL (using HTTP-Redirect binding)
        redirect_url = self.sp.build_sso_redirect_url(
            request,
            relay_state=state.flow_id,
        )

        # Update state
        state.status = FlowStatus.INITIATED
        state.request_id = request.id
        state.request_xml = request.to_xml()

        return state, redirect_url

    def process_response(
        self,
        state: FlowState,
        saml_response: str,
    ) -> FlowState:
        """Process the SAML Response from the IdP.

        Args:
            state: Current flow state.
            saml_response: Base64-encoded SAML Response from POST.

        Returns:
            Updated flow state with response data.
        """
        state.completed_at = datetime.now(UTC)

        try:
            response = self.sp.process_response(saml_response)
            state.response = response

            # Check if response matches our request
            if response.in_response_to and response.in_response_to != state.request_id:
                response.validation_errors.append(
                    f"Response InResponseTo ({response.in_response_to}) "
                    f"does not match request ID ({state.request_id})"
                )

            if response.is_success and not response.validation_errors:
                state.status = FlowStatus.COMPLETED
            else:
                state.status = FlowStatus.FAILED
                state.error = "; ".join(response.validation_errors) or "Authentication failed"

        except Exception as e:
            state.status = FlowStatus.FAILED
            state.error = f"Error processing response: {e}"

        return state

    def record_result(self, state: FlowState) -> int:
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
        if state.status == FlowStatus.COMPLETED:
            outcome = TestOutcome.PASSED
        elif state.status == FlowStatus.FAILED:
            outcome = TestOutcome.FAILED
        else:
            outcome = TestOutcome.ERROR

        # Build request data
        request_data = {
            "request_id": state.request_id,
            "request_xml": state.request_xml,
            "options": state.options,
        }

        # Build response data
        response_data = None
        if state.response:
            response_data = _response_to_dict(state.response)
            response_data["raw_xml"] = state.response.raw_xml

        result = TestResult(
            idp_provider_id=state.idp_id,
            test_name="SP-Initiated SSO",
            test_type="saml",
            status=outcome.value,
            error_message=state.error,
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

    def get_flow_result(self, state: FlowState) -> SPInitiatedFlowResult:
        """Get the final result of the flow.

        Args:
            state: Completed flow state.

        Returns:
            SPInitiatedFlowResult with outcome summary.
        """
        duration_ms = None
        if state.started_at and state.completed_at:
            duration = state.completed_at - state.started_at
            duration_ms = int(duration.total_seconds() * 1000)

        if state.status == FlowStatus.COMPLETED:
            outcome = TestOutcome.PASSED
            summary = "Authentication successful"
            if state.response and state.response.assertions:
                assertion = state.response.assertions[0]
                if assertion.subject_name_id:
                    summary = f"Authenticated as: {assertion.subject_name_id}"
        elif state.status == FlowStatus.FAILED:
            outcome = TestOutcome.FAILED
            summary = state.error or "Authentication failed"
        else:
            outcome = TestOutcome.ERROR
            summary = state.error or f"Flow ended in unexpected state: {state.status}"

        return FlowResult(
            flow_state=state,
            outcome=outcome,
            duration_ms=duration_ms,
            summary=summary,
        )


class IdPInitiatedFlow:
    """Orchestrates the IdP-Initiated SSO flow.

    In IdP-Initiated SSO, the IdP sends an unsolicited SAML Response
    to the SP's ACS endpoint without a prior AuthnRequest. This flow:
    1. Receives SAML Response at ACS
    2. Validates assertion format and signatures
    3. Extracts user identity and attributes
    4. Records test result
    """

    def __init__(
        self,
        idp: IdPProvider,
        db: Database,
        base_url: str = "https://localhost:8443",
    ) -> None:
        """Initialize the flow handler.

        Args:
            idp: Identity Provider configuration.
            db: Database instance for recording results.
            base_url: Base URL of this application.
        """
        self.idp = idp
        self.db = db
        self.base_url = base_url
        self.sp = SAMLServiceProvider(idp, base_url=base_url)

    def process_unsolicited_response(self, saml_response: str) -> FlowState:
        """Process an unsolicited SAML Response from the IdP.

        Args:
            saml_response: Base64-encoded SAML Response from POST.

        Returns:
            FlowState with response data and validation results.
        """
        flow_id = f"idp_flow_{secrets.token_hex(16)}"
        started_at = datetime.now(UTC)

        state = FlowState(
            flow_id=flow_id,
            idp_id=self.idp.id,
            idp_name=self.idp.name,
            status=FlowStatus.WAITING_RESPONSE,
            started_at=started_at,
            options={"flow_type": "idp_initiated"},
        )

        try:
            response = self.sp.process_response(saml_response)
            state.response = response
            state.completed_at = datetime.now(UTC)

            # For IdP-initiated, InResponseTo should be empty or not present
            if response.in_response_to:
                response.validation_errors.append(
                    f"IdP-Initiated response should not have InResponseTo attribute, "
                    f"but found: {response.in_response_to}"
                )

            if response.is_success and not response.validation_errors:
                state.status = FlowStatus.COMPLETED
            else:
                state.status = FlowStatus.FAILED
                state.error = "; ".join(response.validation_errors) or "Authentication failed"

        except Exception as e:
            state.completed_at = datetime.now(UTC)
            state.status = FlowStatus.FAILED
            state.error = f"Error processing response: {e}"

        return state

    def record_result(self, state: FlowState) -> int:
        """Record the test result to the database.

        Args:
            state: Completed flow state.

        Returns:
            ID of the created TestResult record.
        """
        from authtest.storage.models import TestResult

        duration_ms = None
        if state.started_at and state.completed_at:
            duration = state.completed_at - state.started_at
            duration_ms = int(duration.total_seconds() * 1000)

        if state.status == FlowStatus.COMPLETED:
            outcome = TestOutcome.PASSED
        elif state.status == FlowStatus.FAILED:
            outcome = TestOutcome.FAILED
        else:
            outcome = TestOutcome.ERROR

        response_data = None
        if state.response:
            response_data = _response_to_dict(state.response)
            response_data["raw_xml"] = state.response.raw_xml

        result = TestResult(
            idp_provider_id=state.idp_id,
            test_name="IdP-Initiated SSO",
            test_type="saml",
            status=outcome.value,
            error_message=state.error,
            started_at=state.started_at or datetime.now(UTC),
            completed_at=state.completed_at,
            duration_ms=duration_ms,
            request_data={"flow_type": "idp_initiated"},
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

    def get_flow_result(self, state: FlowState) -> FlowResult:
        """Get the final result of the flow.

        Args:
            state: Completed flow state.

        Returns:
            FlowResult with outcome summary.
        """
        duration_ms = None
        if state.started_at and state.completed_at:
            duration = state.completed_at - state.started_at
            duration_ms = int(duration.total_seconds() * 1000)

        if state.status == FlowStatus.COMPLETED:
            outcome = TestOutcome.PASSED
            summary = "IdP-Initiated SSO successful"
            if state.response and state.response.assertions:
                assertion = state.response.assertions[0]
                if assertion.subject_name_id:
                    summary = f"Authenticated as: {assertion.subject_name_id}"
        elif state.status == FlowStatus.FAILED:
            outcome = TestOutcome.FAILED
            summary = state.error or "Authentication failed"
        else:
            outcome = TestOutcome.ERROR
            summary = state.error or f"Flow ended in unexpected state: {state.status}"

        return FlowResult(
            flow_state=state,
            outcome=outcome,
            duration_ms=duration_ms,
            summary=summary,
        )


class ArtifactFlow:
    """Orchestrates the SAML HTTP-Artifact binding flow.

    This flow tests artifact resolution:
    1. Send AuthnRequest requesting HTTP-Artifact binding
    2. Receive artifact from IdP (instead of full assertion)
    3. Resolve artifact via SOAP back-channel request
    4. Process the resolved SAML Response
    5. Record test result
    """

    def __init__(
        self,
        idp: IdPProvider,
        db: Database,
        base_url: str = "https://localhost:8443",
    ) -> None:
        """Initialize the flow handler.

        Args:
            idp: Identity Provider configuration.
            db: Database instance for recording results.
            base_url: Base URL of this application.
        """
        self.idp = idp
        self.db = db
        self.base_url = base_url
        self.sp = SAMLServiceProvider(idp, base_url=base_url)

    def start_flow(
        self,
        force_authn: bool = False,
        is_passive: bool = False,
        authn_context: str | None = None,
    ) -> FlowState:
        """Start a new Artifact binding SSO flow.

        Args:
            force_authn: Request fresh authentication.
            is_passive: Request passive (non-interactive) authentication.
            authn_context: Requested authentication context.

        Returns:
            FlowState with preflight results.
        """
        flow_id = f"artifact_flow_{secrets.token_hex(16)}"

        # Run pre-flight checks including artifact-specific checks
        preflight = self._run_preflight_checks()

        state = FlowState(
            flow_id=flow_id,
            idp_id=self.idp.id,
            idp_name=self.idp.name,
            status=FlowStatus.PREFLIGHT,
            started_at=datetime.now(UTC),
            preflight=preflight,
            options={
                "force_authn": force_authn,
                "is_passive": is_passive,
                "authn_context": authn_context,
                "flow_type": "artifact",
            },
        )

        return state

    def _run_preflight_checks(self) -> PreflightResult:
        """Run pre-flight checks including artifact-specific ones."""
        from authtest.core.saml.sp import PreflightCheck

        # Get standard checks first
        base_result = self.sp.run_preflight_checks()
        checks = list(base_result.checks)
        warnings = list(base_result.warnings)

        # Add artifact-specific checks
        ars_url = self._get_artifact_resolution_url()
        ars_check = PreflightCheck(
            name="Artifact Resolution URL",
            description="IdP Artifact Resolution Service endpoint is configured",
            passed=bool(ars_url),
            details=ars_url or "Not configured - set 'artifact_resolution_url' in IdP settings",
        )
        checks.append(ars_check)

        if not ars_url:
            warnings.append(
                "Artifact Resolution Service URL not configured. "
                "Artifact binding requires a SOAP endpoint for resolving artifacts."
            )

        # All standard checks + ARS check must pass for artifact flow
        all_passed = all(
            c.passed for c in checks if c.name in ["IdP SSO URL", "IdP Entity ID", "Artifact Resolution URL"]
        )

        return PreflightResult(
            checks=checks,
            all_passed=all_passed,
            warnings=warnings,
        )

    def _get_artifact_resolution_url(self) -> str | None:
        """Get the artifact resolution service URL from IdP settings."""
        if self.idp.settings and "artifact_resolution_url" in self.idp.settings:
            url = self.idp.settings["artifact_resolution_url"]
            return str(url) if url else None
        return None

    def initiate_sso(self, state: FlowState) -> tuple[FlowState, str]:
        """Initiate the SSO redirect requesting artifact binding.

        Args:
            state: Current flow state.

        Returns:
            Tuple of (updated state, redirect URL).
        """
        if state.status != FlowStatus.PREFLIGHT:
            raise ValueError(f"Cannot initiate SSO from state: {state.status}")

        if state.preflight and not state.preflight.all_passed:
            state.status = FlowStatus.FAILED
            state.error = "Pre-flight checks failed"
            return state, ""

        # Create AuthnRequest requesting artifact binding
        request = self.sp.create_authn_request(
            force_authn=state.options.get("force_authn", False),
            is_passive=state.options.get("is_passive", False),
            authn_context=state.options.get("authn_context"),
            protocol_binding=BINDING_HTTP_ARTIFACT,
        )

        # Build redirect URL
        redirect_url = self.sp.build_sso_redirect_url(
            request,
            relay_state=state.flow_id,
        )

        # Update state
        state.status = FlowStatus.INITIATED
        state.request_id = request.id
        state.request_xml = request.to_xml()

        return state, redirect_url

    def process_artifact(
        self,
        state: FlowState,
        artifact: str,
        resolution_url: str | None = None,
    ) -> FlowState:
        """Process a received artifact by resolving it with the IdP.

        Args:
            state: Current flow state.
            artifact: The base64-encoded SAML artifact received from IdP.
            resolution_url: Optional override for artifact resolution URL.

        Returns:
            Updated flow state with response data.
        """
        from authtest.core.saml.artifact import ArtifactResolver, SAMLArtifact

        state.completed_at = datetime.now(UTC)

        # Store the artifact in options for result recording
        state.options["artifact"] = artifact

        # Parse artifact for validation
        parsed_artifact = SAMLArtifact.parse(artifact)
        if not parsed_artifact.is_valid_format:
            state.status = FlowStatus.FAILED
            state.error = "Invalid artifact format - not a valid SAML 2.0 artifact"
            return state

        # Get resolution URL
        url = resolution_url or self._get_artifact_resolution_url()
        if not url:
            state.status = FlowStatus.FAILED
            state.error = "No Artifact Resolution Service URL configured"
            return state

        # Resolve the artifact
        try:
            resolver = ArtifactResolver(
                idp=self.idp,
                sp_entity_id=self.sp.sp_entity_id,
            )
            artifact_response, trace = resolver.resolve(artifact, resolution_url=url)

            # Store trace information
            state.options["artifact_trace"] = trace

            if artifact_response.validation_errors:
                state.status = FlowStatus.FAILED
                state.error = "; ".join(artifact_response.validation_errors)
                return state

            if not artifact_response.is_success:
                state.status = FlowStatus.FAILED
                state.error = (
                    f"Artifact resolution failed: {artifact_response.status_code}"
                )
                return state

            # Extract and process the embedded SAML Response
            if not artifact_response.saml_response_xml:
                state.status = FlowStatus.FAILED
                state.error = "No SAML Response found in ArtifactResponse"
                return state

            # The embedded response is XML, not base64 - we need to parse it directly
            response = self._parse_embedded_response(artifact_response.saml_response_xml)
            state.response = response

            # Check if response matches our request
            if response.in_response_to and response.in_response_to != state.request_id:
                response.validation_errors.append(
                    f"Response InResponseTo ({response.in_response_to}) "
                    f"does not match request ID ({state.request_id})"
                )

            if response.is_success and not response.validation_errors:
                state.status = FlowStatus.COMPLETED
            else:
                state.status = FlowStatus.FAILED
                state.error = "; ".join(response.validation_errors) or "Authentication failed"

        except Exception as e:
            state.status = FlowStatus.FAILED
            state.error = f"Error resolving artifact: {e}"

        return state

    def _parse_embedded_response(self, xml_string: str) -> SAMLResponse:
        """Parse an embedded SAML Response (not base64 encoded).

        Args:
            xml_string: Raw XML string of the SAML Response.

        Returns:
            Parsed SAMLResponse with validation results.
        """
        from xml.etree import ElementTree

        from authtest.core.saml.signature import SignatureStatus, validate_signature
        from authtest.core.saml.sp import SAMLAssertion

        try:
            root = ElementTree.fromstring(xml_string)
        except ElementTree.ParseError as e:
            return SAMLResponse(
                raw_xml=xml_string,
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
        issuer_elem = root.find("{urn:oasis:names:tc:SAML:2.0:assertion}Issuer")
        issuer = issuer_elem.text if issuer_elem is not None else None

        # Extract status
        status_elem = root.find(
            "{urn:oasis:names:tc:SAML:2.0:protocol}Status/"
            "{urn:oasis:names:tc:SAML:2.0:protocol}StatusCode"
        )
        status_code = status_elem.get("Value") if status_elem is not None else None

        status_msg_elem = root.find(
            "{urn:oasis:names:tc:SAML:2.0:protocol}Status/"
            "{urn:oasis:names:tc:SAML:2.0:protocol}StatusMessage"
        )
        status_message = status_msg_elem.text if status_msg_elem is not None else None

        is_success = status_code == "urn:oasis:names:tc:SAML:2.0:status:Success"

        # Parse assertions
        assertions = []
        for assertion_elem in root.findall("{urn:oasis:names:tc:SAML:2.0:assertion}Assertion"):
            assertion = SAMLAssertion.from_element(assertion_elem)
            assertions.append(assertion)

        response = SAMLResponse(
            raw_xml=xml_string,
            response_id=response_id,
            in_response_to=in_response_to,
            issue_instant=issue_instant,
            issuer=issuer,
            status_code=status_code,
            status_message=status_message,
            assertions=assertions,
            is_success=is_success,
        )

        # Validate signature
        sig_result = validate_signature(xml_string, self.idp.x509_cert)
        response.signature_validation = sig_result

        if sig_result.status == SignatureStatus.INVALID:
            response.validation_errors.append(
                f"Signature validation failed: {sig_result.message}"
            )
        elif sig_result.status == SignatureStatus.ERROR:
            response.validation_errors.append(
                f"Signature validation error: {sig_result.message}"
            )

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

        return response

    def record_result(self, state: FlowState) -> int:
        """Record the test result to the database.

        Args:
            state: Completed flow state.

        Returns:
            ID of the created TestResult record.
        """
        from authtest.storage.models import TestResult

        duration_ms = None
        if state.started_at and state.completed_at:
            duration = state.completed_at - state.started_at
            duration_ms = int(duration.total_seconds() * 1000)

        if state.status == FlowStatus.COMPLETED:
            outcome = TestOutcome.PASSED
        elif state.status == FlowStatus.FAILED:
            outcome = TestOutcome.FAILED
        else:
            outcome = TestOutcome.ERROR

        # Build request data including artifact info
        request_data = {
            "request_id": state.request_id,
            "request_xml": state.request_xml,
            "options": state.options,
            "flow_type": "artifact",
        }
        if "artifact" in state.options:
            request_data["artifact"] = state.options["artifact"]
        if "artifact_trace" in state.options:
            request_data["artifact_trace"] = state.options["artifact_trace"]

        # Build response data
        response_data = None
        if state.response:
            response_data = _response_to_dict(state.response)
            response_data["raw_xml"] = state.response.raw_xml

        result = TestResult(
            idp_provider_id=state.idp_id,
            test_name="Artifact Binding SSO",
            test_type="saml",
            status=outcome.value,
            error_message=state.error,
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

    def get_flow_result(self, state: FlowState) -> FlowResult:
        """Get the final result of the flow.

        Args:
            state: Completed flow state.

        Returns:
            FlowResult with outcome summary.
        """
        duration_ms = None
        if state.started_at and state.completed_at:
            duration = state.completed_at - state.started_at
            duration_ms = int(duration.total_seconds() * 1000)

        if state.status == FlowStatus.COMPLETED:
            outcome = TestOutcome.PASSED
            summary = "Artifact binding SSO successful"
            if state.response and state.response.assertions:
                assertion = state.response.assertions[0]
                if assertion.subject_name_id:
                    summary = f"Authenticated as: {assertion.subject_name_id}"
        elif state.status == FlowStatus.FAILED:
            outcome = TestOutcome.FAILED
            summary = state.error or "Authentication failed"
        else:
            outcome = TestOutcome.ERROR
            summary = state.error or f"Flow ended in unexpected state: {state.status}"

        return FlowResult(
            flow_state=state,
            outcome=outcome,
            duration_ms=duration_ms,
            summary=summary,
        )
