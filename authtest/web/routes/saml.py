"""SAML testing routes."""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

from flask import (
    Blueprint,
    Response,
    current_app,
    flash,
    redirect,
    render_template,
    request,
    session,
    url_for,
)
from markupsafe import Markup

if TYPE_CHECKING:
    from werkzeug.wrappers import Response as WerkzeugResponse

from authtest.core.saml.flows import (
    ArtifactFlow,
    FlowState,
    FlowStatus,
    IdPInitiatedFlow,
    IdPInitiatedSLOFlow,
    SLOFlowState,
    SLOFlowStatus,
    SPInitiatedFlow,
    SPInitiatedSLOFlow,
)
from authtest.core.saml.utils import (
    get_attribute_info,
    get_authn_context_description,
    get_nameid_format_description,
    pretty_print_xml,
)
from authtest.storage.database import get_database
from authtest.storage.models import IdPProvider, IdPType

# Get the directories relative to this package
_web_dir = Path(__file__).parent.parent
_templates_dir = _web_dir / "templates"

saml_bp = Blueprint(
    "saml",
    __name__,
    template_folder=str(_templates_dir),
    url_prefix="/saml",
)

# Session key for storing flow state
FLOW_STATE_KEY = "saml_flow_state"


# Register template filters for SAML utilities
@saml_bp.app_template_filter("pretty_xml")
def pretty_xml_filter(xml_string: str) -> str:
    """Template filter to pretty-print XML."""
    return pretty_print_xml(xml_string)


@saml_bp.app_template_filter("saml_attr_info")
def saml_attr_info_filter(attr_name: str) -> dict[str, str]:
    """Template filter to get SAML attribute info."""
    return get_attribute_info(attr_name)


@saml_bp.app_template_filter("nameid_format_desc")
def nameid_format_desc_filter(format_uri: str) -> str:
    """Template filter to get NameID format description."""
    return get_nameid_format_description(format_uri)


@saml_bp.app_template_filter("authn_context_desc")
def authn_context_desc_filter(context_uri: str) -> str:
    """Template filter to get authentication context description."""
    return get_authn_context_description(context_uri)


def highlight_xml(xml_string: str) -> str:
    """Apply syntax highlighting to XML string.

    Returns HTML with span tags for syntax highlighting.
    """
    import html
    import re

    # Escape HTML first
    escaped = html.escape(xml_string)

    # Highlight XML tags
    # Match opening/closing tags and self-closing tags
    escaped = re.sub(
        r"(&lt;/?)([\w:-]+)",
        r'<span class="xml-bracket">\1</span><span class="xml-tag">\2</span>',
        escaped,
    )
    # Match closing bracket
    escaped = re.sub(
        r"(/?)(&gt;)",
        r'<span class="xml-bracket">\1\2</span>',
        escaped,
    )
    # Match attributes (name="value")
    escaped = re.sub(
        r"([\w:-]+)(=)(&quot;)([^&]*)(&quot;)",
        r'<span class="xml-attr">\1</span><span class="xml-equals">\2</span>'
        r'<span class="xml-string">\3\4\5</span>',
        escaped,
    )
    # Match XML declaration
    escaped = re.sub(
        r"(&lt;\?xml)",
        r'<span class="xml-decl">\1</span>',
        escaped,
    )
    escaped = re.sub(
        r"(\?&gt;)",
        r'<span class="xml-decl">\1</span>',
        escaped,
    )
    # Match comments
    escaped = re.sub(
        r"(&lt;!--.*?--&gt;)",
        r'<span class="xml-comment">\1</span>',
        escaped,
        flags=re.DOTALL,
    )

    return escaped


@saml_bp.app_template_filter("highlight_xml")
def highlight_xml_filter(xml_string: str) -> Markup:
    """Template filter to highlight XML syntax."""
    return Markup(highlight_xml(xml_string))


def get_base_url() -> str:
    """Get the base URL for this application."""
    # Use request URL scheme and host
    scheme = request.scheme
    host = request.host
    return f"{scheme}://{host}"


@saml_bp.route("/")
def index() -> str:
    """SAML testing home page - select IdP and test type."""
    db = get_database()
    db_session = db.get_session()

    try:
        # Get all SAML IdPs
        idps = (
            db_session.query(IdPProvider)
            .filter(IdPProvider.idp_type == IdPType.SAML)
            .filter(IdPProvider.enabled.is_(True))
            .all()
        )
    finally:
        db_session.close()

    return render_template("saml/index.html", idps=idps)


@saml_bp.route("/sp-initiated", methods=["GET", "POST"])
def sp_initiated() -> str | WerkzeugResponse:
    """SP-Initiated SSO test page."""
    if request.method == "GET":
        # Show IdP selection or redirect if IdP already selected
        idp_id = request.args.get("idp_id", type=int)
        if not idp_id:
            return redirect(url_for("saml.index"))

        db = get_database()
        db_session = db.get_session()

        try:
            idp = db_session.query(IdPProvider).get(idp_id)
            if not idp or idp.idp_type != IdPType.SAML:
                flash("Invalid IdP selected", "error")
                return redirect(url_for("saml.index"))

            # Start the flow and run preflight checks
            base_url = get_base_url()
            flow = SPInitiatedFlow(idp, db, base_url=base_url)
            state = flow.start_flow()

            # Store state in session
            session[FLOW_STATE_KEY] = state.to_dict()

            return render_template(
                "saml/sp_initiated.html",
                idp=idp,
                state=state,
                preflight=state.preflight,
            )
        finally:
            db_session.close()

    # POST - user confirmed, initiate SSO
    state_dict = session.get(FLOW_STATE_KEY)
    if not state_dict:
        flash("No active flow found", "error")
        return redirect(url_for("saml.index"))

    state = FlowState.from_dict(state_dict)

    db = get_database()
    db_session = db.get_session()

    try:
        idp = db_session.query(IdPProvider).get(state.idp_id)
        if not idp:
            flash("IdP not found", "error")
            return redirect(url_for("saml.index"))

        base_url = get_base_url()
        flow = SPInitiatedFlow(idp, db, base_url=base_url)

        # Get options from form
        force_authn = request.form.get("force_authn") == "on"
        is_passive = request.form.get("is_passive") == "on"

        state.options["force_authn"] = force_authn
        state.options["is_passive"] = is_passive

        # Initiate SSO
        state, redirect_url = flow.initiate_sso(state)

        if state.status == FlowStatus.FAILED:
            flash(state.error or "Failed to initiate SSO", "error")
            return render_template(
                "saml/sp_initiated.html",
                idp=idp,
                state=state,
                preflight=state.preflight,
            )

        # Update session state
        session[FLOW_STATE_KEY] = state.to_dict()

        # Redirect to IdP
        return redirect(redirect_url)
    finally:
        db_session.close()


@saml_bp.route("/acs", methods=["POST"])
def acs() -> str | WerkzeugResponse:
    """Assertion Consumer Service - handles SAML Response from IdP.

    Handles both SP-Initiated (with prior AuthnRequest) and IdP-Initiated
    (unsolicited assertion) SSO flows.
    """
    saml_response = request.form.get("SAMLResponse")
    relay_state = request.form.get("RelayState")

    if not saml_response:
        flash("No SAML Response received", "error")
        return redirect(url_for("saml.index"))

    # Get flow state from session (may be None for IdP-Initiated)
    state_dict = session.get(FLOW_STATE_KEY)

    if state_dict:
        # SP-Initiated flow - we have a pending flow state
        state = FlowState.from_dict(state_dict)

        # Verify relay state matches if present
        if relay_state and relay_state != state.flow_id:
            flash("RelayState mismatch", "error")
            return redirect(url_for("saml.index"))

        db = get_database()
        db_session = db.get_session()

        try:
            idp = db_session.query(IdPProvider).get(state.idp_id)
            if not idp:
                flash("IdP not found", "error")
                return redirect(url_for("saml.index"))

            base_url = get_base_url()
            flow = SPInitiatedFlow(idp, db, base_url=base_url)

            # Process the response
            state = flow.process_response(state, saml_response)

            # Record the result
            result_id = flow.record_result(state)

            # Get the flow result for display
            result = flow.get_flow_result(state)

            # Clear the flow state
            session.pop(FLOW_STATE_KEY, None)

            return render_template(
                "saml/result.html",
                idp=idp,
                state=state,
                result=result,
                result_id=result_id,
                flow_type="sp_initiated",
            )
        finally:
            db_session.close()
    else:
        # IdP-Initiated flow - unsolicited assertion
        return handle_idp_initiated_acs(saml_response)


def handle_idp_initiated_acs(saml_response: str) -> str | WerkzeugResponse:
    """Handle IdP-Initiated SSO (unsolicited assertion).

    Args:
        saml_response: Base64-encoded SAML Response from IdP.

    Returns:
        Rendered result page or redirect on error.
    """
    from authtest.core.saml.sp import SAMLResponse

    # First, parse the response to identify the IdP
    parsed = SAMLResponse.parse(saml_response)

    if not parsed.issuer:
        flash("Could not determine IdP from SAML Response (missing Issuer)", "error")
        return redirect(url_for("saml.index"))

    db = get_database()
    db_session = db.get_session()

    try:
        # Find IdP by entity_id
        idp = (
            db_session.query(IdPProvider)
            .filter(IdPProvider.entity_id == parsed.issuer)
            .filter(IdPProvider.idp_type == IdPType.SAML)
            .filter(IdPProvider.enabled.is_(True))
            .first()
        )

        if not idp:
            flash(
                f"Unknown Identity Provider: {parsed.issuer}. Please configure this IdP first.",
                "error",
            )
            return redirect(url_for("saml.index"))

        base_url = get_base_url()
        flow = IdPInitiatedFlow(idp, db, base_url=base_url)

        # Process the unsolicited response
        state = flow.process_unsolicited_response(saml_response)

        # Record the result
        result_id = flow.record_result(state)

        # Get the flow result for display
        result = flow.get_flow_result(state)

        return render_template(
            "saml/result.html",
            idp=idp,
            state=state,
            result=result,
            result_id=result_id,
            flow_type="idp_initiated",
        )
    finally:
        db_session.close()


@saml_bp.route("/idp-initiated")
def idp_initiated() -> str | WerkzeugResponse:
    """IdP-Initiated SSO information page."""
    idp_id = request.args.get("idp_id", type=int)

    db = get_database()
    db_session = db.get_session()

    try:
        if idp_id:
            idp = db_session.query(IdPProvider).get(idp_id)
            if not idp or idp.idp_type != IdPType.SAML:
                flash("Invalid IdP selected", "error")
                return redirect(url_for("saml.index"))
        else:
            idp = None

        # Get all SAML IdPs for selection
        idps = (
            db_session.query(IdPProvider)
            .filter(IdPProvider.idp_type == IdPType.SAML)
            .filter(IdPProvider.enabled.is_(True))
            .all()
        )

        base_url = get_base_url()
        acs_url = f"{base_url}/saml/acs"

        return render_template(
            "saml/idp_initiated.html",
            idp=idp,
            idps=idps,
            acs_url=acs_url,
        )
    finally:
        db_session.close()


@saml_bp.route("/metadata")
def metadata() -> Response:
    """Generate SP metadata XML."""
    base_url = get_base_url()
    entity_id = f"{base_url}/saml/metadata"
    acs_url = f"{base_url}/saml/acs"
    artifact_acs_url = f"{base_url}/saml/artifact/acs"
    slo_url = f"{base_url}/saml/slo"

    # SP metadata with POST, Artifact binding, and SLO support
    metadata_xml = f"""<?xml version="1.0" encoding="UTF-8"?>
<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata"
    entityID="{entity_id}">
    <md:SPSSODescriptor AuthnRequestsSigned="false"
        WantAssertionsSigned="true"
        protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
        <md:SingleLogoutService
            Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
            Location="{slo_url}"/>
        <md:SingleLogoutService
            Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
            Location="{slo_url}"/>
        <md:NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified</md:NameIDFormat>
        <md:NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress</md:NameIDFormat>
        <md:AssertionConsumerService
            Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
            Location="{acs_url}"
            index="0"
            isDefault="true"/>
        <md:AssertionConsumerService
            Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Artifact"
            Location="{artifact_acs_url}"
            index="1"/>
    </md:SPSSODescriptor>
</md:EntityDescriptor>"""

    response: Response = current_app.make_response(metadata_xml)
    response.headers["Content-Type"] = "application/xml"
    return response


@saml_bp.route("/cancel", methods=["POST"])
def cancel() -> WerkzeugResponse:
    """Cancel an in-progress flow."""
    session.pop(FLOW_STATE_KEY, None)
    flash("SSO test cancelled", "info")
    return redirect(url_for("saml.index"))


# Session key for artifact flow state
ARTIFACT_FLOW_STATE_KEY = "saml_artifact_flow_state"


@saml_bp.route("/artifact", methods=["GET", "POST"])
def artifact() -> str | WerkzeugResponse:
    """SAML Artifact Binding test page."""
    if request.method == "GET":
        # Show IdP selection or preflight if IdP already selected
        idp_id = request.args.get("idp_id", type=int)
        if not idp_id:
            return redirect(url_for("saml.index"))

        db = get_database()
        db_session = db.get_session()

        try:
            idp = db_session.query(IdPProvider).get(idp_id)
            if not idp or idp.idp_type != IdPType.SAML:
                flash("Invalid IdP selected", "error")
                return redirect(url_for("saml.index"))

            # Start the flow and run preflight checks
            base_url = get_base_url()
            flow = ArtifactFlow(idp, db, base_url=base_url)
            state = flow.start_flow()

            # Store state in session
            session[ARTIFACT_FLOW_STATE_KEY] = state.to_dict()

            return render_template(
                "saml/artifact.html",
                idp=idp,
                state=state,
                preflight=state.preflight,
            )
        finally:
            db_session.close()

    # POST - user confirmed, initiate SSO with artifact binding
    state_dict = session.get(ARTIFACT_FLOW_STATE_KEY)
    if not state_dict:
        flash("No active flow found", "error")
        return redirect(url_for("saml.index"))

    state = FlowState.from_dict(state_dict)

    db = get_database()
    db_session = db.get_session()

    try:
        idp = db_session.query(IdPProvider).get(state.idp_id)
        if not idp:
            flash("IdP not found", "error")
            return redirect(url_for("saml.index"))

        base_url = get_base_url()
        flow = ArtifactFlow(idp, db, base_url=base_url)

        # Get options from form
        force_authn = request.form.get("force_authn") == "on"
        is_passive = request.form.get("is_passive") == "on"

        state.options["force_authn"] = force_authn
        state.options["is_passive"] = is_passive

        # Initiate SSO
        state, redirect_url = flow.initiate_sso(state)

        if state.status == FlowStatus.FAILED:
            flash(state.error or "Failed to initiate SSO", "error")
            return render_template(
                "saml/artifact.html",
                idp=idp,
                state=state,
                preflight=state.preflight,
            )

        # Update session state
        session[ARTIFACT_FLOW_STATE_KEY] = state.to_dict()

        # Redirect to IdP
        return redirect(redirect_url)
    finally:
        db_session.close()


@saml_bp.route("/artifact/acs", methods=["GET", "POST"])
def artifact_acs() -> str | WerkzeugResponse:
    """Artifact Consumer Service - handles artifacts from IdP.

    The IdP redirects here with the artifact instead of sending
    a full SAML Response.
    """
    # Get artifact from query params (GET) or form (POST)
    artifact = request.args.get("SAMLart") or request.form.get("SAMLart")
    relay_state = request.args.get("RelayState") or request.form.get("RelayState")

    if not artifact:
        flash("No SAML artifact received", "error")
        return redirect(url_for("saml.index"))

    # Get flow state from session
    state_dict = session.get(ARTIFACT_FLOW_STATE_KEY)
    if not state_dict:
        flash("No active artifact flow found", "error")
        return redirect(url_for("saml.index"))

    state = FlowState.from_dict(state_dict)

    # Verify relay state matches if present
    if relay_state and relay_state != state.flow_id:
        flash("RelayState mismatch", "error")
        return redirect(url_for("saml.index"))

    db = get_database()
    db_session = db.get_session()

    try:
        idp = db_session.query(IdPProvider).get(state.idp_id)
        if not idp:
            flash("IdP not found", "error")
            return redirect(url_for("saml.index"))

        base_url = get_base_url()
        flow = ArtifactFlow(idp, db, base_url=base_url)

        # Process the artifact (resolve via back-channel)
        state = flow.process_artifact(state, artifact)

        # Record the result
        result_id = flow.record_result(state)

        # Get the flow result for display
        result = flow.get_flow_result(state)

        # Clear the flow state
        session.pop(ARTIFACT_FLOW_STATE_KEY, None)

        return render_template(
            "saml/result.html",
            idp=idp,
            state=state,
            result=result,
            result_id=result_id,
            flow_type="artifact",
        )
    finally:
        db_session.close()


# Session key for SLO flow state
SLO_FLOW_STATE_KEY = "saml_slo_flow_state"


@saml_bp.route("/slo", methods=["GET", "POST"])
def slo() -> str | WerkzeugResponse:
    """Single Logout (SLO) test page and endpoint.

    GET: Show SLO test configuration page
    POST: Process SP-initiated logout or IdP-initiated LogoutRequest
    """
    # Check for IdP-initiated logout (LogoutRequest from IdP)
    saml_request = request.args.get("SAMLRequest") or request.form.get("SAMLRequest")
    if saml_request:
        return handle_idp_initiated_slo(saml_request)

    # Check for SP-initiated logout response (LogoutResponse from IdP)
    saml_response = request.args.get("SAMLResponse") or request.form.get("SAMLResponse")
    if saml_response:
        return handle_slo_response(saml_response)

    if request.method == "GET":
        # Show SLO test configuration page
        idp_id = request.args.get("idp_id", type=int)
        if not idp_id:
            return redirect(url_for("saml.index"))

        db = get_database()
        db_session = db.get_session()

        try:
            idp = db_session.query(IdPProvider).get(idp_id)
            if not idp or idp.idp_type != IdPType.SAML:
                flash("Invalid IdP selected", "error")
                return redirect(url_for("saml.index"))

            # Start the flow
            base_url = get_base_url()
            flow = SPInitiatedSLOFlow(idp, db, base_url=base_url)

            # Use dummy data for testing - in real use, this would come from
            # a previous SSO session
            state = flow.start_flow(
                name_id="test-user@example.com",
                name_id_format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
            )

            # Store state in session
            session[SLO_FLOW_STATE_KEY] = state.to_dict()

            preflight = state.options.get("preflight", {})

            return render_template(
                "saml/slo.html",
                idp=idp,
                state=state,
                preflight=preflight,
            )
        finally:
            db_session.close()

    # POST - user submitted SLO test form
    state_dict = session.get(SLO_FLOW_STATE_KEY)
    if not state_dict:
        flash("No active SLO flow found", "error")
        return redirect(url_for("saml.index"))

    state = SLOFlowState.from_dict(state_dict)

    db = get_database()
    db_session = db.get_session()

    try:
        idp = db_session.query(IdPProvider).get(state.idp_id)
        if not idp:
            flash("IdP not found", "error")
            return redirect(url_for("saml.index"))

        base_url = get_base_url()
        flow = SPInitiatedSLOFlow(idp, db, base_url=base_url)

        # Get form values and update state
        name_id = request.form.get("name_id", "test-user@example.com")
        name_id_format = request.form.get(
            "name_id_format",
            "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"
        )
        session_index = request.form.get("session_index") or None
        logout_reason = request.form.get("logout_reason") or None

        # Create a new flow with the actual values
        state = flow.start_flow(
            name_id=name_id,
            name_id_format=name_id_format,
            session_index=session_index,
            logout_reason=logout_reason,
        )

        # Initiate logout
        state, redirect_url = flow.initiate_logout(state)

        if state.status == SLOFlowStatus.FAILED:
            flash(state.error or "Failed to initiate SLO", "error")
            preflight = state.options.get("preflight", {})
            return render_template(
                "saml/slo.html",
                idp=idp,
                state=state,
                preflight=preflight,
            )

        # Update session state
        session[SLO_FLOW_STATE_KEY] = state.to_dict()

        # Redirect to IdP
        return redirect(redirect_url)
    finally:
        db_session.close()


def handle_slo_response(saml_response: str) -> str | WerkzeugResponse:
    """Handle LogoutResponse from IdP (SP-initiated logout completion).

    Args:
        saml_response: Base64-encoded SAML LogoutResponse.

    Returns:
        Rendered result page or redirect on error.
    """
    relay_state = request.args.get("RelayState") or request.form.get("RelayState")

    # Get flow state from session
    state_dict = session.get(SLO_FLOW_STATE_KEY)
    if not state_dict:
        flash("No active SLO flow found", "error")
        return redirect(url_for("saml.index"))

    state = SLOFlowState.from_dict(state_dict)

    # Verify relay state matches if present
    if relay_state and relay_state != state.flow_id:
        flash("RelayState mismatch", "error")
        return redirect(url_for("saml.index"))

    db = get_database()
    db_session = db.get_session()

    try:
        idp = db_session.query(IdPProvider).get(state.idp_id)
        if not idp:
            flash("IdP not found", "error")
            return redirect(url_for("saml.index"))

        base_url = get_base_url()
        flow = SPInitiatedSLOFlow(idp, db, base_url=base_url)

        # Determine if this is redirect or POST binding
        is_redirect = request.method == "GET"

        # Process the response
        state = flow.process_response(state, saml_response, is_redirect=is_redirect)

        # Record the result
        result_id = flow.record_result(state)

        # Get the flow result for display
        result = flow.get_flow_result(state)

        # Clear the flow state
        session.pop(SLO_FLOW_STATE_KEY, None)

        return render_template(
            "saml/slo_result.html",
            idp=idp,
            state=state,
            result=result,
            result_id=result_id,
            flow_type="sp_initiated",
        )
    finally:
        db_session.close()


def handle_idp_initiated_slo(saml_request: str) -> str | WerkzeugResponse:
    """Handle LogoutRequest from IdP (IdP-initiated logout).

    Args:
        saml_request: Base64-encoded SAML LogoutRequest.

    Returns:
        Redirect to IdP with LogoutResponse or error page.
    """
    from authtest.core.saml.logout import SAMLLogoutRequest

    relay_state = request.args.get("RelayState") or request.form.get("RelayState")
    is_redirect = request.method == "GET"

    # First, parse the request to identify the IdP
    try:
        parsed_request = SAMLLogoutRequest.parse(saml_request, is_redirect=is_redirect)
    except ValueError as e:
        flash(f"Invalid LogoutRequest: {e}", "error")
        return redirect(url_for("saml.index"))

    if not parsed_request.issuer:
        flash("Could not determine IdP from LogoutRequest (missing Issuer)", "error")
        return redirect(url_for("saml.index"))

    db = get_database()
    db_session = db.get_session()

    try:
        # Find IdP by entity_id
        idp = (
            db_session.query(IdPProvider)
            .filter(IdPProvider.entity_id == parsed_request.issuer)
            .filter(IdPProvider.idp_type == IdPType.SAML)
            .filter(IdPProvider.enabled.is_(True))
            .first()
        )

        if not idp:
            flash(
                f"Unknown Identity Provider: {parsed_request.issuer}. "
                "Please configure this IdP first.",
                "error",
            )
            return redirect(url_for("saml.index"))

        base_url = get_base_url()
        flow = IdPInitiatedSLOFlow(idp, db, base_url=base_url)

        # Process the logout request and get response URL
        state, redirect_url = flow.process_logout_request(
            saml_request,
            is_redirect=is_redirect,
            relay_state=relay_state,
        )

        # Record the result
        result_id = flow.record_result(state)

        # If we have a redirect URL, redirect to IdP with response
        if redirect_url:
            # Store state briefly for potential display (optional)
            session["last_slo_result"] = {
                "idp_id": idp.id,
                "result_id": result_id,
                "state": state.to_dict(),
            }
            return redirect(redirect_url)

        # If no redirect URL (IdP SLO URL not configured), show result page
        result = flow.get_flow_result(state)
        return render_template(
            "saml/slo_result.html",
            idp=idp,
            state=state,
            result=result,
            result_id=result_id,
            flow_type="idp_initiated",
        )
    finally:
        db_session.close()


@saml_bp.route("/slo/info")
def slo_info() -> str | WerkzeugResponse:
    """SLO information page showing SP SLO endpoint details."""
    idp_id = request.args.get("idp_id", type=int)

    db = get_database()
    db_session = db.get_session()

    try:
        if idp_id:
            idp = db_session.query(IdPProvider).get(idp_id)
            if not idp or idp.idp_type != IdPType.SAML:
                flash("Invalid IdP selected", "error")
                return redirect(url_for("saml.index"))
        else:
            idp = None

        # Get all SAML IdPs for selection
        idps = (
            db_session.query(IdPProvider)
            .filter(IdPProvider.idp_type == IdPType.SAML)
            .filter(IdPProvider.enabled.is_(True))
            .all()
        )

        base_url = get_base_url()
        slo_url = f"{base_url}/saml/slo"

        return render_template(
            "saml/slo_info.html",
            idp=idp,
            idps=idps,
            slo_url=slo_url,
        )
    finally:
        db_session.close()


@saml_bp.route("/slo/cancel", methods=["POST"])
def slo_cancel() -> WerkzeugResponse:
    """Cancel an in-progress SLO flow."""
    session.pop(SLO_FLOW_STATE_KEY, None)
    flash("SLO test cancelled", "info")
    return redirect(url_for("saml.index"))
