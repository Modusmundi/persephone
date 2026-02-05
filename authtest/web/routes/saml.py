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

if TYPE_CHECKING:
    from werkzeug.wrappers import Response as WerkzeugResponse

from authtest.core.saml.flows import FlowState, FlowStatus, SPInitiatedFlow
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
    """Assertion Consumer Service - handles SAML Response from IdP."""
    saml_response = request.form.get("SAMLResponse")
    relay_state = request.form.get("RelayState")

    if not saml_response:
        flash("No SAML Response received", "error")
        return redirect(url_for("saml.index"))

    # Get flow state from session
    state_dict = session.get(FLOW_STATE_KEY)
    if not state_dict:
        # No state - might be unsolicited response
        flash("No active SSO flow found", "error")
        return redirect(url_for("saml.index"))

    state = FlowState.from_dict(state_dict)

    # Verify relay state matches
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
        )
    finally:
        db_session.close()


@saml_bp.route("/metadata")
def metadata() -> Response:
    """Generate SP metadata XML."""
    base_url = get_base_url()
    entity_id = f"{base_url}/saml/metadata"
    acs_url = f"{base_url}/saml/acs"

    # Simple SP metadata
    metadata_xml = f"""<?xml version="1.0" encoding="UTF-8"?>
<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata"
    entityID="{entity_id}">
    <md:SPSSODescriptor AuthnRequestsSigned="false"
        WantAssertionsSigned="true"
        protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
        <md:NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified</md:NameIDFormat>
        <md:NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress</md:NameIDFormat>
        <md:AssertionConsumerService
            Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
            Location="{acs_url}"
            index="0"
            isDefault="true"/>
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
