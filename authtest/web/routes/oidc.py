"""OIDC testing routes."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING

from flask import (
    Blueprint,
    flash,
    redirect,
    render_template,
    request,
    session,
    url_for,
)

if TYPE_CHECKING:
    from werkzeug.wrappers import Response as WerkzeugResponse

from authtest.core.oidc.flows import AuthorizationCodeFlow, OIDCFlowState, OIDCFlowStatus
from authtest.storage.database import get_database
from authtest.storage.models import ClientConfig, IdPProvider, IdPType

# Get the directories relative to this package
_web_dir = Path(__file__).parent.parent
_templates_dir = _web_dir / "templates"

oidc_bp = Blueprint(
    "oidc",
    __name__,
    template_folder=str(_templates_dir),
    url_prefix="/oidc",
)

# Session key for storing flow state
OIDC_FLOW_STATE_KEY = "oidc_flow_state"


# Template filter for timestamp conversion
@oidc_bp.app_template_filter("timestamp_to_datetime")
def timestamp_to_datetime_filter(timestamp: int | float) -> str:
    """Convert Unix timestamp to datetime string."""
    try:
        dt = datetime.fromtimestamp(timestamp, tz=UTC)
        return dt.strftime("%Y-%m-%d %H:%M:%S UTC")
    except Exception:
        return str(timestamp)


def get_base_url() -> str:
    """Get the base URL for this application."""
    scheme = request.scheme
    host = request.host
    return f"{scheme}://{host}"


def get_client_config(idp: IdPProvider) -> tuple[str, str | None]:
    """Get client credentials for an IdP.

    First checks for a ClientConfig associated with the IdP,
    then falls back to settings stored on the IdP itself.

    Args:
        idp: The IdP provider.

    Returns:
        Tuple of (client_id, client_secret).
    """
    db = get_database()
    db_session = db.get_session()

    try:
        # Look for a client config associated with this IdP
        client_config = (
            db_session.query(ClientConfig)
            .filter(ClientConfig.idp_provider_id == idp.id)
            .filter(ClientConfig.client_type == "oidc")
            .first()
        )

        if client_config and client_config.client_id:
            return client_config.client_id, client_config.client_secret

        # Fall back to IdP settings
        if idp.settings:
            client_id = idp.settings.get("client_id", "")
            client_secret = idp.settings.get("client_secret")
            return client_id, client_secret

        return "", None
    finally:
        db_session.close()


@oidc_bp.route("/")
def index() -> str:
    """OIDC testing home page - select IdP and flow type."""
    db = get_database()
    db_session = db.get_session()

    try:
        # Get all OIDC IdPs
        idps = (
            db_session.query(IdPProvider)
            .filter(IdPProvider.idp_type == IdPType.OIDC)
            .filter(IdPProvider.enabled.is_(True))
            .all()
        )
    finally:
        db_session.close()

    return render_template("oidc/index.html", idps=idps)


@oidc_bp.route("/authorization-code", methods=["GET", "POST"])
def authorization_code() -> str | WerkzeugResponse:
    """Authorization Code flow test page."""
    if request.method == "GET":
        # Show IdP selection or preflight if IdP already selected
        idp_id = request.args.get("idp_id", type=int)
        if not idp_id:
            return redirect(url_for("oidc.index"))

        db = get_database()
        db_session = db.get_session()

        try:
            idp = db_session.query(IdPProvider).get(idp_id)
            if not idp or idp.idp_type != IdPType.OIDC:
                flash("Invalid IdP selected", "error")
                return redirect(url_for("oidc.index"))

            # Get client credentials
            client_id, client_secret = get_client_config(idp)

            if not client_id:
                flash(
                    "No client credentials configured for this IdP. "
                    "Please configure client_id in IdP settings or create a Client Config.",
                    "error",
                )
                return redirect(url_for("oidc.index"))

            # Start the flow and run preflight checks
            base_url = get_base_url()
            flow = AuthorizationCodeFlow(
                idp=idp,
                db=db,
                client_id=client_id,
                client_secret=client_secret,
                base_url=base_url,
            )
            state = flow.start_flow()

            # Store state in session
            session[OIDC_FLOW_STATE_KEY] = state.to_dict()

            return render_template(
                "oidc/authorization_code.html",
                idp=idp,
                state=state,
                preflight=state.preflight,
            )
        finally:
            db_session.close()

    # POST - user confirmed, initiate authorization
    state_dict = session.get(OIDC_FLOW_STATE_KEY)
    if not state_dict:
        flash("No active flow found", "error")
        return redirect(url_for("oidc.index"))

    state = OIDCFlowState.from_dict(state_dict)

    db = get_database()
    db_session = db.get_session()

    try:
        idp = db_session.query(IdPProvider).get(state.idp_id)
        if not idp:
            flash("IdP not found", "error")
            return redirect(url_for("oidc.index"))

        # Get client credentials
        client_id, client_secret = get_client_config(idp)

        base_url = get_base_url()
        flow = AuthorizationCodeFlow(
            idp=idp,
            db=db,
            client_id=client_id,
            client_secret=client_secret,
            base_url=base_url,
        )

        # Get options from form
        prompt = request.form.get("prompt") or None
        login_hint = request.form.get("login_hint") or None

        state.options["prompt"] = prompt
        state.options["login_hint"] = login_hint

        # Create authorization request
        state, authorization_url = flow.create_authorization_request(state)

        if state.status == OIDCFlowStatus.FAILED:
            flash(state.error or "Failed to create authorization request", "error")
            return render_template(
                "oidc/authorization_code.html",
                idp=idp,
                state=state,
                preflight=state.preflight,
            )

        # Update session state
        session[OIDC_FLOW_STATE_KEY] = state.to_dict()

        # Redirect to IdP
        return redirect(authorization_url)
    finally:
        db_session.close()


@oidc_bp.route("/callback")
def callback() -> str | WerkzeugResponse:
    """Handle the authorization callback from the IdP."""
    # Get callback parameters
    code = request.args.get("code")
    error = request.args.get("error")
    error_description = request.args.get("error_description")
    returned_state = request.args.get("state")

    # Get flow state from session
    state_dict = session.get(OIDC_FLOW_STATE_KEY)
    if not state_dict:
        flash("No active OIDC flow found. Please start a new test.", "error")
        return redirect(url_for("oidc.index"))

    state = OIDCFlowState.from_dict(state_dict)

    db = get_database()
    db_session = db.get_session()

    try:
        idp = db_session.query(IdPProvider).get(state.idp_id)
        if not idp:
            flash("IdP not found", "error")
            return redirect(url_for("oidc.index"))

        # Get client credentials
        client_id, client_secret = get_client_config(idp)

        base_url = get_base_url()
        flow = AuthorizationCodeFlow(
            idp=idp,
            db=db,
            client_id=client_id,
            client_secret=client_secret,
            base_url=base_url,
        )

        # Process the callback
        state = flow.process_callback(
            state=state,
            code=code,
            error=error,
            error_description=error_description,
            returned_state=returned_state,
        )

        # Record the result
        result_id = flow.record_result(state)

        # Get the flow result for display
        result = flow.get_flow_result(state)

        # Clear the flow state
        session.pop(OIDC_FLOW_STATE_KEY, None)

        return render_template(
            "oidc/result.html",
            idp=idp,
            state=state,
            result=result,
            result_id=result_id,
        )
    finally:
        db_session.close()


@oidc_bp.route("/cancel", methods=["POST"])
def cancel() -> WerkzeugResponse:
    """Cancel an in-progress flow."""
    session.pop(OIDC_FLOW_STATE_KEY, None)
    flash("OIDC test cancelled", "info")
    return redirect(url_for("oidc.index"))
