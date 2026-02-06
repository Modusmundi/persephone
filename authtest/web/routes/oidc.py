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

from authtest.core.oidc.flows import (
    AuthorizationCodeFlow,
    ClientCredentialsFlow,
    DeviceCodeFlow,
    DeviceCodeFlowState,
    ImplicitFlow,
    OIDCFlowState,
    OIDCFlowStatus,
)
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


# Standard OIDC/JWT claim descriptions
_CLAIM_DESCRIPTIONS = {
    "iss": "Token issuer (identity provider)",
    "sub": "Subject identifier (unique user ID)",
    "aud": "Intended audience (client ID)",
    "exp": "Expiration time",
    "iat": "Time token was issued",
    "nbf": "Token not valid before this time",
    "jti": "Unique token identifier",
    "nonce": "Value to prevent replay attacks",
    "auth_time": "Time of user authentication",
    "acr": "Authentication context class reference",
    "amr": "Authentication methods used",
    "azp": "Authorized party (client that requested token)",
    "at_hash": "Access token hash",
    "c_hash": "Authorization code hash",
    "name": "User's full name",
    "given_name": "User's first/given name",
    "family_name": "User's last/family name",
    "middle_name": "User's middle name",
    "nickname": "User's casual name",
    "preferred_username": "User's preferred username",
    "profile": "URL of user's profile page",
    "picture": "URL of user's profile picture",
    "website": "URL of user's website",
    "email": "User's email address",
    "email_verified": "Whether email has been verified",
    "gender": "User's gender",
    "birthdate": "User's date of birth",
    "zoneinfo": "User's time zone",
    "locale": "User's locale/language preference",
    "phone_number": "User's phone number",
    "phone_number_verified": "Whether phone has been verified",
    "address": "User's address",
    "updated_at": "Time profile was last updated",
    "sid": "Session identifier",
    "scope": "Granted scopes",
    "client_id": "OAuth2 client identifier",
    "typ": "Token type",
    "realm_access": "Realm-level role access (Keycloak)",
    "resource_access": "Resource-level role access (Keycloak)",
    "allowed-origins": "Allowed CORS origins",
}


@oidc_bp.app_template_global("get_claim_description")
def get_claim_description(claim: str) -> str:
    """Get human-readable description for a JWT claim."""
    return _CLAIM_DESCRIPTIONS.get(claim, "Custom claim")


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
        use_pkce = request.form.get("use_pkce") == "on"
        code_challenge_method = request.form.get("code_challenge_method", "S256")

        state.options["prompt"] = prompt
        state.options["login_hint"] = login_hint
        state.options["use_pkce"] = use_pkce
        state.options["code_challenge_method"] = code_challenge_method

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


# Session key for client credentials flow state
OIDC_CC_FLOW_STATE_KEY = "oidc_cc_flow_state"


@oidc_bp.route("/client-credentials", methods=["GET", "POST"])
def client_credentials() -> str | WerkzeugResponse:
    """Client Credentials flow test page."""
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

            if not client_secret:
                flash(
                    "Client secret is required for the Client Credentials flow. "
                    "Please configure client_secret in IdP settings or Client Config.",
                    "error",
                )
                return redirect(url_for("oidc.index"))

            # Start the flow and run preflight checks
            flow = ClientCredentialsFlow(
                idp=idp,
                db=db,
                client_id=client_id,
                client_secret=client_secret,
            )
            state = flow.start_flow()

            # Store state in session
            session[OIDC_CC_FLOW_STATE_KEY] = state.to_dict()

            # Get default scopes (without 'openid')
            default_scopes = [s for s in (idp.settings.get("default_scopes", ["openid", "profile", "email"]) if idp.settings else ["openid", "profile", "email"]) if s != "openid"]

            return render_template(
                "oidc/client_credentials.html",
                idp=idp,
                state=state,
                preflight=state.preflight,
                default_scopes=default_scopes,
            )
        finally:
            db_session.close()

    # POST - user confirmed, execute the flow
    state_dict = session.get(OIDC_CC_FLOW_STATE_KEY)
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

        flow = ClientCredentialsFlow(
            idp=idp,
            db=db,
            client_id=client_id,
            client_secret=client_secret or "",
        )

        # Get scopes from form
        scopes_input = request.form.get("scopes", "").strip()
        scopes = scopes_input.split() if scopes_input else None

        # Execute the flow
        state = flow.execute_flow(state, scopes=scopes)

        # Record the result
        result_id = flow.record_result(state)

        # Get the flow result for display
        result = flow.get_flow_result(state)

        # Clear the flow state
        session.pop(OIDC_CC_FLOW_STATE_KEY, None)

        return render_template(
            "oidc/client_credentials_result.html",
            idp=idp,
            state=state,
            result=result,
            result_id=result_id,
        )
    finally:
        db_session.close()


@oidc_bp.route("/client-credentials/cancel", methods=["POST"])
def cancel_client_credentials() -> WerkzeugResponse:
    """Cancel an in-progress client credentials flow."""
    session.pop(OIDC_CC_FLOW_STATE_KEY, None)
    flash("Client Credentials test cancelled", "info")
    return redirect(url_for("oidc.index"))


# Session key for implicit flow state
OIDC_IMPLICIT_FLOW_STATE_KEY = "oidc_implicit_flow_state"


@oidc_bp.route("/implicit", methods=["GET", "POST"])
def implicit() -> str | WerkzeugResponse:
    """Implicit flow test page (LEGACY - NOT RECOMMENDED)."""
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

            # Get client credentials (only need client_id for implicit flow)
            client_id, _ = get_client_config(idp)

            if not client_id:
                flash(
                    "No client credentials configured for this IdP. "
                    "Please configure client_id in IdP settings or create a Client Config.",
                    "error",
                )
                return redirect(url_for("oidc.index"))

            # Start the flow and run preflight checks
            base_url = get_base_url()
            flow = ImplicitFlow(
                idp=idp,
                db=db,
                client_id=client_id,
                base_url=base_url,
            )
            state = flow.start_flow()

            # Store state in session
            session[OIDC_IMPLICIT_FLOW_STATE_KEY] = state.to_dict()

            return render_template(
                "oidc/implicit.html",
                idp=idp,
                state=state,
                preflight=state.preflight,
            )
        finally:
            db_session.close()

    # POST - user confirmed, initiate authorization
    state_dict = session.get(OIDC_IMPLICIT_FLOW_STATE_KEY)
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
        client_id, _ = get_client_config(idp)

        base_url = get_base_url()
        flow = ImplicitFlow(
            idp=idp,
            db=db,
            client_id=client_id,
            base_url=base_url,
        )

        # Get options from form
        response_type = request.form.get("response_type", "id_token token")
        prompt = request.form.get("prompt") or None
        login_hint = request.form.get("login_hint") or None

        state.options["response_type"] = response_type
        state.options["prompt"] = prompt
        state.options["login_hint"] = login_hint

        # Create authorization request
        state, authorization_url = flow.create_authorization_request(state)

        if state.status == OIDCFlowStatus.FAILED:
            flash(state.error or "Failed to create authorization request", "error")
            return render_template(
                "oidc/implicit.html",
                idp=idp,
                state=state,
                preflight=state.preflight,
            )

        # Update session state
        session[OIDC_IMPLICIT_FLOW_STATE_KEY] = state.to_dict()

        # Redirect to IdP
        return redirect(authorization_url)
    finally:
        db_session.close()


@oidc_bp.route("/implicit/callback")
def implicit_callback() -> str | WerkzeugResponse:
    """Handle the implicit flow callback - this page extracts tokens from URL fragment.

    Since URL fragments are not sent to the server, this page includes JavaScript
    to extract the tokens from the fragment and submit them to the process endpoint.
    """
    # Check if we have an active flow
    state_dict = session.get(OIDC_IMPLICIT_FLOW_STATE_KEY)
    if not state_dict:
        flash("No active Implicit flow found. Please start a new test.", "error")
        return redirect(url_for("oidc.index"))

    state = OIDCFlowState.from_dict(state_dict)

    db = get_database()
    db_session = db.get_session()

    try:
        idp = db_session.query(IdPProvider).get(state.idp_id)
        if not idp:
            flash("IdP not found", "error")
            return redirect(url_for("oidc.index"))

        # Render a page with JavaScript to extract tokens from fragment
        return render_template(
            "oidc/implicit_callback.html",
            idp=idp,
            state=state,
        )
    finally:
        db_session.close()


@oidc_bp.route("/implicit/process", methods=["POST"])
def implicit_process() -> str | WerkzeugResponse:
    """Process the tokens extracted from the URL fragment by client-side JavaScript."""
    state_dict = session.get(OIDC_IMPLICIT_FLOW_STATE_KEY)
    if not state_dict:
        flash("No active Implicit flow found. Please start a new test.", "error")
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
        client_id, _ = get_client_config(idp)

        base_url = get_base_url()
        flow = ImplicitFlow(
            idp=idp,
            db=db,
            client_id=client_id,
            base_url=base_url,
        )

        # Get fragment parameters from form
        access_token = request.form.get("access_token") or None
        id_token = request.form.get("id_token") or None
        token_type = request.form.get("token_type") or None
        expires_in_str = request.form.get("expires_in")
        expires_in = int(expires_in_str) if expires_in_str else None
        scope = request.form.get("scope") or None
        error = request.form.get("error") or None
        error_description = request.form.get("error_description") or None
        returned_state = request.form.get("state") or None

        # Process the fragment response
        state = flow.process_fragment_response(
            state=state,
            access_token=access_token,
            id_token=id_token,
            token_type=token_type,
            expires_in=expires_in,
            scope=scope,
            error=error,
            error_description=error_description,
            returned_state=returned_state,
        )

        # Record the result
        result_id = flow.record_result(state)

        # Get the flow result for display
        result = flow.get_flow_result(state)

        # Clear the flow state
        session.pop(OIDC_IMPLICIT_FLOW_STATE_KEY, None)

        return render_template(
            "oidc/implicit_result.html",
            idp=idp,
            state=state,
            result=result,
            result_id=result_id,
        )
    finally:
        db_session.close()


@oidc_bp.route("/implicit/cancel", methods=["POST"])
def cancel_implicit() -> WerkzeugResponse:
    """Cancel an in-progress implicit flow."""
    session.pop(OIDC_IMPLICIT_FLOW_STATE_KEY, None)
    flash("Implicit flow test cancelled", "info")
    return redirect(url_for("oidc.index"))


# Session key for device code flow state
OIDC_DEVICE_FLOW_STATE_KEY = "oidc_device_flow_state"


@oidc_bp.route("/device-code", methods=["GET", "POST"])
def device_code() -> str | WerkzeugResponse:
    """Device Code flow test page."""
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

            # Check for device authorization endpoint
            device_endpoint = idp.settings.get("device_authorization_endpoint") if idp.settings else None
            if not device_endpoint:
                flash(
                    "Device authorization endpoint not configured. "
                    "Please add device_authorization_endpoint to IdP settings.",
                    "error",
                )
                return redirect(url_for("oidc.index"))

            # Start the flow and run preflight checks
            flow = DeviceCodeFlow(
                idp=idp,
                db=db,
                client_id=client_id,
                client_secret=client_secret,
            )
            state = flow.start_flow()

            # Store state in session
            session[OIDC_DEVICE_FLOW_STATE_KEY] = state.to_dict()

            return render_template(
                "oidc/device_code.html",
                idp=idp,
                state=state,
                preflight=state.preflight,
            )
        finally:
            db_session.close()

    # POST - user confirmed, request device authorization
    state_dict = session.get(OIDC_DEVICE_FLOW_STATE_KEY)
    if not state_dict:
        flash("No active flow found", "error")
        return redirect(url_for("oidc.index"))

    state = DeviceCodeFlowState.from_dict(state_dict)

    db = get_database()
    db_session = db.get_session()

    try:
        idp = db_session.query(IdPProvider).get(state.idp_id)
        if not idp:
            flash("IdP not found", "error")
            return redirect(url_for("oidc.index"))

        # Get client credentials
        client_id, client_secret = get_client_config(idp)

        flow = DeviceCodeFlow(
            idp=idp,
            db=db,
            client_id=client_id,
            client_secret=client_secret,
        )

        # Get scopes from form
        scopes_input = request.form.get("scopes", "").strip()
        scopes = scopes_input.split() if scopes_input else None

        # Request device authorization
        state = flow.request_device_authorization(state, scopes=scopes)

        if state.status == OIDCFlowStatus.FAILED:
            flash(state.error_description or state.error or "Device authorization failed", "error")
            session.pop(OIDC_DEVICE_FLOW_STATE_KEY, None)
            return redirect(url_for("oidc.device_code", idp_id=idp.id))

        # Update session state
        session[OIDC_DEVICE_FLOW_STATE_KEY] = state.to_dict()

        # Redirect to the polling page
        return redirect(url_for("oidc.device_code_poll"))
    finally:
        db_session.close()


@oidc_bp.route("/device-code/poll")
def device_code_poll() -> str | WerkzeugResponse:
    """Device Code polling page - displays user_code and verification_uri."""
    state_dict = session.get(OIDC_DEVICE_FLOW_STATE_KEY)
    if not state_dict:
        flash("No active Device Code flow found. Please start a new test.", "error")
        return redirect(url_for("oidc.index"))

    state = DeviceCodeFlowState.from_dict(state_dict)

    if state.status not in (OIDCFlowStatus.WAITING_CALLBACK, OIDCFlowStatus.EXCHANGING):
        flash("Device Code flow is not in polling state", "error")
        return redirect(url_for("oidc.index"))

    db = get_database()
    db_session = db.get_session()

    try:
        idp = db_session.query(IdPProvider).get(state.idp_id)
        if not idp:
            flash("IdP not found", "error")
            return redirect(url_for("oidc.index"))

        return render_template(
            "oidc/device_code_poll.html",
            idp=idp,
            state=state,
        )
    finally:
        db_session.close()


@oidc_bp.route("/device-code/check", methods=["POST"])
def device_code_check() -> str | WerkzeugResponse:
    """Check if user has completed device authorization (called via AJAX or form)."""
    state_dict = session.get(OIDC_DEVICE_FLOW_STATE_KEY)
    if not state_dict:
        flash("No active Device Code flow found", "error")
        return redirect(url_for("oidc.index"))

    state = DeviceCodeFlowState.from_dict(state_dict)

    db = get_database()
    db_session = db.get_session()

    try:
        idp = db_session.query(IdPProvider).get(state.idp_id)
        if not idp:
            flash("IdP not found", "error")
            return redirect(url_for("oidc.index"))

        # Get client credentials
        client_id, client_secret = get_client_config(idp)

        flow = DeviceCodeFlow(
            idp=idp,
            db=db,
            client_id=client_id,
            client_secret=client_secret,
        )

        # Poll for token
        state = flow.poll_for_token(state)

        # Update session state
        session[OIDC_DEVICE_FLOW_STATE_KEY] = state.to_dict()

        # Check if completed or failed
        if state.status == OIDCFlowStatus.COMPLETED:
            # Record result and redirect to result page
            result_id = flow.record_result(state)
            result = flow.get_flow_result(state)
            session.pop(OIDC_DEVICE_FLOW_STATE_KEY, None)

            return render_template(
                "oidc/device_code_result.html",
                idp=idp,
                state=state,
                result=result,
                result_id=result_id,
            )

        if state.status == OIDCFlowStatus.FAILED:
            # Record failed result
            result_id = flow.record_result(state)
            result = flow.get_flow_result(state)
            session.pop(OIDC_DEVICE_FLOW_STATE_KEY, None)

            return render_template(
                "oidc/device_code_result.html",
                idp=idp,
                state=state,
                result=result,
                result_id=result_id,
            )

        # Still pending - redirect back to poll page
        return redirect(url_for("oidc.device_code_poll"))
    finally:
        db_session.close()


@oidc_bp.route("/device-code/cancel", methods=["POST"])
def cancel_device_code() -> WerkzeugResponse:
    """Cancel an in-progress device code flow."""
    session.pop(OIDC_DEVICE_FLOW_STATE_KEY, None)
    flash("Device Code flow test cancelled", "info")
    return redirect(url_for("oidc.index"))
