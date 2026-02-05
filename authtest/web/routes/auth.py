"""Authentication routes for AuthTest."""

from __future__ import annotations

import secrets
from collections.abc import Callable
from functools import wraps
from pathlib import Path
from typing import TYPE_CHECKING, Any, cast

from flask import (
    Blueprint,
    current_app,
    g,
    redirect,
    render_template,
    request,
    session,
    url_for,
)

if TYPE_CHECKING:
    from werkzeug.wrappers import Response as WerkzeugResponse

    from authtest.core.auth import AuthManager

# Get the directories relative to this package
_web_dir = Path(__file__).parent.parent
_templates_dir = _web_dir / "templates"

auth_bp = Blueprint(
    "auth",
    __name__,
    template_folder=str(_templates_dir),
    url_prefix="/auth",
)


# Session key constants
SESSION_TOKEN_KEY = "auth_token"
CSRF_TOKEN_KEY = "csrf_token"


def get_auth_manager() -> AuthManager:
    """Get the auth manager from the app context."""
    return cast("AuthManager", current_app.config["AUTH_MANAGER"])


def is_auth_enabled() -> bool:
    """Check if authentication is enabled."""
    return bool(current_app.config.get("AUTH_ENABLED", True))


def generate_csrf_token() -> str:
    """Generate a CSRF token and store it in the session."""
    if CSRF_TOKEN_KEY not in session:
        session[CSRF_TOKEN_KEY] = secrets.token_hex(32)
    return str(session[CSRF_TOKEN_KEY])


def validate_csrf_token() -> bool:
    """Validate the CSRF token from the form."""
    form_token = request.form.get("csrf_token")
    session_token = session.get(CSRF_TOKEN_KEY)
    if not form_token or not session_token:
        return False
    return secrets.compare_digest(form_token, session_token)


def login_required(f: Callable[..., Any]) -> Callable[..., Any]:
    """Decorator to require authentication for a route."""
    @wraps(f)
    def decorated_function(*args: Any, **kwargs: Any) -> Any:
        if not is_auth_enabled():
            return f(*args, **kwargs)

        auth_manager = get_auth_manager()

        # Check if setup is required
        if auth_manager.is_setup_required():
            return redirect(url_for("auth.setup"))

        # Check for valid session
        token = session.get(SESSION_TOKEN_KEY)
        if not token:
            return redirect(url_for("auth.login", next=request.url))

        session_info = auth_manager.validate_session(token)
        if not session_info:
            session.pop(SESSION_TOKEN_KEY, None)
            return redirect(url_for("auth.login", next=request.url))

        # Store session info in g for access in route
        g.session_info = session_info
        return f(*args, **kwargs)

    return decorated_function


@auth_bp.route("/login", methods=["GET", "POST"])
def login() -> str | WerkzeugResponse:
    """Handle login page and authentication."""
    if not is_auth_enabled():
        return redirect(url_for("main.index"))

    auth_manager = get_auth_manager()

    # Redirect to setup if needed
    if auth_manager.is_setup_required():
        return redirect(url_for("auth.setup"))

    # Check if already logged in
    token = session.get(SESSION_TOKEN_KEY)
    if token and auth_manager.validate_session(token, update_activity=False):
        next_url = request.args.get("next", url_for("main.index"))
        return redirect(next_url)

    error = None
    next_url = request.args.get("next", "")

    if request.method == "POST":
        if not validate_csrf_token():
            error = "Invalid request. Please try again."
        else:
            password = request.form.get("password", "")
            session_info = auth_manager.authenticate(password)

            if session_info:
                session[SESSION_TOKEN_KEY] = session_info.session_token
                # Regenerate CSRF token on login
                session.pop(CSRF_TOKEN_KEY, None)

                next_url = request.form.get("next", url_for("main.index"))
                if not next_url or not next_url.startswith("/"):
                    next_url = url_for("main.index")
                return redirect(next_url)
            else:
                error = "Invalid password. Please try again."

    return render_template(
        "login.html",
        error=error,
        csrf_token=generate_csrf_token(),
        next_url=next_url,
    )


@auth_bp.route("/logout", methods=["POST"])
def logout() -> WerkzeugResponse:
    """Handle logout."""
    if not is_auth_enabled():
        return redirect(url_for("main.index"))

    auth_manager = get_auth_manager()
    token = session.get(SESSION_TOKEN_KEY)

    if token:
        auth_manager.logout(token)
        session.pop(SESSION_TOKEN_KEY, None)

    # Clear CSRF token on logout
    session.pop(CSRF_TOKEN_KEY, None)

    return redirect(url_for("auth.login"))


@auth_bp.route("/setup", methods=["GET", "POST"])
def setup() -> str | WerkzeugResponse:
    """Handle first-run setup wizard."""
    if not is_auth_enabled():
        return redirect(url_for("main.index"))

    auth_manager = get_auth_manager()

    # Redirect if already set up
    if not auth_manager.is_setup_required():
        return redirect(url_for("auth.login"))

    error = None

    if request.method == "POST":
        if not validate_csrf_token():
            error = "Invalid request. Please try again."
        else:
            password = request.form.get("password", "")
            password_confirm = request.form.get("password_confirm", "")

            if len(password) < 8:
                error = "Password must be at least 8 characters long."
            elif password != password_confirm:
                error = "Passwords do not match."
            else:
                try:
                    auth_manager.setup_password(password)

                    # Auto-login after setup
                    session_info = auth_manager.authenticate(password)
                    if session_info:
                        session[SESSION_TOKEN_KEY] = session_info.session_token

                    return redirect(url_for("main.index"))
                except ValueError as e:
                    error = str(e)

    return render_template(
        "setup.html",
        error=error,
        csrf_token=generate_csrf_token(),
    )


def init_auth(app: Any) -> None:
    """Initialize authentication for the Flask app.

    Args:
        app: Flask application instance.
    """
    from authtest.core.auth import AuthManager
    from authtest.storage.database import get_database

    # Get configuration
    auth_enabled = app.config.get("AUTH_ENABLED", True)
    session_timeout = app.config.get("SESSION_TIMEOUT_MINUTES", 60)

    if auth_enabled:
        db = get_database()
        auth_manager = AuthManager(db, session_timeout_minutes=session_timeout)
        app.config["AUTH_MANAGER"] = auth_manager

    app.config["AUTH_ENABLED"] = auth_enabled

    # Register the blueprint
    app.register_blueprint(auth_bp)

    # Add before_request hook to protect all routes
    @app.before_request
    def check_authentication() -> WerkzeugResponse | None:
        """Check authentication before each request."""
        # Skip auth check if disabled
        if not app.config.get("AUTH_ENABLED", True):
            return None

        # Allow unauthenticated access to specific endpoints
        allowed_endpoints = {
            "auth.login",
            "auth.setup",
            "auth.logout",
            "main.health",
            "main.static",  # Static files
        }

        if request.endpoint in allowed_endpoints:
            return None

        # Allow static file access
        if request.endpoint and request.endpoint.endswith(".static"):
            return None

        auth_manager = app.config.get("AUTH_MANAGER")
        if not auth_manager:
            return None

        # Check if setup is required
        if auth_manager.is_setup_required():
            return redirect(url_for("auth.setup"))

        # Check for valid session
        token = session.get(SESSION_TOKEN_KEY)
        if not token:
            return redirect(url_for("auth.login", next=request.url))

        session_info = auth_manager.validate_session(token)
        if not session_info:
            session.pop(SESSION_TOKEN_KEY, None)
            return redirect(url_for("auth.login", next=request.url))

        # Store session info in g for access in routes
        g.session_info = session_info
        return None
