"""Web routes for AuthTest."""

from pathlib import Path

from flask import Blueprint, Flask, render_template

# Get the directories relative to this package
_web_dir = Path(__file__).parent.parent
_templates_dir = _web_dir / "templates"
_static_dir = _web_dir / "static"

main_bp = Blueprint(
    "main",
    __name__,
    template_folder=str(_templates_dir),
    static_folder=str(_static_dir),
    static_url_path="/assets",
)


@main_bp.route("/")
def index() -> str:
    """Render the main dashboard."""
    return render_template("index.html")


@main_bp.route("/health")
def health() -> dict[str, str]:
    """Health check endpoint (unauthenticated)."""
    return {"status": "healthy"}


def init_app(app: Flask) -> None:
    """Register blueprints with the Flask app."""
    from authtest.web.routes.certs import certs_bp
    from authtest.web.routes.oidc import oidc_bp
    from authtest.web.routes.saml import saml_bp

    app.register_blueprint(main_bp)
    app.register_blueprint(saml_bp)
    app.register_blueprint(oidc_bp)
    app.register_blueprint(certs_bp)
