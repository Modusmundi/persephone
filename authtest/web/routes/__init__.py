"""Web routes for AuthTest."""

from pathlib import Path

from flask import Blueprint, Flask, render_template

# Get the templates directory relative to this package
_templates_dir = Path(__file__).parent.parent / "templates"

main_bp = Blueprint("main", __name__, template_folder=str(_templates_dir))


@main_bp.route("/")
def index() -> str:
    """Render the main dashboard."""
    return render_template("index.html")


@main_bp.route("/health")
def health() -> dict:
    """Health check endpoint."""
    return {"status": "healthy"}


def init_app(app: Flask) -> None:
    """Register blueprints with the Flask app."""
    app.register_blueprint(main_bp)
