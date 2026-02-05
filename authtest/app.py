"""Flask application factory."""

from flask import Flask


def create_app(config: dict | None = None) -> Flask:
    """Create and configure the Flask application.

    Args:
        config: Optional configuration dictionary to override defaults.

    Returns:
        Configured Flask application instance.
    """
    app = Flask(__name__)

    # Default configuration
    app.config.from_mapping(
        SECRET_KEY="dev",
        DATABASE_PATH="~/.authtest/data.db",
    )

    if config:
        app.config.from_mapping(config)

    # Register blueprints
    from authtest.web import routes

    routes.init_app(app)

    return app
