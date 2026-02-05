"""Flask application factory."""

from __future__ import annotations

import os
import secrets
import ssl
from pathlib import Path
from typing import TYPE_CHECKING

from flask import Flask

if TYPE_CHECKING:
    from authtest.core.config import AppConfig


def create_app(config: dict | None = None) -> Flask:
    """Create and configure the Flask application.

    Args:
        config: Optional configuration dictionary to override defaults.

    Returns:
        Configured Flask application instance.
    """
    app = Flask(__name__)

    # Generate a secure secret key if not provided
    secret_key = os.environ.get("AUTHTEST_SECRET_KEY")
    if not secret_key:
        # Use a persistent secret key from the config directory
        key_path = Path.home() / ".authtest" / "flask_secret.key"
        if key_path.exists():
            secret_key = key_path.read_text().strip()
        else:
            secret_key = secrets.token_hex(32)
            key_path.parent.mkdir(parents=True, exist_ok=True)
            key_path.write_text(secret_key)
            key_path.chmod(0o600)

    # Default configuration
    app.config.from_mapping(
        SECRET_KEY=secret_key,
        DATABASE_PATH="~/.authtest/data.db",
        AUTH_ENABLED=True,
        SESSION_TIMEOUT_MINUTES=60,
    )

    if config:
        app.config.from_mapping(config)

    # Register main blueprints
    from authtest.web import routes

    routes.init_app(app)

    # Initialize authentication
    from authtest.web.routes.auth import init_auth

    init_auth(app)

    return app


def create_ssl_context(
    cert_path: Path,
    key_path: Path,
) -> ssl.SSLContext:
    """Create an SSL context for HTTPS.

    Args:
        cert_path: Path to the certificate file (PEM format).
        key_path: Path to the private key file (PEM format).

    Returns:
        Configured SSL context.
    """
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(str(cert_path), str(key_path))
    return context


def run_server(
    app_config: AppConfig | None = None,
    host: str | None = None,
    port: int | None = None,
) -> None:
    """Run the Flask development server with TLS support.

    Args:
        app_config: Application configuration. Loads from file/env if not provided.
        host: Override host from config.
        port: Override port from config.
    """
    from authtest.core.config import load_config
    from authtest.core.crypto import ensure_tls_certificate
    from authtest.storage.database import get_database

    # Load configuration
    if app_config is None:
        app_config = load_config()

    # Initialize database (ensures tables exist)
    db = get_database()
    db.init_db()

    # Apply overrides
    server_host = host or app_config.server.host
    server_port = port or app_config.server.port
    tls_settings = app_config.server.tls

    # Create Flask app with auth settings
    app = create_app({
        "AUTH_ENABLED": app_config.auth.enabled,
        "SESSION_TIMEOUT_MINUTES": app_config.auth.session_timeout_minutes,
    })
    app.debug = app_config.server.debug

    ssl_context: ssl.SSLContext | None = None

    if tls_settings.enabled:
        # Ensure TLS certificate exists
        tls_config = ensure_tls_certificate(
            cert_path=tls_settings.cert_path,
            key_path=tls_settings.key_path,
            common_name=tls_settings.common_name,
            days_valid=tls_settings.days_valid,
            regenerate=False,
        )

        ssl_context = create_ssl_context(tls_config.cert_path, tls_config.key_path)

        protocol = "https"
        if tls_config.auto_generated:
            print("Auto-generated self-signed TLS certificate:")
            print(f"  Certificate: {tls_config.cert_path}")
            print(f"  Private key: {tls_config.key_path}")
            print("")
    else:
        protocol = "http"
        print("WARNING: TLS is disabled. HTTPS is required for OAuth/OIDC.")
        print("")

    print("Starting AuthTest server...")
    print(f"  URL: {protocol}://{server_host}:{server_port}")
    print("")

    app.run(
        host=server_host,
        port=server_port,
        ssl_context=ssl_context,
    )
