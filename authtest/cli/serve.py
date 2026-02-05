"""Server CLI commands."""

from pathlib import Path

import click


@click.command()
@click.option(
    "--host",
    "-h",
    default=None,
    help="Host to bind to (default: from config or 127.0.0.1)",
)
@click.option(
    "--port",
    "-p",
    type=int,
    default=None,
    help="Port to bind to (default: from config or 8443)",
)
@click.option(
    "--no-tls",
    is_flag=True,
    help="Disable TLS (not recommended, required for OIDC)",
)
@click.option(
    "--cert",
    type=click.Path(exists=True, path_type=Path),  # type: ignore[type-var]
    help="Path to TLS certificate (PEM format)",
)
@click.option(
    "--key",
    type=click.Path(exists=True, path_type=Path),  # type: ignore[type-var]
    help="Path to TLS private key (PEM format)",
)
@click.option(
    "--debug",
    is_flag=True,
    help="Enable debug mode",
)
def serve(
    host: str | None,
    port: int | None,
    no_tls: bool,
    cert: Path | None,
    key: Path | None,
    debug: bool,
) -> None:
    """Start the AuthTest web server.

    By default, the server runs with HTTPS using an auto-generated self-signed
    certificate. Custom certificates can be provided via --cert and --key options
    or configured in config.yaml.

    Examples:

        # Start with auto-generated certificate
        authtest serve

        # Start on custom port
        authtest serve --port 9443

        # Use custom certificate
        authtest serve --cert /path/to/cert.pem --key /path/to/key.pem

        # Disable TLS (not recommended)
        authtest serve --no-tls
    """
    from authtest.app import run_server
    from authtest.core.config import load_config

    # Load config
    config = load_config()

    # Apply CLI overrides
    if no_tls:
        config.server.tls.enabled = False

    if cert:
        config.server.tls.cert_path = cert

    if key:
        config.server.tls.key_path = key

    if debug:
        config.server.debug = True

    # Validate cert/key pair
    if cert and not key:
        raise click.ClickException("--key is required when --cert is provided")
    if key and not cert:
        raise click.ClickException("--cert is required when --key is provided")

    # Run server
    run_server(app_config=config, host=host, port=port)
