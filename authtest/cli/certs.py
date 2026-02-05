"""Certificate management CLI commands."""

from pathlib import Path

import click


@click.group()
def certs() -> None:
    """Manage TLS certificates and keys.

    AuthTest uses TLS certificates for HTTPS, which is required for
    OAuth/OIDC authentication flows. By default, a self-signed certificate
    is auto-generated on first run.
    """
    pass


@certs.command("generate")
@click.option(
    "--type",
    "cert_type",
    type=click.Choice(["tls", "signing"]),
    default="tls",
    help="Certificate type (tls for server, signing for SAML)",
)
@click.option(
    "--common-name",
    "-cn",
    default="localhost",
    help="Common Name (CN) for the certificate",
)
@click.option(
    "--days",
    "-d",
    type=int,
    default=365,
    help="Days the certificate is valid",
)
@click.option(
    "--output",
    "-o",
    type=click.Path(path_type=Path),  # type: ignore[type-var]
    help="Output directory for certificate files",
)
@click.option(
    "--force",
    "-f",
    is_flag=True,
    help="Overwrite existing certificate files",
)
def certs_generate(
    cert_type: str,
    common_name: str,
    days: int,
    output: Path | None,
    force: bool,
) -> None:
    """Generate a new self-signed certificate.

    Creates a new RSA key pair and self-signed X.509 certificate.
    For TLS certificates, Subject Alternative Names (SANs) include
    localhost and 127.0.0.1 by default.

    Examples:

        # Generate default TLS certificate
        authtest certs generate

        # Generate with custom common name
        authtest certs generate --common-name myserver.local

        # Generate to specific directory
        authtest certs generate --output /path/to/certs

        # Generate SAML signing certificate
        authtest certs generate --type signing
    """
    from authtest.core.crypto import (
        DEFAULT_CERT_DIR,
        generate_private_key,
        generate_self_signed_certificate,
        get_certificate_info,
        save_certificate,
        save_private_key,
    )

    # Determine output paths
    output_dir = output or DEFAULT_CERT_DIR

    if cert_type == "tls":
        cert_path = output_dir / "server.crt"
        key_path = output_dir / "server.key"
    else:  # signing
        cert_path = output_dir / "signing.crt"
        key_path = output_dir / "signing.key"

    # Check for existing files
    if not force and (cert_path.exists() or key_path.exists()):
        raise click.ClickException(
            f"Certificate files already exist at {output_dir}. Use --force to overwrite."
        )

    click.echo(f"Generating {cert_type} certificate...")
    click.echo(f"  Common Name: {common_name}")
    click.echo(f"  Valid for: {days} days")
    click.echo("")

    # Generate key and certificate
    private_key = generate_private_key()
    cert = generate_self_signed_certificate(
        private_key,
        common_name=common_name,
        days_valid=days,
    )

    # Save files
    save_private_key(private_key, key_path)
    save_certificate(cert, cert_path)

    # Get certificate info for display
    info = get_certificate_info(cert)

    click.echo("Certificate generated successfully!")
    click.echo("")
    click.echo("Files created:")
    click.echo(f"  Certificate: {cert_path}")
    click.echo(f"  Private key: {key_path}")
    click.echo("")
    click.echo("Certificate details:")
    click.echo(f"  Subject: {info.subject}")
    click.echo(f"  Valid from: {info.not_before.strftime('%Y-%m-%d %H:%M:%S UTC')}")
    click.echo(f"  Valid until: {info.not_after.strftime('%Y-%m-%d %H:%M:%S UTC')}")
    click.echo(f"  Fingerprint (SHA-256): {info.fingerprint_sha256}")


@certs.command("import")
@click.argument("cert_path", type=click.Path(exists=True, path_type=Path))  # type: ignore[type-var]
@click.option(
    "--key",
    "-k",
    "key_path",
    type=click.Path(exists=True, path_type=Path),  # type: ignore[type-var]
    help="Private key path (PEM format)",
)
@click.option(
    "--password",
    "-p",
    help="Password for encrypted key or PKCS#12 file",
)
@click.option(
    "--name",
    "-n",
    default="imported",
    help="Name for the imported certificate",
)
@click.option(
    "--output",
    "-o",
    type=click.Path(path_type=Path),  # type: ignore[type-var]
    help="Output directory for converted files",
)
def certs_import(
    cert_path: Path,
    key_path: Path | None,
    password: str | None,
    name: str,
    output: Path | None,
) -> None:
    """Import an existing certificate.

    Supports PEM format certificates and PKCS#12 (.p12, .pfx) files.
    For PKCS#12 files, the certificate and key are extracted and saved
    as separate PEM files.

    Examples:

        # Import PEM certificate and key
        authtest certs import /path/to/cert.pem --key /path/to/key.pem

        # Import PKCS#12 file
        authtest certs import /path/to/cert.p12 --password mypassword

        # Import with custom name
        authtest certs import /path/to/cert.pem --key /path/to/key.pem --name production
    """
    from authtest.core.crypto import (
        DEFAULT_CERT_DIR,
        CertificateLoadError,
        KeyLoadError,
        get_certificate_info,
        load_certificate,
        load_pkcs12,
        load_private_key,
        save_certificate,
        save_private_key,
    )

    output_dir = output or DEFAULT_CERT_DIR
    password_bytes = password.encode() if password else None

    # Detect file type by extension
    suffix = cert_path.suffix.lower()

    if suffix in (".p12", ".pfx"):
        # PKCS#12 format
        click.echo(f"Importing PKCS#12 file: {cert_path}")

        try:
            private_key, cert, chain = load_pkcs12(cert_path, password_bytes)
        except CertificateLoadError as e:
            raise click.ClickException(str(e)) from None

        # Save extracted files
        out_cert_path = output_dir / f"{name}.crt"
        out_key_path = output_dir / f"{name}.key"

        save_certificate(cert, out_cert_path)
        save_private_key(private_key, out_key_path)

        if chain:
            # Save certificate chain
            chain_path = output_dir / f"{name}-chain.crt"
            chain_pem = b""
            for chain_cert in chain:
                from cryptography.hazmat.primitives import serialization

                chain_pem += chain_cert.public_bytes(serialization.Encoding.PEM)
            chain_path.write_bytes(chain_pem)
            click.echo(f"  Certificate chain: {chain_path}")

    else:
        # PEM format
        if not key_path:
            raise click.ClickException(
                "Private key path (--key) is required for PEM certificates"
            )

        click.echo(f"Importing PEM certificate: {cert_path}")
        click.echo(f"Importing PEM private key: {key_path}")

        try:
            cert = load_certificate(cert_path)
        except CertificateLoadError as e:
            raise click.ClickException(str(e)) from None

        try:
            private_key = load_private_key(key_path, password_bytes)
        except KeyLoadError as e:
            raise click.ClickException(str(e)) from None

        # Copy to output directory
        out_cert_path = output_dir / f"{name}.crt"
        out_key_path = output_dir / f"{name}.key"

        save_certificate(cert, out_cert_path)
        save_private_key(private_key, out_key_path)

    # Display info
    info = get_certificate_info(cert)

    click.echo("")
    click.echo("Certificate imported successfully!")
    click.echo("")
    click.echo("Files created:")
    click.echo(f"  Certificate: {out_cert_path}")
    click.echo(f"  Private key: {out_key_path}")
    click.echo("")
    click.echo("Certificate details:")
    click.echo(f"  Subject: {info.subject}")
    click.echo(f"  Issuer: {info.issuer}")
    click.echo(f"  Self-signed: {info.is_self_signed}")
    click.echo(f"  Valid from: {info.not_before.strftime('%Y-%m-%d %H:%M:%S UTC')}")
    click.echo(f"  Valid until: {info.not_after.strftime('%Y-%m-%d %H:%M:%S UTC')}")


@certs.command("list")
@click.option(
    "--dir",
    "-d",
    "cert_dir",
    type=click.Path(exists=True, path_type=Path),  # type: ignore[type-var]
    help="Certificate directory to list",
)
def certs_list(cert_dir: Path | None) -> None:
    """List all managed certificates.

    Shows certificates in the default certificate directory or
    a specified directory.
    """
    from authtest.core.crypto import (
        DEFAULT_CERT_DIR,
        CertificateLoadError,
        get_certificate_info,
        is_certificate_valid,
        load_certificate,
    )

    search_dir = cert_dir or DEFAULT_CERT_DIR

    if not search_dir.exists():
        click.echo(f"Certificate directory does not exist: {search_dir}")
        return

    # Find all .crt and .pem files
    cert_files = list(search_dir.glob("*.crt")) + list(search_dir.glob("*.pem"))

    if not cert_files:
        click.echo(f"No certificates found in: {search_dir}")
        return

    click.echo(f"Certificates in {search_dir}:")
    click.echo("")

    for cert_file in sorted(cert_files):
        try:
            cert = load_certificate(cert_file)
            info = get_certificate_info(cert)
            valid = is_certificate_valid(cert)

            status = "VALID" if valid else "EXPIRED"
            status_color = "green" if valid else "red"

            click.echo(f"  {cert_file.name}")
            click.echo(f"    Subject: {info.subject}")
            click.echo(f"    Expires: {info.not_after.strftime('%Y-%m-%d')}")
            click.echo(click.style(f"    Status: {status}", fg=status_color))
            click.echo("")

        except CertificateLoadError:
            click.echo(f"  {cert_file.name}")
            click.echo(click.style("    Status: INVALID (could not load)", fg="red"))
            click.echo("")


@certs.command("inspect")
@click.argument("cert_path", type=click.Path(exists=True, path_type=Path))  # type: ignore[type-var]
def certs_inspect(cert_path: Path) -> None:
    """Inspect a certificate's details.

    Shows detailed information about an X.509 certificate including
    subject, issuer, validity period, extensions, and fingerprints.
    """
    from cryptography import x509

    from authtest.core.crypto import (
        CertificateLoadError,
        get_certificate_info,
        is_certificate_valid,
        load_certificate,
    )

    try:
        cert = load_certificate(cert_path)
    except CertificateLoadError as e:
        raise click.ClickException(str(e)) from None

    info = get_certificate_info(cert)
    valid = is_certificate_valid(cert)

    click.echo(f"Certificate: {cert_path}")
    click.echo("")
    click.echo("Subject Information:")
    click.echo(f"  Subject: {info.subject}")
    click.echo(f"  Issuer: {info.issuer}")
    click.echo(f"  Self-signed: {info.is_self_signed}")
    click.echo("")
    click.echo("Validity Period:")
    click.echo(f"  Not Before: {info.not_before.strftime('%Y-%m-%d %H:%M:%S UTC')}")
    click.echo(f"  Not After: {info.not_after.strftime('%Y-%m-%d %H:%M:%S UTC')}")

    status = "VALID" if valid else "EXPIRED"
    status_color = "green" if valid else "red"
    click.echo(click.style(f"  Status: {status}", fg=status_color))

    click.echo("")
    click.echo("Key Information:")
    click.echo(f"  Key Type: {info.key_type}")
    click.echo(f"  Key Size: {info.key_size} bits")
    click.echo("")
    click.echo("Fingerprints:")
    click.echo(f"  SHA-256: {info.fingerprint_sha256}")
    click.echo(f"  Serial Number: {info.serial_number}")

    # Show Subject Alternative Names if present
    try:
        san_ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        san_names = san_ext.value
        click.echo("")
        click.echo("Subject Alternative Names:")
        for name in san_names:
            if isinstance(name, x509.DNSName):
                click.echo(f"  DNS: {name.value}")
            elif isinstance(name, x509.IPAddress):
                click.echo(f"  IP: {name.value}")
    except x509.ExtensionNotFound:
        pass


@certs.command("status")
def certs_status() -> None:
    """Show TLS certificate status for the server.

    Displays the current TLS configuration and certificate status.
    """
    from authtest.core.config import load_config
    from authtest.core.crypto import (
        CertificateLoadError,
        get_cert_path,
        get_certificate_info,
        get_key_path,
        is_certificate_valid,
        load_certificate,
    )

    config = load_config()
    tls = config.server.tls

    click.echo("TLS Configuration:")
    click.echo(f"  Enabled: {tls.enabled}")
    click.echo(f"  Auto-generate: {tls.auto_generate}")
    click.echo("")

    # Get effective paths
    cert_path = tls.cert_path or get_cert_path()
    key_path = tls.key_path or get_key_path()

    click.echo("Certificate Paths:")
    click.echo(f"  Certificate: {cert_path}")
    click.echo(f"  Private Key: {key_path}")
    click.echo("")

    # Check if files exist
    cert_exists = cert_path.exists()
    key_exists = key_path.exists()

    click.echo("File Status:")
    click.echo(f"  Certificate exists: {cert_exists}")
    click.echo(f"  Private key exists: {key_exists}")

    if cert_exists:
        click.echo("")
        try:
            cert = load_certificate(cert_path)
            info = get_certificate_info(cert)
            valid = is_certificate_valid(cert)

            click.echo("Certificate Details:")
            click.echo(f"  Subject: {info.subject}")
            click.echo(f"  Expires: {info.not_after.strftime('%Y-%m-%d %H:%M:%S UTC')}")

            status = "VALID" if valid else "EXPIRED"
            status_color = "green" if valid else "red"
            click.echo(click.style(f"  Status: {status}", fg=status_color))

            if info.is_self_signed:
                click.echo(click.style("  Self-signed: Yes", fg="yellow"))

        except CertificateLoadError as e:
            click.echo(click.style(f"  Error loading certificate: {e}", fg="red"))
    elif tls.auto_generate:
        click.echo("")
        click.echo(
            "Note: Certificate will be auto-generated when the server starts."
        )
