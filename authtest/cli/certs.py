"""Certificate management CLI commands."""

import click


@click.group()
def certs() -> None:
    """Manage certificates and keys."""
    pass


@certs.command("generate")
@click.option("--type", "cert_type", type=click.Choice(["tls", "signing"]), default="tls", help="Certificate type")
@click.option("--output", "-o", type=click.Path(), help="Output path for certificate")
def certs_generate(cert_type: str, _output: str | None) -> None:
    """Generate a new self-signed certificate."""
    click.echo(f"Generating {cert_type} certificate...")


@certs.command("import")
@click.argument("cert_path", type=click.Path(exists=True))
@click.option("--key", "-k", type=click.Path(exists=True), help="Private key path")
def certs_import(cert_path: str, _key: str | None) -> None:
    """Import an existing certificate."""
    click.echo(f"Importing certificate from: {cert_path}")


@certs.command("list")
def certs_list() -> None:
    """List all managed certificates."""
    click.echo("Listing certificates...")


@certs.command("inspect")
@click.argument("cert_name")
def certs_inspect(cert_name: str) -> None:
    """Inspect a certificate's details."""
    click.echo(f"Inspecting certificate: {cert_name}")
