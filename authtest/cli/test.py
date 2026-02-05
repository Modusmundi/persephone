"""Test execution CLI commands."""

import click


@click.group()
def test() -> None:
    """Execute authentication flow tests."""
    pass


@test.command("saml")
@click.argument("flow_type", type=click.Choice(["sp-initiated", "idp-initiated", "slo"]))
@click.option("--idp", "-i", required=True, help="IdP configuration to use")
@click.option("--json", "output_json", is_flag=True, help="Output results as JSON")
def test_saml(flow_type: str, idp: str, _output_json: bool) -> None:
    """Execute a SAML authentication flow test."""
    click.echo(f"Testing SAML {flow_type} flow against IdP: {idp}")


@test.command("oidc")
@click.argument(
    "grant_type",
    type=click.Choice(["authorization-code", "authorization-code-pkce", "implicit", "client-credentials", "device-code"]),
)
@click.option("--idp", "-i", required=True, help="IdP configuration to use")
@click.option("--json", "output_json", is_flag=True, help="Output results as JSON")
def test_oidc(grant_type: str, idp: str, _output_json: bool) -> None:
    """Execute an OIDC authentication flow test."""
    click.echo(f"Testing OIDC {grant_type} flow against IdP: {idp}")
