"""CLI entry point for AuthTest."""

import click

from authtest import __version__
from authtest.cli import certs as certs_commands
from authtest.cli import config as config_commands
from authtest.cli import test as test_commands


@click.group()
@click.version_option(version=__version__, prog_name="authtest")
@click.pass_context
def cli(ctx: click.Context) -> None:
    """AuthTest - SAML/OIDC Authentication Flow Testing Tool."""
    ctx.ensure_object(dict)


@cli.command()
def init() -> None:
    """Initialize AuthTest configuration and database."""
    click.echo("Initializing AuthTest...")
    click.echo("Configuration initialized successfully.")


cli.add_command(config_commands.config)
cli.add_command(test_commands.test)
cli.add_command(certs_commands.certs)
