"""CLI entry point for AuthTest."""

import click

from authtest import __version__
from authtest.cli import certs as certs_commands
from authtest.cli import config as config_commands
from authtest.cli import db as db_commands
from authtest.cli import serve as serve_commands
from authtest.cli import test as test_commands


@click.group()
@click.version_option(version=__version__, prog_name="authtest")
@click.pass_context
def cli(ctx: click.Context) -> None:
    """AuthTest - SAML/OIDC Authentication Flow Testing Tool."""
    ctx.ensure_object(dict)


@cli.command()
@click.option(
    "--force",
    is_flag=True,
    help="Overwrite existing database and key files.",
)
def init(force: bool) -> None:
    """Initialize AuthTest configuration and database.

    This is a convenience command that runs 'authtest db init'.
    For more options, use the db subcommands directly.
    """
    from authtest.storage import (
        DEFAULT_DB_PATH,
        DEFAULT_KEY_PATH,
        Database,
        KeyNotFoundError,
        generate_encryption_key,
        save_encryption_key,
    )

    db_path = DEFAULT_DB_PATH
    key_path = DEFAULT_KEY_PATH

    # Check if already initialized
    if key_path.exists() and db_path.exists() and not force:
        click.echo("AuthTest is already initialized.")
        click.echo(f"  Database: {db_path}")
        click.echo(f"  Key file: {key_path}")
        click.echo("")
        click.echo("Use --force to reinitialize (WARNING: this will delete existing data)")
        return

    # Check if we need to generate a new key
    need_new_key = not key_path.exists() or force

    if need_new_key:
        click.echo("Generating AES-256 encryption key...")
        key = generate_encryption_key()
        save_encryption_key(key, key_path)
        click.echo(f"Encryption key saved to: {key_path}")

    # Remove existing database if force
    if force and db_path.exists():
        db_path.unlink()
        click.echo(f"Removed existing database: {db_path}")

    # Initialize database
    click.echo(f"Creating encrypted database at: {db_path}")
    try:
        database = Database(db_path=db_path)
        database.init_db()
        database.verify_connection()
        database.close()
    except KeyNotFoundError as e:
        raise click.ClickException(str(e)) from None

    click.echo("")
    click.echo("AuthTest initialized successfully!")
    click.echo("")
    click.echo("Next steps:")
    click.echo("  1. Run 'authtest config idp add <name>' to add an Identity Provider")
    click.echo("  2. Run 'authtest test saml' or 'authtest test oidc' to test authentication")


cli.add_command(config_commands.config)
cli.add_command(db_commands.db)
cli.add_command(test_commands.test)
cli.add_command(certs_commands.certs)
cli.add_command(serve_commands.serve)
