"""Database management CLI commands."""

from __future__ import annotations

from pathlib import Path

import click


@click.group()
def db() -> None:
    """Manage AuthTest database."""
    pass


@db.command("init")
@click.option(
    "--db-path",
    type=click.Path(path_type=Path),  # type: ignore[type-var]
    help="Path to database file. Defaults to ~/.authtest/authtest.db",
)
@click.option(
    "--key-path",
    type=click.Path(path_type=Path),  # type: ignore[type-var]
    help="Path to encryption key file. Defaults to ~/.authtest/db.key",
)
@click.option(
    "--force",
    is_flag=True,
    help="Overwrite existing database and key files.",
)
def db_init(db_path: Path | None, key_path: Path | None, force: bool) -> None:
    """Initialize encrypted database with a new encryption key.

    This command:
    1. Generates a new AES-256 encryption key
    2. Saves the key to a secure file
    3. Creates the encrypted SQLCipher database
    4. Initializes the database schema
    """
    from authtest.storage import (
        DEFAULT_DB_PATH,
        DEFAULT_KEY_PATH,
        Database,
        generate_encryption_key,
        save_encryption_key,
    )

    db_path = db_path or DEFAULT_DB_PATH
    key_path = key_path or DEFAULT_KEY_PATH

    # Check for existing files
    if not force:
        if key_path.exists():
            raise click.ClickException(
                f"Key file already exists: {key_path}\n"
                "Use --force to overwrite (this will make existing database unreadable)"
            )
        if db_path.exists():
            raise click.ClickException(
                f"Database already exists: {db_path}\n"
                "Use --force to overwrite"
            )

    # Generate and save encryption key
    click.echo("Generating AES-256 encryption key...")
    key = generate_encryption_key()
    saved_path = save_encryption_key(key, key_path)
    click.echo(f"Encryption key saved to: {saved_path}")
    click.echo("Key file permissions: 0600 (owner read/write only)")

    # Remove existing database if force
    if force and db_path.exists():
        db_path.unlink()
        click.echo(f"Removed existing database: {db_path}")

    # Initialize database
    click.echo(f"Creating encrypted database at: {db_path}")
    database = Database(db_path=db_path)
    database.init_db()
    database.verify_connection()
    database.close()

    click.echo("")
    click.echo("Database initialized successfully!")
    click.echo("")
    click.echo("Important: Keep your encryption key safe!")
    click.echo(f"  Key file: {key_path}")
    click.echo(f"  Database: {db_path}")
    click.echo("")
    click.echo("You can also set the key via environment variable:")
    click.echo("  export AUTHTEST_DB_KEY=<key>")


@db.command("verify")
@click.option(
    "--db-path",
    type=click.Path(path_type=Path, exists=True),  # type: ignore[type-var]
    help="Path to database file.",
)
def db_verify(db_path: Path | None) -> None:
    """Verify database connection and encryption.

    Tests that the database can be opened with the current encryption key.
    """
    from authtest.storage import Database, DatabaseError, KeyNotFoundError

    try:
        database = Database(db_path=db_path)
        database.verify_connection()
        click.echo("Database connection verified successfully.")
        database.close()
    except KeyNotFoundError as e:
        raise click.ClickException(str(e)) from None
    except DatabaseError as e:
        raise click.ClickException(f"Database verification failed: {e}") from None


@db.command("migrate")
@click.option(
    "--db-path",
    type=click.Path(path_type=Path, exists=True),  # type: ignore[type-var]
    help="Path to database file.",
)
@click.option(
    "--target",
    help="Target migration version. Defaults to latest.",
)
def db_migrate(db_path: Path | None, target: str | None) -> None:
    """Apply pending database migrations."""
    from authtest.storage import Database, KeyNotFoundError
    from authtest.storage.migrations import MigrationManager

    try:
        database = Database(db_path=db_path)
        manager = MigrationManager(database)

        pending = manager.get_pending_migrations()
        if not pending:
            click.echo("Database is up to date. No migrations to apply.")
            database.close()
            return

        click.echo(f"Pending migrations: {', '.join(pending)}")
        applied = manager.upgrade(target)

        if applied:
            click.echo(f"Applied migrations: {', '.join(applied)}")
        else:
            click.echo("No migrations applied.")

        database.close()
    except KeyNotFoundError as e:
        raise click.ClickException(str(e)) from None


@db.command("rollback")
@click.option(
    "--db-path",
    type=click.Path(path_type=Path, exists=True),  # type: ignore[type-var]
    help="Path to database file.",
)
@click.option(
    "--target",
    help="Target migration version to rollback to.",
)
def db_rollback(db_path: Path | None, target: str | None) -> None:
    """Rollback database migrations."""
    from authtest.storage import Database, KeyNotFoundError
    from authtest.storage.migrations import MigrationManager

    try:
        database = Database(db_path=db_path)
        manager = MigrationManager(database)

        current = manager.get_current_version()
        if not current:
            click.echo("No migrations to rollback.")
            database.close()
            return

        click.echo(f"Current version: {current}")
        reverted = manager.downgrade(target)

        if reverted:
            click.echo(f"Reverted migrations: {', '.join(reverted)}")
        else:
            click.echo("No migrations reverted.")

        database.close()
    except KeyNotFoundError as e:
        raise click.ClickException(str(e)) from None


@db.command("status")
@click.option(
    "--db-path",
    type=click.Path(path_type=Path, exists=True),  # type: ignore[type-var]
    help="Path to database file.",
)
def db_status(db_path: Path | None) -> None:
    """Show database migration status."""
    from authtest.storage import Database, KeyNotFoundError
    from authtest.storage.migrations import MigrationManager

    try:
        database = Database(db_path=db_path)
        manager = MigrationManager(database)

        current = manager.get_current_version()
        applied = manager.get_applied_migrations()
        pending = manager.get_pending_migrations()

        click.echo(f"Current version: {current or '(none)'}")
        click.echo(f"Applied migrations: {len(applied)}")
        if applied:
            for v in applied:
                click.echo(f"  - {v}")

        click.echo(f"Pending migrations: {len(pending)}")
        if pending:
            for v in pending:
                click.echo(f"  - {v}")

        database.close()
    except KeyNotFoundError as e:
        raise click.ClickException(str(e)) from None


@db.command("rotate-key")
@click.option(
    "--db-path",
    type=click.Path(path_type=Path, exists=True),  # type: ignore[type-var]
    required=True,
    help="Path to database file.",
)
@click.option(
    "--old-key",
    prompt=True,
    hide_input=True,
    help="Current encryption key.",
)
@click.option(
    "--new-key",
    help="New encryption key. If not provided, a new key will be generated.",
)
@click.option(
    "--save-key",
    type=click.Path(path_type=Path),  # type: ignore[type-var]
    help="Path to save the new key file.",
)
def db_rotate_key(
    db_path: Path,
    old_key: str,
    new_key: str | None,
    save_key: Path | None,
) -> None:
    """Rotate database encryption key.

    Re-encrypts the database with a new key. This operation requires
    exclusive access to the database - ensure no other processes are
    accessing it.

    WARNING: If the operation fails mid-way, the database may become
    corrupted. Always backup your database before key rotation.
    """
    from authtest.storage import (
        KeyRotationError,
        generate_encryption_key,
        rotate_encryption_key,
        save_encryption_key,
    )

    # Generate new key if not provided
    if not new_key:
        new_key = generate_encryption_key()
        click.echo("Generated new encryption key.")

    click.echo(f"Rotating encryption key for: {db_path}")
    click.echo("WARNING: Ensure you have a backup of your database!")

    if not click.confirm("Continue with key rotation?"):
        raise click.Abort()

    try:
        rotate_encryption_key(db_path, old_key, new_key)
        click.echo("Key rotation completed successfully.")

        # Save new key if requested
        if save_key:
            save_encryption_key(new_key, save_key)
            click.echo(f"New key saved to: {save_key}")
        else:
            click.echo("")
            click.echo("New encryption key (save this securely):")
            click.echo(new_key)

    except KeyRotationError as e:
        raise click.ClickException(str(e)) from None


@db.command("generate-key")
def db_generate_key() -> None:
    """Generate a new AES-256 encryption key.

    Outputs a new random key that can be used for database encryption.
    """
    from authtest.storage import generate_encryption_key

    key = generate_encryption_key()
    click.echo(key)
