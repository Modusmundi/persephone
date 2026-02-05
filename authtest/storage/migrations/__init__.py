"""Database migrations for AuthTest.

This module provides a simple migration system that works with SQLCipher
encrypted databases. Migrations are Python modules that define upgrade
and downgrade functions.
"""

from __future__ import annotations

import importlib
import pkgutil
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING, Protocol

from sqlalchemy import text

if TYPE_CHECKING:
    from sqlalchemy.orm import Session

    from authtest.storage.database import Database


class Migration(Protocol):
    """Protocol for migration modules."""

    version: str
    description: str

    def upgrade(self, session: Session) -> None:
        """Apply the migration."""
        ...

    def downgrade(self, session: Session) -> None:
        """Revert the migration."""
        ...


class MigrationManager:
    """Manages database migrations.

    Handles tracking and applying migrations in order, supporting
    both upgrades and downgrades.
    """

    def __init__(self, database: Database) -> None:
        """Initialize migration manager.

        Args:
            database: Database instance to manage migrations for.
        """
        self._db = database
        self._migrations: dict[str, Migration] = {}
        self._load_migrations()

    def _load_migrations(self) -> None:
        """Load all migration modules from the versions directory."""
        versions_path = Path(__file__).parent / "versions"
        if not versions_path.exists():
            return

        # Dynamically import all migration modules
        package_name = "authtest.storage.migrations.versions"
        try:
            importlib.import_module(package_name)
        except ImportError:
            return

        for _, module_name, _ in pkgutil.iter_modules([str(versions_path)]):
            if module_name.startswith("_"):
                continue
            try:
                module = importlib.import_module(f"{package_name}.{module_name}")
                if hasattr(module, "version") and hasattr(module, "upgrade"):
                    self._migrations[module.version] = module
            except ImportError:
                continue

    def _ensure_migration_table(self) -> None:
        """Ensure the migration history table exists."""
        with self._db.engine.connect() as conn:
            conn.execute(
                text("""
                CREATE TABLE IF NOT EXISTS migration_history (
                    id INTEGER PRIMARY KEY,
                    version VARCHAR(50) UNIQUE NOT NULL,
                    description VARCHAR(500),
                    applied_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
                """)
            )
            conn.commit()

    def get_applied_migrations(self) -> list[str]:
        """Get list of applied migration versions.

        Returns:
            List of version strings in order of application.
        """
        self._ensure_migration_table()
        with self._db.engine.connect() as conn:
            result = conn.execute(
                text("SELECT version FROM migration_history ORDER BY id")
            )
            return [row[0] for row in result]

    def get_pending_migrations(self) -> list[str]:
        """Get list of pending migration versions.

        Returns:
            List of version strings that haven't been applied yet.
        """
        applied = set(self.get_applied_migrations())
        all_versions = sorted(self._migrations.keys())
        return [v for v in all_versions if v not in applied]

    def apply_migration(self, version: str) -> None:
        """Apply a specific migration.

        Args:
            version: Version string of the migration to apply.

        Raises:
            ValueError: If migration version not found.
        """
        if version not in self._migrations:
            raise ValueError(f"Migration version not found: {version}")

        migration = self._migrations[version]
        session = self._db.get_session()

        try:
            migration.upgrade(session)

            # Record the migration
            session.execute(
                text(
                    "INSERT INTO migration_history (version, description, applied_at) "
                    "VALUES (:version, :description, :applied_at)"
                ),
                {
                    "version": version,
                    "description": getattr(migration, "description", ""),
                    "applied_at": datetime.now(UTC),
                },
            )
            session.commit()
        except Exception:
            session.rollback()
            raise
        finally:
            session.close()

    def revert_migration(self, version: str) -> None:
        """Revert a specific migration.

        Args:
            version: Version string of the migration to revert.

        Raises:
            ValueError: If migration version not found or has no downgrade.
        """
        if version not in self._migrations:
            raise ValueError(f"Migration version not found: {version}")

        migration = self._migrations[version]
        if not hasattr(migration, "downgrade"):
            raise ValueError(f"Migration {version} does not support downgrade")

        session = self._db.get_session()

        try:
            migration.downgrade(session)

            # Remove the migration record
            session.execute(
                text("DELETE FROM migration_history WHERE version = :version"),
                {"version": version},
            )
            session.commit()
        except Exception:
            session.rollback()
            raise
        finally:
            session.close()

    def upgrade(self, target_version: str | None = None) -> list[str]:
        """Apply all pending migrations up to target version.

        Args:
            target_version: Optional version to upgrade to. If None,
                applies all pending migrations.

        Returns:
            List of applied migration versions.
        """
        self._ensure_migration_table()
        pending = self.get_pending_migrations()

        if target_version:
            # Only apply up to target version
            try:
                idx = pending.index(target_version)
                pending = pending[: idx + 1]
            except ValueError:
                pass  # Target already applied or not found

        applied = []
        for version in pending:
            self.apply_migration(version)
            applied.append(version)
            if version == target_version:
                break

        return applied

    def downgrade(self, target_version: str | None = None) -> list[str]:
        """Revert migrations down to target version.

        Args:
            target_version: Version to downgrade to. If None,
                reverts only the latest migration.

        Returns:
            List of reverted migration versions.
        """
        applied = self.get_applied_migrations()
        if not applied:
            return []

        reverted = []
        for version in reversed(applied):
            if version == target_version:
                break
            self.revert_migration(version)
            reverted.append(version)
            if target_version is None:
                break  # Only revert one if no target specified

        return reverted

    def get_current_version(self) -> str | None:
        """Get the current migration version.

        Returns:
            The latest applied migration version, or None if no migrations.
        """
        applied = self.get_applied_migrations()
        return applied[-1] if applied else None
