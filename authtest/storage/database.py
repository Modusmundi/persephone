"""SQLCipher database integration with AES-256 encryption."""

from __future__ import annotations

import os
import secrets
from pathlib import Path
from typing import TYPE_CHECKING

from sqlalchemy import Engine, create_engine, event, text
from sqlalchemy.orm import Session, sessionmaker

if TYPE_CHECKING:
    from sqlalchemy.engine.interfaces import DBAPIConnection
    from sqlalchemy.pool import ConnectionPoolEntry

# Default database location
DEFAULT_DB_DIR = Path.home() / ".authtest"
DEFAULT_DB_PATH = DEFAULT_DB_DIR / "authtest.db"
DEFAULT_KEY_PATH = DEFAULT_DB_DIR / "db.key"

# Environment variable names
ENV_DB_KEY = "AUTHTEST_DB_KEY"
ENV_DB_KEY_FILE = "AUTHTEST_DB_KEY_FILE"
ENV_DB_PATH = "AUTHTEST_DB_PATH"


class DatabaseError(Exception):
    """Base exception for database errors."""


class KeyNotFoundError(DatabaseError):
    """Raised when encryption key cannot be found."""


class KeyRotationError(DatabaseError):
    """Raised when key rotation fails."""


def get_encryption_key() -> str:
    """Get encryption key from environment variable or key file.

    Priority:
    1. AUTHTEST_DB_KEY environment variable (direct key)
    2. AUTHTEST_DB_KEY_FILE environment variable (path to key file)
    3. Default key file at ~/.authtest/db.key

    Returns:
        The encryption key as a hex string.

    Raises:
        KeyNotFoundError: If no key is found in any location.
    """
    # Check direct environment variable first
    key = os.environ.get(ENV_DB_KEY)
    if key:
        return key

    # Check key file path from environment
    key_file_path = os.environ.get(ENV_DB_KEY_FILE)
    if key_file_path:
        key_path = Path(key_file_path)
        if key_path.exists():
            return key_path.read_text().strip()
        raise KeyNotFoundError(f"Key file not found: {key_file_path}")

    # Check default key file location
    if DEFAULT_KEY_PATH.exists():
        return DEFAULT_KEY_PATH.read_text().strip()

    raise KeyNotFoundError(
        f"No encryption key found. Set {ENV_DB_KEY} environment variable, "
        f"set {ENV_DB_KEY_FILE} to point to a key file, "
        f"or create key file at {DEFAULT_KEY_PATH}"
    )


def generate_encryption_key() -> str:
    """Generate a new AES-256 encryption key.

    Returns:
        A 64-character hex string (256 bits).
    """
    return secrets.token_hex(32)


def save_encryption_key(key: str, key_path: Path | None = None) -> Path:
    """Save encryption key to a file with secure permissions.

    Args:
        key: The encryption key to save.
        key_path: Path to save the key. Defaults to ~/.authtest/db.key.

    Returns:
        The path where the key was saved.
    """
    if key_path is None:
        key_path = DEFAULT_KEY_PATH

    # Ensure parent directory exists
    key_path.parent.mkdir(parents=True, exist_ok=True)

    # Write key file with restricted permissions (owner read/write only)
    key_path.write_text(key)
    key_path.chmod(0o600)

    return key_path


def get_database_path() -> Path:
    """Get database path from environment or default.

    Returns:
        Path to the SQLCipher database file.
    """
    db_path = os.environ.get(ENV_DB_PATH)
    if db_path:
        return Path(db_path)
    return DEFAULT_DB_PATH


def _configure_sqlcipher(dbapi_connection: DBAPIConnection, _connection_record: ConnectionPoolEntry) -> None:
    """Configure SQLCipher connection with encryption key.

    This is called by SQLAlchemy's event system for each new connection.
    """
    key = get_encryption_key()
    cursor = dbapi_connection.cursor()
    # PRAGMA key must be the first statement after opening the database
    cursor.execute(f"PRAGMA key = \"x'{key}'\"")
    # Use AES-256 encryption (SQLCipher default, but explicit is better)
    cursor.execute("PRAGMA cipher_page_size = 4096")
    cursor.execute("PRAGMA kdf_iter = 256000")
    cursor.execute("PRAGMA cipher_hmac_algorithm = HMAC_SHA512")
    cursor.execute("PRAGMA cipher_kdf_algorithm = PBKDF2_HMAC_SHA512")
    cursor.close()


def create_database_engine(db_path: Path | None = None, echo: bool = False) -> Engine:
    """Create SQLAlchemy engine with SQLCipher encryption.

    Args:
        db_path: Path to the database file. Defaults to configured path.
        echo: Whether to echo SQL statements (for debugging).

    Returns:
        Configured SQLAlchemy Engine.
    """
    if db_path is None:
        db_path = get_database_path()

    # Ensure parent directory exists
    db_path.parent.mkdir(parents=True, exist_ok=True)

    # Use sqlcipher3 module as the driver
    connection_string = f"sqlite+pysqlcipher:///{db_path}"

    engine = create_engine(
        connection_string,
        echo=echo,
        pool_pre_ping=True,
    )

    # Register event listener to configure encryption on each connection
    event.listen(engine, "connect", _configure_sqlcipher)

    return engine


def create_session_factory(engine: Engine) -> sessionmaker[Session]:
    """Create a session factory for the given engine.

    Args:
        engine: SQLAlchemy engine.

    Returns:
        Session factory.
    """
    return sessionmaker(bind=engine, expire_on_commit=False)


class Database:
    """Database manager for AuthTest.

    Provides a high-level interface for database operations with
    SQLCipher encryption.
    """

    def __init__(self, db_path: Path | None = None, echo: bool = False) -> None:
        """Initialize database manager.

        Args:
            db_path: Path to the database file.
            echo: Whether to echo SQL statements.
        """
        self._db_path = db_path or get_database_path()
        self._engine: Engine | None = None
        self._session_factory: sessionmaker[Session] | None = None
        self._echo = echo

    @property
    def engine(self) -> Engine:
        """Get or create the database engine."""
        if self._engine is None:
            self._engine = create_database_engine(self._db_path, self._echo)
        return self._engine

    @property
    def session_factory(self) -> sessionmaker[Session]:
        """Get or create the session factory."""
        if self._session_factory is None:
            self._session_factory = create_session_factory(self.engine)
        return self._session_factory

    def get_session(self) -> Session:
        """Create a new database session.

        Returns:
            A new SQLAlchemy Session.
        """
        return self.session_factory()

    def init_db(self) -> None:
        """Initialize database schema.

        Creates all tables defined in the models.
        """
        from authtest.storage.models import Base

        Base.metadata.create_all(self.engine)

    def verify_connection(self) -> bool:
        """Verify database connection and encryption.

        Returns:
            True if connection is successful.

        Raises:
            DatabaseError: If connection or decryption fails.
        """
        try:
            with self.engine.connect() as conn:
                # Simple query to verify connection works
                result = conn.execute(text("SELECT 1"))
                result.fetchone()
            return True
        except Exception as e:
            raise DatabaseError(f"Database connection failed: {e}") from e

    def close(self) -> None:
        """Close database connections."""
        if self._engine is not None:
            self._engine.dispose()
            self._engine = None
            self._session_factory = None


def rotate_encryption_key(db_path: Path, old_key: str, new_key: str) -> None:
    """Rotate database encryption key.

    Re-encrypts the database with a new key. This operation requires
    exclusive access to the database.

    Args:
        db_path: Path to the database file.
        old_key: Current encryption key.
        new_key: New encryption key.

    Raises:
        KeyRotationError: If key rotation fails.
    """
    import sqlite3

    try:
        # Connect with the old key
        conn = sqlite3.connect(str(db_path))
        cursor = conn.cursor()

        # Decrypt with old key
        cursor.execute(f"PRAGMA key = \"x'{old_key}'\"")

        # Verify we can read the database
        cursor.execute("SELECT count(*) FROM sqlite_master")

        # Re-encrypt with new key
        cursor.execute(f"PRAGMA rekey = \"x'{new_key}'\"")

        conn.commit()
        conn.close()

    except Exception as e:
        raise KeyRotationError(f"Key rotation failed: {e}") from e


# Global database instance (lazy initialization)
_db: Database | None = None


def get_database() -> Database:
    """Get the global database instance.

    Returns:
        The Database singleton.
    """
    global _db
    if _db is None:
        _db = Database()
    return _db


def init_database(db_path: Path | None = None, echo: bool = False) -> Database:
    """Initialize the global database instance.

    Args:
        db_path: Path to the database file.
        echo: Whether to echo SQL statements.

    Returns:
        The initialized Database instance.
    """
    global _db
    _db = Database(db_path=db_path, echo=echo)
    return _db
