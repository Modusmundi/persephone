"""Storage module for AuthTest.

Provides SQLCipher-encrypted database storage for configuration,
credentials, and test results.
"""

from authtest.storage.database import (
    DEFAULT_DB_PATH,
    DEFAULT_KEY_PATH,
    ENV_DB_KEY,
    ENV_DB_KEY_FILE,
    ENV_DB_PATH,
    Database,
    DatabaseError,
    KeyNotFoundError,
    KeyRotationError,
    create_database_engine,
    generate_encryption_key,
    get_database,
    get_database_path,
    get_encryption_key,
    init_database,
    rotate_encryption_key,
    save_encryption_key,
)
from authtest.storage.models import (
    AppSetting,
    Base,
    Certificate,
    ClientConfig,
    IdPProvider,
    IdPType,
    MigrationHistory,
    TestResult,
)

__all__ = [
    # Database management
    "Database",
    "DatabaseError",
    "KeyNotFoundError",
    "KeyRotationError",
    "create_database_engine",
    "get_database",
    "get_database_path",
    "get_encryption_key",
    "generate_encryption_key",
    "init_database",
    "rotate_encryption_key",
    "save_encryption_key",
    # Constants
    "DEFAULT_DB_PATH",
    "DEFAULT_KEY_PATH",
    "ENV_DB_KEY",
    "ENV_DB_KEY_FILE",
    "ENV_DB_PATH",
    # Models
    "Base",
    "AppSetting",
    "Certificate",
    "ClientConfig",
    "IdPProvider",
    "IdPType",
    "MigrationHistory",
    "TestResult",
]
