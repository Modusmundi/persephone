"""Application configuration management.

Loads configuration from config.yaml files and environment variables.
Environment variables take precedence over config file settings.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

# Default config locations
DEFAULT_CONFIG_DIR = Path.home() / ".authtest"
DEFAULT_CONFIG_FILE = DEFAULT_CONFIG_DIR / "config.yaml"

# Environment variable prefix
ENV_PREFIX = "AUTHTEST_"


@dataclass
class LoggingSettings:
    """Protocol logging configuration settings."""

    level: str = "INFO"  # ERROR, INFO, DEBUG, TRACE
    trace_enabled: bool = False  # Must be explicitly enabled for sensitive data
    log_file: str | None = None  # Optional file path for protocol logs

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> LoggingSettings:
        """Create LoggingSettings from a dictionary."""
        return cls(
            level=data.get("level", "INFO"),
            trace_enabled=data.get("trace_enabled", False),
            log_file=data.get("log_file"),
        )

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "level": self.level,
            "trace_enabled": self.trace_enabled,
            "log_file": self.log_file,
        }


@dataclass
class TLSSettings:
    """TLS/HTTPS configuration settings."""

    enabled: bool = True
    cert_path: Path | None = None
    key_path: Path | None = None
    auto_generate: bool = True
    common_name: str = "localhost"
    days_valid: int = 365

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> TLSSettings:
        """Create TLSSettings from a dictionary."""
        return cls(
            enabled=data.get("enabled", True),
            cert_path=Path(data["cert_path"]) if data.get("cert_path") else None,
            key_path=Path(data["key_path"]) if data.get("key_path") else None,
            auto_generate=data.get("auto_generate", True),
            common_name=data.get("common_name", "localhost"),
            days_valid=data.get("days_valid", 365),
        )

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "enabled": self.enabled,
            "cert_path": str(self.cert_path) if self.cert_path else None,
            "key_path": str(self.key_path) if self.key_path else None,
            "auto_generate": self.auto_generate,
            "common_name": self.common_name,
            "days_valid": self.days_valid,
        }


@dataclass
class AuthSettings:
    """Authentication configuration settings."""

    enabled: bool = True
    session_timeout_minutes: int = 60

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> AuthSettings:
        """Create AuthSettings from a dictionary."""
        return cls(
            enabled=data.get("enabled", True),
            session_timeout_minutes=data.get("session_timeout_minutes", 60),
        )

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "enabled": self.enabled,
            "session_timeout_minutes": self.session_timeout_minutes,
        }


@dataclass
class ServerSettings:
    """Server configuration settings."""

    host: str = "127.0.0.1"
    port: int = 8443
    debug: bool = False
    tls: TLSSettings = field(default_factory=TLSSettings)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ServerSettings:
        """Create ServerSettings from a dictionary."""
        tls_data = data.get("tls", {})
        return cls(
            host=data.get("host", "127.0.0.1"),
            port=data.get("port", 8443),
            debug=data.get("debug", False),
            tls=TLSSettings.from_dict(tls_data) if tls_data else TLSSettings(),
        )

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "host": self.host,
            "port": self.port,
            "debug": self.debug,
            "tls": self.tls.to_dict(),
        }


@dataclass
class AppConfig:
    """Main application configuration."""

    server: ServerSettings = field(default_factory=ServerSettings)
    auth: AuthSettings = field(default_factory=AuthSettings)
    logging: LoggingSettings = field(default_factory=LoggingSettings)
    config_path: Path | None = None

    @classmethod
    def from_dict(cls, data: dict[str, Any], config_path: Path | None = None) -> AppConfig:
        """Create AppConfig from a dictionary."""
        server_data = data.get("server", {})
        auth_data = data.get("auth", {})
        logging_data = data.get("logging", {})
        return cls(
            server=ServerSettings.from_dict(server_data) if server_data else ServerSettings(),
            auth=AuthSettings.from_dict(auth_data) if auth_data else AuthSettings(),
            logging=LoggingSettings.from_dict(logging_data) if logging_data else LoggingSettings(),
            config_path=config_path,
        )

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "server": self.server.to_dict(),
            "auth": self.auth.to_dict(),
            "logging": self.logging.to_dict(),
        }

    def save(self, path: Path | None = None) -> None:
        """Save configuration to a YAML file.

        Args:
            path: Path to save to. Uses config_path or default if not specified.
        """
        save_path = path or self.config_path or DEFAULT_CONFIG_FILE
        save_path.parent.mkdir(parents=True, exist_ok=True)

        with open(save_path, "w") as f:
            yaml.safe_dump(self.to_dict(), f, default_flow_style=False)


def _get_env_bool(key: str, default: bool) -> bool:
    """Get a boolean from environment variable."""
    value = os.environ.get(key)
    if value is None:
        return default
    return value.lower() in ("true", "1", "yes", "on")


def _get_env_int(key: str, default: int) -> int:
    """Get an integer from environment variable."""
    value = os.environ.get(key)
    if value is None:
        return default
    try:
        return int(value)
    except ValueError:
        return default


def load_config(config_path: Path | None = None) -> AppConfig:
    """Load application configuration.

    Configuration is loaded in this order (later values override earlier):
    1. Default values
    2. config.yaml file (if exists)
    3. Environment variables

    Args:
        config_path: Path to config file. Uses default if not specified.

    Returns:
        AppConfig with merged settings.
    """
    # Start with defaults
    config = AppConfig()

    # Try to load from config file
    file_path = config_path or DEFAULT_CONFIG_FILE
    if file_path.exists():
        try:
            with open(file_path) as f:
                data = yaml.safe_load(f) or {}
            config = AppConfig.from_dict(data, config_path=file_path)
        except Exception:
            # If config file is invalid, use defaults
            pass

    # Override with environment variables
    # Server settings
    if os.environ.get(f"{ENV_PREFIX}HOST"):
        config.server.host = os.environ[f"{ENV_PREFIX}HOST"]

    if os.environ.get(f"{ENV_PREFIX}PORT"):
        config.server.port = _get_env_int(f"{ENV_PREFIX}PORT", config.server.port)

    config.server.debug = _get_env_bool(f"{ENV_PREFIX}DEBUG", config.server.debug)

    # TLS settings
    tls = config.server.tls

    tls.enabled = _get_env_bool(f"{ENV_PREFIX}TLS_ENABLED", tls.enabled)

    if os.environ.get(f"{ENV_PREFIX}TLS_CERT"):
        tls.cert_path = Path(os.environ[f"{ENV_PREFIX}TLS_CERT"])

    if os.environ.get(f"{ENV_PREFIX}TLS_KEY"):
        tls.key_path = Path(os.environ[f"{ENV_PREFIX}TLS_KEY"])

    tls.auto_generate = _get_env_bool(f"{ENV_PREFIX}TLS_AUTO_GENERATE", tls.auto_generate)

    if os.environ.get(f"{ENV_PREFIX}TLS_COMMON_NAME"):
        tls.common_name = os.environ[f"{ENV_PREFIX}TLS_COMMON_NAME"]

    if os.environ.get(f"{ENV_PREFIX}TLS_DAYS_VALID"):
        tls.days_valid = _get_env_int(f"{ENV_PREFIX}TLS_DAYS_VALID", tls.days_valid)

    # Auth settings
    auth = config.auth
    auth.enabled = _get_env_bool(f"{ENV_PREFIX}AUTH_ENABLED", auth.enabled)

    if os.environ.get(f"{ENV_PREFIX}SESSION_TIMEOUT"):
        auth.session_timeout_minutes = _get_env_int(
            f"{ENV_PREFIX}SESSION_TIMEOUT", auth.session_timeout_minutes
        )

    # Logging settings
    logging_settings = config.logging
    if os.environ.get(f"{ENV_PREFIX}LOG_LEVEL"):
        logging_settings.level = os.environ[f"{ENV_PREFIX}LOG_LEVEL"]

    logging_settings.trace_enabled = _get_env_bool(
        f"{ENV_PREFIX}TRACE_ENABLED", logging_settings.trace_enabled
    )

    if os.environ.get(f"{ENV_PREFIX}LOG_FILE"):
        logging_settings.log_file = os.environ[f"{ENV_PREFIX}LOG_FILE"]

    return config


def get_default_config_yaml() -> str:
    """Get the default config.yaml content as a string.

    Useful for generating example configuration files.
    """
    return """\
# AuthTest Configuration File
# Environment variables override these settings (prefix: AUTHTEST_)

server:
  # Server bind address
  host: "127.0.0.1"

  # Server port (HTTPS)
  port: 8443

  # Enable debug mode (not recommended for production)
  debug: false

  # TLS/HTTPS settings
  tls:
    # Enable HTTPS (required for OAuth/OIDC callbacks)
    enabled: true

    # Path to TLS certificate (PEM format)
    # If not specified and auto_generate is true, a self-signed cert will be created
    # cert_path: ~/.authtest/certs/server.crt

    # Path to TLS private key (PEM format)
    # key_path: ~/.authtest/certs/server.key

    # Auto-generate self-signed certificate if none provided
    auto_generate: true

    # Common name for auto-generated certificate
    common_name: "localhost"

    # Days the auto-generated certificate is valid
    days_valid: 365

# Authentication settings
auth:
  # Enable password protection for the application
  # Set to false for local-only deployments that don't need authentication
  enabled: true

  # Session timeout in minutes
  # After this time of inactivity, users must log in again
  session_timeout_minutes: 60

# Protocol logging settings
logging:
  # Log level: ERROR, INFO, DEBUG, TRACE
  # - ERROR: Only log errors
  # - INFO: Log flow milestones (requests initiated, responses received)
  # - DEBUG: Log HTTP details (headers, status codes, timing)
  # - TRACE: Log full request/response bodies (requires trace_enabled: true)
  level: "INFO"

  # Enable TRACE level logging for sensitive data (tokens, secrets)
  # WARNING: Setting this to true will log sensitive authentication data!
  # Only enable for debugging in secure environments
  trace_enabled: false

  # Optional file path to write protocol logs
  # log_file: ~/.authtest/protocol.log
"""
