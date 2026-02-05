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
    config_path: Path | None = None

    @classmethod
    def from_dict(cls, data: dict[str, Any], config_path: Path | None = None) -> AppConfig:
        """Create AppConfig from a dictionary."""
        server_data = data.get("server", {})
        return cls(
            server=ServerSettings.from_dict(server_data) if server_data else ServerSettings(),
            config_path=config_path,
        )

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "server": self.server.to_dict(),
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
"""
