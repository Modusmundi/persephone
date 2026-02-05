"""SQLAlchemy 2.x ORM models for AuthTest configuration data."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any

from sqlalchemy import JSON, DateTime, ForeignKey, String, Text, func
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


class Base(DeclarativeBase):
    """Base class for all ORM models."""

    type_annotation_map = {
        dict[str, Any]: JSON,
    }


class IdPType(StrEnum):
    """Identity Provider types."""

    SAML = "saml"
    OIDC = "oidc"


class IdPProvider(Base):
    """Identity Provider configuration.

    Stores SAML and OIDC IdP configurations including metadata,
    endpoints, and credentials.
    """

    __tablename__ = "idp_providers"

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(255), unique=True, nullable=False)
    display_name: Mapped[str | None] = mapped_column(String(255))
    idp_type: Mapped[str] = mapped_column(String(50), nullable=False)
    enabled: Mapped[bool] = mapped_column(default=True)

    # Common settings (stored as JSON for flexibility)
    settings: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)

    # SAML-specific fields
    entity_id: Mapped[str | None] = mapped_column(String(500))
    sso_url: Mapped[str | None] = mapped_column(String(500))
    slo_url: Mapped[str | None] = mapped_column(String(500))
    metadata_url: Mapped[str | None] = mapped_column(String(500))
    metadata_xml: Mapped[str | None] = mapped_column(Text)
    x509_cert: Mapped[str | None] = mapped_column(Text)

    # OIDC-specific fields
    issuer: Mapped[str | None] = mapped_column(String(500))
    authorization_endpoint: Mapped[str | None] = mapped_column(String(500))
    token_endpoint: Mapped[str | None] = mapped_column(String(500))
    userinfo_endpoint: Mapped[str | None] = mapped_column(String(500))
    jwks_uri: Mapped[str | None] = mapped_column(String(500))

    # Timestamps
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )

    # Relationships
    client_configs: Mapped[list[ClientConfig]] = relationship(
        back_populates="idp_provider", cascade="all, delete-orphan"
    )
    test_results: Mapped[list[TestResult]] = relationship(
        back_populates="idp_provider", cascade="all, delete-orphan"
    )

    def __repr__(self) -> str:
        return f"<IdPProvider(name='{self.name}', type='{self.idp_type}')>"


class ClientConfig(Base):
    """Client/SP configuration for authentication testing.

    Stores client credentials, certificates, and configuration for
    both SAML Service Providers and OIDC clients.
    """

    __tablename__ = "client_configs"

    id: Mapped[int] = mapped_column(primary_key=True)
    idp_provider_id: Mapped[int] = mapped_column(
        ForeignKey("idp_providers.id"), nullable=False
    )
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    client_type: Mapped[str] = mapped_column(String(50), nullable=False)

    # Client credentials (encrypted at rest via SQLCipher)
    client_id: Mapped[str | None] = mapped_column(String(500))
    client_secret: Mapped[str | None] = mapped_column(Text)

    # SAML SP settings
    sp_entity_id: Mapped[str | None] = mapped_column(String(500))
    acs_url: Mapped[str | None] = mapped_column(String(500))
    sp_private_key: Mapped[str | None] = mapped_column(Text)  # PEM-encoded
    sp_certificate: Mapped[str | None] = mapped_column(Text)  # PEM-encoded

    # OIDC client settings
    redirect_uris: Mapped[dict[str, Any] | None] = mapped_column(JSON)
    scopes: Mapped[dict[str, Any] | None] = mapped_column(JSON)  # List stored as JSON
    grant_types: Mapped[dict[str, Any] | None] = mapped_column(JSON)

    # Additional settings
    settings: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)

    # Timestamps
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )

    # Relationships
    idp_provider: Mapped[IdPProvider] = relationship(back_populates="client_configs")

    def __repr__(self) -> str:
        return f"<ClientConfig(name='{self.name}', type='{self.client_type}')>"


class Certificate(Base):
    """Certificate storage for signing and encryption.

    Stores X.509 certificates and private keys used for
    SAML signing/encryption and OIDC JWT signing.
    """

    __tablename__ = "certificates"

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(255), unique=True, nullable=False)
    purpose: Mapped[str] = mapped_column(String(100), nullable=False)  # signing, encryption

    # Certificate data (PEM-encoded, encrypted at rest)
    private_key: Mapped[str | None] = mapped_column(Text)
    certificate: Mapped[str | None] = mapped_column(Text)
    certificate_chain: Mapped[str | None] = mapped_column(Text)

    # Certificate metadata
    subject: Mapped[str | None] = mapped_column(String(500))
    issuer_cn: Mapped[str | None] = mapped_column(String(500))
    serial_number: Mapped[str | None] = mapped_column(String(100))
    not_before: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    not_after: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    fingerprint_sha256: Mapped[str | None] = mapped_column(String(64))

    # Timestamps
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )

    def __repr__(self) -> str:
        return f"<Certificate(name='{self.name}', purpose='{self.purpose}')>"


class TestResult(Base):
    """Test execution results and logs.

    Stores results from authentication flow tests including
    timing data, assertions, and error details.
    """

    __tablename__ = "test_results"

    id: Mapped[int] = mapped_column(primary_key=True)
    idp_provider_id: Mapped[int | None] = mapped_column(
        ForeignKey("idp_providers.id")
    )
    test_name: Mapped[str] = mapped_column(String(255), nullable=False)
    test_type: Mapped[str] = mapped_column(String(50), nullable=False)  # saml, oidc

    # Test outcome
    status: Mapped[str] = mapped_column(String(50), nullable=False)  # passed, failed, error
    error_message: Mapped[str | None] = mapped_column(Text)
    error_details: Mapped[dict[str, Any] | None] = mapped_column(JSON)

    # Timing data
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    duration_ms: Mapped[int | None] = mapped_column()

    # Test data (assertions, claims, etc.)
    request_data: Mapped[dict[str, Any] | None] = mapped_column(JSON)
    response_data: Mapped[dict[str, Any] | None] = mapped_column(JSON)

    # Relationships
    idp_provider: Mapped[IdPProvider | None] = relationship(back_populates="test_results")

    def __repr__(self) -> str:
        return f"<TestResult(test='{self.test_name}', status='{self.status}')>"


class AppSetting(Base):
    """Application-wide settings storage.

    Key-value store for application configuration that
    persists across sessions.
    """

    __tablename__ = "app_settings"

    key: Mapped[str] = mapped_column(String(255), primary_key=True)
    value: Mapped[str | None] = mapped_column(Text)
    value_type: Mapped[str] = mapped_column(String(50), default="string")  # string, json, int, bool

    # Timestamps
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )

    def __repr__(self) -> str:
        return f"<AppSetting(key='{self.key}')>"


class MigrationHistory(Base):
    """Track applied database migrations.

    Used by the custom migration system to track which
    migrations have been applied.
    """

    __tablename__ = "migration_history"

    id: Mapped[int] = mapped_column(primary_key=True)
    version: Mapped[str] = mapped_column(String(50), unique=True, nullable=False)
    description: Mapped[str | None] = mapped_column(String(500))
    applied_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )

    def __repr__(self) -> str:
        return f"<MigrationHistory(version='{self.version}')>"
