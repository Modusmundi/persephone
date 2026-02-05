"""Initial database schema migration.

Creates all base tables for AuthTest configuration storage.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from sqlalchemy import text

if TYPE_CHECKING:
    from sqlalchemy.orm import Session

version = "001"
description = "Initial database schema"


def upgrade(session: Session) -> None:
    """Create initial database tables."""
    # IdP Providers table
    session.execute(
        text("""
        CREATE TABLE IF NOT EXISTS idp_providers (
            id INTEGER PRIMARY KEY,
            name VARCHAR(255) UNIQUE NOT NULL,
            display_name VARCHAR(255),
            idp_type VARCHAR(50) NOT NULL,
            enabled BOOLEAN DEFAULT 1,
            settings JSON DEFAULT '{}',
            entity_id VARCHAR(500),
            sso_url VARCHAR(500),
            slo_url VARCHAR(500),
            metadata_url VARCHAR(500),
            metadata_xml TEXT,
            x509_cert TEXT,
            issuer VARCHAR(500),
            authorization_endpoint VARCHAR(500),
            token_endpoint VARCHAR(500),
            userinfo_endpoint VARCHAR(500),
            jwks_uri VARCHAR(500),
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
        """)
    )

    # Client configurations table
    session.execute(
        text("""
        CREATE TABLE IF NOT EXISTS client_configs (
            id INTEGER PRIMARY KEY,
            idp_provider_id INTEGER NOT NULL,
            name VARCHAR(255) NOT NULL,
            client_type VARCHAR(50) NOT NULL,
            client_id VARCHAR(500),
            client_secret TEXT,
            sp_entity_id VARCHAR(500),
            acs_url VARCHAR(500),
            sp_private_key TEXT,
            sp_certificate TEXT,
            redirect_uris JSON,
            scopes JSON,
            grant_types JSON,
            settings JSON DEFAULT '{}',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (idp_provider_id) REFERENCES idp_providers(id)
        )
        """)
    )

    # Certificates table
    session.execute(
        text("""
        CREATE TABLE IF NOT EXISTS certificates (
            id INTEGER PRIMARY KEY,
            name VARCHAR(255) UNIQUE NOT NULL,
            purpose VARCHAR(100) NOT NULL,
            private_key TEXT,
            certificate TEXT,
            certificate_chain TEXT,
            subject VARCHAR(500),
            issuer_cn VARCHAR(500),
            serial_number VARCHAR(100),
            not_before TIMESTAMP,
            not_after TIMESTAMP,
            fingerprint_sha256 VARCHAR(64),
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
        """)
    )

    # Test results table
    session.execute(
        text("""
        CREATE TABLE IF NOT EXISTS test_results (
            id INTEGER PRIMARY KEY,
            idp_provider_id INTEGER,
            test_name VARCHAR(255) NOT NULL,
            test_type VARCHAR(50) NOT NULL,
            status VARCHAR(50) NOT NULL,
            error_message TEXT,
            error_details JSON,
            started_at TIMESTAMP NOT NULL,
            completed_at TIMESTAMP,
            duration_ms INTEGER,
            request_data JSON,
            response_data JSON,
            FOREIGN KEY (idp_provider_id) REFERENCES idp_providers(id)
        )
        """)
    )

    # Application settings table
    session.execute(
        text("""
        CREATE TABLE IF NOT EXISTS app_settings (
            key VARCHAR(255) PRIMARY KEY,
            value TEXT,
            value_type VARCHAR(50) DEFAULT 'string',
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
        """)
    )

    # Create indexes for common queries
    session.execute(
        text("CREATE INDEX IF NOT EXISTS idx_idp_providers_type ON idp_providers(idp_type)")
    )
    session.execute(
        text("CREATE INDEX IF NOT EXISTS idx_client_configs_idp ON client_configs(idp_provider_id)")
    )
    session.execute(
        text("CREATE INDEX IF NOT EXISTS idx_test_results_idp ON test_results(idp_provider_id)")
    )
    session.execute(
        text("CREATE INDEX IF NOT EXISTS idx_test_results_status ON test_results(status)")
    )


def downgrade(session: Session) -> None:
    """Drop all tables."""
    session.execute(text("DROP TABLE IF EXISTS test_results"))
    session.execute(text("DROP TABLE IF EXISTS client_configs"))
    session.execute(text("DROP TABLE IF EXISTS certificates"))
    session.execute(text("DROP TABLE IF EXISTS app_settings"))
    session.execute(text("DROP TABLE IF EXISTS idp_providers"))
