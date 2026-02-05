"""Add authentication tables migration.

Creates tables for user authentication and session management.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from sqlalchemy import text

if TYPE_CHECKING:
    from sqlalchemy.orm import Session

version = "002"
description = "Add authentication tables"


def upgrade(session: Session) -> None:
    """Create authentication tables."""
    # App users table
    session.execute(
        text("""
        CREATE TABLE IF NOT EXISTS app_users (
            id INTEGER PRIMARY KEY,
            username VARCHAR(255) UNIQUE NOT NULL,
            password_hash VARCHAR(64) NOT NULL,
            password_salt VARCHAR(64) NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
        """)
    )

    # User sessions table
    session.execute(
        text("""
        CREATE TABLE IF NOT EXISTS user_sessions (
            id INTEGER PRIMARY KEY,
            user_id INTEGER NOT NULL,
            token_hash VARCHAR(64) UNIQUE NOT NULL,
            created_at TIMESTAMP NOT NULL,
            expires_at TIMESTAMP NOT NULL,
            last_activity TIMESTAMP NOT NULL,
            FOREIGN KEY (user_id) REFERENCES app_users(id) ON DELETE CASCADE
        )
        """)
    )

    # Create indexes
    session.execute(
        text("CREATE INDEX IF NOT EXISTS idx_user_sessions_token ON user_sessions(token_hash)")
    )
    session.execute(
        text("CREATE INDEX IF NOT EXISTS idx_user_sessions_expires ON user_sessions(expires_at)")
    )


def downgrade(session: Session) -> None:
    """Drop authentication tables."""
    session.execute(text("DROP TABLE IF EXISTS user_sessions"))
    session.execute(text("DROP TABLE IF EXISTS app_users"))
