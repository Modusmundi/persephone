"""Password authentication and session management for AuthTest."""

from __future__ import annotations

import hashlib
import hmac
import os
import secrets
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from authtest.storage.database import Database

# Session token settings
SESSION_TOKEN_BYTES = 32  # 256-bit tokens


@dataclass
class SessionInfo:
    """Information about an authenticated session."""

    user_id: int
    session_token: str
    created_at: datetime
    expires_at: datetime
    last_activity: datetime

    @property
    def is_expired(self) -> bool:
        """Check if the session has expired."""
        return datetime.now(UTC) > self.expires_at


def hash_password(password: str, salt: bytes | None = None) -> tuple[str, str]:
    """Hash a password using PBKDF2-HMAC-SHA256.

    Args:
        password: The plaintext password to hash.
        salt: Optional salt bytes. If not provided, generates a random 32-byte salt.

    Returns:
        Tuple of (password_hash, salt) as hex strings.
    """
    if salt is None:
        salt = os.urandom(32)

    # Use PBKDF2 with 600,000 iterations (OWASP 2023 recommendation)
    password_hash = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt,
        iterations=600_000,
        dklen=32,
    )

    return password_hash.hex(), salt.hex()


def verify_password(password: str, stored_hash: str, salt: str) -> bool:
    """Verify a password against a stored hash.

    Args:
        password: The plaintext password to verify.
        stored_hash: The stored password hash (hex string).
        salt: The salt used to create the hash (hex string).

    Returns:
        True if the password matches, False otherwise.
    """
    salt_bytes = bytes.fromhex(salt)
    computed_hash, _ = hash_password(password, salt_bytes)

    # Use constant-time comparison to prevent timing attacks
    return hmac.compare_digest(computed_hash, stored_hash)


def generate_session_token() -> str:
    """Generate a secure random session token.

    Returns:
        A 64-character hex string (256 bits).
    """
    return secrets.token_hex(SESSION_TOKEN_BYTES)


def hash_session_token(token: str) -> str:
    """Hash a session token for secure storage.

    We store hashed tokens so that if the database is compromised,
    attackers cannot directly use the tokens.

    Args:
        token: The raw session token.

    Returns:
        SHA-256 hash of the token as a hex string.
    """
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


class AuthManager:
    """Manages authentication and session state.

    Handles password verification, session creation/validation,
    and enforces session timeouts.
    """

    def __init__(self, db: Database, session_timeout_minutes: int = 60) -> None:
        """Initialize the authentication manager.

        Args:
            db: Database instance for user/session storage.
            session_timeout_minutes: Session timeout in minutes. Default 60.
        """
        self._db = db
        self._session_timeout = timedelta(minutes=session_timeout_minutes)

    def is_setup_required(self) -> bool:
        """Check if initial password setup is needed.

        Returns:
            True if no user exists and setup is required.
        """
        from authtest.storage.models import AppUser

        with self._db.get_session() as session:
            user = session.query(AppUser).first()
            return user is None

    def setup_password(self, password: str) -> bool:
        """Set up the initial admin password.

        This should only be called during first-run setup.

        Args:
            password: The password to set.

        Returns:
            True if setup succeeded.

        Raises:
            ValueError: If a password is already set.
        """
        from authtest.storage.models import AppUser

        with self._db.get_session() as session:
            existing = session.query(AppUser).first()
            if existing:
                raise ValueError("Password already configured. Use change_password() instead.")

            password_hash, salt = hash_password(password)
            user = AppUser(
                username="admin",
                password_hash=password_hash,
                password_salt=salt,
            )
            session.add(user)
            session.commit()
            return True

    def authenticate(self, password: str) -> SessionInfo | None:
        """Authenticate with password and create a new session.

        Args:
            password: The password to verify.

        Returns:
            SessionInfo if authentication succeeded, None otherwise.
        """
        from authtest.storage.models import AppUser, UserSession

        with self._db.get_session() as session:
            user = session.query(AppUser).first()
            if not user:
                return None

            if not verify_password(password, user.password_hash, user.password_salt):
                return None

            # Create new session
            now = datetime.now(UTC)
            token = generate_session_token()
            token_hash = hash_session_token(token)

            user_session = UserSession(
                user_id=user.id,
                token_hash=token_hash,
                created_at=now,
                expires_at=now + self._session_timeout,
                last_activity=now,
            )
            session.add(user_session)
            session.commit()

            return SessionInfo(
                user_id=user.id,
                session_token=token,  # Return unhashed token to client
                created_at=now,
                expires_at=user_session.expires_at,
                last_activity=now,
            )

    def validate_session(self, token: str, update_activity: bool = True) -> SessionInfo | None:
        """Validate a session token and optionally extend it.

        Args:
            token: The session token to validate.
            update_activity: If True, updates last_activity and may extend expiry.

        Returns:
            SessionInfo if valid, None if invalid or expired.
        """
        from authtest.storage.models import UserSession

        token_hash = hash_session_token(token)

        with self._db.get_session() as session:
            user_session = (
                session.query(UserSession)
                .filter(UserSession.token_hash == token_hash)
                .first()
            )

            if not user_session:
                return None

            now = datetime.now(UTC)

            if now > user_session.expires_at:
                # Session expired, clean it up
                session.delete(user_session)
                session.commit()
                return None

            if update_activity:
                user_session.last_activity = now
                # Extend session if it was about to expire (sliding window)
                time_remaining = user_session.expires_at - now
                if time_remaining < self._session_timeout / 2:
                    user_session.expires_at = now + self._session_timeout
                session.commit()

            return SessionInfo(
                user_id=user_session.user_id,
                session_token=token,
                created_at=user_session.created_at,
                expires_at=user_session.expires_at,
                last_activity=user_session.last_activity,
            )

    def logout(self, token: str) -> bool:
        """Invalidate a session.

        Args:
            token: The session token to invalidate.

        Returns:
            True if session was found and invalidated.
        """
        from authtest.storage.models import UserSession

        token_hash = hash_session_token(token)

        with self._db.get_session() as session:
            user_session = (
                session.query(UserSession)
                .filter(UserSession.token_hash == token_hash)
                .first()
            )

            if user_session:
                session.delete(user_session)
                session.commit()
                return True
            return False

    def change_password(self, current_password: str, new_password: str) -> bool:
        """Change the admin password.

        Args:
            current_password: The current password for verification.
            new_password: The new password to set.

        Returns:
            True if password was changed successfully.

        Raises:
            ValueError: If current password is incorrect.
        """
        from authtest.storage.models import AppUser, UserSession

        with self._db.get_session() as session:
            user = session.query(AppUser).first()
            if not user:
                raise ValueError("No user configured")

            if not verify_password(current_password, user.password_hash, user.password_salt):
                raise ValueError("Current password is incorrect")

            # Update password
            password_hash, salt = hash_password(new_password)
            user.password_hash = password_hash
            user.password_salt = salt

            # Invalidate all existing sessions
            session.query(UserSession).filter(UserSession.user_id == user.id).delete()

            session.commit()
            return True

    def cleanup_expired_sessions(self) -> int:
        """Remove all expired sessions from the database.

        Returns:
            Number of sessions removed.
        """
        from authtest.storage.models import UserSession

        with self._db.get_session() as session:
            now = datetime.now(UTC)
            count = (
                session.query(UserSession)
                .filter(UserSession.expires_at < now)
                .delete()
            )
            session.commit()
            return count
