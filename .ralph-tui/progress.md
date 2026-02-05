# Ralph Progress Log

This file tracks progress across iterations. Agents update this file
after each iteration and it's included in prompts for context.

## Codebase Patterns (Study These First)

### Flask Response Types
- Use `WerkzeugResponse` from `werkzeug.wrappers` for redirect return types
- Flask's `redirect()` returns werkzeug Response, not flask Response
- Use `TYPE_CHECKING` block to import `WerkzeugResponse` for type hints

### Auth Pattern
- `before_request` hook in Flask for global authentication checks
- Allow list for unauthenticated endpoints (login, setup, health, static files)
- Session tokens stored hashed (SHA-256) in database for security
- Sliding window session expiry: extend if < half timeout remaining

### Test Configuration
- Use `AUTH_ENABLED=False` in test fixtures to bypass authentication
- Tests should run without database encryption key configured

---

## 2026-02-05 - US-005
- What was implemented:
  - Password authentication with PBKDF2-HMAC-SHA256 (600k iterations per OWASP 2023)
  - Session management with secure random tokens and sliding window expiry
  - First-run setup wizard for password creation
  - Login page with CSRF protection
  - Auth middleware (before_request hook) protecting all routes
  - Configurable session timeout and auth enable/disable
  - Logout functionality with session invalidation
- Files changed:
  - `authtest/core/auth.py` - New auth module with password hashing and session management
  - `authtest/core/config.py` - Added AuthSettings (enabled, session_timeout_minutes)
  - `authtest/storage/models.py` - Added AppUser and UserSession models
  - `authtest/storage/migrations/versions/v002_auth_tables.py` - New migration for auth tables
  - `authtest/web/routes/auth.py` - Login, logout, setup routes and before_request hook
  - `authtest/web/templates/login.html` - Login page template
  - `authtest/web/templates/setup.html` - First-run setup wizard template
  - `authtest/web/templates/base.html` - Added logout button
  - `authtest/app.py` - Integrated auth initialization and persistent secret key
  - `tests/conftest.py` - Disabled auth for test fixtures
- **Learnings:**
  - Flask redirect returns werkzeug.wrappers.Response, not flask.wrappers.Response - use WerkzeugResponse type hint
  - before_request hooks are ideal for global auth middleware
  - Use cast() to satisfy mypy for config values from current_app.config
  - Session tokens should be stored hashed to prevent compromise if DB is leaked
---

