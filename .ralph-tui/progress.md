# Ralph Progress Log

This file tracks progress across iterations. Agents update this file
after each iteration and it's included in prompts for context.

## Codebase Patterns (Study These First)

### Flask Blueprint Template and Static Registration
When creating Flask blueprints in submodules, templates and static files must be explicitly registered using `template_folder` and `static_folder` parameters. Use a custom `static_url_path` (e.g., `/assets`) to avoid conflicts with Flask's default `/static` route. Example from `authtest/web/routes/__init__.py`:
```python
_web_dir = Path(__file__).parent.parent
_templates_dir = _web_dir / "templates"
_static_dir = _web_dir / "static"

main_bp = Blueprint(
    "main",
    __name__,
    template_folder=str(_templates_dir),
    static_folder=str(_static_dir),
    static_url_path="/assets",
)
```
In templates, reference with: `{{ url_for('main.static', filename='css/tailwind.min.css') }}`

### CLI Structure with Click
CLI uses Click with group/command pattern. Subcommands are organized in separate modules and registered via `cli.add_command()`. Use underscore prefix (`_param`) for intentionally unused CLI parameters to satisfy ruff linting. Note: parameter names must match the Click option name for Click to properly map them.

### SQLCipher Database Integration
Database uses SQLCipher via `sqlcipher3` package with SQLAlchemy 2.x. Key patterns:
- Use `sqlite+pysqlcipher:///path` as connection string
- Configure encryption via SQLAlchemy event listener on "connect" event
- Set PRAGMA key as first statement after opening connection
- Store encryption key in file with 0600 permissions or via `AUTHTEST_DB_KEY` env var
- Click's `path_type=Path` requires `# type: ignore[type-var]` for mypy compatibility

---

## 2026-02-05 - US-001
- What was implemented:
  - Full project scaffolding per PRD section 6.1 architecture
  - pyproject.toml with all key dependencies (Flask, Click, python3-saml, authlib, sqlalchemy, etc.)
  - Development tooling (pytest, mypy, ruff, pre-commit)
  - CLI skeleton with config, test, and certs command groups
  - Flask app factory pattern with HTMX/Tailwind templates
  - Basic test infrastructure (conftest.py, test_app.py, test_cli.py)
  - Docker configuration (Dockerfile + docker-compose.yml)
  - README with installation and usage instructions

- Files created:
  - `pyproject.toml` - Project metadata and dependencies
  - `README.md` - Project documentation
  - `authtest/` - Main package with all submodules:
    - `__init__.py`, `__main__.py`, `app.py`
    - `cli/` - CLI commands (main.py, config.py, test.py, certs.py)
    - `web/` - Web UI (routes, templates)
    - `core/` - Auth flow implementations (saml/, oidc/, crypto/)
    - `storage/` - Database layer
    - `idp_presets/` - IdP configuration presets
    - `reports/` - Report generators
  - `tests/` - Test suite
  - `docker/` - Docker configuration

- **Learnings:**
  - Flask blueprints in submodules need explicit template_folder paths
  - Click command groups should be imported at module level to avoid E402 lint errors
  - Python 3.14 is available on this system (installed at /Library/Frameworks/Python.framework)
  - Use `pip install -e ".[dev]"` for editable install with dev dependencies
---

## 2026-02-05 - US-002
- What was implemented:
  - Enhanced Flask app with offline-capable static assets
  - Bundled Tailwind CSS (minimal custom bundle for offline use)
  - Bundled HTMX 1.9.10 JavaScript for offline use
  - Dark/light theme toggle with localStorage persistence
  - Improved sidebar navigation with categorized sections (SAML, OIDC, Settings)
  - SVG icons for navigation items
  - Active route highlighting

- Files changed:
  - `authtest/web/routes/__init__.py` - Added static_folder and static_url_path
  - `authtest/web/templates/base.html` - Enhanced with theme toggle, icons, better structure
  - `authtest/web/static/css/tailwind.min.css` - Custom Tailwind CSS bundle (new)
  - `authtest/web/static/js/htmx.min.js` - HTMX 1.9.10 for offline use (new)
  - `authtest/web/static/js/theme.js` - Theme toggle functionality (new)

- **Learnings:**
  - Blueprint static files need `static_url_path` different from Flask's default `/static` to avoid route conflicts
  - Theme toggle should apply immediately on script load (before DOMContentLoaded) to prevent flash of wrong theme
  - Tailwind dark mode classes work with `.dark` class on document root
---

## 2026-02-05 - US-003
- What was implemented:
  - SQLCipher database integration with AES-256 encryption
  - SQLAlchemy 2.x ORM models for IdPProvider, ClientConfig, Certificate, TestResult, AppSetting
  - Encryption key management from environment variable or key file (~/.authtest/db.key)
  - Key rotation support with `authtest db rotate-key` command
  - Custom migration system (not Alembic - simpler for SQLCipher compatibility)
  - CLI commands: db init, verify, migrate, rollback, status, rotate-key, generate-key

- Files changed/created:
  - `pyproject.toml` - Added sqlcipher3 and alembic dependencies, mypy ignores for sqlcipher3
  - `authtest/storage/__init__.py` - Module exports for database and models
  - `authtest/storage/database.py` - SQLCipher engine, key management, Database class
  - `authtest/storage/models.py` - SQLAlchemy 2.x ORM models with proper type annotations
  - `authtest/storage/migrations/__init__.py` - MigrationManager class
  - `authtest/storage/migrations/versions/__init__.py` - Versions package
  - `authtest/storage/migrations/versions/v001_initial_schema.py` - Initial migration
  - `authtest/cli/db.py` - Database CLI commands
  - `authtest/cli/main.py` - Updated init command to initialize database
  - `tests/test_cli.py` - Added tests for db commands

- **Learnings:**
  - Click parameter names must match option names exactly (no underscore prefix for used params)
  - SQLCipher PRAGMA key must be first statement after opening connection
  - Use StrEnum instead of str+Enum inheritance (Python 3.11+)
  - SQLAlchemy relationship forward references don't need quotes with `from __future__ import annotations`
  - Click's `path_type=Path` has mypy incompatibility - use `# type: ignore[type-var]`
  - `raise ... from None` is better than `raise ... from e` for user-facing exceptions to hide traceback
---

## 2026-02-05 - US-004
- What was implemented:
  - Self-signed TLS certificate generation using cryptography library
  - PKCS#12 (.p12, .pfx) and PEM certificate loading support
  - Certificate inspection and validation utilities
  - TLS configuration via config.yaml or environment variables
  - Auto-generation of self-signed certificates on first server run
  - Flask HTTPS server support with ssl_context
  - CLI commands: certs generate, import, list, inspect, status
  - serve command with TLS support (--cert, --key, --no-tls options)

- Files changed/created:
  - `authtest/core/crypto/certs.py` - Certificate generation, loading, validation utilities
  - `authtest/core/crypto/__init__.py` - Module exports for crypto functions
  - `authtest/core/config.py` - TLSSettings, ServerSettings, AppConfig dataclasses with YAML/env support
  - `authtest/app.py` - Added create_ssl_context() and run_server() with TLS support
  - `authtest/cli/certs.py` - Full implementation of certs commands
  - `authtest/cli/serve.py` - Server command with TLS options
  - `authtest/cli/main.py` - Registered serve command

- **Learnings:**
  - Use `datetime.UTC` alias instead of `timezone.utc` (Python 3.11+ / ruff UP017)
  - Cryptography library's x509.CertificateBuilder() needs `.sign()` called last
  - Subject Alternative Names (SANs) should include localhost + 127.0.0.1 + ::1 for dev certs
  - Private key files should have 0600 permissions for security
  - PKCS#12 loading returns (key, cert, chain) tuple where chain may be None
  - Flask's ssl_context can be an ssl.SSLContext or tuple of (cert_path, key_path)
  - Use dataclasses with from_dict()/to_dict() methods for config objects with YAML serialization
---
