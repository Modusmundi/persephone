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
CLI uses Click with group/command pattern. Subcommands are organized in separate modules and registered via `cli.add_command()`. Use underscore prefix (`_param`) for intentionally unused CLI parameters to satisfy ruff linting.

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
