# Ralph Progress Log

This file tracks progress across iterations. Agents update this file
after each iteration and it's included in prompts for context.

## Codebase Patterns (Study These First)

- **Flask Blueprint Pattern**: Routes are organized in blueprints under `authtest/web/routes/`. Each protocol (SAML, OIDC) gets its own blueprint with `url_prefix`.
- **Template Organization**: Templates live in `authtest/web/templates/` with subdirectories per feature (e.g., `saml/`).
- **Database Session Pattern**: Use `db.get_session()` in try/finally blocks, always close session in finally.
- **Flow State Pattern**: Multi-step authentication flows store state in Flask session as dicts via `to_dict()`/`from_dict()`.
- **Use `datetime.UTC`**: Import `UTC` from datetime (not `timezone.utc`) per ruff UP017 preference.

---

## 2026-02-05 - US-007
- **What was implemented**: SAML SP-Initiated SSO flow was already implemented. Fixed minor lint/type issues.
- **Files changed**:
  - `authtest/core/saml/sp.py` - Updated datetime import to use `UTC` alias, fixed nested if (SIM102)
  - `authtest/core/saml/flows.py` - Removed unused import, updated datetime to use `UTC` alias
  - `authtest/web/routes/saml.py` - Fixed return type annotation for metadata route
- **Learnings:**
  - Ruff prefers `datetime.UTC` over `timezone.utc` (UP017)
  - Flask Response type must be imported from `flask` for proper type hints
  - `current_app.make_response()` returns Any, need type annotation for mypy
---

