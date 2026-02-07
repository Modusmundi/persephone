# Ralph Progress Log

This file tracks progress across iterations. Agents update this file
after each iteration and it's included in prompts for context.

## Codebase Patterns (Study These First)

### IdP Preset Pattern
Each IdP preset module follows a consistent structure:
1. A `XxxConfig` dataclass with `@property` methods for endpoint URLs
2. `get_saml_preset()` function returning dict with `idp_type`, `entity_id`, `sso_url`, `slo_url`, `metadata_url`, and `settings`
3. `get_oidc_preset()` function returning dict with `idp_type`, `issuer`, endpoints, and `settings`
4. `XXX_SETUP_GUIDE` constant with comprehensive markdown documentation
5. `get_setup_guide()` function that optionally customizes the guide with user-provided values
6. Register preset in `PRESETS` dict in `__init__.py` with `name`, `description`, `module`, `requires`, `optional`, and `supports` keys

---

## 2026-02-07 - US-026
- Implemented 6 new IdP presets: Auth0, Google Workspace, PingFederate, ADFS, OneLogin, JumpCloud
- Files changed:
  - Created: `authtest/idp_presets/auth0.py`
  - Created: `authtest/idp_presets/google.py`
  - Created: `authtest/idp_presets/ping_federate.py`
  - Created: `authtest/idp_presets/adfs.py`
  - Created: `authtest/idp_presets/onelogin.py`
  - Created: `authtest/idp_presets/jumpcloud.py`
  - Updated: `authtest/idp_presets/__init__.py` (added imports, exports, and PRESETS registry entries)
- **Learnings:**
  - Each IdP has unique URL patterns - Google uses static URLs while others are subdomain/domain-based
  - Some IdPs (like JumpCloud) use separate domains for SAML vs OIDC endpoints
  - ADFS entity IDs use `http://` scheme (not https) as per Microsoft's convention
  - Google OIDC endpoints are global, while SAML requires per-app configuration via Admin Console
  - PingFederate uses `.oauth2` and `.saml2` suffixes for endpoint paths
---

