# Ralph Progress Log

This file tracks progress across iterations. Agents update this file
after each iteration and it's included in prompts for context.

## Codebase Patterns (Study These First)

### IdP Preset Module Structure
- Presets live in `authtest/idp_presets/` with one file per provider
- Each preset module exports functions like `get_saml_preset()`, `get_oidc_preset()`, `get_setup_guide()`
- Discovery functions in `discovery.py` handle metadata/config fetching
- Registry in `__init__.py` with `PRESETS` dict for CLI integration

### CLI Command Pattern
- Commands in `authtest/cli/` use Click framework
- `@json_option` decorator for `--json` flag on all commands
- `output_result()` and `error_result()` helpers for consistent output
- Commands support both interactive and non-interactive modes

### OIDC Flow Pattern
- Flow handlers in `authtest/core/oidc/flows.py` follow same pattern as SAML flows
- OIDCFlowState dataclass with to_dict()/from_dict() for session storage
- AuthorizationCodeFlow class orchestrates the flow with start_flow(), create_authorization_request(), process_callback()
- Web routes in `authtest/web/routes/oidc.py` with blueprint registration in `__init__.py`
- Client credentials can come from ClientConfig model or IdP.settings['client_id']

---

## 2026-02-05 - US-011
- **What was implemented**: Keycloak IdP preset was already fully implemented
- **Files verified**:
  - `authtest/idp_presets/keycloak.py` - KeycloakConfig class, get_saml_preset(), get_oidc_preset(), KEYCLOAK_SETUP_GUIDE
  - `authtest/idp_presets/discovery.py` - fetch_saml_metadata(), fetch_oidc_discovery() for auto-discovery
  - `authtest/idp_presets/__init__.py` - PRESETS registry, list_presets(), get_preset_info()
  - `authtest/cli/config.py` - from-preset, setup-guide, discover commands
  - `docs/idp-setup/keycloak.md` - Comprehensive setup documentation
  - `docs/idp-setup/README.md` - Index of IdP setup guides
- **Learnings:**
  - Implementation was complete from prior work, just needed verification
  - The preset system is well-architected for adding new providers (okta, azure_ad, etc.)
  - Test environment needs pysqlcipher3 and httpx modules for full test suite
---

## 2026-02-05 - US-012
- **What was implemented**: OIDC Authorization Code flow
- **Files created/modified**:
  - `authtest/core/oidc/client.py` - OIDCClient, OIDCClientConfig, AuthorizationRequest, TokenResponse, UserInfoResponse
  - `authtest/core/oidc/utils.py` - decode_jwt(), DecodedToken, format_token_claims(), algorithm helpers
  - `authtest/core/oidc/flows.py` - AuthorizationCodeFlow, OIDCFlowState, OIDCFlowStatus, PreflightCheck/Result
  - `authtest/core/oidc/__init__.py` - Exports all public classes/functions
  - `authtest/web/routes/oidc.py` - oidc_bp blueprint with /authorization-code and /callback routes
  - `authtest/web/routes/__init__.py` - Added oidc_bp registration
  - `authtest/web/templates/oidc/index.html` - IdP selection and flow overview
  - `authtest/web/templates/oidc/authorization_code.html` - Preflight and flow initiation
  - `authtest/web/templates/oidc/result.html` - Token display with decoded JWT claims
- **Learnings:**
  - Followed SAML flow patterns for consistency (FlowState, preflight checks, session storage)
  - Client credentials lookup chain: ClientConfig model > IdP.settings
  - httpx used for HTTP client with verify=False for self-signed cert testing
  - JWT decoding without verification (for inspection) uses manual base64url decode
  - Template filters for timestamp conversion registered on blueprint
---

## 2026-02-05 - US-013
- **What was implemented**: OIDC Authorization Code + PKCE flow
- **Files modified**:
  - `authtest/core/oidc/client.py` - Added `generate_code_verifier()` and `generate_code_challenge()` functions, updated `create_authorization_request()` with `use_pkce` and `code_challenge_method` parameters
  - `authtest/core/oidc/flows.py` - Added `code_challenge` and `code_challenge_method` fields to OIDCFlowState, updated `create_authorization_request()` to pass PKCE options, PKCE info included in recorded test results
  - `authtest/core/oidc/__init__.py` - Exported PKCE utility functions
  - `authtest/web/routes/oidc.py` - Added form field handling for `use_pkce` checkbox and `code_challenge_method` select
  - `authtest/web/templates/oidc/authorization_code.html` - Added PKCE toggle checkbox with S256/plain method selector
  - `authtest/web/templates/oidc/result.html` - Added PKCE badge in timeline when PKCE was used
- **Learnings:**
  - PKCE implementation follows RFC 7636 - verified with official test vector
  - code_verifier is URL-safe base64 (no + or /), 43-128 chars (default 64)
  - code_challenge for S256 is SHA-256 hash of verifier, base64url encoded without padding
  - S256 produces 43-char challenge (256 bits / 6 bits per base64 char ≈ 43)
  - PKCE is required for public clients (SPAs, mobile apps) but optional for confidential clients
---

