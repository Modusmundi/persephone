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

### JWT Token Validation Pattern
- Validation module in `authtest/core/oidc/validation.py` with TokenValidator class
- Separate signature validation (JWKS) from claim validation for partial success reporting
- ValidationCheck dataclass with name, description, status (valid/invalid/warning/skipped), expected, actual, message
- TokenValidationResult aggregates checks with `to_dict()`/`from_dict()` for serialization
- PyJWT library handles JWKS fetching via PyJWKClient and signature verification
- Clock skew tolerance (default 120s) for time-based claim validation

---

### OIDC Discovery Pattern
- Discovery module in `authtest/idp_presets/discovery.py` with `fetch_oidc_discovery()` and `OIDCDiscoveryResult`
- Auto-appends `.well-known/openid-configuration` path if not present in URL
- Returns all standard OIDC endpoints plus `raw_config` for custom fields
- CLI `idp discover` command supports auto-detection (SAML vs OIDC) and both JSON/text output
- `from-preset --discover` flag auto-populates endpoints during IdP creation
- Discovery results integrated with IdP storage model fields (issuer, authorization_endpoint, token_endpoint, userinfo_endpoint, jwks_uri)

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

## 2026-02-05 - US-014
- **What was implemented**: OIDC token decoding and validation
- **Files created/modified**:
  - `authtest/core/oidc/validation.py` (NEW) - TokenValidator, TokenValidationResult, ValidationCheck, ValidationStatus, JWKSManager classes for comprehensive JWT validation
  - `authtest/core/oidc/flows.py` - Added `id_token_validation` and `access_token_validation` fields to OIDCFlowState, integrated TokenValidator in `process_callback()`
  - `authtest/core/oidc/__init__.py` - Exported validation classes and functions
  - `authtest/web/routes/oidc.py` - Added `get_claim_description()` template global with OIDC claim descriptions
  - `authtest/web/templates/oidc/result.html` - Enhanced ID Token and Access Token sections with validation check display, claim-by-claim breakdown with descriptions, signature display
  - `tests/test_oidc_validation.py` (NEW) - Unit tests for TokenValidator and validation functions
- **Features implemented**:
  - JWT decoding with header/payload/signature display (enhanced existing)
  - Signature validation against IdP JWKS using PyJWT library
  - Standard claim validation: iss (issuer), aud (audience), exp (expiration), nbf (not before), iat (issued at), nonce
  - Algorithm security warnings (flags insecure algorithms like 'none')
  - Claim-by-claim validation breakdown with expected/actual values
  - Human-readable claim descriptions (40+ OIDC/JWT claims documented)
  - Clock skew tolerance for time-based validations
- **Learnings:**
  - PyJWT's `PyJWKClient` handles JWKS fetching and key matching by 'kid' automatically
  - Signature validation separate from claim validation allows partial success reporting
  - Access token validation may differ from ID token (audience claim semantics differ)
  - ValidationStatus enum uses StrEnum for easy serialization/display
  - Template globals via `@blueprint.app_template_global()` for reusable template functions
---

## 2026-02-05 - US-015
- **What was implemented**: OIDC Discovery integration was already fully implemented
- **Files verified**:
  - `authtest/idp_presets/discovery.py` - `fetch_oidc_discovery()`, `OIDCDiscoveryResult` dataclass with all OIDC endpoints
  - `authtest/idp_presets/__init__.py` - Exports discovery functions
  - `authtest/cli/config.py` - `idp discover` command with auto-detection and JSON output, `from-preset --discover` for auto-population
  - `authtest/core/oidc/validation.py` - `TokenValidator` uses `jwks_uri` for signature validation
- **Features present**:
  - Fetches `.well-known/openid-configuration` (auto-appends path if needed)
  - Auto-populates: issuer, authorization_endpoint, token_endpoint, userinfo_endpoint, jwks_uri, end_session_endpoint, revocation_endpoint, introspection_endpoint
  - Retrieves scopes_supported, response_types_supported, grant_types_supported
  - CLI display in both human-readable and JSON formats
  - Preserves raw_config for custom IdP fields
- **Learnings:**
  - Discovery was implemented as part of US-011 (Keycloak preset) foundation
  - URL handling auto-appends well-known path if not present
  - httpx client used for HTTP requests with configurable SSL verification
  - Discovery data seamlessly integrates with IdP storage model fields
---

## 2026-02-05 - US-016
- **What was implemented**: Okta IdP preset with OIDC and SAML support
- **Files created/modified**:
  - `authtest/idp_presets/okta.py` - Full implementation with OktaConfig dataclass, get_saml_preset(), get_oidc_preset(), OKTA_SETUP_GUIDE, get_setup_guide()
  - `authtest/idp_presets/__init__.py` - Added Okta exports and PRESETS registry entry with 'okta' key
  - `authtest/cli/config.py` - Updated `from-preset` and `setup-guide` commands to support Okta with options: --okta-domain, --app-id, --authorization-server
- **Features implemented**:
  - OktaConfig dataclass with all OIDC and SAML endpoints as properties
  - URL normalization (auto-adds https:// if missing)
  - OIDC support with three authorization server modes: 'default', 'org', or custom server ID
  - SAML support with optional app_id for app-specific URLs
  - Comprehensive setup guide with OIDC and SAML configuration instructions
  - CLI integration with full preset workflow support
- **Learnings:**
  - Okta has two types of authorization servers: Org (limited scopes) vs Custom/Default (full scopes)
  - Org auth server uses different URL pattern (no /oauth2/{server} prefix)
  - SAML in Okta requires app-specific SSO URLs that include the app ID
  - Okta SAML metadata is per-app, not org-level like OIDC discovery
  - Default name_id_format for Okta SAML is emailAddress, unlike Keycloak's persistent
---

## 2026-02-05 - US-017
- **What was implemented**: Azure AD / Entra ID preset with OIDC and SAML support
- **Files created/modified**:
  - `authtest/idp_presets/azure_ad.py` (NEW) - Full implementation with AzureADConfig dataclass, get_saml_preset(), get_oidc_preset(), AZURE_AD_SETUP_GUIDE, get_setup_guide()
  - `authtest/idp_presets/__init__.py` - Added Azure AD exports and PRESETS registry entry with 'azure_ad' key
  - `authtest/cli/config.py` - Updated `from-preset` and `setup-guide` commands with Azure AD options: --tenant-id, --use-v2-endpoints/--use-v1-endpoints
- **Features implemented**:
  - AzureADConfig dataclass with all OIDC and SAML endpoints as properties
  - Support for v2.0 endpoints (default, recommended) and v1.0 (legacy)
  - Multi-tenant configuration options: single-tenant (GUID/domain), "common", "organizations", "consumers"
  - Tenant type detection in settings (single-tenant, multi-tenant-all, multi-tenant-work-school, personal-accounts)
  - OIDC support with Microsoft identity platform v2.0 endpoints
  - SAML support with federation metadata URL pattern
  - Comprehensive setup guide with Azure Portal instructions, OIDC/SAML configuration, and troubleshooting
  - CLI integration with full preset workflow support
- **Learnings:**
  - Azure AD uses `login.microsoftonline.com` as the base URL for all tenants
  - v2.0 issuer format: `https://login.microsoftonline.com/{tenant}/v2.0`
  - v1.0 issuer format: `https://sts.windows.net/{tenant}/`
  - SAML entity ID uses `sts.windows.net` domain, not `login.microsoftonline.com`
  - UserInfo endpoint for Azure AD is via Microsoft Graph: `https://graph.microsoft.com/oidc/userinfo`
  - Multi-tenant values (common, organizations, consumers) use same URL pattern but allow different account types
  - Federation metadata uses XML format at `/federationmetadata/2007-06/federationmetadata.xml`
---

