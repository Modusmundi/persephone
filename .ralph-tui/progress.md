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
- ClientCredentialsFlow class uses simpler pattern: start_flow() → execute_flow() (no redirects)
- Web routes in `authtest/web/routes/oidc.py` with blueprint registration in `__init__.py`
- Client credentials can come from ClientConfig model or IdP.settings['client_id']
- Different flows share OIDCFlowState but use grant_type field to distinguish

### JWT Token Validation Pattern
- Validation module in `authtest/core/oidc/validation.py` with TokenValidator class
- Separate signature validation (JWKS) from claim validation for partial success reporting
- ValidationCheck dataclass with name, description, status (valid/invalid/warning/skipped), expected, actual, message
- TokenValidationResult aggregates checks with `to_dict()`/`from_dict()` for serialization
- PyJWT library handles JWKS fetching via PyJWKClient and signature verification
- Clock skew tolerance (default 120s) for time-based claim validation

### OIDC Implicit Flow Pattern (Legacy)
- ImplicitFlow class in `authtest/core/oidc/flows.py` - follows same pattern as other flows
- Uses separate callback URL (`/oidc/implicit/callback`) that renders JS to extract tokens from fragment
- URL fragments (#) are NOT sent to server - client-side JS must parse and POST to `/implicit/process`
- response_type determines which tokens are returned: "token", "id_token", or "id_token token"
- No client_secret needed (public client flow)
- Security warnings are mandatory - this flow is deprecated per OAuth 2.0 Security BCP

### Test History Management Pattern
- History CLI in `authtest/cli/history.py` with list/show/export/delete commands
- History web routes in `authtest/web/routes/history.py` with history_bp blueprint
- Date filters support absolute (YYYY-MM-DD) and relative durations (7d, 24h, 30m)
- Pagination with filters preserved via url_for() parameter passing
- Bulk operations: export to JSON/CSV, delete with filters
- API endpoint `/history/api/results` for dynamic JavaScript updates

---

### OIDC Discovery Pattern
- Discovery module in `authtest/idp_presets/discovery.py` with `fetch_oidc_discovery()` and `OIDCDiscoveryResult`
- Auto-appends `.well-known/openid-configuration` path if not present in URL
- Returns all standard OIDC endpoints plus `raw_config` for custom fields
- CLI `idp discover` command supports auto-detection (SAML vs OIDC) and both JSON/text output
- `from-preset --discover` flag auto-populates endpoints during IdP creation
- Discovery results integrated with IdP storage model fields (issuer, authorization_endpoint, token_endpoint, userinfo_endpoint, jwks_uri)

### SAML SLO Pattern
- SLO module in `authtest/core/saml/logout.py` with SAMLLogoutRequest, SAMLLogoutResponse, SAMLLogoutHandler
- Follows same flow pattern as SSO: SLOFlowState dataclass with to_dict()/from_dict() for session storage
- SPInitiatedSLOFlow and IdPInitiatedSLOFlow classes in flows.py orchestrate the SLO flows
- LogoutValidationResult aggregates validation checks similar to JWT TokenValidationResult
- SP-initiated: create request → redirect to IdP → process response → validate
- IdP-initiated: receive request → validate → create response → redirect back to IdP
- Web routes support both HTTP-Redirect and HTTP-POST bindings
- SP metadata includes SingleLogoutService endpoints for IdP configuration

### Protocol Logging Pattern
- Logging module in `authtest/core/logging.py` with ProtocolLogger, HTTPExchange, ProtocolLog classes
- LoggingClient wraps httpx.Client to capture all HTTP traffic automatically
- Log levels: ERROR, INFO (default), DEBUG, TRACE (requires explicit trace_enabled flag)
- Sensitive data (tokens, secrets, cookies) auto-redacted at all levels except TRACE
- Flows start logging with `protocol_logger.start_flow()` and end with `end_flow()`
- HTTPExchange captures method, url, headers, body, status, duration, redirects
- ProtocolLog attached to flow state and included in test results for debugging
- Config via LoggingSettings (level, trace_enabled, log_file) in config.yaml or env vars

### Token Manipulation Pattern
- JWT manipulation in `authtest/core/crypto/tokens.py` with JWTManipulator class
- SAML manipulation in `authtest/core/saml/manipulation.py` with SAMLManipulator class
- Builder pattern: manipulator.modify_claim().extend_expiration().sign_with_rsa_key()
- ManipulatedToken/ManipulatedAssertion dataclasses track all manipulations applied
- Each manipulation recorded with type, description, original_value, new_value
- Signing options: strip_signature() (alg=none), sign_with_rsa_key(), sign_with_hs_secret() (algorithm confusion)
- generate_signing_key_pair() creates RSA/EC keys with get_public_key_jwk() for export
- SAML manipulation requires lxml for XML parsing, signxml for re-signing (optional)
- Clear warning labels on all manipulated tokens for security testing attribution

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

## 2026-02-05 - US-018
- **What was implemented**: SAML Single Logout (SLO) with SP-initiated and IdP-initiated flows
- **Files created**:
  - `authtest/core/saml/logout.py` (NEW) - SAMLLogoutRequest, SAMLLogoutResponse, SAMLLogoutHandler, LogoutStatus, LogoutSessionInfo, LogoutValidationCheck, LogoutValidationResult, validate_logout_response()
  - `authtest/web/templates/saml/slo.html` (NEW) - SP-initiated SLO test configuration page with preflight checks and logout form
  - `authtest/web/templates/saml/slo_result.html` (NEW) - SLO test result page with timeline, validation results, and XML display
  - `authtest/web/templates/saml/slo_info.html` (NEW) - SLO configuration info page for IdP setup
- **Files modified**:
  - `authtest/core/saml/flows.py` - Added SLOFlowStatus, SLOFlowState, SLOFlowResult, SPInitiatedSLOFlow, IdPInitiatedSLOFlow classes
  - `authtest/core/saml/__init__.py` - Exported all SLO classes and functions
  - `authtest/web/routes/saml.py` - Added /slo, /slo/info, /slo/cancel routes, handle_slo_response(), handle_idp_initiated_slo()
  - `authtest/web/templates/saml/index.html` - Enabled SLO section (was "Coming Soon")
- **Features implemented**:
  - SP-initiated logout request with configurable NameID, format, SessionIndex, and reason
  - IdP-initiated logout handling (receiving LogoutRequest from IdP)
  - LogoutResponse generation and validation
  - Signature validation on LogoutResponse (when IdP certificate configured)
  - Comprehensive validation checks: status code, InResponseTo, issuer, timestamps
  - Session cleanup verification
  - SP metadata updated with SingleLogoutService endpoints (HTTP-Redirect and HTTP-POST)
  - Full web UI for testing SLO flows
- **Learnings:**
  - SAML SLO uses same deflate+base64 encoding as SSO for HTTP-Redirect binding
  - LogoutRequest must include NameID (user identifier) and optionally SessionIndex
  - LogoutResponse uses same status codes as other SAML responses (Success, Requester, Responder)
  - IdP-initiated SLO requires SP to send LogoutResponse back to IdP after processing
  - SLO flow state follows similar pattern to SSO flow state (stored in Flask session)
  - SP metadata SingleLogoutService must be placed before NameIDFormat elements per SAML schema
---

## 2026-02-05 - US-019
- **What was implemented**: OIDC Client Credentials flow for machine-to-machine authentication
- **Files created/modified**:
  - `authtest/core/oidc/client.py` - Added `client_credentials_grant()` method to OIDCClient for direct token endpoint requests
  - `authtest/core/oidc/flows.py` - Added `ClientCredentialsFlow` class following same patterns as AuthorizationCodeFlow
  - `authtest/core/oidc/__init__.py` - Exported ClientCredentialsFlow
  - `authtest/web/routes/oidc.py` - Added `/client-credentials` and `/client-credentials/cancel` routes
  - `authtest/web/templates/oidc/client_credentials.html` (NEW) - Preflight checks and scope configuration UI
  - `authtest/web/templates/oidc/client_credentials_result.html` (NEW) - Token display with decoded JWT and validation
  - `authtest/web/templates/oidc/index.html` - Added Client Credentials button, updated PKCE description (already available)
- **Features implemented**:
  - Client authenticates with client_id and client_secret directly to token endpoint
  - Access token retrieved without user interaction (machine-to-machine)
  - Preflight checks: token endpoint, client_id, client_secret (required)
  - Configurable scopes (defaults exclude 'openid' since it's user auth)
  - Access token JWT decoding and signature validation
  - Full test result recording to database
  - Web UI with timeline, validation checks, claim display
- **Acceptance Criteria Met**:
  - [x] Client authenticates with client_id and client_secret
  - [x] Retrieves access token without user interaction
  - [x] Supports various client authentication methods (POST body with credentials)
- **Learnings:**
  - Client Credentials grant does NOT return id_token (no user context)
  - The 'openid' scope is typically not used with client_credentials (it's for user authentication)
  - Access tokens may or may not be JWTs depending on IdP configuration
  - Flow is simpler than Authorization Code - no redirects, single POST request
  - Reused existing OIDCFlowState dataclass with grant_type field to distinguish flows
---

## 2026-02-05 - US-020
- **What was implemented**: OIDC Implicit flow for testing legacy implementations
- **Files created/modified**:
  - `authtest/core/oidc/flows.py` - Added `ImplicitFlow` class with start_flow(), create_authorization_request(), process_fragment_response(), record_result(), get_flow_result() methods
  - `authtest/core/oidc/__init__.py` - Exported ImplicitFlow class
  - `authtest/web/routes/oidc.py` - Added `/implicit`, `/implicit/callback`, `/implicit/process`, `/implicit/cancel` routes
  - `authtest/web/templates/oidc/implicit.html` (NEW) - Preflight checks and flow configuration UI with security warning
  - `authtest/web/templates/oidc/implicit_callback.html` (NEW) - Client-side JavaScript to extract tokens from URL fragment
  - `authtest/web/templates/oidc/implicit_result.html` (NEW) - Token display with decoded JWT, validation, and security warnings
  - `authtest/web/templates/oidc/index.html` - Added Implicit flow button and description
- **Features implemented**:
  - Authorization request with response_type=token, id_token, or id_token token
  - Tokens returned directly in URL fragment (no code exchange)
  - Client-side JavaScript extracts tokens from fragment and POSTs to server
  - Token decoding and signature validation
  - Prominent security warnings about implicit flow deprecation
  - Full test result recording to database
- **Acceptance Criteria Met**:
  - [x] Authorization request with response_type=token or id_token
  - [x] Token returned in URL fragment
  - [x] Warning about implicit flow security concerns
- **Learnings:**
  - Implicit flow returns tokens in URL fragment (#), not query string (?)
  - URL fragments are never sent to server, so client-side JS must extract them
  - response_type can be: "token" (access_token only), "id_token" (ID token only), or "id_token token" (both)
  - No client_secret needed for implicit flow (public client)
  - Security warnings are crucial - this flow is deprecated per OAuth 2.0 Security BCP
  - Fragment parsing uses URLSearchParams after removing the leading #
---

## 2026-02-05 - US-021
- **What was implemented**: Full protocol logging for authentication flows with configurable log levels
- **Files created**:
  - `authtest/core/logging.py` (NEW) - ProtocolLogger, HTTPExchange, ProtocolLog, LoggingClient, LoggingTransport classes; redact_sensitive() function; configure_logging() for setup
  - `tests/test_protocol_logging.py` (NEW) - Unit tests for logging module
- **Files modified**:
  - `authtest/core/config.py` - Added LoggingSettings dataclass with level, trace_enabled, log_file; updated AppConfig, load_config(), get_default_config_yaml()
  - `authtest/core/__init__.py` - Added logging exports
  - `authtest/core/oidc/client.py` - OIDCClient now uses LoggingClient for HTTP requests; accepts optional protocol_logger
  - `authtest/core/oidc/flows.py` - AuthorizationCodeFlow, ClientCredentialsFlow, ImplicitFlow now accept protocol_logger; OIDCFlowState has protocol_log field; flows start/end protocol logging and include logs in results
  - `authtest/idp_presets/discovery.py` - fetch_saml_metadata() and fetch_oidc_discovery() use LoggingClient
  - `authtest/cli/serve.py` - Added --log-level and --trace options; initializes protocol logging from config
- **Features implemented**:
  - Full request/response logging for all HTTP exchanges
  - Raw HTTP traffic capture (headers, redirects, cookies, POST bodies)
  - Configurable log levels: ERROR, INFO, DEBUG, TRACE
  - TRACE level requires explicit enable (trace_enabled: true) for sensitive data
  - Automatic redaction of sensitive data (client_secret, tokens, Authorization headers, cookies)
  - Protocol logs attached to test results for debugging
  - Environment variable support: AUTHTEST_LOG_LEVEL, AUTHTEST_TRACE_ENABLED, AUTHTEST_LOG_FILE
- **Acceptance Criteria Met**:
  - [x] Full request/response logging for all exchanges
  - [x] Raw HTTP traffic capture (headers, redirects, cookies, POST bodies)
  - [x] Configurable log levels (ERROR, INFO, DEBUG, TRACE)
  - [x] TRACE level requires explicit enable for sensitive data
- **Learnings:**
  - httpx Client doesn't easily support transport-level hooks, so created LoggingClient wrapper that logs before/after requests
  - Sensitive data redaction uses regex patterns for URL params, headers, JSON fields, cookies
  - Header dict values don't include key prefix, so need separate patterns for "Bearer token" vs "Authorization: Bearer token"
  - ProtocolLog stores exchanges with start/complete timestamps; attached to flow state for result recording
  - IntEnum used for LogLevel to allow numeric comparisons (TRACE < DEBUG < INFO < ERROR)
---

## 2026-02-05 - US-022
- **What was implemented**: Token manipulation tools for security testing (JWT and SAML)
- **Files created**:
  - `authtest/core/crypto/tokens.py` - JWT manipulation module with JWTManipulator class, ManipulatedToken dataclass, key generation utilities
  - `authtest/core/saml/manipulation.py` - SAML assertion manipulation module with SAMLManipulator class, ManipulatedAssertion dataclass
  - `authtest/web/routes/tools.py` - Web routes for token manipulation tools (/tools, /tools/jwt, /tools/saml, /tools/generate-key)
  - `authtest/web/templates/tools/index.html` - Token tools landing page
  - `authtest/web/templates/tools/jwt.html` - JWT manipulation UI
  - `authtest/web/templates/tools/saml.html` - SAML manipulation UI
  - `authtest/web/templates/tools/key_generated.html` - Generated key display page
- **Files modified**:
  - `authtest/core/crypto/__init__.py` - Added exports for token manipulation classes/functions
  - `authtest/core/saml/__init__.py` - Added exports for SAML manipulation classes/functions
  - `authtest/web/routes/__init__.py` - Registered tools_bp blueprint
  - `authtest/web/templates/base.html` - Added Security Tools navigation section
  - `authtest/web/templates/index.html` - Added Token Manipulation card to dashboard
- **Features implemented**:
  - JWT token decoding and inspection
  - JWT claim modification (sub, iss, aud, roles, custom claims)
  - JWT expiration extension
  - JWT signature stripping (alg=none attack testing)
  - JWT algorithm confusion attack (RS256 to HS256)
  - JWT re-signing with generated RSA/EC keys
  - SAML assertion parsing and attribute extraction
  - SAML NameID modification
  - SAML validity period extension
  - SAML issuer/audience modification
  - SAML attribute addition/modification
  - SAML signature stripping
  - Clear labeling of manipulated tokens ("MANIPULATED TOKEN - FOR SECURITY TESTING ONLY")
  - JWK generation and export for re-signed tokens
- **Acceptance Criteria Met**:
  - [x] Modify SAML assertions and re-sign
  - [x] Modify JWT tokens and re-sign
  - [x] Use application's own key for re-signing (generated key with JWK export)
  - [x] Clear labeling of manipulated tokens
- **Learnings:**
  - PyJWT library handles JWT signing/encoding with various algorithms (RS256, ES256, HS256)
  - signxml library provides XMLSigner for SAML re-signing (optional dependency)
  - lxml etree is essential for SAML XML manipulation with namespaces
  - Base64url encoding for JWTs requires padding handling (4 - len % 4)
  - JWK format requires base64url encoding of RSA modulus (n) and exponent (e)
  - SAML namespaces: saml=urn:oasis:names:tc:SAML:2.0:assertion, samlp=urn:oasis:names:tc:SAML:2.0:protocol
  - Token manipulation tools need prominent security warnings for authorized testing use
  - Flask session can store generated keys for use across manipulation operations
---

## 2026-02-05 - US-033
- **What was implemented**: Test history management with searchable history, CLI commands, and web UI
- **Files created**:
  - `authtest/cli/history.py` - CLI commands: list, show, export, delete with filters (IdP, type, status, date range)
  - `authtest/web/routes/history.py` - Web routes for history browsing, export, and bulk delete operations
  - `authtest/web/templates/history/index.html` - History browser with filters, pagination, bulk selection
  - `authtest/web/templates/history/show.html` - Detailed view of a single test result
  - `authtest/web/templates/history/export.html` - Export configuration with bulk delete option
- **Files modified**:
  - `authtest/cli/main.py` - Added history command registration
  - `authtest/web/routes/__init__.py` - Added history_bp blueprint registration
  - `authtest/web/templates/index.html` - Added History card to dashboard
- **Features implemented**:
  - CLI: `authtest history list` - Searchable list with filters (--idp, --type, --status, --since, --until)
  - CLI: `authtest history show <id>` - Detailed view of a test result with request/response data
  - CLI: `authtest history export <file>` - Export to JSON/CSV with filters
  - CLI: `authtest history delete` - Bulk delete with filters (--idp, --type, --status, --before, --ids, --all)
  - Web: History browser with search, IdP/type/status filters, date range, pagination
  - Web: Detailed result view with tokens, claims, validation checks
  - Web: Bulk selection and export/delete operations
  - Web: API endpoint for dynamic result fetching (/history/api/results)
- **Acceptance Criteria Met**:
  - [x] Searchable history by IdP, flow type, date, status
  - [x] history list/show/export CLI commands
  - [x] Web UI history browser with filters
  - [x] Bulk export and delete operations
- **Learnings:**
  - Date filters support both absolute dates (YYYY-MM-DD) and relative durations (7d, 24h, 30m)
  - Flask Response object with Content-Disposition header enables file downloads from POST forms
  - SQLAlchemy's `delete(synchronize_session="fetch")` is needed when using filters with joins
  - Pagination in templates requires passing filter params via url_for() to preserve state
  - History link was already in sidebar (base.html) - just needed route implementation
---

