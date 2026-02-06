# Ralph Progress Log

This file tracks progress across iterations. Agents update this file
after each iteration and it's included in prompts for context.

## Codebase Patterns (Study These First)

*Add reusable patterns discovered during development here.*

### IdP Presets Pattern
- Use dataclasses with `@property` methods to derive computed URLs from base config
- Separate discovery logic (fetching/parsing metadata) from preset generation
- Return configuration dicts with consistent structure (`idp_type`, `settings` subdict)
- Include setup guide documentation as module-level constants

### SAML Flow Pattern
- Each flow type (SP-Initiated, IdP-Initiated, Artifact) has its own class in `flows.py`
- Flows use a shared `FlowState` dataclass for tracking state across redirects
- Pre-flight checks validate configuration before initiating SSO
- Response processing and signature validation are in `sp.py` and `signature.py`
- Store artifact resolution URLs in IdP `settings` dict as `artifact_resolution_url`

---

## 2026-02-05 - US-011
- **What was implemented**: Keycloak IdP preset - already fully implemented in previous iteration
- **Files verified**:
  - `authtest/idp_presets/keycloak.py` - Complete Keycloak config with SAML/OIDC presets and setup guide
  - `authtest/idp_presets/discovery.py` - SAML metadata and OIDC discovery functions
  - `authtest/idp_presets/__init__.py` - Module exports and preset registry
- **Verification**:
  - Type checks pass (mypy)
  - Linting passes (ruff)
  - All 33 tests pass
  - Module imports and functions work correctly
- **Learnings:**
  - Keycloak follows a consistent URL pattern: `{base_url}/realms/{realm}/protocol/{saml|openid-connect}/{endpoint}`
  - SAML metadata XML parsing requires careful namespace handling
  - OIDC discovery just needs to append `.well-known/openid-configuration` to issuer URL
---

## 2026-02-05 - US-028
- **What was implemented**: Comprehensive user documentation
- **Files created/changed**:
  - `README.md` - Enhanced with complete quick start guide, environment variables, config example
  - `docs/cli-reference.md` - Complete CLI command reference with all commands, options, and examples
  - `docs/web-ui-guide.md` - Web interface user guide covering all features
  - `docs/idp-setup/README.md` - Index for IdP setup guides with general instructions
  - `docs/idp-setup/keycloak.md` - Comprehensive Keycloak setup guide with Docker quick start
- **Verification**:
  - Linting passes (ruff)
  - All 33 tests pass
  - Documentation structure follows standard patterns
- **Learnings:**
  - Documentation should match actual CLI command structure from code
  - IdP setup guides should include Docker quick start for easy testing
  - CLI reference should include practical examples for each command
---

## 2026-02-05 - US-029
- **What was implemented**: SAML Artifact Resolution (HTTP-Artifact binding)
- **Files created/changed**:
  - `authtest/core/saml/artifact.py` - New module with SAMLArtifact, ArtifactResolveRequest, ArtifactResolveResponse, ArtifactResolver classes
  - `authtest/core/saml/sp.py` - Added protocol_binding parameter to AuthnRequest, BINDING_HTTP_* constants
  - `authtest/core/saml/flows.py` - Added ArtifactFlow class for orchestrating artifact binding flow
  - `authtest/core/saml/__init__.py` - Exported new artifact classes and binding constants
  - `authtest/web/routes/saml.py` - Added /artifact and /artifact/acs routes, updated metadata with artifact ACS
  - `authtest/web/templates/saml/artifact.html` - New template for artifact binding test page
  - `authtest/web/templates/saml/index.html` - Added Artifact Binding option to SAML test menu
- **Verification**:
  - Type checks pass (mypy)
  - Linting passes (ruff)
  - All 33 tests pass
  - Module imports and functions work correctly
- **Learnings:**
  - SAML 2.0 artifacts are 44 bytes: TypeCode(2) + EndpointIndex(2) + SourceID(20) + MessageHandle(20)
  - Artifact resolution uses SOAP 1.1 envelope with SOAPAction header
  - The embedded SAML Response in ArtifactResponse is XML (not base64), requires direct parsing
  - IdP settings dict stores additional config like `artifact_resolution_url`
  - Type annotations from `dict[str, Any]` in models require explicit casting when returning specific types
---

