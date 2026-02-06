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

## 2026-02-05 - US-031
- **What was implemented**: Certificate management web UI
- **Files created/changed**:
  - `authtest/web/routes/certs.py` - New route module with:
    - `/certs/` - List all certificates with status
    - `/certs/generate` - Generate self-signed certificates (signing or TLS)
    - `/certs/import` - Import PEM or PKCS#12 certificates
    - `/certs/view/<name>` - View certificate details (subject, issuer, SANs, key usage)
    - `/certs/download/<name>` - Download certificate as PEM
    - `/certs/delete/<name>` - Delete certificate and key
    - `/certs/validate/<name>` - Validate certificate chain
  - `authtest/web/templates/certs/index.html` - Certificate list with table view
  - `authtest/web/templates/certs/generate.html` - Form for certificate generation
  - `authtest/web/templates/certs/import.html` - Form for importing PEM/PKCS#12
  - `authtest/web/templates/certs/view.html` - Detailed certificate view with all extensions
  - `authtest/web/templates/certs/validate.html` - Chain validation results page
  - `authtest/web/routes/__init__.py` - Registered certs_bp blueprint
  - `authtest/web/templates/base.html` - Added Certificates link to navigation
  - `authtest/web/templates/index.html` - Added Certificates card to dashboard
- **Verification**:
  - Type checks pass (mypy)
  - Linting passes (ruff)
  - All 33 tests pass
  - Routes correctly registered in Flask app
- **Learnings:**
  - Web UI reuses core `authtest.core.crypto` module which already has all certificate functions
  - Flask blueprints need `template_folder` to find templates in subdirectories
  - PKCS#12 format detection can use file extension (.p12, .pfx)
  - Certificate chain validation needs to parse multiple PEM certs from single file
---

## 2026-02-05 - US-032
- **What was implemented**: CLI certificate commands (already complete from previous work)
- **Files verified**:
  - `authtest/cli/certs.py` - Complete CLI with all required commands:
    - `certs generate` - Generate self-signed TLS or signing certs with options for CN, days, output dir
    - `certs import` - Import PEM or PKCS#12 certificates with password support
    - `certs list` - List all certificates in a directory with validity status (VALID/EXPIRED)
    - `certs inspect` - Decode full X.509 details (subject, issuer, validity, SANs, fingerprints)
    - `certs status` - Show current TLS configuration status
  - `authtest/cli/main.py` - Certs command group registered at line 89
  - `authtest/core/crypto/certs.py` - Core crypto functions used by CLI
- **Verification**:
  - Type checks pass (mypy)
  - Linting passes (ruff)
  - All 33 tests pass
  - CLI commands accessible via `authtest certs <command>`
- **Learnings:**
  - CLI already fully implemented as part of earlier crypto/TLS work
  - Click's `path_type=Path` requires `# type: ignore[type-var]` due to typing quirks
  - Certificate status coloring uses `click.style(fg="green"/"red")` for visual feedback
---

