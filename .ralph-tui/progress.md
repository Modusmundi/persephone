# Ralph Progress Log

This file tracks progress across iterations. Agents update this file
after each iteration and it's included in prompts for context.

## Codebase Patterns (Study These First)

- **Flask Blueprint Pattern**: Routes are organized in blueprints under `authtest/web/routes/`. Each protocol (SAML, OIDC) gets its own blueprint with `url_prefix`.
- **Template Organization**: Templates live in `authtest/web/templates/` with subdirectories per feature (e.g., `saml/`).
- **Database Session Pattern**: Use `db.get_session()` in try/finally blocks, always close session in finally.
- **Flow State Pattern**: Multi-step authentication flows store state in Flask session as dicts via `to_dict()`/`from_dict()`.
- **Use `datetime.UTC`**: Import `UTC` from datetime (not `timezone.utc`) per ruff UP017 preference.

- **IdP-Initiated Flow Pattern**: For unsolicited assertions, identify the IdP by parsing the Issuer from the SAML Response and looking it up by `entity_id` in the database.
- **Template Filter Pattern**: Use `@blueprint.app_template_filter('filter_name')` to register Jinja2 filters scoped to a blueprint. Use `markupsafe.Markup` for HTML-safe filter returns.
- **XML Signature Validation Pattern**: Use `signxml.XMLVerifier` for cryptographic signature validation. Parse XML with `lxml.etree` for namespace-aware signature element extraction.

---

## 2026-02-05 - US-010
- **What was implemented**: SAML signature validation against IdP X.509 certificates with detailed debug output.
- **Files changed**:
  - `authtest/core/saml/signature.py` - New module with:
    - `SignatureValidationResult` dataclass for comprehensive validation results
    - `SignatureInfo` for per-signature metadata (algorithm, digest, c14n method)
    - `validate_signature()` function using signxml library
    - Support for RSA-SHA1/256/384/512, DSA, ECDSA signature algorithms
    - Debug trace logging for step-by-step validation tracking
    - Friendly algorithm name mappings
  - `authtest/core/saml/sp.py` - Updated `SAMLResponse` dataclass and `process_response()` to include signature validation
  - `authtest/core/saml/flows.py` - Added `_signature_validation_to_dict()` for storing validation results
  - `authtest/core/saml/__init__.py` - Export new signature types
  - `authtest/web/templates/saml/result.html` - Added signature validation display section with:
    - Status icon (valid/invalid/missing/unchecked/error)
    - Signature details (algorithm, digest, canonicalization)
    - Warnings for deprecated algorithms (SHA-1)
    - Collapsible debug trace for troubleshooting
  - `pyproject.toml` - Added signxml>=4.0.0 and lxml>=5.0.0 dependencies
- **Learnings:**
  - signxml returns `VerifyResult` or `list[VerifyResult]`; handle both cases
  - Use `getattr()` with fallback for accessing VerifyResult attributes safely
  - IdP certificate can be stored with or without PEM headers; normalize before use
  - `lxml.etree.fromstring()` requires bytes, not str
  - Signature can be at Response or Assertion level; SAML allows both
  - SHA-1 signatures are deprecated but still common; warn rather than fail
---

## 2026-02-05 - US-009
- **What was implemented**: SAML assertion decoding and display with enhanced visualization features.
- **Files changed**:
  - `authtest/core/saml/utils.py` - Added XML pretty-printing, SAML attribute descriptions, NameID format descriptions, and AuthnContext descriptions
  - `authtest/web/routes/saml.py` - Added template filters for XML pretty-print, syntax highlighting, and SAML metadata lookups
  - `authtest/web/templates/saml/result.html` - Completely revamped with:
    - XML syntax highlighting (VS Code-style colors, light/dark mode support)
    - Authentication flow timeline with visual status indicators
    - Enhanced attribute table with friendly names and descriptions
    - NameID format and AuthnContext descriptions
    - Copy-to-clipboard functionality for XML
- **Learnings:**
  - Use `xml.dom.minidom.parseString().toprettyxml()` for XML pretty-printing
  - For simple syntax highlighting, regex-based HTML generation works well without external dependencies
  - `markupsafe.Markup()` wraps HTML strings to mark them safe for Jinja2 rendering
  - CSS timeline patterns: use `::before` pseudo-element for the vertical line, positioned dots for events
  - Common SAML attribute URIs follow patterns: `urn:oid:*` (LDAP OIDs), `http://schemas.xmlsoap.org/ws/2005/05/identity/claims/*` (WS-Federation), and simple names (Okta-style)
---

## 2026-02-05 - US-008
- **What was implemented**: SAML IdP-Initiated SSO flow for receiving and processing unsolicited assertions from IdPs.
- **Files changed**:
  - `authtest/core/saml/flows.py` - Added `IdPInitiatedFlow` class and renamed `SPInitiatedFlowResult` to generic `FlowResult`
  - `authtest/web/routes/saml.py` - Updated ACS endpoint to handle both SP-Initiated and IdP-Initiated flows, added `/idp-initiated` route
  - `authtest/web/templates/saml/idp_initiated.html` - New template with IdP configuration instructions
  - `authtest/web/templates/saml/index.html` - Enabled IdP-Initiated SSO section (was "Coming Soon")
  - `authtest/web/templates/saml/result.html` - Added flow_type awareness for proper labeling
- **Learnings:**
  - IdP-Initiated flows have no session state since there's no prior AuthnRequest
  - Must identify IdP from the Issuer element in the SAML Response
  - InResponseTo should NOT be present in IdP-Initiated responses (it's a validation check)
  - Can reuse most of the SAMLServiceProvider code; main difference is flow orchestration
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

