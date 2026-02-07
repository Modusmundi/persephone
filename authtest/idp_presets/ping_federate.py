"""PingFederate IdP preset configuration.

Provides pre-configured templates and discovery support for PingFederate
identity servers, supporting both SAML and OIDC protocols.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass
class PingFederateConfig:
    """PingFederate-specific configuration parameters.

    PingFederate is an enterprise federation server that supports
    SAML, OIDC, and WS-Federation protocols. It uses a server-based
    architecture where applications (SP connections) are configured
    within the PingFederate admin console.
    """

    base_url: str  # e.g., "https://sso.example.com" or "https://sso.example.com:9031"

    @property
    def _base(self) -> str:
        """Get the normalized base URL."""
        return self.base_url.rstrip("/")

    # SAML Properties
    @property
    def saml_entity_id(self) -> str:
        """Get the SAML IdP entity ID.

        Default PingFederate entity ID is the base URL.
        Can be customized in Server Configuration > Server Settings.
        """
        return self._base

    @property
    def saml_sso_url(self) -> str:
        """Get the SAML SSO endpoint (POST/Redirect binding)."""
        return f"{self._base}/idp/SSO.saml2"

    @property
    def saml_slo_url(self) -> str:
        """Get the SAML SLO endpoint."""
        return f"{self._base}/idp/SLO.saml2"

    @property
    def saml_metadata_url(self) -> str:
        """Get the SAML IdP metadata URL."""
        return f"{self._base}/pf/federation_metadata.ping?PartnerIdpId={self._base}"

    @property
    def saml_artifact_resolution_url(self) -> str:
        """Get the SAML artifact resolution endpoint."""
        return f"{self._base}/idp/ARS.saml2"

    # OIDC Properties
    @property
    def oidc_issuer(self) -> str:
        """Get the OIDC issuer URL."""
        return self._base

    @property
    def oidc_discovery_url(self) -> str:
        """Get the OIDC well-known configuration URL."""
        return f"{self._base}/.well-known/openid-configuration"

    @property
    def oidc_authorization_endpoint(self) -> str:
        """Get the OIDC authorization endpoint."""
        return f"{self._base}/as/authorization.oauth2"

    @property
    def oidc_token_endpoint(self) -> str:
        """Get the OIDC token endpoint."""
        return f"{self._base}/as/token.oauth2"

    @property
    def oidc_userinfo_endpoint(self) -> str:
        """Get the OIDC userinfo endpoint."""
        return f"{self._base}/idp/userinfo.openid"

    @property
    def oidc_jwks_uri(self) -> str:
        """Get the OIDC JWKS URI."""
        return f"{self._base}/pf/JWKS"

    @property
    def oidc_logout_endpoint(self) -> str:
        """Get the OIDC logout (end session) endpoint."""
        return f"{self._base}/idp/startSLO.ping"

    @property
    def oidc_revoke_endpoint(self) -> str:
        """Get the token revocation endpoint."""
        return f"{self._base}/as/revoke_token.oauth2"

    @property
    def oidc_introspection_endpoint(self) -> str:
        """Get the token introspection endpoint."""
        return f"{self._base}/as/introspect.oauth2"

    @property
    def oidc_device_authorization_endpoint(self) -> str:
        """Get the device authorization endpoint."""
        return f"{self._base}/as/device_authz.oauth2"


def get_saml_preset(base_url: str) -> dict[str, Any]:
    """Get SAML IdP configuration preset for PingFederate.

    Args:
        base_url: PingFederate server base URL.

    Returns:
        Dictionary with pre-populated SAML configuration fields.
    """
    config = PingFederateConfig(base_url=base_url)
    return {
        "idp_type": "saml",
        "entity_id": config.saml_entity_id,
        "sso_url": config.saml_sso_url,
        "slo_url": config.saml_slo_url,
        "metadata_url": config.saml_metadata_url,
        "settings": {
            "preset": "ping_federate",
            "ping_base_url": base_url,
            "artifact_resolution_url": config.saml_artifact_resolution_url,
            # PingFederate default settings
            "sign_authn_requests": True,
            "want_assertions_signed": True,
            "want_response_signed": True,
            "name_id_format": "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified",
        },
    }


def get_oidc_preset(base_url: str) -> dict[str, Any]:
    """Get OIDC IdP configuration preset for PingFederate.

    Args:
        base_url: PingFederate server base URL.

    Returns:
        Dictionary with pre-populated OIDC configuration fields.
    """
    config = PingFederateConfig(base_url=base_url)

    return {
        "idp_type": "oidc",
        "issuer": config.oidc_issuer,
        "authorization_endpoint": config.oidc_authorization_endpoint,
        "token_endpoint": config.oidc_token_endpoint,
        "userinfo_endpoint": config.oidc_userinfo_endpoint,
        "jwks_uri": config.oidc_jwks_uri,
        "settings": {
            "preset": "ping_federate",
            "ping_base_url": base_url,
            "discovery_url": config.oidc_discovery_url,
            "logout_endpoint": config.oidc_logout_endpoint,
            "revocation_endpoint": config.oidc_revoke_endpoint,
            "introspection_endpoint": config.oidc_introspection_endpoint,
            "device_authorization_endpoint": config.oidc_device_authorization_endpoint,
            # PingFederate default scopes
            "default_scopes": ["openid", "profile", "email"],
            # PingFederate supports these grant types (configurable)
            "supported_grant_types": [
                "authorization_code",
                "client_credentials",
                "refresh_token",
                "password",
                "device_code",
                "implicit",
            ],
        },
    }


# PingFederate setup documentation
PING_FEDERATE_SETUP_GUIDE = """
# PingFederate Setup Guide

This guide walks you through setting up PingFederate for testing with AuthTest.

## Prerequisites

- PingFederate server installed and running
- Admin access to PingFederate admin console
- License for SAML and/or OAuth/OIDC features

## 1. PingFederate Overview

PingFederate uses these concepts:
- **IdP Adapter**: Authenticates users (e.g., HTML Form Adapter)
- **SP Connection**: SAML Service Provider configuration
- **OAuth Client**: OIDC/OAuth 2.0 application
- **Access Token Manager**: Manages OAuth token generation

Default ports:
- Admin console: 9999 (HTTPS)
- Runtime: 9031 (HTTPS)

## 2. SAML SP Connection Setup

### Create SP Connection

1. Go to **Identity Provider** > **SP Connections**
2. Click **Create New**

### Connection Type
- Select **Browser SSO Profiles**
- Protocol: **SAML 2.0**

### Connection Options
- Enable:
  - ✓ Browser SSO
  - ✓ Attribute Query (optional)

### General Info
| Setting | Value |
|---------|-------|
| Partner's Entity ID | `http://localhost:5000/saml/metadata` |
| Connection Name | AuthTest |
| Virtual Server IDs | (leave blank or configure) |

### Browser SSO Configuration

#### SAML Profiles
Enable:
- ✓ IdP-Initiated SSO
- ✓ SP-Initiated SSO

#### Assertion Lifetime
| Setting | Value |
|---------|-------|
| Minutes Before | 5 |
| Minutes After | 5 |

#### Assertion Creation

1. **Identity Mapping**: Standard
2. **Attribute Contract**:
   - Extend with: `email`, `firstName`, `lastName`

3. **Authentication Source Mapping**:
   - Adapter Instance: HTML Form Adapter (or your adapter)
   - Map attributes from user directory

#### Protocol Settings

**Assertion Consumer Service (ACS) URL**:
| Binding | Endpoint URL | Index |
|---------|-------------|-------|
| POST | `http://localhost:5000/saml/acs` | 0 (Default) |

**Allowable SAML Bindings**:
- ✓ POST
- ✓ Redirect (optional)

**Signature Policy**:
| Setting | Value |
|---------|-------|
| Sign Response | As Required |
| Sign Assertion | Always |

**Encryption Policy**: None (or configure as needed)

### Credentials

#### Signing Certificate
- Select your IdP signing certificate

#### Signature Verification (for signed AuthnRequests)
- Import SP certificate if signing is required

### Activation & Summary
- Connection Status: **Active**
- Review and save

## 3. OIDC Client Setup

### Create OAuth Client

1. Go to **OAuth Settings** > **Client Management**
2. Click **Add Client**

### Client Configuration

| Setting | Value |
|---------|-------|
| Client ID | `authtest-client` |
| Name | AuthTest OIDC |
| Client Authentication | Client Secret |
| Client Secret | (generate or set) |

### Redirect URIs
Add: `http://localhost:5000/oidc/callback`

### Allowed Grant Types
Enable:
- ✓ Authorization Code
- ✓ Refresh Token
- ✓ Device Authorization (for device flow)
- ✓ Client Credentials (if needed)

### Default Access Token Manager
Select your configured Access Token Manager

### OpenID Connect Settings

1. **ID Token Signing Algorithm**: RS256
2. **ID Token Content**: Select policy for claims

### Scopes
Allow: `openid`, `profile`, `email`

## 4. Access Token Manager Setup

1. Go to **OAuth Settings** > **Access Token Management**
2. Create or select an Access Token Manager

### Configuration

| Setting | Value |
|---------|-------|
| Type | JSON Web Token |
| Name | JWT Token Manager |

### Token Configuration
| Setting | Value |
|---------|-------|
| Token Lifetime | 60 (minutes) |
| Signing Algorithm | RS256 |

### Attribute Contract
Add claims: `sub`, `email`, `name`

## 5. Create Test Users

### Using Local Identity

1. Go to **Data Store** > Your data store
2. Add test users with required attributes

### Using LDAP/AD

1. Configure LDAP Data Store under **Data & Credential Stores**
2. Map attributes in your IdP Adapter

## Quick Reference URLs

For PingFederate at `https://sso.example.com`:

### SAML URLs
| Endpoint | URL |
|----------|-----|
| Metadata | `https://sso.example.com/pf/federation_metadata.ping?PartnerIdpId={entityId}` |
| SSO (POST) | `https://sso.example.com/idp/SSO.saml2` |
| SSO (Redirect) | `https://sso.example.com/idp/SSO.saml2` |
| SLO | `https://sso.example.com/idp/SLO.saml2` |
| Artifact Resolution | `https://sso.example.com/idp/ARS.saml2` |

### OIDC/OAuth URLs
| Endpoint | URL |
|----------|-----|
| Discovery | `https://sso.example.com/.well-known/openid-configuration` |
| Authorize | `https://sso.example.com/as/authorization.oauth2` |
| Token | `https://sso.example.com/as/token.oauth2` |
| UserInfo | `https://sso.example.com/idp/userinfo.openid` |
| JWKS | `https://sso.example.com/pf/JWKS` |
| Logout | `https://sso.example.com/idp/startSLO.ping` |
| Revoke | `https://sso.example.com/as/revoke_token.oauth2` |
| Introspect | `https://sso.example.com/as/introspect.oauth2` |
| Device Auth | `https://sso.example.com/as/device_authz.oauth2` |

## Troubleshooting

### "Unable to find SP connection"
- Verify Partner Entity ID matches exactly
- Check SP Connection is Active
- Ensure Virtual Server IDs are correct

### "Invalid redirect_uri"
- Check redirect URI matches OAuth client configuration exactly
- Include or exclude trailing slashes consistently

### "User not found" or Authentication Fails
- Check IdP Adapter configuration
- Verify data store connection
- Test adapter mapping in isolation

### "Invalid signature" (SAML)
- Verify signing certificate is configured
- Check certificate hasn't expired
- Ensure algorithm matches (RSA-SHA256)

### "Access token validation failed"
- Check Access Token Manager configuration
- Verify JWKS endpoint is accessible
- Check token expiration

### "Scope not allowed"
- Configure allowed scopes in OAuth client
- Check scope-to-policy mappings

### Debug Logging

Enable debug logging:
1. Go to **Server Configuration** > **Log Settings**
2. Set appropriate log levels for OAuth and SAML

Check logs at:
- `<PF_HOME>/log/server.log`
- `<PF_HOME>/log/audit.log`

## Advanced Configuration

### Custom Token Claims

1. Create Token Attribute Mapping in Access Token Manager
2. Map user attributes to token claims

### Multi-Factor Authentication

1. Configure Authentication Selector
2. Chain adapters in Authentication Policy

### Attribute Query (SAML)

1. Enable Attribute Query in SP Connection
2. Configure Attribute Authority in IdP settings

## Certificate Management

### Export IdP Certificate

1. Go to **Security** > **Signing & Decryption Keys & Certificates**
2. Export your signing certificate
3. Provide to SP for signature verification

### Import SP Certificate

1. Go to **Security** > **Trusted CAs**
2. Import SP's signing certificate (if required)
"""


def get_setup_guide(base_url: str | None = None) -> str:
    """Get the PingFederate setup guide, optionally customized with URLs.

    Args:
        base_url: Optional PingFederate server URL to customize examples.

    Returns:
        Markdown-formatted setup guide.
    """
    guide = PING_FEDERATE_SETUP_GUIDE

    if base_url:
        url = base_url.rstrip("/")
        guide = guide.replace("https://sso.example.com", url)

    return guide
