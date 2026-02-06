"""Keycloak IdP preset configuration.

Provides pre-configured templates and discovery support for Keycloak
realms, supporting both SAML and OIDC protocols.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass
class KeycloakConfig:
    """Keycloak-specific configuration parameters.

    Keycloak uses a realm-based architecture where each realm is an
    isolated authentication domain with its own users, clients, and
    identity providers.
    """

    base_url: str
    realm: str

    @property
    def realm_url(self) -> str:
        """Get the full realm URL."""
        return f"{self.base_url.rstrip('/')}/realms/{self.realm}"

    @property
    def saml_entity_id(self) -> str:
        """Get the SAML IdP entity ID."""
        return self.realm_url

    @property
    def saml_sso_url(self) -> str:
        """Get the SAML SSO endpoint (POST binding)."""
        return f"{self.realm_url}/protocol/saml"

    @property
    def saml_slo_url(self) -> str:
        """Get the SAML SLO endpoint."""
        return f"{self.realm_url}/protocol/saml"

    @property
    def saml_metadata_url(self) -> str:
        """Get the SAML IdP metadata URL."""
        return f"{self.realm_url}/protocol/saml/descriptor"

    @property
    def oidc_issuer(self) -> str:
        """Get the OIDC issuer URL."""
        return self.realm_url

    @property
    def oidc_discovery_url(self) -> str:
        """Get the OIDC well-known configuration URL."""
        return f"{self.realm_url}/.well-known/openid-configuration"

    @property
    def oidc_authorization_endpoint(self) -> str:
        """Get the OIDC authorization endpoint."""
        return f"{self.realm_url}/protocol/openid-connect/auth"

    @property
    def oidc_token_endpoint(self) -> str:
        """Get the OIDC token endpoint."""
        return f"{self.realm_url}/protocol/openid-connect/token"

    @property
    def oidc_userinfo_endpoint(self) -> str:
        """Get the OIDC userinfo endpoint."""
        return f"{self.realm_url}/protocol/openid-connect/userinfo"

    @property
    def oidc_jwks_uri(self) -> str:
        """Get the OIDC JWKS URI."""
        return f"{self.realm_url}/protocol/openid-connect/certs"

    @property
    def oidc_logout_endpoint(self) -> str:
        """Get the OIDC logout endpoint."""
        return f"{self.realm_url}/protocol/openid-connect/logout"


def get_saml_preset(base_url: str, realm: str) -> dict[str, Any]:
    """Get SAML IdP configuration preset for Keycloak.

    Args:
        base_url: Keycloak server base URL (e.g., https://keycloak.example.com).
        realm: Keycloak realm name.

    Returns:
        Dictionary with pre-populated SAML configuration fields.
    """
    config = KeycloakConfig(base_url=base_url, realm=realm)
    return {
        "idp_type": "saml",
        "entity_id": config.saml_entity_id,
        "sso_url": config.saml_sso_url,
        "slo_url": config.saml_slo_url,
        "metadata_url": config.saml_metadata_url,
        "settings": {
            "preset": "keycloak",
            "keycloak_base_url": base_url,
            "keycloak_realm": realm,
            # Keycloak default settings
            "sign_authn_requests": True,
            "want_assertions_signed": True,
            "want_response_signed": False,  # Keycloak signs assertions by default
            "name_id_format": "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent",
        },
    }


def get_oidc_preset(base_url: str, realm: str) -> dict[str, Any]:
    """Get OIDC IdP configuration preset for Keycloak.

    Args:
        base_url: Keycloak server base URL (e.g., https://keycloak.example.com).
        realm: Keycloak realm name.

    Returns:
        Dictionary with pre-populated OIDC configuration fields.
    """
    config = KeycloakConfig(base_url=base_url, realm=realm)
    return {
        "idp_type": "oidc",
        "issuer": config.oidc_issuer,
        "authorization_endpoint": config.oidc_authorization_endpoint,
        "token_endpoint": config.oidc_token_endpoint,
        "userinfo_endpoint": config.oidc_userinfo_endpoint,
        "jwks_uri": config.oidc_jwks_uri,
        "settings": {
            "preset": "keycloak",
            "keycloak_base_url": base_url,
            "keycloak_realm": realm,
            "discovery_url": config.oidc_discovery_url,
            "logout_endpoint": config.oidc_logout_endpoint,
            # Keycloak default scopes
            "default_scopes": ["openid", "profile", "email"],
            # Keycloak supports all standard grant types
            "supported_grant_types": [
                "authorization_code",
                "client_credentials",
                "refresh_token",
                "password",
            ],
        },
    }


# Keycloak realm setup documentation
KEYCLOAK_SETUP_GUIDE = """
# Keycloak Realm Setup Guide

This guide walks you through setting up a Keycloak realm for testing with AuthTest.

## Prerequisites

- Keycloak server running (Docker: `docker run -p 8080:8080 quay.io/keycloak/keycloak start-dev`)
- Admin access to the Keycloak console

## 1. Create a Realm

1. Log into the Keycloak Admin Console
2. Hover over the realm name dropdown (top-left)
3. Click "Create Realm"
4. Enter a realm name (e.g., "authtest")
5. Click "Create"

## 2. SAML Client Setup

1. Go to Clients -> Create Client
2. Select "SAML" as client type
3. Enter Client ID (this will be your SP Entity ID):
   - Example: `http://localhost:5000/saml/metadata`
4. Click Next, then configure:
   - **Name**: AuthTest SAML Client
   - **Valid redirect URIs**: `http://localhost:5000/saml/acs`
   - **Home URL**: `http://localhost:5000`
   - **Master SAML Processing URL**: `http://localhost:5000/saml/acs`
5. In the "Keys" tab:
   - Client Signature Required: OFF (or configure signing)
6. In the "Advanced" tab:
   - **Assertion Consumer Service POST Binding URL**: `http://localhost:5000/saml/acs`
   - **Logout Service POST Binding URL**: `http://localhost:5000/saml/slo`

### SAML Attribute Mapping

1. Go to Client -> Client Scopes tab
2. Click on the dedicated scope (e.g., "authtest-saml-dedicated")
3. Add mappers for common attributes:

| Name | Mapper Type | Property | SAML Attribute Name |
|------|-------------|----------|---------------------|
| email | User Property | email | email |
| firstName | User Property | firstName | firstName |
| lastName | User Property | lastName | lastName |
| username | User Property | username | username |

## 3. OIDC Client Setup

1. Go to Clients -> Create Client
2. Select "OpenID Connect" as client type
3. Enter Client ID (e.g., "authtest-oidc")
4. Click Next, configure:
   - **Client authentication**: ON (confidential client)
   - **Authorization**: OFF
5. Click Next, configure:
   - **Valid redirect URIs**: `http://localhost:5000/oidc/callback`
   - **Web origins**: `http://localhost:5000`
6. Click Save
7. In the Credentials tab, copy the Client Secret

### OIDC Scope Mapping

The following scopes are available by default:
- `openid` - Required for OIDC
- `profile` - Name, username, etc.
- `email` - Email address
- `roles` - Realm and client roles

## 4. Create Test Users

1. Go to Users -> Add User
2. Fill in:
   - Username: testuser
   - Email: testuser@example.com
   - First Name: Test
   - Last Name: User
3. Click Create
4. In Credentials tab, set a password:
   - Set "Temporary" to OFF
   - Click "Set Password"

## 5. Export Configuration

### SAML Metadata
Download from: `{realm_url}/protocol/saml/descriptor`

### OIDC Discovery
Fetch from: `{realm_url}/.well-known/openid-configuration`

## Quick Reference URLs

For a Keycloak at `https://keycloak.example.com` with realm `authtest`:

| Endpoint | URL |
|----------|-----|
| SAML Metadata | `https://keycloak.example.com/realms/authtest/protocol/saml/descriptor` |
| SAML SSO | `https://keycloak.example.com/realms/authtest/protocol/saml` |
| OIDC Discovery | `https://keycloak.example.com/realms/authtest/.well-known/openid-configuration` |
| OIDC Auth | `https://keycloak.example.com/realms/authtest/protocol/openid-connect/auth` |
| OIDC Token | `https://keycloak.example.com/realms/authtest/protocol/openid-connect/token` |
| JWKS | `https://keycloak.example.com/realms/authtest/protocol/openid-connect/certs` |

## Troubleshooting

### "Invalid redirect URI"
- Ensure the redirect URI in AuthTest exactly matches what's configured in Keycloak
- Check for trailing slashes

### "Client not found"
- Verify the client ID/entity ID matches exactly
- Check that the client is enabled

### "Invalid signature"
- For SAML: Check that signing settings match between client config and AuthTest
- Download the latest IdP certificate from the realm

### Certificate Download
Get the realm's signing certificate:
1. Go to Realm Settings -> Keys
2. Click the certificate icon next to the active RS256 key
3. Copy the certificate (includes BEGIN/END markers)
"""


def get_setup_guide(base_url: str | None = None, realm: str | None = None) -> str:
    """Get the Keycloak setup guide, optionally customized with URLs.

    Args:
        base_url: Optional Keycloak server URL to customize examples.
        realm: Optional realm name to customize examples.

    Returns:
        Markdown-formatted setup guide.
    """
    guide = KEYCLOAK_SETUP_GUIDE

    if base_url and realm:
        config = KeycloakConfig(base_url=base_url, realm=realm)
        guide = guide.replace("{realm_url}", config.realm_url)

    return guide
