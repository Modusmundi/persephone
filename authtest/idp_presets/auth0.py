"""Auth0 IdP preset configuration.

Provides pre-configured templates and discovery support for Auth0
tenants, supporting both SAML and OIDC protocols.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass
class Auth0Config:
    """Auth0-specific configuration parameters.

    Auth0 uses a tenant-based architecture where each tenant has its own
    subdomain (e.g., mytenant.auth0.com or mytenant.us.auth0.com).
    Applications (called "Applications" in Auth0) are configured within
    the tenant.
    """

    auth0_domain: str  # e.g., "mytenant.auth0.com" or "mytenant.us.auth0.com"
    client_id: str | None = None  # Required for SAML app-specific URLs

    @property
    def base_url(self) -> str:
        """Get the full base URL."""
        domain = self.auth0_domain.rstrip("/")
        if not domain.startswith("https://"):
            domain = f"https://{domain}"
        return domain

    # SAML Properties
    @property
    def saml_entity_id(self) -> str:
        """Get the SAML IdP entity ID (issuer).

        Auth0 uses the format: urn:{domain}
        """
        domain = self.auth0_domain.replace("https://", "").replace("http://", "")
        return f"urn:{domain}"

    @property
    def saml_sso_url(self) -> str:
        """Get the SAML SSO endpoint."""
        return f"{self.base_url}/samlp/{self.client_id}" if self.client_id else f"{self.base_url}/samlp"

    @property
    def saml_slo_url(self) -> str:
        """Get the SAML SLO endpoint."""
        return f"{self.base_url}/samlp/{self.client_id}/logout" if self.client_id else f"{self.base_url}/samlp/logout"

    @property
    def saml_metadata_url(self) -> str:
        """Get the SAML IdP metadata URL."""
        if self.client_id:
            return f"{self.base_url}/samlp/metadata/{self.client_id}"
        return f"{self.base_url}/samlp/metadata"

    # OIDC Properties
    @property
    def oidc_issuer(self) -> str:
        """Get the OIDC issuer URL."""
        return f"{self.base_url}/"

    @property
    def oidc_discovery_url(self) -> str:
        """Get the OIDC well-known configuration URL."""
        return f"{self.base_url}/.well-known/openid-configuration"

    @property
    def oidc_authorization_endpoint(self) -> str:
        """Get the OIDC authorization endpoint."""
        return f"{self.base_url}/authorize"

    @property
    def oidc_token_endpoint(self) -> str:
        """Get the OIDC token endpoint."""
        return f"{self.base_url}/oauth/token"

    @property
    def oidc_userinfo_endpoint(self) -> str:
        """Get the OIDC userinfo endpoint."""
        return f"{self.base_url}/userinfo"

    @property
    def oidc_jwks_uri(self) -> str:
        """Get the OIDC JWKS URI."""
        return f"{self.base_url}/.well-known/jwks.json"

    @property
    def oidc_logout_endpoint(self) -> str:
        """Get the OIDC logout endpoint."""
        return f"{self.base_url}/v2/logout"

    @property
    def oidc_revoke_endpoint(self) -> str:
        """Get the OIDC token revocation endpoint."""
        return f"{self.base_url}/oauth/revoke"

    @property
    def oidc_device_authorization_endpoint(self) -> str:
        """Get the device authorization endpoint for device code flow."""
        return f"{self.base_url}/oauth/device/code"


def get_saml_preset(auth0_domain: str, client_id: str | None = None) -> dict[str, Any]:
    """Get SAML IdP configuration preset for Auth0.

    Args:
        auth0_domain: Auth0 tenant domain (e.g., mytenant.auth0.com).
        client_id: Auth0 Application (client) ID for app-specific URLs.

    Returns:
        Dictionary with pre-populated SAML configuration fields.
    """
    config = Auth0Config(auth0_domain=auth0_domain, client_id=client_id)
    return {
        "idp_type": "saml",
        "entity_id": config.saml_entity_id,
        "sso_url": config.saml_sso_url,
        "slo_url": config.saml_slo_url,
        "metadata_url": config.saml_metadata_url if client_id else None,
        "settings": {
            "preset": "auth0",
            "auth0_domain": auth0_domain,
            "auth0_client_id": client_id,
            # Auth0 default settings
            "sign_authn_requests": False,
            "want_assertions_signed": True,
            "want_response_signed": True,
            "name_id_format": "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
        },
    }


def get_oidc_preset(
    auth0_domain: str,
    audience: str | None = None,
) -> dict[str, Any]:
    """Get OIDC IdP configuration preset for Auth0.

    Args:
        auth0_domain: Auth0 tenant domain (e.g., mytenant.auth0.com).
        audience: API audience identifier for access tokens.

    Returns:
        Dictionary with pre-populated OIDC configuration fields.
    """
    config = Auth0Config(auth0_domain=auth0_domain)

    return {
        "idp_type": "oidc",
        "issuer": config.oidc_issuer,
        "authorization_endpoint": config.oidc_authorization_endpoint,
        "token_endpoint": config.oidc_token_endpoint,
        "userinfo_endpoint": config.oidc_userinfo_endpoint,
        "jwks_uri": config.oidc_jwks_uri,
        "settings": {
            "preset": "auth0",
            "auth0_domain": auth0_domain,
            "audience": audience,
            "discovery_url": config.oidc_discovery_url,
            "logout_endpoint": config.oidc_logout_endpoint,
            "revocation_endpoint": config.oidc_revoke_endpoint,
            "device_authorization_endpoint": config.oidc_device_authorization_endpoint,
            # Auth0 default scopes
            "default_scopes": ["openid", "profile", "email"],
            # Auth0 supports these grant types
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


# Auth0 setup documentation
AUTH0_SETUP_GUIDE = """
# Auth0 Setup Guide

This guide walks you through setting up Auth0 for testing with AuthTest.

## Prerequisites

- An Auth0 account (sign up at https://auth0.com/signup)
- Admin access to your Auth0 tenant

## 1. Auth0 Tenant Overview

Auth0 uses a tenant-based architecture. Your tenant URL will be:
- Default: `https://your-tenant.auth0.com`
- Custom domain: `https://auth.yourcompany.com`
- Regional: `https://your-tenant.us.auth0.com` or `https://your-tenant.eu.auth0.com`

## 2. OIDC Application Setup

1. Log into the Auth0 Dashboard
2. Go to **Applications** > **Applications**
3. Click **Create Application**
4. Select **Regular Web Applications** and click **Create**

### Application Settings

1. In the **Settings** tab:

| Setting | Value |
|---------|-------|
| Name | AuthTest OIDC |
| Application Type | Regular Web Application |
| Allowed Callback URLs | `http://localhost:5000/oidc/callback` |
| Allowed Logout URLs | `http://localhost:5000/` |
| Allowed Web Origins | `http://localhost:5000` |

2. Note these values:
   - **Domain**: Your Auth0 domain (e.g., `mytenant.auth0.com`)
   - **Client ID**: Your application's client ID
   - **Client Secret**: Your application's client secret

3. Click **Save Changes**

### Advanced Settings

In the **Advanced Settings** section:
1. Go to **Grant Types** tab
2. Ensure these are enabled:
   - Authorization Code
   - Refresh Token
   - Client Credentials (if needed)
   - Device Code (for device flow testing)

## 3. SAML Application Setup

1. Go to **Applications** > **Applications**
2. Click **Create Application**
3. Select **Regular Web Applications** and click **Create**
4. Go to **Addons** tab
5. Enable **SAML2 Web App**

### SAML Configuration

In the SAML2 Web App settings:

```json
{
  "audience": "http://localhost:5000/saml/metadata",
  "recipient": "http://localhost:5000/saml/acs",
  "destination": "http://localhost:5000/saml/acs",
  "mappings": {
    "email": "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress",
    "name": "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name",
    "given_name": "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname",
    "family_name": "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname"
  },
  "logout": {
    "callback": "http://localhost:5000/saml/slo"
  }
}
```

Click **Save** and then **Enable**.

### Download SAML Metadata

1. In the SAML2 Web App addon settings
2. Click **Usage** tab
3. Download the **Identity Provider Metadata** or copy the URL

## 4. Create Test Users

### Using Database Connection

1. Go to **User Management** > **Users**
2. Click **Create User**
3. Fill in:
   - Email: `testuser@example.com`
   - Password: (set a password)
   - Connection: Username-Password-Authentication
4. Click **Create**

### Social Connections (Optional)

1. Go to **Authentication** > **Social**
2. Enable providers like Google, GitHub, etc.
3. Configure each with your OAuth credentials

## 5. API Configuration (For Access Tokens)

If you need access tokens with specific audiences:

1. Go to **Applications** > **APIs**
2. Click **Create API**
3. Configure:
   - Name: AuthTest API
   - Identifier: `https://api.authtest.local`
   - Signing Algorithm: RS256
4. Click **Create**

Use this identifier as the `audience` parameter when getting tokens.

## 6. Configure Connections

### Database Connection
1. Go to **Authentication** > **Database**
2. Ensure **Username-Password-Authentication** is enabled
3. In the **Applications** tab, enable it for your application

### Passwordless (Optional)
1. Go to **Authentication** > **Passwordless**
2. Enable **Email** or **SMS** as needed

## Quick Reference URLs

For a tenant at `mytenant.auth0.com`:

### OIDC URLs
| Endpoint | URL |
|----------|-----|
| Discovery | `https://mytenant.auth0.com/.well-known/openid-configuration` |
| Authorize | `https://mytenant.auth0.com/authorize` |
| Token | `https://mytenant.auth0.com/oauth/token` |
| UserInfo | `https://mytenant.auth0.com/userinfo` |
| JWKS | `https://mytenant.auth0.com/.well-known/jwks.json` |
| Logout | `https://mytenant.auth0.com/v2/logout` |
| Device Code | `https://mytenant.auth0.com/oauth/device/code` |

### SAML URLs
| Endpoint | URL |
|----------|-----|
| Metadata | `https://mytenant.auth0.com/samlp/metadata/{clientId}` |
| SSO | `https://mytenant.auth0.com/samlp/{clientId}` |
| SLO | `https://mytenant.auth0.com/samlp/{clientId}/logout` |

## Troubleshooting

### "Callback URL mismatch"
- Ensure callback URLs in Auth0 exactly match AuthTest configuration
- Check for trailing slashes
- Verify http vs https

### "Invalid client" or "Unauthorized client"
- Verify Client ID and Client Secret are correct
- Check the application is not disabled
- Ensure the connection is enabled for the application

### "Access denied"
- User may not be assigned to the application
- Check that the database connection is enabled
- Verify the user exists and is not blocked

### "Invalid audience"
- When requesting access tokens, use the correct API identifier
- Check that the API is created and enabled

### "Invalid scope"
- Auth0 requires `openid` scope for OIDC
- Check that requested scopes are enabled in the API
- Some scopes require the appropriate API audience

### SAML Response Issues
- Verify the SAML addon is enabled
- Check the audience and callback URLs match
- Download the latest IdP certificate

### Token Validation Errors
- Ensure you're using the correct issuer (with trailing slash)
- Verify the JWKS endpoint is accessible
- Check `aud` claim matches your client ID or API identifier

## Auth0 Actions (Optional)

For custom token claims or logic:

1. Go to **Actions** > **Flows**
2. Select **Login** flow
3. Create an action to add custom claims:

```javascript
exports.onExecutePostLogin = async (event, api) => {
  api.idToken.setCustomClaim('custom_claim', 'value');
  api.accessToken.setCustomClaim('custom_claim', 'value');
};
```

## Multi-factor Authentication (Optional)

1. Go to **Security** > **Multi-factor Auth**
2. Enable desired factors (SMS, Email, Authenticator)
3. Configure policies in **Policies** section
"""


def get_setup_guide(auth0_domain: str | None = None) -> str:
    """Get the Auth0 setup guide, optionally customized with URLs.

    Args:
        auth0_domain: Optional Auth0 domain to customize examples.

    Returns:
        Markdown-formatted setup guide.
    """
    guide = AUTH0_SETUP_GUIDE

    if auth0_domain:
        # Normalize domain
        domain = auth0_domain.rstrip("/")
        if domain.startswith("https://"):
            domain = domain[8:]
        if domain.startswith("http://"):
            domain = domain[7:]

        # Replace example domain with actual domain
        guide = guide.replace("mytenant.auth0.com", domain)

    return guide
