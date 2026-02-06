"""Okta IdP preset configuration.

Provides pre-configured templates and discovery support for Okta
organizations, supporting both SAML and OIDC protocols.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass
class OktaConfig:
    """Okta-specific configuration parameters.

    Okta uses an organization-based architecture where each org has
    its own subdomain (e.g., dev-123456.okta.com or company.okta.com).
    Applications are configured within the org.
    """

    okta_domain: str  # e.g., "dev-123456.okta.com" or "company.okta.com"
    app_id: str | None = None  # For SAML app-specific URLs

    @property
    def base_url(self) -> str:
        """Get the full base URL."""
        domain = self.okta_domain.rstrip("/")
        if not domain.startswith("https://"):
            domain = f"https://{domain}"
        return domain

    @property
    def saml_entity_id(self) -> str:
        """Get the SAML IdP entity ID (issuer)."""
        return f"{self.base_url}"

    @property
    def saml_sso_url(self) -> str:
        """Get the SAML SSO endpoint.

        Okta uses app-specific SSO URLs with the format:
        https://{domain}/app/{app_name}/{app_id}/sso/saml
        For generic IdP-initiated: https://{domain}/app/template_saml_2_0/{app_id}/sso/saml
        """
        if self.app_id:
            return f"{self.base_url}/app/template_saml_2_0/{self.app_id}/sso/saml"
        return f"{self.base_url}/app/saml2/sso"

    @property
    def saml_slo_url(self) -> str:
        """Get the SAML SLO endpoint."""
        return f"{self.base_url}/app/saml2/slo"

    @property
    def saml_metadata_url(self) -> str:
        """Get the SAML IdP metadata URL.

        Okta provides metadata at: /app/{app_id}/sso/saml/metadata
        or the org-level metadata at /app/exk.../sso/saml/metadata
        """
        if self.app_id:
            return f"{self.base_url}/app/{self.app_id}/sso/saml/metadata"
        # Generic org-level SAML metadata endpoint
        return f"{self.base_url}/api/v1/apps"

    @property
    def oidc_issuer(self) -> str:
        """Get the OIDC issuer URL.

        Okta uses org-level issuer or custom authorization server issuer:
        - Org: https://{domain}
        - Custom: https://{domain}/oauth2/{authServerId}
        - Default: https://{domain}/oauth2/default
        """
        return self.base_url

    @property
    def oidc_discovery_url(self) -> str:
        """Get the OIDC well-known configuration URL."""
        return f"{self.base_url}/.well-known/openid-configuration"

    @property
    def oidc_authorization_endpoint(self) -> str:
        """Get the OIDC authorization endpoint."""
        return f"{self.base_url}/oauth2/v1/authorize"

    @property
    def oidc_token_endpoint(self) -> str:
        """Get the OIDC token endpoint."""
        return f"{self.base_url}/oauth2/v1/token"

    @property
    def oidc_userinfo_endpoint(self) -> str:
        """Get the OIDC userinfo endpoint."""
        return f"{self.base_url}/oauth2/v1/userinfo"

    @property
    def oidc_jwks_uri(self) -> str:
        """Get the OIDC JWKS URI."""
        return f"{self.base_url}/oauth2/v1/keys"

    @property
    def oidc_logout_endpoint(self) -> str:
        """Get the OIDC logout endpoint."""
        return f"{self.base_url}/oauth2/v1/logout"

    @property
    def oidc_revoke_endpoint(self) -> str:
        """Get the OIDC token revocation endpoint."""
        return f"{self.base_url}/oauth2/v1/revoke"

    @property
    def oidc_introspect_endpoint(self) -> str:
        """Get the OIDC token introspection endpoint."""
        return f"{self.base_url}/oauth2/v1/introspect"


def get_saml_preset(okta_domain: str, app_id: str | None = None) -> dict[str, Any]:
    """Get SAML IdP configuration preset for Okta.

    Args:
        okta_domain: Okta org domain (e.g., dev-123456.okta.com).
        app_id: Optional Okta SAML app ID for app-specific URLs.

    Returns:
        Dictionary with pre-populated SAML configuration fields.
    """
    config = OktaConfig(okta_domain=okta_domain, app_id=app_id)
    return {
        "idp_type": "saml",
        "entity_id": config.saml_entity_id,
        "sso_url": config.saml_sso_url,
        "slo_url": config.saml_slo_url,
        "metadata_url": config.saml_metadata_url if app_id else None,
        "settings": {
            "preset": "okta",
            "okta_domain": okta_domain,
            "okta_app_id": app_id,
            # Okta default settings
            "sign_authn_requests": True,
            "want_assertions_signed": True,
            "want_response_signed": True,
            "name_id_format": "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
        },
    }


def get_oidc_preset(
    okta_domain: str,
    authorization_server: str = "default",
) -> dict[str, Any]:
    """Get OIDC IdP configuration preset for Okta.

    Args:
        okta_domain: Okta org domain (e.g., dev-123456.okta.com).
        authorization_server: Authorization server ID. Use "default" for the
            default authorization server, or a custom server ID.
            Use "org" for the org authorization server (limited scopes).

    Returns:
        Dictionary with pre-populated OIDC configuration fields.
    """
    config = OktaConfig(okta_domain=okta_domain)

    # Determine base path based on authorization server
    if authorization_server == "org":
        # Org authorization server (limited functionality)
        auth_base = config.base_url
        issuer = config.base_url
    else:
        # Custom or default authorization server
        auth_base = f"{config.base_url}/oauth2/{authorization_server}"
        issuer = auth_base

    return {
        "idp_type": "oidc",
        "issuer": issuer,
        "authorization_endpoint": f"{auth_base}/v1/authorize",
        "token_endpoint": f"{auth_base}/v1/token",
        "userinfo_endpoint": f"{auth_base}/v1/userinfo",
        "jwks_uri": f"{auth_base}/v1/keys",
        "settings": {
            "preset": "okta",
            "okta_domain": okta_domain,
            "authorization_server": authorization_server,
            "discovery_url": f"{auth_base}/.well-known/openid-configuration",
            "logout_endpoint": f"{auth_base}/v1/logout",
            "revocation_endpoint": f"{auth_base}/v1/revoke",
            "introspection_endpoint": f"{auth_base}/v1/introspect",
            # Okta default scopes
            "default_scopes": ["openid", "profile", "email"],
            # Okta supports these grant types
            "supported_grant_types": [
                "authorization_code",
                "client_credentials",
                "refresh_token",
                "password",
                "implicit",
            ],
        },
    }


# Okta organization setup documentation
OKTA_SETUP_GUIDE = """
# Okta Organization Setup Guide

This guide walks you through setting up Okta for testing with AuthTest.

## Prerequisites

- An Okta organization (sign up at https://developer.okta.com/signup/)
- Admin access to the Okta Admin Console

## 1. Okta Organization Overview

Okta provides a cloud-based identity platform. Your Okta domain will be:
- Developer org: `dev-XXXXXX.okta.com`
- Production org: `yourcompany.okta.com` or custom domain

## 2. SAML Application Setup

1. Log into the Okta Admin Console
2. Go to **Applications** > **Applications**
3. Click **Create App Integration**
4. Select **SAML 2.0** and click **Next**

### General Settings
- **App name**: AuthTest SAML
- **App logo**: (optional)
- Click **Next**

### SAML Settings
Configure these settings:

| Setting | Value |
|---------|-------|
| Single sign on URL | `http://localhost:5000/saml/acs` |
| Recipient URL | `http://localhost:5000/saml/acs` |
| Destination URL | `http://localhost:5000/saml/acs` |
| Audience URI (SP Entity ID) | `http://localhost:5000/saml/metadata` |
| Default RelayState | (leave blank) |
| Name ID format | EmailAddress |
| Application username | Email |

### Attribute Statements
Add these attribute mappings:

| Name | Name format | Value |
|------|-------------|-------|
| email | Unspecified | user.email |
| firstName | Unspecified | user.firstName |
| lastName | Unspecified | user.lastName |
| displayName | Unspecified | user.displayName |

Click **Next**, then select **I'm an Okta customer** and click **Finish**.

### Get SAML Configuration
1. In the application's **Sign On** tab
2. Scroll to **SAML Signing Certificates**
3. Click **View SAML setup instructions**
4. Note the following:
   - **Identity Provider Single Sign-On URL**
   - **Identity Provider Issuer**
   - **X.509 Certificate**

Or use the **Metadata URL** (under **SAML Signing Certificates** > **Actions** > **View IdP metadata**).

## 3. OIDC Application Setup

1. Go to **Applications** > **Applications**
2. Click **Create App Integration**
3. Select **OIDC - OpenID Connect**
4. Select **Web Application** and click **Next**

### App Settings
| Setting | Value |
|---------|-------|
| App integration name | AuthTest OIDC |
| Grant type | ✓ Authorization Code |
| Sign-in redirect URIs | `http://localhost:5000/oidc/callback` |
| Sign-out redirect URIs | `http://localhost:5000/` |
| Controlled access | Allow everyone (or specific groups) |

Click **Save**.

### Get Client Credentials
1. In the application's **General** tab
2. Copy:
   - **Client ID**
   - **Client Secret** (generate if needed)

### Authorization Servers
Okta has two types of authorization servers:

1. **Org Authorization Server** (limited)
   - URL: `https://{yourOktaDomain}`
   - Only supports `openid`, `profile`, `email`, `address`, `phone` scopes
   - Cannot add custom scopes or claims

2. **Custom Authorization Server** (recommended)
   - Default: `https://{yourOktaDomain}/oauth2/default`
   - Custom: `https://{yourOktaDomain}/oauth2/{authServerId}`
   - Supports custom scopes and claims
   - Go to **Security** > **API** > **Authorization Servers** to view/create

## 4. Create Test Users

1. Go to **Directory** > **People**
2. Click **Add Person**
3. Fill in:
   - First name: Test
   - Last name: User
   - Username: testuser@example.com
   - Primary email: testuser@example.com
4. Select password option:
   - **Set by user** or **Set by admin**
5. Click **Save**

### Assign User to Application
1. Go to **Applications** > **Applications**
2. Select your application
3. Go to **Assignments** tab
4. Click **Assign** > **Assign to People**
5. Select the test user and click **Assign**

## 5. OIDC Scopes Configuration

For custom authorization servers, configure scopes:

1. Go to **Security** > **API** > **Authorization Servers**
2. Select your authorization server (e.g., "default")
3. Go to **Scopes** tab
4. Verify these scopes exist:
   - `openid` - Required for OIDC
   - `profile` - Name, username, etc.
   - `email` - Email address
   - `groups` - Group membership (optional)

### Add Custom Claims
1. In the authorization server, go to **Claims** tab
2. Click **Add Claim**
3. Example claim:
   - Name: `groups`
   - Include in token type: ID Token, Always
   - Value type: Groups
   - Filter: Matches regex `.*`

## Quick Reference URLs

For an Okta org at `dev-123456.okta.com`:

### SAML URLs
| Endpoint | URL |
|----------|-----|
| Metadata | `https://dev-123456.okta.com/app/{appId}/sso/saml/metadata` |
| SSO | `https://dev-123456.okta.com/app/{appName}/{appId}/sso/saml` |

### OIDC URLs (Default Authorization Server)
| Endpoint | URL |
|----------|-----|
| Discovery | `https://dev-123456.okta.com/oauth2/default/.well-known/openid-configuration` |
| Authorize | `https://dev-123456.okta.com/oauth2/default/v1/authorize` |
| Token | `https://dev-123456.okta.com/oauth2/default/v1/token` |
| UserInfo | `https://dev-123456.okta.com/oauth2/default/v1/userinfo` |
| JWKS | `https://dev-123456.okta.com/oauth2/default/v1/keys` |
| Logout | `https://dev-123456.okta.com/oauth2/default/v1/logout` |

### OIDC URLs (Org Authorization Server)
| Endpoint | URL |
|----------|-----|
| Discovery | `https://dev-123456.okta.com/.well-known/openid-configuration` |
| Authorize | `https://dev-123456.okta.com/oauth2/v1/authorize` |
| Token | `https://dev-123456.okta.com/oauth2/v1/token` |
| UserInfo | `https://dev-123456.okta.com/oauth2/v1/userinfo` |
| JWKS | `https://dev-123456.okta.com/oauth2/v1/keys` |

## Troubleshooting

### "Invalid redirect URI"
- Ensure redirect URIs in AuthTest exactly match Okta configuration
- Check for trailing slashes
- Verify you're using the correct protocol (http vs https)

### "Client authentication failed"
- Verify Client ID and Client Secret are correct
- Ensure the application is active (not deactivated)
- Check the client authentication method matches

### "User is not assigned to the client application"
- Go to the application's Assignments tab
- Assign the user or a group containing the user

### "Invalid scope"
- Org authorization server only supports standard OIDC scopes
- Use a custom authorization server for additional scopes
- Verify the scope is configured in Security > API > Authorization Servers

### "Invalid token" or JWT validation errors
- Ensure you're using the correct authorization server's JWKS endpoint
- Check the `aud` claim matches your client ID
- Verify the `iss` claim matches the authorization server URL

### SAML Response Errors
- Download and verify the IdP certificate
- Check Name ID format matches between IdP and SP
- Verify ACS URL is correctly configured
"""


def get_setup_guide(okta_domain: str | None = None) -> str:
    """Get the Okta setup guide, optionally customized with URLs.

    Args:
        okta_domain: Optional Okta domain to customize examples.

    Returns:
        Markdown-formatted setup guide.
    """
    guide = OKTA_SETUP_GUIDE

    if okta_domain:
        # Normalize domain
        domain = okta_domain.rstrip("/")
        if domain.startswith("https://"):
            domain = domain[8:]
        if domain.startswith("http://"):
            domain = domain[7:]

        # Replace example domain with actual domain
        guide = guide.replace("dev-123456.okta.com", domain)

    return guide
