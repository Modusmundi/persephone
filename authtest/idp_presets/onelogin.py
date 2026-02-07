"""OneLogin IdP preset configuration.

Provides pre-configured templates and discovery support for OneLogin
identity platform, supporting both SAML and OIDC protocols.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass
class OneLoginConfig:
    """OneLogin-specific configuration parameters.

    OneLogin is a cloud-based identity and access management platform.
    Each organization has a unique subdomain (e.g., company.onelogin.com)
    and applications are configured within the admin console.
    """

    onelogin_subdomain: str  # e.g., "mycompany" (without .onelogin.com)
    app_id: str | None = None  # OneLogin Application ID (for SAML)
    client_id: str | None = None  # OIDC Client ID

    @property
    def base_url(self) -> str:
        """Get the full base URL."""
        subdomain = self.onelogin_subdomain.rstrip("/")
        if ".onelogin.com" in subdomain:
            if not subdomain.startswith("https://"):
                subdomain = f"https://{subdomain}"
            return subdomain
        return f"https://{subdomain}.onelogin.com"

    # SAML Properties
    @property
    def saml_entity_id(self) -> str:
        """Get the SAML IdP entity ID.

        OneLogin uses the format:
        https://app.onelogin.com/saml/metadata/{app_id}
        """
        if self.app_id:
            return f"https://app.onelogin.com/saml/metadata/{self.app_id}"
        return f"{self.base_url}/saml/metadata"

    @property
    def saml_sso_url(self) -> str:
        """Get the SAML SSO endpoint (HTTP-POST or HTTP-Redirect)."""
        subdomain = self._get_subdomain()
        return f"https://{subdomain}.onelogin.com/trust/saml2/http-post/sso"

    @property
    def saml_sso_redirect_url(self) -> str:
        """Get the SAML SSO endpoint (HTTP-Redirect)."""
        subdomain = self._get_subdomain()
        return f"https://{subdomain}.onelogin.com/trust/saml2/http-redirect/sso"

    @property
    def saml_slo_url(self) -> str:
        """Get the SAML SLO endpoint."""
        subdomain = self._get_subdomain()
        return f"https://{subdomain}.onelogin.com/trust/saml2/http-redirect/slo"

    @property
    def saml_metadata_url(self) -> str:
        """Get the SAML IdP metadata URL."""
        if self.app_id:
            return f"https://app.onelogin.com/saml/metadata/{self.app_id}"
        subdomain = self._get_subdomain()
        return f"https://{subdomain}.onelogin.com/saml/metadata"

    # OIDC Properties
    @property
    def oidc_issuer(self) -> str:
        """Get the OIDC issuer URL."""
        subdomain = self._get_subdomain()
        return f"https://{subdomain}.onelogin.com/oidc/2"

    @property
    def oidc_discovery_url(self) -> str:
        """Get the OIDC well-known configuration URL."""
        subdomain = self._get_subdomain()
        return f"https://{subdomain}.onelogin.com/oidc/2/.well-known/openid-configuration"

    @property
    def oidc_authorization_endpoint(self) -> str:
        """Get the OIDC authorization endpoint."""
        subdomain = self._get_subdomain()
        return f"https://{subdomain}.onelogin.com/oidc/2/auth"

    @property
    def oidc_token_endpoint(self) -> str:
        """Get the OIDC token endpoint."""
        subdomain = self._get_subdomain()
        return f"https://{subdomain}.onelogin.com/oidc/2/token"

    @property
    def oidc_userinfo_endpoint(self) -> str:
        """Get the OIDC userinfo endpoint."""
        subdomain = self._get_subdomain()
        return f"https://{subdomain}.onelogin.com/oidc/2/me"

    @property
    def oidc_jwks_uri(self) -> str:
        """Get the OIDC JWKS URI."""
        subdomain = self._get_subdomain()
        return f"https://{subdomain}.onelogin.com/oidc/2/certs"

    @property
    def oidc_logout_endpoint(self) -> str:
        """Get the OIDC logout endpoint."""
        subdomain = self._get_subdomain()
        return f"https://{subdomain}.onelogin.com/oidc/2/logout"

    @property
    def oidc_revoke_endpoint(self) -> str:
        """Get the token revocation endpoint."""
        subdomain = self._get_subdomain()
        return f"https://{subdomain}.onelogin.com/oidc/2/token/revocation"

    @property
    def oidc_introspection_endpoint(self) -> str:
        """Get the token introspection endpoint."""
        subdomain = self._get_subdomain()
        return f"https://{subdomain}.onelogin.com/oidc/2/token/introspection"

    def _get_subdomain(self) -> str:
        """Extract just the subdomain portion."""
        subdomain = self.onelogin_subdomain
        if ".onelogin.com" in subdomain:
            subdomain = subdomain.replace("https://", "").replace("http://", "")
            subdomain = subdomain.split(".onelogin.com")[0]
        return subdomain


def get_saml_preset(
    onelogin_subdomain: str,
    app_id: str | None = None,
) -> dict[str, Any]:
    """Get SAML IdP configuration preset for OneLogin.

    Args:
        onelogin_subdomain: OneLogin subdomain (e.g., "mycompany").
        app_id: OneLogin SAML Application ID for app-specific URLs.

    Returns:
        Dictionary with pre-populated SAML configuration fields.
    """
    config = OneLoginConfig(onelogin_subdomain=onelogin_subdomain, app_id=app_id)
    return {
        "idp_type": "saml",
        "entity_id": config.saml_entity_id,
        "sso_url": config.saml_sso_url,
        "slo_url": config.saml_slo_url,
        "metadata_url": config.saml_metadata_url if app_id else None,
        "settings": {
            "preset": "onelogin",
            "onelogin_subdomain": onelogin_subdomain,
            "onelogin_app_id": app_id,
            "sso_redirect_url": config.saml_sso_redirect_url,
            # OneLogin default settings
            "sign_authn_requests": False,
            "want_assertions_signed": True,
            "want_response_signed": True,
            "name_id_format": "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
        },
    }


def get_oidc_preset(onelogin_subdomain: str) -> dict[str, Any]:
    """Get OIDC IdP configuration preset for OneLogin.

    Args:
        onelogin_subdomain: OneLogin subdomain (e.g., "mycompany").

    Returns:
        Dictionary with pre-populated OIDC configuration fields.
    """
    config = OneLoginConfig(onelogin_subdomain=onelogin_subdomain)

    return {
        "idp_type": "oidc",
        "issuer": config.oidc_issuer,
        "authorization_endpoint": config.oidc_authorization_endpoint,
        "token_endpoint": config.oidc_token_endpoint,
        "userinfo_endpoint": config.oidc_userinfo_endpoint,
        "jwks_uri": config.oidc_jwks_uri,
        "settings": {
            "preset": "onelogin",
            "onelogin_subdomain": onelogin_subdomain,
            "discovery_url": config.oidc_discovery_url,
            "logout_endpoint": config.oidc_logout_endpoint,
            "revocation_endpoint": config.oidc_revoke_endpoint,
            "introspection_endpoint": config.oidc_introspection_endpoint,
            # OneLogin default scopes
            "default_scopes": ["openid", "profile", "email", "groups"],
            # OneLogin supports these grant types
            "supported_grant_types": [
                "authorization_code",
                "client_credentials",
                "refresh_token",
                "password",
                "implicit",
            ],
        },
    }


# OneLogin setup documentation
ONELOGIN_SETUP_GUIDE = """
# OneLogin Setup Guide

This guide walks you through setting up OneLogin for testing with AuthTest.

## Prerequisites

- A OneLogin account (sign up at https://www.onelogin.com/free-trial)
- Admin access to your OneLogin admin console

## 1. OneLogin Overview

OneLogin uses a subdomain-based architecture:
- Admin console: `https://yourcompany.onelogin.com/admin`
- User portal: `https://yourcompany.onelogin.com/portal`
- API: `https://yourcompany.onelogin.com/`

## 2. SAML Application Setup

### Create SAML Application

1. Log into the OneLogin Admin Console
2. Go to **Applications** > **Add App**
3. Search for "SAML Custom Connector (Advanced)"
4. Select and click **Save**

### Configure Application

In the **Configuration** tab:

| Setting | Value |
|---------|-------|
| Display Name | AuthTest SAML |
| Visible in portal | Yes |
| Logo | (optional) |

### SAML Configuration

In the **Configuration** tab, continue:

| Setting | Value |
|---------|-------|
| Audience (EntityID) | `http://localhost:5000/saml/metadata` |
| Recipient | `http://localhost:5000/saml/acs` |
| ACS (Consumer) URL | `http://localhost:5000/saml/acs` |
| ACS (Consumer) URL Validator | `.*` |
| Single Logout URL | `http://localhost:5000/saml/slo` |
| SAML signature element | Both (Response and Assertion) |
| SAML nameID format | Email |

Click **Save**.

### SSO Tab

Note these values from the **SSO** tab:
- **Issuer URL** (IdP Entity ID)
- **SAML 2.0 Endpoint (HTTP)** (SSO URL)
- **SLO Endpoint (HTTP)**
- **X.509 Certificate** (Download)

Or use the **More Actions** > **SAML Metadata** to download metadata XML.

### Parameters (Attribute Mapping)

Add custom parameters for attribute mapping:

1. Click **Parameters** > **Add Parameter**
2. Add mappings:

| Field name | OneLogin field |
|------------|----------------|
| email | Email |
| firstName | First Name |
| lastName | Last Name |
| displayName | Name |

Check **Include in SAML assertion** for each.

### Access Control

1. Go to **Access** tab
2. Configure which roles/groups can access the app

## 3. OIDC Application Setup

### Create OIDC Application

1. Go to **Applications** > **Add App**
2. Search for "OpenId Connect" or "OIDC"
3. Select **OpenId Connect (OIDC)** and click **Save**

### Configure Application

In the **Configuration** tab:

| Setting | Value |
|---------|-------|
| Login URL | `http://localhost:5000/` |
| Redirect URIs | `http://localhost:5000/oidc/callback` |
| Post Logout Redirect URIs | `http://localhost:5000/` |
| Token Endpoint Authentication Method | POST |
| Application Type | Web |

Click **Save**.

### SSO Tab

Note these values from the **SSO** tab:
- **Client ID**
- **Client Secret** (click eye icon to reveal)

### Scopes

Configure available scopes:
- ✓ openid (required)
- ✓ profile
- ✓ email
- ✓ groups (optional)

## 4. Create Test Users

### Add User

1. Go to **Users** > **New User**
2. Fill in:
   - First Name: Test
   - Last Name: User
   - Email: testuser@example.com
   - Username: testuser@example.com
3. Click **Save User**

### Set Password

1. In the user profile, go to **Authentication**
2. Set a password or send a password reset email

### Assign Application

1. In the user profile, go to **Applications**
2. Click **+** to add the application
3. Select your SAML or OIDC app

## 5. Roles and Groups (Optional)

### Create Role

1. Go to **Users** > **Roles** > **New Role**
2. Name: AuthTest Users
3. Assign applications to the role
4. Assign users to the role

### Create Group

1. Go to **Users** > **Groups** > **New Group**
2. Configure group settings
3. Groups can be synced to OIDC `groups` claim

## Quick Reference URLs

For a OneLogin subdomain `mycompany`:

### SAML URLs
| Endpoint | URL |
|----------|-----|
| Metadata | `https://app.onelogin.com/saml/metadata/{app_id}` |
| SSO (POST) | `https://mycompany.onelogin.com/trust/saml2/http-post/sso` |
| SSO (Redirect) | `https://mycompany.onelogin.com/trust/saml2/http-redirect/sso` |
| SLO | `https://mycompany.onelogin.com/trust/saml2/http-redirect/slo` |

### OIDC URLs
| Endpoint | URL |
|----------|-----|
| Discovery | `https://mycompany.onelogin.com/oidc/2/.well-known/openid-configuration` |
| Authorize | `https://mycompany.onelogin.com/oidc/2/auth` |
| Token | `https://mycompany.onelogin.com/oidc/2/token` |
| UserInfo | `https://mycompany.onelogin.com/oidc/2/me` |
| JWKS | `https://mycompany.onelogin.com/oidc/2/certs` |
| Logout | `https://mycompany.onelogin.com/oidc/2/logout` |
| Revocation | `https://mycompany.onelogin.com/oidc/2/token/revocation` |

## Troubleshooting

### "The response was received at a different URL than expected"
- ACS URL doesn't match what's configured
- Check for trailing slashes
- Verify http vs https

### "Audience restriction check failed"
- Entity ID doesn't match
- Check the Audience field in SAML configuration

### "User is not authorized for this application"
- User not assigned to the application
- Check user's Applications tab or role assignments

### "Invalid redirect_uri"
- Redirect URI not in allowed list
- Check exact match including scheme and path

### "Invalid client credentials"
- Client ID or Secret is incorrect
- Regenerate secret if needed

### "Invalid scope"
- Requested scope not enabled for the application
- Check Scopes configuration in SSO tab

### SAML Certificate Issues
- Download the latest certificate from SSO tab
- Certificates can be rotated; keep them updated

### User Cannot Log In
- Check user status (Active vs Suspended)
- Verify password policy compliance
- Check authentication factors

## OneLogin API (Advanced)

OneLogin provides APIs for automation:

### API Credentials

1. Go to **Developers** > **API Credentials**
2. Create new credentials with appropriate scopes
3. Use for automation and integrations

### Common API Operations

```bash
# Get access token
curl -X POST https://mycompany.onelogin.com/auth/oauth2/v2/token \\
  -H "Content-Type: application/x-www-form-urlencoded" \\
  -d "grant_type=client_credentials&client_id=xxx&client_secret=xxx"

# List users
curl -X GET https://mycompany.onelogin.com/api/2/users \\
  -H "Authorization: Bearer {access_token}"
```

## Multi-Factor Authentication

### Configure MFA

1. Go to **Security** > **Authentication Factors**
2. Enable desired factors:
   - OneLogin Protect (push)
   - Authenticator apps (TOTP)
   - SMS
   - Email
   - Security questions

### Apply MFA Policy

1. Go to **Security** > **Authentication Policies**
2. Create or edit a policy
3. Configure MFA requirements
4. Apply to user groups
"""


def get_setup_guide(onelogin_subdomain: str | None = None) -> str:
    """Get the OneLogin setup guide, optionally customized with URLs.

    Args:
        onelogin_subdomain: Optional OneLogin subdomain to customize examples.

    Returns:
        Markdown-formatted setup guide.
    """
    guide = ONELOGIN_SETUP_GUIDE

    if onelogin_subdomain:
        subdomain = onelogin_subdomain
        if ".onelogin.com" in subdomain:
            subdomain = subdomain.replace("https://", "").replace("http://", "")
            subdomain = subdomain.split(".onelogin.com")[0]

        guide = guide.replace("mycompany", subdomain)

    return guide
