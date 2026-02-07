"""JumpCloud IdP preset configuration.

Provides pre-configured templates and discovery support for JumpCloud
identity management platform, supporting both SAML and OIDC protocols.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass
class JumpCloudConfig:
    """JumpCloud-specific configuration parameters.

    JumpCloud is a cloud directory platform that provides identity and
    access management. It supports SAML 2.0 and OpenID Connect for
    SSO applications.

    JumpCloud uses organization-based architecture where each org
    has its own applications and users.
    """

    org_id: str | None = None  # JumpCloud Organization ID
    app_id: str | None = None  # Application ID for SAML

    @property
    def base_url(self) -> str:
        """Get the JumpCloud base URL."""
        return "https://sso.jumpcloud.com"

    # SAML Properties
    @property
    def saml_entity_id(self) -> str:
        """Get the SAML IdP entity ID.

        JumpCloud uses the format:
        https://sso.jumpcloud.com/saml2/{app_id or org_id}
        """
        if self.app_id:
            return f"https://sso.jumpcloud.com/saml2/{self.app_id}"
        if self.org_id:
            return f"https://sso.jumpcloud.com/saml2/{self.org_id}"
        return "https://sso.jumpcloud.com/saml2"

    @property
    def saml_sso_url(self) -> str:
        """Get the SAML SSO endpoint (POST binding)."""
        if self.app_id:
            return f"https://sso.jumpcloud.com/saml2/{self.app_id}"
        return "https://sso.jumpcloud.com/saml2/sso"

    @property
    def saml_slo_url(self) -> str:
        """Get the SAML SLO endpoint.

        Note: JumpCloud SAML SLO support varies by configuration.
        """
        return "https://sso.jumpcloud.com/saml2/slo"

    @property
    def saml_metadata_url(self) -> str:
        """Get the SAML IdP metadata URL.

        Note: JumpCloud provides metadata per-application in the admin console.
        """
        if self.app_id:
            return f"https://sso.jumpcloud.com/saml2/{self.app_id}/metadata"
        return ""

    # OIDC Properties
    @property
    def oidc_issuer(self) -> str:
        """Get the OIDC issuer URL."""
        return "https://oauth.id.jumpcloud.com/"

    @property
    def oidc_discovery_url(self) -> str:
        """Get the OIDC well-known configuration URL."""
        return "https://oauth.id.jumpcloud.com/.well-known/openid-configuration"

    @property
    def oidc_authorization_endpoint(self) -> str:
        """Get the OIDC authorization endpoint."""
        return "https://oauth.id.jumpcloud.com/oauth2/auth"

    @property
    def oidc_token_endpoint(self) -> str:
        """Get the OIDC token endpoint."""
        return "https://oauth.id.jumpcloud.com/oauth2/token"

    @property
    def oidc_userinfo_endpoint(self) -> str:
        """Get the OIDC userinfo endpoint."""
        return "https://oauth.id.jumpcloud.com/userinfo"

    @property
    def oidc_jwks_uri(self) -> str:
        """Get the OIDC JWKS URI."""
        return "https://oauth.id.jumpcloud.com/.well-known/jwks.json"

    @property
    def oidc_logout_endpoint(self) -> str:
        """Get the OIDC logout endpoint."""
        return "https://oauth.id.jumpcloud.com/oauth2/sessions/logout"

    @property
    def oidc_revoke_endpoint(self) -> str:
        """Get the token revocation endpoint."""
        return "https://oauth.id.jumpcloud.com/oauth2/revoke"


def get_saml_preset(
    app_id: str | None = None,
    org_id: str | None = None,
) -> dict[str, Any]:
    """Get SAML IdP configuration preset for JumpCloud.

    Args:
        app_id: JumpCloud SAML Application ID.
        org_id: JumpCloud Organization ID.

    Returns:
        Dictionary with pre-populated SAML configuration fields.
    """
    config = JumpCloudConfig(app_id=app_id, org_id=org_id)
    return {
        "idp_type": "saml",
        "entity_id": config.saml_entity_id,
        "sso_url": config.saml_sso_url,
        "slo_url": config.saml_slo_url,
        "metadata_url": config.saml_metadata_url if app_id else None,
        "settings": {
            "preset": "jumpcloud",
            "jumpcloud_app_id": app_id,
            "jumpcloud_org_id": org_id,
            # JumpCloud default settings
            "sign_authn_requests": False,
            "want_assertions_signed": True,
            "want_response_signed": True,
            "name_id_format": "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
        },
    }


def get_oidc_preset() -> dict[str, Any]:
    """Get OIDC IdP configuration preset for JumpCloud.

    Returns:
        Dictionary with pre-populated OIDC configuration fields.

    Note:
        JumpCloud OIDC uses a centralized OAuth domain (oauth.id.jumpcloud.com)
        that is shared across all organizations.
    """
    config = JumpCloudConfig()

    return {
        "idp_type": "oidc",
        "issuer": config.oidc_issuer,
        "authorization_endpoint": config.oidc_authorization_endpoint,
        "token_endpoint": config.oidc_token_endpoint,
        "userinfo_endpoint": config.oidc_userinfo_endpoint,
        "jwks_uri": config.oidc_jwks_uri,
        "settings": {
            "preset": "jumpcloud",
            "discovery_url": config.oidc_discovery_url,
            "logout_endpoint": config.oidc_logout_endpoint,
            "revocation_endpoint": config.oidc_revoke_endpoint,
            # JumpCloud default scopes
            "default_scopes": ["openid", "profile", "email"],
            # JumpCloud supports these grant types
            "supported_grant_types": [
                "authorization_code",
                "refresh_token",
                "implicit",
            ],
        },
    }


# JumpCloud setup documentation
JUMPCLOUD_SETUP_GUIDE = """
# JumpCloud Setup Guide

This guide walks you through setting up JumpCloud for testing with AuthTest.

## Prerequisites

- A JumpCloud account (sign up at https://jumpcloud.com/signup)
- Admin access to your JumpCloud organization

## 1. JumpCloud Overview

JumpCloud provides cloud directory services with:
- User and device management
- SSO applications (SAML and OIDC)
- LDAP and RADIUS services
- Conditional access policies

Access the admin console at: https://console.jumpcloud.com

## 2. SAML Application Setup

### Create SAML Application

1. Log into the JumpCloud Admin Console
2. Go to **SSO** (Applications) in the left menu
3. Click **+ Add New Application**
4. Select **Custom SAML App**

### General Settings

| Setting | Value |
|---------|-------|
| Display Label | AuthTest |
| Logo | (optional) |
| Show this application in User Portal | Yes |

### SSO Tab - Identity Provider Configuration

These values are provided by JumpCloud:
- **IdP Entity ID**: Copy this value
- **IDP URL**: Copy the SSO URL
- **IDP Certificate**: Download this

### SSO Tab - Service Provider Configuration

| Setting | Value |
|---------|-------|
| SP Entity ID | `http://localhost:5000/saml/metadata` |
| ACS URL | `http://localhost:5000/saml/acs` |
| SAMLSubject's NameID | Email |
| SAMLSubject's NameID Format | emailAddress |
| Signature Algorithm | RSA-SHA256 |
| Sign Assertion | Yes |
| Sign Response | Yes |
| Login URL | `http://localhost:5000/saml/login` |

### Attribute Mapping

Add constant or user attributes:

1. Click **add attribute**
2. Add mappings:

| Service Provider Attribute | JumpCloud Attribute |
|---------------------------|---------------------|
| email | email |
| firstName | firstname |
| lastName | lastname |
| displayName | displayname |

### Groups Tab

1. Select which groups can access this application
2. Or select specific users in the **User Groups** tab

Click **Activate** to enable the application.

## 3. OIDC Application Setup

### Create OIDC Application

1. Go to **SSO** (Applications)
2. Click **+ Add New Application**
3. Search for and select **Custom OIDC App**

### General Settings

| Setting | Value |
|---------|-------|
| Display Label | AuthTest OIDC |
| Show this application in User Portal | Yes |

### SSO Tab - OAuth/OIDC Settings

| Setting | Value |
|---------|-------|
| Redirect URIs | `http://localhost:5000/oidc/callback` |
| Login URL | `http://localhost:5000/` |
| Client Authentication Type | Client Secret Basic (or Post) |
| Grant Types | ✓ Authorization Code, ✓ Refresh Token |

### SSO Tab - Client Credentials

Note these values:
- **Client ID**: Copy this
- **Client Secret**: Click to reveal and copy

### Attribute Mapping (Claims)

Standard OIDC claims are included by default:
- `sub` (user ID)
- `email`
- `name`
- `given_name`
- `family_name`

### Groups Tab

Configure which groups can access this application.

Click **Activate** to enable the application.

## 4. Create Test Users

### Add User

1. Go to **User Management** > **Users**
2. Click **+ Add New User**
3. Fill in:
   - Username: testuser
   - Email: testuser@example.com
   - First Name: Test
   - Last Name: User
4. Configure password or send activation email
5. Click **Create**

### Assign to Groups

1. Select the user
2. Go to **User Groups** tab
3. Add to groups that have access to your SSO apps

### Activate User

Ensure the user is **Active** and has completed account setup.

## 5. User Groups

### Create Group

1. Go to **User Management** > **User Groups**
2. Click **+ New User Group**
3. Name: AuthTest Users
4. Add users to the group
5. Save

### Grant Application Access

1. Go to **SSO** > Select your app
2. Go to **User Groups** tab
3. Select the group

## Quick Reference URLs

### SAML URLs (Per-Application)
| Endpoint | URL |
|----------|-----|
| Entity ID | `https://sso.jumpcloud.com/saml2/{app_id}` |
| SSO URL | `https://sso.jumpcloud.com/saml2/{app_id}` |
| Metadata | Download from admin console |

### OIDC URLs (Global)
| Endpoint | URL |
|----------|-----|
| Discovery | `https://oauth.id.jumpcloud.com/.well-known/openid-configuration` |
| Authorize | `https://oauth.id.jumpcloud.com/oauth2/auth` |
| Token | `https://oauth.id.jumpcloud.com/oauth2/token` |
| UserInfo | `https://oauth.id.jumpcloud.com/userinfo` |
| JWKS | `https://oauth.id.jumpcloud.com/.well-known/jwks.json` |
| Logout | `https://oauth.id.jumpcloud.com/oauth2/sessions/logout` |

## Troubleshooting

### "SAML response validation failed"
- Check SP Entity ID matches exactly
- Verify ACS URL is correct
- Download fresh IdP certificate

### "User not authorized for application"
- User not in a group with app access
- Check User Groups tab on the application
- Verify user is Active

### "Invalid redirect URI"
- Add the exact redirect URI to the OIDC app
- Check for trailing slashes
- Verify http vs https

### "Invalid client credentials"
- Verify Client ID and Client Secret
- Check client authentication type (Basic vs POST)

### "User not found"
- User may not exist in JumpCloud
- Check user status (Active, Staged, etc.)
- Verify email/username

### Certificate Issues
- Download latest certificate from app settings
- JumpCloud may rotate certificates

### SSO Loop or Redirect Issues
- Check Login URL configuration
- Verify browser cookies are enabled
- Clear browser session/cookies

## JumpCloud API (Advanced)

### API Keys

1. Go to your avatar > **My API Key**
2. Or create a system/service account API key

### Common API Operations

```bash
# List users
curl -X GET "https://console.jumpcloud.com/api/systemusers" \\
  -H "x-api-key: YOUR_API_KEY" \\
  -H "Content-Type: application/json"

# Get organization info
curl -X GET "https://console.jumpcloud.com/api/organizations" \\
  -H "x-api-key: YOUR_API_KEY" \\
  -H "Content-Type: application/json"
```

## Multi-Factor Authentication

### Configure MFA

1. Go to **Security** > **MFA**
2. Enable MFA for your organization
3. Configure allowed methods:
   - TOTP (Authenticator apps)
   - Push (JumpCloud Protect)
   - WebAuthn (Security keys)

### Require MFA for SSO Apps

1. Go to the SSO Application
2. Enable **Require MFA**
3. Users will be prompted for MFA during SSO

## Conditional Access

### Create Policy

1. Go to **Security** > **Conditional Access**
2. Click **+ Add Policy**
3. Configure conditions:
   - User groups
   - Device trust
   - Network location
   - MFA requirements

### Apply to Applications

Policies can be applied to:
- Specific SSO applications
- All SSO applications
- User Portal access

## Device Trust (Optional)

For enhanced security:
1. Deploy JumpCloud agent to devices
2. Configure Device Trust policies
3. Require managed devices for SSO access
"""


def get_setup_guide(app_id: str | None = None) -> str:
    """Get the JumpCloud setup guide, optionally customized with URLs.

    Args:
        app_id: Optional JumpCloud application ID to customize examples.

    Returns:
        Markdown-formatted setup guide.
    """
    guide = JUMPCLOUD_SETUP_GUIDE

    if app_id:
        guide = guide.replace("{app_id}", app_id)

    return guide
