"""Google Workspace IdP preset configuration.

Provides pre-configured templates and discovery support for Google Workspace
(formerly G Suite), supporting both SAML and OIDC protocols.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass
class GoogleConfig:
    """Google Workspace-specific configuration parameters.

    Google Workspace uses organization-based architecture. SAML is configured
    per-application in the Admin Console, while OIDC uses Google Cloud Console
    OAuth 2.0 credentials.

    For SAML, Google acts as the IdP and applications are configured as
    custom SAML apps in the Google Admin Console.
    """

    # For SAML: The Google Workspace domain and IdP ID
    google_domain: str | None = None  # e.g., "yourcompany.com"
    idp_id: str | None = None  # The unique IdP entity ID from Google

    @property
    def base_url(self) -> str:
        """Get the Google accounts base URL."""
        return "https://accounts.google.com"

    # SAML Properties (Google as IdP)
    @property
    def saml_entity_id(self) -> str:
        """Get the SAML IdP entity ID.

        Google's IdP entity ID format:
        https://accounts.google.com/o/saml2?idpid={idpid}
        """
        if self.idp_id:
            return f"https://accounts.google.com/o/saml2?idpid={self.idp_id}"
        return "https://accounts.google.com/o/saml2"

    @property
    def saml_sso_url(self) -> str:
        """Get the SAML SSO endpoint.

        Google SSO URL format:
        https://accounts.google.com/o/saml2/idp?idpid={idpid}
        """
        if self.idp_id:
            return f"https://accounts.google.com/o/saml2/idp?idpid={self.idp_id}"
        return "https://accounts.google.com/o/saml2/idp"

    @property
    def saml_slo_url(self) -> str:
        """Get the SAML SLO endpoint.

        Note: Google Workspace supports SLO but it's handled differently.
        """
        return "https://accounts.google.com/Logout"

    @property
    def saml_metadata_url(self) -> str:
        """Get the SAML IdP metadata URL.

        Note: Google provides metadata per custom SAML app in Admin Console.
        The metadata can be downloaded from the app configuration page.
        """
        if self.idp_id:
            return f"https://admin.google.com/ac/apps/unified/{self.idp_id}/saml/metadata"
        return ""

    # OIDC Properties
    @property
    def oidc_issuer(self) -> str:
        """Get the OIDC issuer URL."""
        return "https://accounts.google.com"

    @property
    def oidc_discovery_url(self) -> str:
        """Get the OIDC well-known configuration URL."""
        return "https://accounts.google.com/.well-known/openid-configuration"

    @property
    def oidc_authorization_endpoint(self) -> str:
        """Get the OIDC authorization endpoint."""
        return "https://accounts.google.com/o/oauth2/v2/auth"

    @property
    def oidc_token_endpoint(self) -> str:
        """Get the OIDC token endpoint."""
        return "https://oauth2.googleapis.com/token"

    @property
    def oidc_userinfo_endpoint(self) -> str:
        """Get the OIDC userinfo endpoint."""
        return "https://openidconnect.googleapis.com/v1/userinfo"

    @property
    def oidc_jwks_uri(self) -> str:
        """Get the OIDC JWKS URI."""
        return "https://www.googleapis.com/oauth2/v3/certs"

    @property
    def oidc_logout_endpoint(self) -> str:
        """Get the logout endpoint (revocation)."""
        return "https://oauth2.googleapis.com/revoke"

    @property
    def oidc_device_authorization_endpoint(self) -> str:
        """Get the device authorization endpoint for device code flow."""
        return "https://oauth2.googleapis.com/device/code"


def get_saml_preset(
    idp_id: str | None = None,
    google_domain: str | None = None,
) -> dict[str, Any]:
    """Get SAML IdP configuration preset for Google Workspace.

    Args:
        idp_id: Google IdP ID (found in Admin Console SAML app settings).
        google_domain: Google Workspace domain (e.g., yourcompany.com).

    Returns:
        Dictionary with pre-populated SAML configuration fields.
    """
    config = GoogleConfig(idp_id=idp_id, google_domain=google_domain)
    return {
        "idp_type": "saml",
        "entity_id": config.saml_entity_id,
        "sso_url": config.saml_sso_url,
        "slo_url": config.saml_slo_url,
        "metadata_url": config.saml_metadata_url if idp_id else None,
        "settings": {
            "preset": "google",
            "google_idp_id": idp_id,
            "google_domain": google_domain,
            # Google default settings
            "sign_authn_requests": False,
            "want_assertions_signed": True,
            "want_response_signed": True,
            "name_id_format": "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
        },
    }


def get_oidc_preset(
    hd: str | None = None,
) -> dict[str, Any]:
    """Get OIDC IdP configuration preset for Google.

    Args:
        hd: Hosted domain parameter to restrict to a specific Google
            Workspace domain (e.g., 'yourcompany.com').

    Returns:
        Dictionary with pre-populated OIDC configuration fields.
    """
    config = GoogleConfig(google_domain=hd)

    return {
        "idp_type": "oidc",
        "issuer": config.oidc_issuer,
        "authorization_endpoint": config.oidc_authorization_endpoint,
        "token_endpoint": config.oidc_token_endpoint,
        "userinfo_endpoint": config.oidc_userinfo_endpoint,
        "jwks_uri": config.oidc_jwks_uri,
        "settings": {
            "preset": "google",
            "hosted_domain": hd,
            "discovery_url": config.oidc_discovery_url,
            "revocation_endpoint": config.oidc_logout_endpoint,
            "device_authorization_endpoint": config.oidc_device_authorization_endpoint,
            # Google default scopes
            "default_scopes": ["openid", "profile", "email"],
            # Google supports these grant types
            "supported_grant_types": [
                "authorization_code",
                "refresh_token",
                "device_code",
                "implicit",
            ],
            # Additional parameters
            "auth_params": {
                "hd": hd,  # Restrict to hosted domain
            } if hd else {},
        },
    }


# Google Workspace setup documentation
GOOGLE_SETUP_GUIDE = """
# Google Workspace Setup Guide

This guide walks you through setting up Google Workspace (formerly G Suite)
for testing with AuthTest.

## Prerequisites

- A Google Workspace account with admin access
- Access to Google Cloud Console (for OIDC)
- Access to Google Admin Console (for SAML)

## Part 1: OIDC Setup (Google Cloud Console)

### 1. Create OAuth 2.0 Credentials

1. Go to [Google Cloud Console](https://console.cloud.google.com/)
2. Select or create a project
3. Go to **APIs & Services** > **Credentials**
4. Click **Create Credentials** > **OAuth client ID**

### 2. Configure OAuth Consent Screen (First Time)

If prompted, configure the OAuth consent screen:

1. Select **Internal** (for Workspace users only) or **External**
2. Fill in:
   - App name: AuthTest
   - User support email: Your email
   - Developer contact: Your email
3. Add scopes:
   - `openid`
   - `profile`
   - `email`
4. Complete the wizard

### 3. Create OAuth Client

1. Application type: **Web application**
2. Name: AuthTest OIDC
3. Authorized redirect URIs:
   - `http://localhost:5000/oidc/callback`
4. Click **Create**
5. Note your **Client ID** and **Client Secret**

### Restricting to Your Domain

To restrict authentication to your Google Workspace domain:

1. Use the `hd` (hosted domain) parameter in authorization requests
2. Example: `hd=yourcompany.com`
3. Always verify the `hd` claim in the ID token on your backend

## Part 2: SAML Setup (Google Admin Console)

### 1. Access Admin Console

1. Go to [Google Admin Console](https://admin.google.com/)
2. Sign in with a super admin account

### 2. Add Custom SAML App

1. Go to **Apps** > **Web and mobile apps**
2. Click **Add App** > **Add custom SAML app**

### 3. App Details

| Setting | Value |
|---------|-------|
| App name | AuthTest |
| App icon | (optional) |

Click **Continue**.

### 4. Google Identity Provider Details

This page shows your Google IdP information:

1. Note the **SSO URL**: `https://accounts.google.com/o/saml2/idp?idpid=XXXXXX`
2. Note the **Entity ID**: `https://accounts.google.com/o/saml2?idpid=XXXXXX`
3. Download the **Certificate**
4. (Optional) Download the **IDP metadata**

The `idpid` value (XXXXXX) is your Google IdP ID.

Click **Continue**.

### 5. Service Provider Details

Configure your SP (AuthTest):

| Setting | Value |
|---------|-------|
| ACS URL | `http://localhost:5000/saml/acs` |
| Entity ID | `http://localhost:5000/saml/metadata` |
| Start URL | `http://localhost:5000/` |
| Signed response | ✓ Enabled |
| Name ID format | EMAIL |
| Name ID | Basic Information > Primary email |

Click **Continue**.

### 6. Attribute Mapping

Map user attributes:

| Google Directory attribute | App attribute |
|---------------------------|---------------|
| Basic Information > Primary email | email |
| Basic Information > First name | firstName |
| Basic Information > Last name | lastName |

Click **Finish**.

### 7. Enable the App

1. The app is OFF by default
2. Click the app name in the list
3. Click **User access**
4. Select **ON for everyone** or specific OUs
5. Click **Save**

## Quick Reference URLs

### OIDC URLs (Static for all Google accounts)
| Endpoint | URL |
|----------|-----|
| Discovery | `https://accounts.google.com/.well-known/openid-configuration` |
| Authorize | `https://accounts.google.com/o/oauth2/v2/auth` |
| Token | `https://oauth2.googleapis.com/token` |
| UserInfo | `https://openidconnect.googleapis.com/v1/userinfo` |
| JWKS | `https://www.googleapis.com/oauth2/v3/certs` |
| Revoke | `https://oauth2.googleapis.com/revoke` |
| Device Code | `https://oauth2.googleapis.com/device/code` |

### SAML URLs (Per-app, with your IdP ID)
| Endpoint | URL |
|----------|-----|
| SSO URL | `https://accounts.google.com/o/saml2/idp?idpid={idpid}` |
| Entity ID | `https://accounts.google.com/o/saml2?idpid={idpid}` |
| Metadata | Download from Admin Console |

## Testing Authentication

### OIDC Test

1. Configure AuthTest with:
   - Client ID: (from Cloud Console)
   - Client Secret: (from Cloud Console)
   - Use the Google OIDC preset

2. Optionally add `hd` parameter to restrict to your domain

### SAML Test

1. Configure AuthTest with:
   - IdP Entity ID: `https://accounts.google.com/o/saml2?idpid={your-idpid}`
   - SSO URL: `https://accounts.google.com/o/saml2/idp?idpid={your-idpid}`
   - Certificate: (downloaded from Admin Console)

2. Ensure the SAML app is enabled for test users

## Troubleshooting

### "Access blocked: This app's request is invalid" (Error 400)
- Redirect URI doesn't match OAuth client configuration
- Check for exact match including http/https and trailing slashes

### "Access blocked: AuthTest has not completed the Google verification process"
- For external apps, you need to verify the app or add test users
- Go to OAuth consent screen > Test users

### "This app is blocked" (SAML)
- The SAML app is not enabled for the user's OU
- Check User access settings in Admin Console

### "SAML Response signature verification failed"
- Download the latest certificate from Admin Console
- Ensure you're using the correct IdP ID

### "Invalid hd claim"
- The `hd` claim doesn't match the expected domain
- User may be using a personal Google account
- Verify `hd` claim on your backend, not just in the request

### "User not found"
- User may not exist in Google Workspace
- For SAML, user needs access to the app

### ID Token Claims

Google ID tokens include:
- `sub`: Unique user identifier
- `email`: User's email address
- `email_verified`: Boolean
- `name`: Full name
- `given_name`: First name
- `family_name`: Last name
- `picture`: Profile photo URL
- `hd`: Hosted domain (for Workspace accounts)

## Security Recommendations

1. **Always verify the `hd` claim** on your backend if restricting to a domain
2. Use **Internal** OAuth consent screen for Workspace-only apps
3. Store client secrets securely, never in client-side code
4. Implement proper token validation
5. Consider using [Identity-Aware Proxy](https://cloud.google.com/iap) for additional security
"""


def get_setup_guide(google_domain: str | None = None, idp_id: str | None = None) -> str:
    """Get the Google Workspace setup guide, optionally customized.

    Args:
        google_domain: Optional Google Workspace domain to customize examples.
        idp_id: Optional IdP ID to customize SAML URLs.

    Returns:
        Markdown-formatted setup guide.
    """
    guide = GOOGLE_SETUP_GUIDE

    if idp_id:
        guide = guide.replace("{idpid}", idp_id)
        guide = guide.replace("{your-idpid}", idp_id)

    if google_domain:
        guide = guide.replace("yourcompany.com", google_domain)

    return guide
