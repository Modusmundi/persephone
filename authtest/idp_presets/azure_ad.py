"""Azure AD / Entra ID preset configuration.

Provides pre-configured templates and discovery support for Microsoft
Entra ID (formerly Azure AD), supporting both SAML and OIDC protocols.

Azure AD supports multiple tenant configurations:
- Single-tenant: Only users from a specific tenant
- Multi-tenant: Users from any Azure AD tenant
- Multi-tenant + Personal: Azure AD + personal Microsoft accounts
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass
class AzureADConfig:
    """Azure AD / Entra ID specific configuration parameters.

    Azure AD uses a tenant-based architecture. Each tenant has a unique
    tenant ID (GUID) or domain name. Applications are registered within
    a tenant but can be configured to accept users from other tenants.

    The v2.0 endpoints are recommended and support both Azure AD and
    personal Microsoft accounts.
    """

    tenant_id: str  # e.g., "contoso.onmicrosoft.com", "12345678-1234-1234-1234-123456789abc", "common", "organizations", "consumers"
    use_v2_endpoints: bool = True  # Use v2.0 endpoints (recommended)

    @property
    def base_url(self) -> str:
        """Get the Azure AD login base URL."""
        return "https://login.microsoftonline.com"

    @property
    def tenant_url(self) -> str:
        """Get the tenant-specific URL."""
        return f"{self.base_url}/{self.tenant_id}"

    @property
    def oauth2_url(self) -> str:
        """Get the OAuth2 endpoint base URL."""
        if self.use_v2_endpoints:
            return f"{self.tenant_url}/oauth2/v2.0"
        return f"{self.tenant_url}/oauth2"

    # SAML Properties
    @property
    def saml_entity_id(self) -> str:
        """Get the SAML IdP entity ID (issuer).

        For Azure AD, the entity ID format is:
        https://sts.windows.net/{tenant_id}/
        """
        return f"https://sts.windows.net/{self.tenant_id}/"

    @property
    def saml_sso_url(self) -> str:
        """Get the SAML SSO endpoint.

        Azure AD SAML endpoint for POST binding.
        """
        return f"{self.tenant_url}/saml2"

    @property
    def saml_slo_url(self) -> str:
        """Get the SAML SLO endpoint."""
        return f"{self.tenant_url}/saml2"

    @property
    def saml_metadata_url(self) -> str:
        """Get the SAML federation metadata URL.

        Azure AD provides metadata at:
        https://login.microsoftonline.com/{tenant}/federationmetadata/2007-06/federationmetadata.xml
        """
        return f"{self.tenant_url}/federationmetadata/2007-06/federationmetadata.xml"

    # OIDC Properties
    @property
    def oidc_issuer(self) -> str:
        """Get the OIDC issuer URL.

        v2.0: https://login.microsoftonline.com/{tenant}/v2.0
        v1.0: https://sts.windows.net/{tenant}/
        """
        if self.use_v2_endpoints:
            return f"{self.tenant_url}/v2.0"
        return f"https://sts.windows.net/{self.tenant_id}/"

    @property
    def oidc_discovery_url(self) -> str:
        """Get the OIDC well-known configuration URL."""
        return f"{self.oauth2_url}/.well-known/openid-configuration"

    @property
    def oidc_authorization_endpoint(self) -> str:
        """Get the OIDC authorization endpoint."""
        return f"{self.oauth2_url}/authorize"

    @property
    def oidc_token_endpoint(self) -> str:
        """Get the OIDC token endpoint."""
        return f"{self.oauth2_url}/token"

    @property
    def oidc_userinfo_endpoint(self) -> str:
        """Get the OIDC userinfo endpoint.

        Note: Azure AD's userinfo endpoint returns limited data.
        For richer user data, use the Microsoft Graph API.
        """
        return "https://graph.microsoft.com/oidc/userinfo"

    @property
    def oidc_jwks_uri(self) -> str:
        """Get the OIDC JWKS URI."""
        return f"{self.oauth2_url}/keys"

    @property
    def oidc_logout_endpoint(self) -> str:
        """Get the OIDC logout endpoint."""
        return f"{self.oauth2_url}/logout"

    @property
    def oidc_device_authorization_endpoint(self) -> str:
        """Get the device authorization endpoint for device code flow."""
        return f"{self.oauth2_url}/devicecode"

    @property
    def graph_api_url(self) -> str:
        """Get the Microsoft Graph API base URL."""
        return "https://graph.microsoft.com/v1.0"


def get_saml_preset(
    tenant_id: str,
) -> dict[str, Any]:
    """Get SAML IdP configuration preset for Azure AD.

    Args:
        tenant_id: Azure AD tenant ID, domain, or special values
            (common, organizations, consumers).

    Returns:
        Dictionary with pre-populated SAML configuration fields.
    """
    config = AzureADConfig(tenant_id=tenant_id)
    return {
        "idp_type": "saml",
        "entity_id": config.saml_entity_id,
        "sso_url": config.saml_sso_url,
        "slo_url": config.saml_slo_url,
        "metadata_url": config.saml_metadata_url,
        "settings": {
            "preset": "azure_ad",
            "azure_tenant_id": tenant_id,
            # Azure AD default settings
            "sign_authn_requests": True,
            "want_assertions_signed": True,
            "want_response_signed": True,
            "name_id_format": "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
        },
    }


def get_oidc_preset(
    tenant_id: str,
    use_v2_endpoints: bool = True,
) -> dict[str, Any]:
    """Get OIDC IdP configuration preset for Azure AD.

    Args:
        tenant_id: Azure AD tenant ID, domain, or special values:
            - Specific tenant: "contoso.onmicrosoft.com" or GUID
            - Multi-tenant work/school: "organizations"
            - Multi-tenant + personal: "common"
            - Personal accounts only: "consumers"
        use_v2_endpoints: Use v2.0 endpoints (recommended, default True).

    Returns:
        Dictionary with pre-populated OIDC configuration fields.
    """
    config = AzureADConfig(tenant_id=tenant_id, use_v2_endpoints=use_v2_endpoints)

    return {
        "idp_type": "oidc",
        "issuer": config.oidc_issuer,
        "authorization_endpoint": config.oidc_authorization_endpoint,
        "token_endpoint": config.oidc_token_endpoint,
        "userinfo_endpoint": config.oidc_userinfo_endpoint,
        "jwks_uri": config.oidc_jwks_uri,
        "settings": {
            "preset": "azure_ad",
            "azure_tenant_id": tenant_id,
            "use_v2_endpoints": use_v2_endpoints,
            "discovery_url": config.oidc_discovery_url,
            "logout_endpoint": config.oidc_logout_endpoint,
            "device_authorization_endpoint": config.oidc_device_authorization_endpoint,
            # Azure AD default scopes
            "default_scopes": ["openid", "profile", "email"],
            # Azure AD supports these grant types (v2.0)
            "supported_grant_types": [
                "authorization_code",
                "client_credentials",
                "refresh_token",
                "password",
                "device_code",
                "implicit",
            ],
            # Multi-tenant info
            "tenant_type": _get_tenant_type(tenant_id),
        },
    }


def _get_tenant_type(tenant_id: str) -> str:
    """Determine the tenant type based on tenant_id value."""
    tenant_lower = tenant_id.lower()
    if tenant_lower == "common":
        return "multi-tenant-all"
    if tenant_lower == "organizations":
        return "multi-tenant-work-school"
    if tenant_lower == "consumers":
        return "personal-accounts"
    return "single-tenant"


# Azure AD / Entra ID setup documentation
AZURE_AD_SETUP_GUIDE = """
# Azure AD / Microsoft Entra ID Setup Guide

This guide walks you through setting up Azure AD (now Microsoft Entra ID)
for testing with AuthTest.

## Prerequisites

- An Azure subscription with Azure AD access
- Admin access to the Azure portal (https://portal.azure.com)
- Or access to the Entra admin center (https://entra.microsoft.com)

## 1. Tenant Configuration Options

Azure AD supports different authentication scopes:

| Tenant Value | Who Can Sign In |
|--------------|-----------------|
| `{tenant-id}` | Only users from your specific tenant |
| `organizations` | Users from any Azure AD tenant (work/school accounts) |
| `common` | Azure AD users + personal Microsoft accounts |
| `consumers` | Only personal Microsoft accounts (outlook.com, etc.) |

Your tenant ID can be:
- A GUID: `12345678-1234-1234-1234-123456789abc`
- A domain: `contoso.onmicrosoft.com` or `contoso.com`

## 2. Register an Application

1. Go to the [Azure Portal](https://portal.azure.com)
2. Navigate to **Microsoft Entra ID** > **App registrations**
3. Click **New registration**

### Registration Settings

| Setting | Value |
|---------|-------|
| Name | AuthTest |
| Supported account types | Choose based on your needs (see Tenant Configuration) |
| Redirect URI (Web) | `http://localhost:5000/oidc/callback` |

Click **Register**.

### Note Your Application Details

After registration, note these values from the **Overview** page:
- **Application (client) ID**: This is your client_id
- **Directory (tenant) ID**: This is your tenant_id

## 3. Configure Authentication

1. Go to **Authentication** in the left menu
2. Under **Platform configurations**, click **Add a platform**
3. Select **Web**

### Configure Web Platform

| Setting | Value |
|---------|-------|
| Redirect URIs | `http://localhost:5000/oidc/callback` |
| Front-channel logout URL | `http://localhost:5000/` |
| ID tokens | ✓ Enable (for implicit flow testing) |
| Access tokens | ✓ Enable (for implicit flow testing) |

Click **Configure**.

### Additional Redirect URIs (Optional)

For SAML testing, add:
- `http://localhost:5000/saml/acs`

## 4. Create a Client Secret

1. Go to **Certificates & secrets**
2. Click **New client secret**
3. Add a description (e.g., "AuthTest Dev")
4. Choose an expiration period
5. Click **Add**

**Important**: Copy the secret value immediately - it won't be shown again!

## 5. Configure API Permissions

1. Go to **API permissions**
2. Click **Add a permission**
3. Select **Microsoft Graph**
4. Choose **Delegated permissions**
5. Add these permissions:
   - `openid` (Sign users in)
   - `profile` (View users' basic profile)
   - `email` (View users' email address)
   - `User.Read` (Sign in and read user profile)

6. Click **Grant admin consent for {your-tenant}** (if available)

### Optional Permissions

For additional functionality:
- `offline_access` - For refresh tokens
- `User.ReadBasic.All` - Read basic profiles of all users

## 6. SAML Configuration (Optional)

For SAML-based authentication:

1. Go to **Enterprise applications** > **New application**
2. Click **Create your own application**
3. Name: AuthTest SAML
4. Select "Integrate any other application you don't find in the gallery (Non-gallery)"
5. Click **Create**

### Configure SAML SSO

1. In the enterprise application, go to **Single sign-on**
2. Select **SAML**
3. Edit **Basic SAML Configuration**:

| Setting | Value |
|---------|-------|
| Identifier (Entity ID) | `http://localhost:5000/saml/metadata` |
| Reply URL (ACS URL) | `http://localhost:5000/saml/acs` |
| Sign on URL | `http://localhost:5000/saml/login` |
| Logout URL | `http://localhost:5000/saml/slo` |

4. Click **Save**

### Download SAML Certificate

1. In **SAML Signing Certificate**, download **Certificate (Base64)**
2. Or use the **Federation Metadata XML** URL

### Attribute Mapping

Default claims sent by Azure AD:
- `http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress`
- `http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname`
- `http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname`
- `http://schemas.microsoft.com/identity/claims/displayname`

## 7. Create Test Users

### For Single-Tenant Apps

1. Go to **Microsoft Entra ID** > **Users**
2. Click **New user** > **Create new user**
3. Fill in:
   - User principal name: `testuser@yourdomain.onmicrosoft.com`
   - Display name: Test User
   - Password: (auto-generate or set)
4. Click **Create**

### Assign User to Application

1. Go to **Enterprise applications** > Your application
2. Go to **Users and groups**
3. Click **Add user/group**
4. Select users and assign

## Quick Reference URLs

For a tenant `contoso.onmicrosoft.com` (or tenant ID):

### OIDC URLs (v2.0 Endpoints - Recommended)
| Endpoint | URL |
|----------|-----|
| Discovery | `https://login.microsoftonline.com/{tenant}/v2.0/.well-known/openid-configuration` |
| Authorize | `https://login.microsoftonline.com/{tenant}/oauth2/v2.0/authorize` |
| Token | `https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token` |
| UserInfo | `https://graph.microsoft.com/oidc/userinfo` |
| JWKS | `https://login.microsoftonline.com/{tenant}/discovery/v2.0/keys` |
| Logout | `https://login.microsoftonline.com/{tenant}/oauth2/v2.0/logout` |

### OIDC URLs (v1.0 Endpoints - Legacy)
| Endpoint | URL |
|----------|-----|
| Discovery | `https://login.microsoftonline.com/{tenant}/.well-known/openid-configuration` |
| Authorize | `https://login.microsoftonline.com/{tenant}/oauth2/authorize` |
| Token | `https://login.microsoftonline.com/{tenant}/oauth2/token` |
| JWKS | `https://login.microsoftonline.com/common/discovery/keys` |

### SAML URLs
| Endpoint | URL |
|----------|-----|
| Metadata | `https://login.microsoftonline.com/{tenant}/federationmetadata/2007-06/federationmetadata.xml` |
| SSO | `https://login.microsoftonline.com/{tenant}/saml2` |
| SLO | `https://login.microsoftonline.com/{tenant}/saml2` |

### Special Multi-Tenant Values
- `common` - Azure AD + Personal accounts
- `organizations` - Any Azure AD tenant
- `consumers` - Personal Microsoft accounts only

## Troubleshooting

### "AADSTS50011: Reply URL does not match"
- Ensure redirect URIs exactly match in Azure and AuthTest
- Check for http vs https
- Check for trailing slashes

### "AADSTS700016: Application not found"
- Verify the client_id is correct
- Check that the app exists in the tenant you're authenticating against
- For multi-tenant apps, ensure the app supports multi-tenant

### "AADSTS65001: User or admin hasn't consented"
- User needs to consent to permissions
- Or admin needs to grant consent for the organization
- Check API permissions in app registration

### "AADSTS50034: User account doesn't exist"
- For single-tenant apps, user must be in that tenant
- For multi-tenant, the user's tenant must have accepted the app
- Check user is assigned to the enterprise application

### "AADSTS7000218: Request body must contain client_assertion or client_secret"
- Token endpoint requires authentication
- Verify client_secret is correct and not expired
- Check client authentication method

### Token Claims Issues
- v2.0 tokens use different claim names than v1.0
- v2.0: `preferred_username`, `name`
- v1.0: `unique_name`, `family_name`, `given_name`
- Use the correct issuer validation for your endpoint version

### SAML Signature Errors
- Download the latest signing certificate from Azure
- Azure rotates certificates periodically
- Check certificate expiration

## Microsoft Graph API

For richer user data, use Microsoft Graph instead of the UserInfo endpoint:

```
GET https://graph.microsoft.com/v1.0/me
Authorization: Bearer {access_token}
```

This returns more detailed profile information when you have the appropriate permissions.
"""


def get_setup_guide(tenant_id: str | None = None) -> str:
    """Get the Azure AD setup guide, optionally customized with URLs.

    Args:
        tenant_id: Optional tenant ID to customize examples.

    Returns:
        Markdown-formatted setup guide.
    """
    guide = AZURE_AD_SETUP_GUIDE

    if tenant_id:
        # Replace placeholder with actual tenant ID
        guide = guide.replace("{tenant}", tenant_id)
        guide = guide.replace("{tenant-id}", tenant_id)

    return guide
