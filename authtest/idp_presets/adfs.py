"""Active Directory Federation Services (ADFS) IdP preset configuration.

Provides pre-configured templates and discovery support for Microsoft
AD FS, supporting both SAML and OIDC protocols.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass
class ADFSConfig:
    """ADFS-specific configuration parameters.

    AD FS (Active Directory Federation Services) is Microsoft's on-premises
    identity federation solution. It integrates with Active Directory and
    supports SAML 2.0, WS-Federation, and OAuth 2.0/OpenID Connect.

    ADFS 3.0+ supports OAuth 2.0, and ADFS 4.0+ supports OpenID Connect.
    """

    adfs_host: str  # e.g., "adfs.example.com" or "sts.contoso.com"

    @property
    def base_url(self) -> str:
        """Get the full base URL."""
        host = self.adfs_host.rstrip("/")
        if not host.startswith("https://"):
            host = f"https://{host}"
        return host

    # SAML Properties
    @property
    def saml_entity_id(self) -> str:
        """Get the SAML IdP entity ID.

        ADFS uses a standard format: http://{adfs_host}/adfs/services/trust
        """
        host = self.adfs_host.replace("https://", "").replace("http://", "")
        return f"http://{host}/adfs/services/trust"

    @property
    def saml_sso_url(self) -> str:
        """Get the SAML SSO endpoint (POST binding)."""
        return f"{self.base_url}/adfs/ls/"

    @property
    def saml_sso_redirect_url(self) -> str:
        """Get the SAML SSO endpoint (Redirect binding)."""
        return f"{self.base_url}/adfs/ls/"

    @property
    def saml_slo_url(self) -> str:
        """Get the SAML SLO endpoint."""
        return f"{self.base_url}/adfs/ls/"

    @property
    def saml_metadata_url(self) -> str:
        """Get the SAML/WS-Federation metadata URL."""
        return f"{self.base_url}/FederationMetadata/2007-06/FederationMetadata.xml"

    # OIDC Properties (ADFS 4.0+)
    @property
    def oidc_issuer(self) -> str:
        """Get the OIDC issuer URL."""
        return f"{self.base_url}/adfs"

    @property
    def oidc_discovery_url(self) -> str:
        """Get the OIDC well-known configuration URL."""
        return f"{self.base_url}/adfs/.well-known/openid-configuration"

    @property
    def oidc_authorization_endpoint(self) -> str:
        """Get the OIDC authorization endpoint."""
        return f"{self.base_url}/adfs/oauth2/authorize"

    @property
    def oidc_token_endpoint(self) -> str:
        """Get the OIDC token endpoint."""
        return f"{self.base_url}/adfs/oauth2/token"

    @property
    def oidc_userinfo_endpoint(self) -> str:
        """Get the OIDC userinfo endpoint."""
        return f"{self.base_url}/adfs/userinfo"

    @property
    def oidc_jwks_uri(self) -> str:
        """Get the OIDC JWKS URI."""
        return f"{self.base_url}/adfs/discovery/keys"

    @property
    def oidc_logout_endpoint(self) -> str:
        """Get the OIDC logout endpoint."""
        return f"{self.base_url}/adfs/oauth2/logout"

    @property
    def oidc_device_authorization_endpoint(self) -> str:
        """Get the device authorization endpoint (ADFS 2019+)."""
        return f"{self.base_url}/adfs/oauth2/devicecode"


def get_saml_preset(adfs_host: str) -> dict[str, Any]:
    """Get SAML IdP configuration preset for ADFS.

    Args:
        adfs_host: ADFS server hostname (e.g., adfs.example.com).

    Returns:
        Dictionary with pre-populated SAML configuration fields.
    """
    config = ADFSConfig(adfs_host=adfs_host)
    return {
        "idp_type": "saml",
        "entity_id": config.saml_entity_id,
        "sso_url": config.saml_sso_url,
        "slo_url": config.saml_slo_url,
        "metadata_url": config.saml_metadata_url,
        "settings": {
            "preset": "adfs",
            "adfs_host": adfs_host,
            # ADFS default settings
            "sign_authn_requests": True,
            "want_assertions_signed": True,
            "want_response_signed": True,
            "name_id_format": "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
        },
    }


def get_oidc_preset(adfs_host: str) -> dict[str, Any]:
    """Get OIDC IdP configuration preset for ADFS.

    Args:
        adfs_host: ADFS server hostname (e.g., adfs.example.com).

    Returns:
        Dictionary with pre-populated OIDC configuration fields.

    Note:
        OIDC support requires ADFS 4.0 or later (Windows Server 2016+).
    """
    config = ADFSConfig(adfs_host=adfs_host)

    return {
        "idp_type": "oidc",
        "issuer": config.oidc_issuer,
        "authorization_endpoint": config.oidc_authorization_endpoint,
        "token_endpoint": config.oidc_token_endpoint,
        "userinfo_endpoint": config.oidc_userinfo_endpoint,
        "jwks_uri": config.oidc_jwks_uri,
        "settings": {
            "preset": "adfs",
            "adfs_host": adfs_host,
            "discovery_url": config.oidc_discovery_url,
            "logout_endpoint": config.oidc_logout_endpoint,
            "device_authorization_endpoint": config.oidc_device_authorization_endpoint,
            # ADFS default scopes
            "default_scopes": ["openid", "profile", "email"],
            # ADFS supports these grant types (configurable per application)
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


# ADFS setup documentation
ADFS_SETUP_GUIDE = """
# AD FS (Active Directory Federation Services) Setup Guide

This guide walks you through setting up AD FS for testing with AuthTest.

## Prerequisites

- Windows Server with AD FS role installed
- Domain admin access or AD FS admin access
- SSL certificate for the AD FS service
- Active Directory domain

## AD FS Version Compatibility

| AD FS Version | Windows Server | OAuth 2.0 | OIDC |
|---------------|----------------|-----------|------|
| AD FS 2.0 | 2008 R2 | No | No |
| AD FS 2.1 | 2012 | No | No |
| AD FS 3.0 | 2012 R2 | Partial | No |
| AD FS 4.0 | 2016 | Yes | Yes |
| AD FS 5.0 | 2019 | Yes | Yes |

## 1. SAML Relying Party Trust Setup

### Create Relying Party Trust

1. Open **AD FS Management** console
2. Navigate to **Trust Relationships** > **Relying Party Trusts**
3. Click **Add Relying Party Trust...**
4. Select **Claims aware** and click **Start**

### Select Data Source

Select **Enter data about the relying party manually**

### Specify Display Name

| Setting | Value |
|---------|-------|
| Display name | AuthTest |
| Notes | (optional) |

### Configure URL

1. Select **Enable support for the SAML 2.0 WebSSO protocol**
2. Enter URL: `http://localhost:5000/saml/acs`

### Configure Identifiers

Add identifier: `http://localhost:5000/saml/metadata`

### Choose Access Control Policy

Select **Permit everyone** (or configure as needed)

### Ready to Add Trust

Review and click **Close**

### Configure Claim Issuance Policy

1. Select the new relying party trust
2. Click **Edit Claim Issuance Policy...**
3. Add rules:

**Rule 1: Send LDAP Attributes as Claims**
| Setting | Value |
|---------|-------|
| Claim rule template | Send LDAP Attributes as Claims |
| Claim rule name | LDAP Attributes |
| Attribute store | Active Directory |

Attribute mappings:
| LDAP Attribute | Outgoing Claim Type |
|----------------|---------------------|
| E-Mail-Addresses | E-Mail Address |
| Given-Name | Given Name |
| Surname | Surname |
| Display-Name | Name |
| User-Principal-Name | UPN |

**Rule 2: Transform UPN to Name ID**
| Setting | Value |
|---------|-------|
| Claim rule template | Transform an Incoming Claim |
| Claim rule name | UPN to Name ID |
| Incoming claim type | UPN |
| Outgoing claim type | Name ID |
| Outgoing name ID format | Email |
| Pass through all claim values | Selected |

## 2. OIDC/OAuth Application Setup (ADFS 4.0+)

### Create Application Group

1. In AD FS Management, go to **Application Groups**
2. Click **Add Application Group...**

### Welcome

| Setting | Value |
|---------|-------|
| Name | AuthTest OIDC |
| Template | Web browser accessing a web application |

### Web Application

| Setting | Value |
|---------|-------|
| Client Identifier | authtest-oidc |
| Redirect URI | `http://localhost:5000/oidc/callback` |

Click **Add** to add the redirect URI.

### Configure Application Credentials

1. Select **Generate a shared secret**
2. Copy and save the generated secret

### Summary

Review and click **Close**

### Configure Permissions

1. Select the application group
2. Click **Properties**
3. Go to **Web Application** properties
4. Under **Permitted scopes**, ensure these are selected:
   - ✓ openid
   - ✓ profile
   - ✓ email

## 3. Configure Token Lifetime (Optional)

### For SAML

1. Open PowerShell as Administrator
2. Run:
```powershell
Set-AdfsRelyingPartyTrust -TargetName "AuthTest" -TokenLifetime 60
```

### For OIDC

1. In Application Group properties
2. Go to **Web Application**
3. Configure token lifetime settings

## 4. Test Users

AD FS authenticates users from Active Directory:

1. Create test users in Active Directory Users and Computers
2. Ensure users have email addresses set
3. Verify user can authenticate to Windows

## 5. Export Federation Metadata

### Download Metadata URL

The metadata is available at:
`https://adfs.example.com/FederationMetadata/2007-06/FederationMetadata.xml`

### Export Signing Certificate

1. In AD FS Management, go to **Service** > **Certificates**
2. Right-click the **Token-signing** certificate
3. Click **View Certificate...**
4. Go to **Details** tab
5. Click **Copy to File...**
6. Export as Base-64 encoded X.509

## Quick Reference URLs

For AD FS at `adfs.example.com`:

### SAML URLs
| Endpoint | URL |
|----------|-----|
| Metadata | `https://adfs.example.com/FederationMetadata/2007-06/FederationMetadata.xml` |
| SSO (POST) | `https://adfs.example.com/adfs/ls/` |
| SSO (Redirect) | `https://adfs.example.com/adfs/ls/` |
| SLO | `https://adfs.example.com/adfs/ls/` |
| Entity ID | `http://adfs.example.com/adfs/services/trust` |

### OIDC URLs (ADFS 4.0+)
| Endpoint | URL |
|----------|-----|
| Discovery | `https://adfs.example.com/adfs/.well-known/openid-configuration` |
| Authorize | `https://adfs.example.com/adfs/oauth2/authorize` |
| Token | `https://adfs.example.com/adfs/oauth2/token` |
| UserInfo | `https://adfs.example.com/adfs/userinfo` |
| JWKS | `https://adfs.example.com/adfs/discovery/keys` |
| Logout | `https://adfs.example.com/adfs/oauth2/logout` |
| Device Code | `https://adfs.example.com/adfs/oauth2/devicecode` |

## Troubleshooting

### "MSIS7093: The message is not signed with expected signature algorithm"
- AuthnRequest signature algorithm mismatch
- Configure in Relying Party Trust > Signature > Add/Edit

### "MSIS7042: The same client browser session has made 'X' requests in the last 'Y' seconds"
- Loop detection triggered
- Check redirect configuration
- Verify ACS URL is correct

### "MSIS0037: No signature verification certificate found"
- ADFS cannot verify AuthnRequest signature
- Import SP certificate if signing is enabled

### "MSIS7015: This request does not contain the expected protocol message"
- Request format or binding mismatch
- Verify you're using the correct endpoint and binding

### "MSIS7068: Access denied because the incoming claim value does not match"
- User doesn't have required claims
- Check claim rules configuration

### OAuth "invalid_client" Error
- Client ID doesn't match
- Client secret is incorrect
- Application group is disabled

### OAuth "invalid_redirect_uri" Error
- Redirect URI not configured in application
- Check for exact match (trailing slashes, etc.)

### Token Signature Validation Fails
- Certificate may have rotated
- Re-download from metadata endpoint
- Check JWKS endpoint accessibility

## PowerShell Commands

### List Relying Party Trusts
```powershell
Get-AdfsRelyingPartyTrust | Select-Object Name, Identifier
```

### Get Relying Party Trust Details
```powershell
Get-AdfsRelyingPartyTrust -Name "AuthTest"
```

### Export Federation Metadata
```powershell
Invoke-WebRequest -Uri "https://localhost/FederationMetadata/2007-06/FederationMetadata.xml" `
    -OutFile "FederationMetadata.xml"
```

### List OAuth Applications (ADFS 4.0+)
```powershell
Get-AdfsApplicationGroup | Select-Object Name, ApplicationGroupIdentifier
Get-AdfsWebApiApplication | Select-Object Name, Identifier
```

### Get OIDC Signing Keys
```powershell
Get-AdfsProperties | Select-Object -ExpandProperty Certificate
```

## Advanced Configuration

### Custom Claim Rules

Custom claim rule language example:
```
c:[Type == "http://schemas.microsoft.com/ws/2008/06/identity/claims/windowsaccountname"]
 => issue(Type = "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier",
    Value = c.Value, Properties["http://schemas.xmlsoap.org/ws/2005/05/identity/claimproperties/format"]
    = "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress");
```

### Multi-Factor Authentication

1. Go to **Authentication Policies**
2. Configure **Primary Authentication** and **Multi-factor Authentication**
3. Enable for specific relying parties or globally

### Extranet Access

1. Configure Web Application Proxy for extranet access
2. Publish AD FS endpoints through WAP
"""


def get_setup_guide(adfs_host: str | None = None) -> str:
    """Get the ADFS setup guide, optionally customized with URLs.

    Args:
        adfs_host: Optional ADFS hostname to customize examples.

    Returns:
        Markdown-formatted setup guide.
    """
    guide = ADFS_SETUP_GUIDE

    if adfs_host:
        host = adfs_host.rstrip("/")
        if host.startswith("https://"):
            host = host[8:]
        if host.startswith("http://"):
            host = host[7:]

        guide = guide.replace("adfs.example.com", host)

    return guide
