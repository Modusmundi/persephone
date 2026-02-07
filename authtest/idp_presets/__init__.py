"""Identity Provider preset configurations.

This module provides pre-configured templates for common Identity Providers,
along with discovery functionality for SAML metadata and OIDC well-known
configuration endpoints.

Available presets:
- keycloak: Red Hat Keycloak / RH-SSO
- okta: Okta Identity
- azure_ad: Microsoft Entra ID (Azure AD)
- auth0: Auth0 Identity Platform
- google: Google Workspace / Google Cloud Identity
- ping_federate: PingFederate
- adfs: Active Directory Federation Services
- onelogin: OneLogin
- jumpcloud: JumpCloud

Discovery functions:
- fetch_saml_metadata: Fetch and parse SAML IdP metadata
- fetch_oidc_discovery: Fetch OIDC configuration from well-known endpoint
"""

# ADFS preset
from authtest.idp_presets.adfs import (
    ADFS_SETUP_GUIDE,
    ADFSConfig,
)
from authtest.idp_presets.adfs import (
    get_oidc_preset as get_adfs_oidc_preset,
)
from authtest.idp_presets.adfs import (
    get_saml_preset as get_adfs_saml_preset,
)
from authtest.idp_presets.adfs import (
    get_setup_guide as get_adfs_setup_guide,
)

# Auth0 preset
from authtest.idp_presets.auth0 import (
    AUTH0_SETUP_GUIDE,
    Auth0Config,
)
from authtest.idp_presets.auth0 import (
    get_oidc_preset as get_auth0_oidc_preset,
)
from authtest.idp_presets.auth0 import (
    get_saml_preset as get_auth0_saml_preset,
)
from authtest.idp_presets.auth0 import (
    get_setup_guide as get_auth0_setup_guide,
)

# Azure AD preset
from authtest.idp_presets.azure_ad import (
    AZURE_AD_SETUP_GUIDE,
    AzureADConfig,
)
from authtest.idp_presets.azure_ad import (
    get_oidc_preset as get_azure_ad_oidc_preset,
)
from authtest.idp_presets.azure_ad import (
    get_saml_preset as get_azure_ad_saml_preset,
)
from authtest.idp_presets.azure_ad import (
    get_setup_guide as get_azure_ad_setup_guide,
)

# Discovery utilities
from authtest.idp_presets.discovery import (
    OIDCDiscoveryResult,
    SAMLMetadataResult,
    fetch_oidc_discovery,
    fetch_saml_metadata,
    parse_saml_metadata,
)

# Google preset
from authtest.idp_presets.google import (
    GOOGLE_SETUP_GUIDE,
    GoogleConfig,
)
from authtest.idp_presets.google import (
    get_oidc_preset as get_google_oidc_preset,
)
from authtest.idp_presets.google import (
    get_saml_preset as get_google_saml_preset,
)
from authtest.idp_presets.google import (
    get_setup_guide as get_google_setup_guide,
)

# JumpCloud preset
from authtest.idp_presets.jumpcloud import (
    JUMPCLOUD_SETUP_GUIDE,
    JumpCloudConfig,
)
from authtest.idp_presets.jumpcloud import (
    get_oidc_preset as get_jumpcloud_oidc_preset,
)
from authtest.idp_presets.jumpcloud import (
    get_saml_preset as get_jumpcloud_saml_preset,
)
from authtest.idp_presets.jumpcloud import (
    get_setup_guide as get_jumpcloud_setup_guide,
)

# Keycloak preset
from authtest.idp_presets.keycloak import (
    KEYCLOAK_SETUP_GUIDE,
    KeycloakConfig,
)
from authtest.idp_presets.keycloak import (
    get_oidc_preset as get_keycloak_oidc_preset,
)
from authtest.idp_presets.keycloak import (
    get_saml_preset as get_keycloak_saml_preset,
)
from authtest.idp_presets.keycloak import (
    get_setup_guide as get_keycloak_setup_guide,
)

# Okta preset
from authtest.idp_presets.okta import (
    OKTA_SETUP_GUIDE,
    OktaConfig,
)
from authtest.idp_presets.okta import (
    get_oidc_preset as get_okta_oidc_preset,
)
from authtest.idp_presets.okta import (
    get_saml_preset as get_okta_saml_preset,
)
from authtest.idp_presets.okta import (
    get_setup_guide as get_okta_setup_guide,
)

# OneLogin preset
from authtest.idp_presets.onelogin import (
    ONELOGIN_SETUP_GUIDE,
    OneLoginConfig,
)
from authtest.idp_presets.onelogin import (
    get_oidc_preset as get_onelogin_oidc_preset,
)
from authtest.idp_presets.onelogin import (
    get_saml_preset as get_onelogin_saml_preset,
)
from authtest.idp_presets.onelogin import (
    get_setup_guide as get_onelogin_setup_guide,
)

# PingFederate preset
from authtest.idp_presets.ping_federate import (
    PING_FEDERATE_SETUP_GUIDE,
    PingFederateConfig,
)
from authtest.idp_presets.ping_federate import (
    get_oidc_preset as get_ping_federate_oidc_preset,
)
from authtest.idp_presets.ping_federate import (
    get_saml_preset as get_ping_federate_saml_preset,
)
from authtest.idp_presets.ping_federate import (
    get_setup_guide as get_ping_federate_setup_guide,
)

__all__ = [
    # Discovery
    "SAMLMetadataResult",
    "OIDCDiscoveryResult",
    "fetch_saml_metadata",
    "fetch_oidc_discovery",
    "parse_saml_metadata",
    # Keycloak preset
    "KeycloakConfig",
    "get_keycloak_saml_preset",
    "get_keycloak_oidc_preset",
    "get_keycloak_setup_guide",
    "KEYCLOAK_SETUP_GUIDE",
    # Okta preset
    "OktaConfig",
    "get_okta_saml_preset",
    "get_okta_oidc_preset",
    "get_okta_setup_guide",
    "OKTA_SETUP_GUIDE",
    # Azure AD preset
    "AzureADConfig",
    "get_azure_ad_saml_preset",
    "get_azure_ad_oidc_preset",
    "get_azure_ad_setup_guide",
    "AZURE_AD_SETUP_GUIDE",
    # Auth0 preset
    "Auth0Config",
    "get_auth0_saml_preset",
    "get_auth0_oidc_preset",
    "get_auth0_setup_guide",
    "AUTH0_SETUP_GUIDE",
    # Google preset
    "GoogleConfig",
    "get_google_saml_preset",
    "get_google_oidc_preset",
    "get_google_setup_guide",
    "GOOGLE_SETUP_GUIDE",
    # PingFederate preset
    "PingFederateConfig",
    "get_ping_federate_saml_preset",
    "get_ping_federate_oidc_preset",
    "get_ping_federate_setup_guide",
    "PING_FEDERATE_SETUP_GUIDE",
    # ADFS preset
    "ADFSConfig",
    "get_adfs_saml_preset",
    "get_adfs_oidc_preset",
    "get_adfs_setup_guide",
    "ADFS_SETUP_GUIDE",
    # OneLogin preset
    "OneLoginConfig",
    "get_onelogin_saml_preset",
    "get_onelogin_oidc_preset",
    "get_onelogin_setup_guide",
    "ONELOGIN_SETUP_GUIDE",
    # JumpCloud preset
    "JumpCloudConfig",
    "get_jumpcloud_saml_preset",
    "get_jumpcloud_oidc_preset",
    "get_jumpcloud_setup_guide",
    "JUMPCLOUD_SETUP_GUIDE",
    # Registry functions
    "PRESETS",
    "get_preset_info",
    "list_presets",
]


# Registry of available presets
PRESETS = {
    "keycloak": {
        "name": "Keycloak",
        "description": "Red Hat Keycloak / RH-SSO identity server",
        "module": "authtest.idp_presets.keycloak",
        "requires": ["base_url", "realm"],
        "supports": ["saml", "oidc"],
    },
    "okta": {
        "name": "Okta",
        "description": "Okta Identity cloud platform",
        "module": "authtest.idp_presets.okta",
        "requires": ["okta_domain"],
        "optional": ["app_id", "authorization_server"],
        "supports": ["saml", "oidc"],
    },
    "azure_ad": {
        "name": "Azure AD / Entra ID",
        "description": "Microsoft Entra ID (formerly Azure AD)",
        "module": "authtest.idp_presets.azure_ad",
        "requires": ["tenant_id"],
        "optional": ["use_v2_endpoints"],
        "supports": ["saml", "oidc"],
    },
    "auth0": {
        "name": "Auth0",
        "description": "Auth0 Identity Platform",
        "module": "authtest.idp_presets.auth0",
        "requires": ["auth0_domain"],
        "optional": ["client_id", "audience"],
        "supports": ["saml", "oidc"],
    },
    "google": {
        "name": "Google Workspace",
        "description": "Google Workspace / Google Cloud Identity",
        "module": "authtest.idp_presets.google",
        "requires": [],
        "optional": ["idp_id", "google_domain", "hd"],
        "supports": ["saml", "oidc"],
    },
    "ping_federate": {
        "name": "PingFederate",
        "description": "Ping Identity PingFederate federation server",
        "module": "authtest.idp_presets.ping_federate",
        "requires": ["base_url"],
        "supports": ["saml", "oidc"],
    },
    "adfs": {
        "name": "AD FS",
        "description": "Microsoft Active Directory Federation Services",
        "module": "authtest.idp_presets.adfs",
        "requires": ["adfs_host"],
        "supports": ["saml", "oidc"],
    },
    "onelogin": {
        "name": "OneLogin",
        "description": "OneLogin Identity and Access Management",
        "module": "authtest.idp_presets.onelogin",
        "requires": ["onelogin_subdomain"],
        "optional": ["app_id"],
        "supports": ["saml", "oidc"],
    },
    "jumpcloud": {
        "name": "JumpCloud",
        "description": "JumpCloud Directory Platform",
        "module": "authtest.idp_presets.jumpcloud",
        "requires": [],
        "optional": ["app_id", "org_id"],
        "supports": ["saml", "oidc"],
    },
}


def get_preset_info(preset_name: str) -> dict | None:
    """Get information about a preset.

    Args:
        preset_name: Name of the preset (e.g., 'keycloak').

    Returns:
        Preset information dict or None if not found.
    """
    return PRESETS.get(preset_name.lower())


def list_presets() -> list[dict]:
    """List all available presets.

    Returns:
        List of preset information dicts.
    """
    return [{"id": k, **v} for k, v in PRESETS.items()]
