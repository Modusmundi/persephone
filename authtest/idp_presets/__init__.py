"""Identity Provider preset configurations.

This module provides pre-configured templates for common Identity Providers,
along with discovery functionality for SAML metadata and OIDC well-known
configuration endpoints.

Available presets:
- keycloak: Red Hat Keycloak / RH-SSO
- okta: Okta Identity
- azure_ad: Microsoft Entra ID (Azure AD)

Discovery functions:
- fetch_saml_metadata: Fetch and parse SAML IdP metadata
- fetch_oidc_discovery: Fetch OIDC configuration from well-known endpoint
"""

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
from authtest.idp_presets.discovery import (
    OIDCDiscoveryResult,
    SAMLMetadataResult,
    fetch_oidc_discovery,
    fetch_saml_metadata,
    parse_saml_metadata,
)
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
    # Future presets
    # "auth0": {...},
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
