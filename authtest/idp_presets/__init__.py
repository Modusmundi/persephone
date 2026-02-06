"""Identity Provider preset configurations.

This module provides pre-configured templates for common Identity Providers,
along with discovery functionality for SAML metadata and OIDC well-known
configuration endpoints.

Available presets:
- keycloak: Red Hat Keycloak / RH-SSO
- okta: Okta Identity

Discovery functions:
- fetch_saml_metadata: Fetch and parse SAML IdP metadata
- fetch_oidc_discovery: Fetch OIDC configuration from well-known endpoint
"""

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
    # Future presets
    # "azure_ad": {...},
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
