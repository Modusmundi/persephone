"""IdP metadata and configuration discovery.

Provides functionality to automatically discover and fetch IdP
configuration from SAML metadata URLs and OIDC well-known endpoints.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any
from xml.etree import ElementTree as ET

import httpx

from authtest.core.logging import LoggingClient, get_protocol_logger

logger = logging.getLogger(__name__)

# SAML namespace mappings
SAML_NAMESPACES = {
    "md": "urn:oasis:names:tc:SAML:2.0:metadata",
    "ds": "http://www.w3.org/2000/09/xmldsig#",
    "saml": "urn:oasis:names:tc:SAML:2.0:assertion",
}


@dataclass
class SAMLMetadataResult:
    """Result of SAML metadata discovery."""

    success: bool
    entity_id: str | None = None
    sso_url: str | None = None
    sso_binding: str | None = None
    slo_url: str | None = None
    slo_binding: str | None = None
    x509_cert: str | None = None
    metadata_xml: str | None = None
    error: str | None = None
    name_id_formats: list[str] = field(default_factory=list)


@dataclass
class OIDCDiscoveryResult:
    """Result of OIDC discovery."""

    success: bool
    issuer: str | None = None
    authorization_endpoint: str | None = None
    token_endpoint: str | None = None
    userinfo_endpoint: str | None = None
    jwks_uri: str | None = None
    end_session_endpoint: str | None = None
    revocation_endpoint: str | None = None
    introspection_endpoint: str | None = None
    scopes_supported: list[str] = field(default_factory=list)
    response_types_supported: list[str] = field(default_factory=list)
    grant_types_supported: list[str] = field(default_factory=list)
    error: str | None = None
    raw_config: dict[str, Any] = field(default_factory=dict)


def fetch_saml_metadata(
    metadata_url: str,
    timeout: float = 10.0,
    verify_ssl: bool = True,
) -> SAMLMetadataResult:
    """Fetch and parse SAML IdP metadata from a URL.

    Args:
        metadata_url: URL to fetch SAML metadata from.
        timeout: Request timeout in seconds.
        verify_ssl: Whether to verify SSL certificates.

    Returns:
        SAMLMetadataResult with parsed metadata or error.
    """
    try:
        logger.debug(f"Fetching SAML metadata from {metadata_url}")
        protocol_logger = get_protocol_logger()
        protocol_logger.start_flow(f"saml_metadata_{id(metadata_url)}", "saml_metadata_fetch")

        with LoggingClient(protocol_logger=protocol_logger, timeout=timeout, verify=verify_ssl) as client:
            response = client.get(metadata_url)
            response.raise_for_status()
            metadata_xml = response.text

        protocol_logger.end_flow()
        return parse_saml_metadata(metadata_xml)

    except httpx.TimeoutException:
        return SAMLMetadataResult(
            success=False,
            error=f"Timeout fetching metadata from {metadata_url}",
        )
    except httpx.HTTPStatusError as e:
        return SAMLMetadataResult(
            success=False,
            error=f"HTTP {e.response.status_code} fetching metadata: {e.response.text[:200]}",
        )
    except httpx.RequestError as e:
        return SAMLMetadataResult(
            success=False,
            error=f"Request error fetching metadata: {e}",
        )
    except Exception as e:
        return SAMLMetadataResult(
            success=False,
            error=f"Error fetching metadata: {e}",
        )


def parse_saml_metadata(metadata_xml: str) -> SAMLMetadataResult:
    """Parse SAML IdP metadata XML.

    Args:
        metadata_xml: Raw XML metadata string.

    Returns:
        SAMLMetadataResult with parsed values.
    """
    try:
        root = ET.fromstring(metadata_xml)

        # Find EntityDescriptor
        entity_descriptor: ET.Element | None
        if root.tag == "{urn:oasis:names:tc:SAML:2.0:metadata}EntityDescriptor":
            entity_descriptor = root
        else:
            entity_descriptor = root.find(".//md:EntityDescriptor", SAML_NAMESPACES)

        if entity_descriptor is None:
            return SAMLMetadataResult(
                success=False,
                error="No EntityDescriptor found in metadata",
            )

        entity_id = entity_descriptor.get("entityID")

        # Find IDPSSODescriptor
        idp_descriptor = entity_descriptor.find(".//md:IDPSSODescriptor", SAML_NAMESPACES)
        if idp_descriptor is None:
            return SAMLMetadataResult(
                success=False,
                error="No IDPSSODescriptor found - this may be SP metadata",
            )

        # Extract SSO endpoint (prefer POST binding)
        sso_url = None
        sso_binding = None
        for sso_service in idp_descriptor.findall("md:SingleSignOnService", SAML_NAMESPACES):
            binding = sso_service.get("Binding", "")
            location = sso_service.get("Location")
            if "POST" in binding:
                sso_url = location
                sso_binding = "POST"
                break
            elif "Redirect" in binding and sso_url is None:
                sso_url = location
                sso_binding = "Redirect"

        # Extract SLO endpoint
        slo_url = None
        slo_binding = None
        for slo_service in idp_descriptor.findall("md:SingleLogoutService", SAML_NAMESPACES):
            binding = slo_service.get("Binding", "")
            location = slo_service.get("Location")
            if "POST" in binding:
                slo_url = location
                slo_binding = "POST"
                break
            elif "Redirect" in binding and slo_url is None:
                slo_url = location
                slo_binding = "Redirect"

        # Extract X.509 certificate (signing key)
        x509_cert = None
        key_descriptor = idp_descriptor.find(
            "md:KeyDescriptor[@use='signing']/ds:KeyInfo/ds:X509Data/ds:X509Certificate",
            SAML_NAMESPACES,
        )
        # Fall back to any key if no signing-specific key
        if key_descriptor is None:
            key_descriptor = idp_descriptor.find(
                "md:KeyDescriptor/ds:KeyInfo/ds:X509Data/ds:X509Certificate",
                SAML_NAMESPACES,
            )
        if key_descriptor is not None and key_descriptor.text:
            # Clean up the certificate (remove whitespace)
            cert_data = "".join(key_descriptor.text.split())
            x509_cert = f"-----BEGIN CERTIFICATE-----\n{cert_data}\n-----END CERTIFICATE-----"

        # Extract NameID formats
        name_id_formats = []
        for nif in idp_descriptor.findall("md:NameIDFormat", SAML_NAMESPACES):
            if nif.text:
                name_id_formats.append(nif.text)

        return SAMLMetadataResult(
            success=True,
            entity_id=entity_id,
            sso_url=sso_url,
            sso_binding=sso_binding,
            slo_url=slo_url,
            slo_binding=slo_binding,
            x509_cert=x509_cert,
            metadata_xml=metadata_xml,
            name_id_formats=name_id_formats,
        )

    except ET.ParseError as e:
        return SAMLMetadataResult(
            success=False,
            error=f"Invalid XML in metadata: {e}",
        )
    except Exception as e:
        return SAMLMetadataResult(
            success=False,
            error=f"Error parsing metadata: {e}",
        )


def fetch_oidc_discovery(
    issuer_or_url: str,
    timeout: float = 10.0,
    verify_ssl: bool = True,
) -> OIDCDiscoveryResult:
    """Fetch OIDC configuration from well-known endpoint.

    Args:
        issuer_or_url: Either an issuer URL or full discovery URL.
            If it doesn't end with .well-known/openid-configuration,
            that path will be appended.
        timeout: Request timeout in seconds.
        verify_ssl: Whether to verify SSL certificates.

    Returns:
        OIDCDiscoveryResult with discovered configuration or error.
    """
    # Build discovery URL
    discovery_url = issuer_or_url.rstrip("/")
    if not discovery_url.endswith(".well-known/openid-configuration"):
        discovery_url = f"{discovery_url}/.well-known/openid-configuration"

    try:
        logger.debug(f"Fetching OIDC discovery from {discovery_url}")
        protocol_logger = get_protocol_logger()
        protocol_logger.start_flow(f"oidc_discovery_{id(discovery_url)}", "oidc_discovery_fetch")

        with LoggingClient(protocol_logger=protocol_logger, timeout=timeout, verify=verify_ssl) as client:
            response = client.get(discovery_url)
            response.raise_for_status()
            config = response.json()

        protocol_logger.end_flow()
        return OIDCDiscoveryResult(
            success=True,
            issuer=config.get("issuer"),
            authorization_endpoint=config.get("authorization_endpoint"),
            token_endpoint=config.get("token_endpoint"),
            userinfo_endpoint=config.get("userinfo_endpoint"),
            jwks_uri=config.get("jwks_uri"),
            end_session_endpoint=config.get("end_session_endpoint"),
            revocation_endpoint=config.get("revocation_endpoint"),
            introspection_endpoint=config.get("introspection_endpoint"),
            scopes_supported=config.get("scopes_supported", []),
            response_types_supported=config.get("response_types_supported", []),
            grant_types_supported=config.get("grant_types_supported", []),
            raw_config=config,
        )

    except httpx.TimeoutException:
        return OIDCDiscoveryResult(
            success=False,
            error=f"Timeout fetching OIDC configuration from {discovery_url}",
        )
    except httpx.HTTPStatusError as e:
        return OIDCDiscoveryResult(
            success=False,
            error=f"HTTP {e.response.status_code} fetching OIDC config: {e.response.text[:200]}",
        )
    except httpx.RequestError as e:
        return OIDCDiscoveryResult(
            success=False,
            error=f"Request error fetching OIDC config: {e}",
        )
    except ValueError as e:  # JSON decode error
        return OIDCDiscoveryResult(
            success=False,
            error=f"Invalid JSON in OIDC configuration: {e}",
        )
    except Exception as e:
        return OIDCDiscoveryResult(
            success=False,
            error=f"Error fetching OIDC config: {e}",
        )
