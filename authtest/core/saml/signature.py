"""SAML signature validation module.

Provides signature verification for SAML Responses and Assertions
using the IdP's X.509 certificate.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import TYPE_CHECKING

from lxml import etree

if TYPE_CHECKING:
    pass


class SignatureLocation(StrEnum):
    """Where the signature was found in the SAML document."""

    RESPONSE = "response"
    ASSERTION = "assertion"
    BOTH = "both"
    NONE = "none"


class SignatureStatus(StrEnum):
    """Result of signature validation."""

    VALID = "valid"
    INVALID = "invalid"
    MISSING = "missing"
    NO_CERTIFICATE = "no_certificate"
    ERROR = "error"


# Mapping of signature algorithm URIs to friendly names
SIGNATURE_ALGORITHMS: dict[str, str] = {
    # RSA with SHA family
    "http://www.w3.org/2000/09/xmldsig#rsa-sha1": "RSA-SHA1",
    "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256": "RSA-SHA256",
    "http://www.w3.org/2001/04/xmldsig-more#rsa-sha384": "RSA-SHA384",
    "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512": "RSA-SHA512",
    # DSA
    "http://www.w3.org/2000/09/xmldsig#dsa-sha1": "DSA-SHA1",
    "http://www.w3.org/2009/xmldsig11#dsa-sha256": "DSA-SHA256",
    # ECDSA
    "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha1": "ECDSA-SHA1",
    "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256": "ECDSA-SHA256",
    "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha384": "ECDSA-SHA384",
    "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha512": "ECDSA-SHA512",
}

# Mapping of digest algorithm URIs to friendly names
DIGEST_ALGORITHMS: dict[str, str] = {
    "http://www.w3.org/2000/09/xmldsig#sha1": "SHA-1",
    "http://www.w3.org/2001/04/xmlenc#sha256": "SHA-256",
    "http://www.w3.org/2001/04/xmldsig-more#sha384": "SHA-384",
    "http://www.w3.org/2001/04/xmlenc#sha512": "SHA-512",
}

# Canonicalization method URIs to friendly names
CANONICALIZATION_METHODS: dict[str, str] = {
    "http://www.w3.org/TR/2001/REC-xml-c14n-20010315": "C14N 1.0",
    "http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments": "C14N 1.0 with Comments",
    "http://www.w3.org/2006/12/xml-c14n11": "C14N 1.1",
    "http://www.w3.org/2006/12/xml-c14n11#WithComments": "C14N 1.1 with Comments",
    "http://www.w3.org/2001/10/xml-exc-c14n#": "Exclusive C14N",
    "http://www.w3.org/2001/10/xml-exc-c14n#WithComments": "Exclusive C14N with Comments",
}


@dataclass
class SignatureInfo:
    """Information about a signature in the SAML document."""

    location: SignatureLocation
    signature_algorithm: str | None = None
    signature_algorithm_name: str | None = None
    digest_algorithm: str | None = None
    digest_algorithm_name: str | None = None
    canonicalization_method: str | None = None
    canonicalization_method_name: str | None = None
    reference_uri: str | None = None
    certificate_embedded: bool = False


@dataclass
class SignatureValidationResult:
    """Result of SAML signature validation."""

    status: SignatureStatus
    message: str
    signatures: list[SignatureInfo] = field(default_factory=list)
    trace: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    @property
    def is_valid(self) -> bool:
        """Check if signature validation passed."""
        return self.status == SignatureStatus.VALID

    def add_trace(self, message: str) -> None:
        """Add a trace message for debug output."""
        self.trace.append(message)


# XML namespace for signatures
DSIG_NS = "http://www.w3.org/2000/09/xmldsig#"
SAML_NS = "urn:oasis:names:tc:SAML:2.0:assertion"
SAMLP_NS = "urn:oasis:names:tc:SAML:2.0:protocol"


def _find_signatures(doc: etree._Element) -> list[tuple[etree._Element, SignatureLocation]]:
    """Find all Signature elements in the document.

    Returns:
        List of (Signature element, location) tuples.
    """
    signatures: list[tuple[etree._Element, SignatureLocation]] = []

    # Check for signature at Response level
    for sig in doc.findall(f"{{{DSIG_NS}}}Signature"):
        signatures.append((sig, SignatureLocation.RESPONSE))

    # Check for signatures inside Assertions
    for assertion in doc.findall(f".//{{{SAML_NS}}}Assertion"):
        for sig in assertion.findall(f"{{{DSIG_NS}}}Signature"):
            signatures.append((sig, SignatureLocation.ASSERTION))

    return signatures


def _extract_signature_info(sig_elem: etree._Element, location: SignatureLocation) -> SignatureInfo:
    """Extract information about a signature element."""
    info = SignatureInfo(location=location)

    # Find SignedInfo element
    signed_info = sig_elem.find(f"{{{DSIG_NS}}}SignedInfo")
    if signed_info is not None:
        # Signature algorithm
        sig_method = signed_info.find(f"{{{DSIG_NS}}}SignatureMethod")
        if sig_method is not None:
            algo = sig_method.get("Algorithm")
            info.signature_algorithm = algo
            info.signature_algorithm_name = SIGNATURE_ALGORITHMS.get(algo or "", algo)

        # Canonicalization method
        c14n_method = signed_info.find(f"{{{DSIG_NS}}}CanonicalizationMethod")
        if c14n_method is not None:
            c14n = c14n_method.get("Algorithm")
            info.canonicalization_method = c14n
            info.canonicalization_method_name = CANONICALIZATION_METHODS.get(c14n or "", c14n)

        # Reference and digest
        reference = signed_info.find(f"{{{DSIG_NS}}}Reference")
        if reference is not None:
            info.reference_uri = reference.get("URI")

            digest_method = reference.find(f"{{{DSIG_NS}}}DigestMethod")
            if digest_method is not None:
                digest = digest_method.get("Algorithm")
                info.digest_algorithm = digest
                info.digest_algorithm_name = DIGEST_ALGORITHMS.get(digest or "", digest)

    # Check for embedded certificate
    key_info = sig_elem.find(f"{{{DSIG_NS}}}KeyInfo")
    if key_info is not None:
        x509_data = key_info.find(f"{{{DSIG_NS}}}X509Data")
        if x509_data is not None:
            x509_cert = x509_data.find(f"{{{DSIG_NS}}}X509Certificate")
            info.certificate_embedded = x509_cert is not None and x509_cert.text is not None

    return info


def _prepare_certificate(cert_pem: str) -> str:
    """Ensure certificate is in proper PEM format."""
    cert = cert_pem.strip()

    # If it doesn't have PEM headers, add them
    if not cert.startswith("-----BEGIN"):
        # Remove any whitespace and join
        cert_data = "".join(cert.split())
        cert = f"-----BEGIN CERTIFICATE-----\n{cert_data}\n-----END CERTIFICATE-----"

    return cert


def validate_signature(xml_string: str, idp_certificate: str | None) -> SignatureValidationResult:
    """Validate signatures in a SAML Response.

    Args:
        xml_string: The raw SAML Response XML.
        idp_certificate: PEM-encoded X.509 certificate from the IdP, or None.

    Returns:
        SignatureValidationResult with validation status and details.
    """
    result = SignatureValidationResult(
        status=SignatureStatus.ERROR,
        message="Validation not completed",
    )

    result.add_trace("Starting signature validation")

    # Parse the XML document
    try:
        doc = etree.fromstring(xml_string.encode("utf-8"))
        result.add_trace("Successfully parsed XML document")
    except etree.XMLSyntaxError as e:
        result.status = SignatureStatus.ERROR
        result.message = f"Failed to parse XML: {e}"
        result.add_trace(f"XML parsing error: {e}")
        return result

    # Find all signatures in the document
    signatures = _find_signatures(doc)

    if not signatures:
        result.status = SignatureStatus.MISSING
        result.message = "No signature found in SAML Response or Assertion"
        result.add_trace("No ds:Signature elements found in document")
        return result

    result.add_trace(f"Found {len(signatures)} signature(s) in document")

    # Extract information about each signature
    for sig_elem, location in signatures:
        sig_info = _extract_signature_info(sig_elem, location)
        result.signatures.append(sig_info)
        result.add_trace(
            f"Signature at {location.value}: "
            f"Algorithm={sig_info.signature_algorithm_name}, "
            f"Digest={sig_info.digest_algorithm_name}"
        )

        # Warn about weak algorithms
        if sig_info.signature_algorithm and "sha1" in sig_info.signature_algorithm.lower():
            result.warnings.append(
                f"Signature at {location.value} uses SHA-1, which is deprecated. "
                "Consider using SHA-256 or stronger."
            )

    # Check if we have a certificate to validate against
    if not idp_certificate:
        result.status = SignatureStatus.NO_CERTIFICATE
        result.message = (
            "Cannot validate signature: No IdP certificate configured. "
            "Configure the IdP's X.509 certificate to enable signature validation."
        )
        result.add_trace("No IdP certificate provided - skipping cryptographic validation")
        return result

    # Prepare certificate for verification
    try:
        cert_pem = _prepare_certificate(idp_certificate)
        result.add_trace("Prepared IdP certificate for verification")
    except Exception as e:
        result.status = SignatureStatus.ERROR
        result.message = f"Failed to prepare IdP certificate: {e}"
        result.add_trace(f"Certificate preparation error: {e}")
        return result

    # Perform cryptographic validation
    try:
        from signxml import XMLVerifier
        from signxml.exceptions import InvalidSignature

        result.add_trace("Initializing XML signature verifier")

        # Create verifier with the IdP certificate
        verifier = XMLVerifier()

        # Verify the document
        # signxml will verify all signatures it finds
        result.add_trace("Verifying signature against IdP certificate")

        verified_data = verifier.verify(
            doc,
            x509_cert=cert_pem,
        )

        # Handle both single result and list of results
        if isinstance(verified_data, list):
            verified_tags = []
            for v in verified_data:
                signed_xml = getattr(v, "signed_xml", None)
                tag = getattr(signed_xml, "tag", "unknown") if signed_xml else "unknown"
                verified_tags.append(str(tag))
            result.add_trace(f"Signature verification successful, verified {len(verified_data)} element(s): {verified_tags}")
        else:
            signed_xml = getattr(verified_data, "signed_xml", None)
            tag = getattr(signed_xml, "tag", "unknown") if signed_xml else "unknown"
            result.add_trace(f"Signature verification successful, verified element: {tag}")

        result.status = SignatureStatus.VALID
        result.message = "Signature validated successfully against IdP certificate"

    except InvalidSignature as e:
        result.status = SignatureStatus.INVALID
        error_msg = str(e)
        result.message = f"Signature validation failed: {error_msg}"
        result.add_trace(f"Signature validation failed: {error_msg}")

        # Provide more specific error messages
        if "digest mismatch" in error_msg.lower():
            result.message = (
                "Signature validation failed: Document has been modified. "
                "The digest of the signed content does not match."
            )
        elif "verification failed" in error_msg.lower() or "signature mismatch" in error_msg.lower():
            result.message = (
                "Signature validation failed: The signature does not match the IdP certificate. "
                "Ensure the correct IdP certificate is configured."
            )

    except Exception as e:
        result.status = SignatureStatus.ERROR
        result.message = f"Signature verification error: {e}"
        result.add_trace(f"Unexpected error during verification: {type(e).__name__}: {e}")

    return result


def get_signature_summary(result: SignatureValidationResult) -> str:
    """Get a human-readable summary of signature validation.

    Args:
        result: The validation result.

    Returns:
        A formatted summary string.
    """
    lines = []

    # Status line
    status_icons = {
        SignatureStatus.VALID: "[VALID]",
        SignatureStatus.INVALID: "[INVALID]",
        SignatureStatus.MISSING: "[MISSING]",
        SignatureStatus.NO_CERTIFICATE: "[UNCHECKED]",
        SignatureStatus.ERROR: "[ERROR]",
    }
    lines.append(f"{status_icons[result.status]} {result.message}")

    # Signature details
    if result.signatures:
        lines.append("")
        lines.append("Signature Details:")
        for i, sig in enumerate(result.signatures, 1):
            lines.append(f"  Signature {i} ({sig.location.value}):")
            lines.append(f"    Algorithm: {sig.signature_algorithm_name or 'Unknown'}")
            lines.append(f"    Digest: {sig.digest_algorithm_name or 'Unknown'}")
            lines.append(f"    C14N: {sig.canonicalization_method_name or 'Unknown'}")
            if sig.certificate_embedded:
                lines.append("    Certificate: Embedded in signature")

    # Warnings
    if result.warnings:
        lines.append("")
        lines.append("Warnings:")
        for warning in result.warnings:
            lines.append(f"  - {warning}")

    return "\n".join(lines)
