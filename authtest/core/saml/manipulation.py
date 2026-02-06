"""SAML assertion manipulation utilities for security testing.

This module provides tools to modify and re-sign SAML assertions
for testing how applications handle manipulated SAML tokens.

WARNING: These tools are intended for authorized security testing only.
Manipulated assertions are clearly labeled and should never be used maliciously.
"""

from __future__ import annotations

import base64
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509 import Certificate
from lxml import etree

# Try to import signxml for re-signing
try:
    from signxml import XMLSigner
    from signxml.algorithms import DigestAlgorithm, SignatureMethod

    SIGNXML_AVAILABLE = True
except ImportError:
    SIGNXML_AVAILABLE = False

# SAML namespaces
SAML_NS = "urn:oasis:names:tc:SAML:2.0:assertion"
SAMLP_NS = "urn:oasis:names:tc:SAML:2.0:protocol"
DSIG_NS = "http://www.w3.org/2000/09/xmldsig#"

NAMESPACES = {
    "saml": SAML_NS,
    "samlp": SAMLP_NS,
    "ds": DSIG_NS,
}


class SAMLManipulationType(StrEnum):
    """Type of manipulation applied to a SAML assertion."""

    ATTRIBUTE_MODIFIED = "attribute_modified"
    ATTRIBUTE_ADDED = "attribute_added"
    ATTRIBUTE_REMOVED = "attribute_removed"
    SUBJECT_MODIFIED = "subject_modified"
    CONDITION_MODIFIED = "condition_modified"
    ISSUER_MODIFIED = "issuer_modified"
    SIGNATURE_STRIPPED = "signature_stripped"
    CUSTOM_SIGNED = "custom_signed"
    TIMESTAMP_MODIFIED = "timestamp_modified"


@dataclass
class SAMLManipulation:
    """Record of a manipulation applied to a SAML assertion."""

    type: SAMLManipulationType
    description: str
    original_value: str | None = None
    new_value: str | None = None


@dataclass
class ManipulatedAssertion:
    """Result of SAML assertion manipulation."""

    original_xml: str
    manipulated_xml: str
    manipulations: list[SAMLManipulation] = field(default_factory=list)
    signed_with: str | None = None

    # Warning label
    warning: str = "MANIPULATED ASSERTION - FOR SECURITY TESTING ONLY"

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "original_xml": self.original_xml,
            "manipulated_xml": self.manipulated_xml,
            "manipulations": [
                {
                    "type": m.type.value,
                    "description": m.description,
                    "original_value": m.original_value,
                    "new_value": m.new_value,
                }
                for m in self.manipulations
            ],
            "signed_with": self.signed_with,
            "warning": self.warning,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ManipulatedAssertion:
        """Reconstruct from dictionary."""
        result = cls(
            original_xml=data.get("original_xml", ""),
            manipulated_xml=data.get("manipulated_xml", ""),
            signed_with=data.get("signed_with"),
            warning=data.get("warning", ""),
        )
        for m_data in data.get("manipulations", []):
            result.manipulations.append(
                SAMLManipulation(
                    type=SAMLManipulationType(m_data["type"]),
                    description=m_data["description"],
                    original_value=m_data.get("original_value"),
                    new_value=m_data.get("new_value"),
                )
            )
        return result

    def encode_base64(self) -> str:
        """Encode the manipulated assertion for HTTP-POST binding."""
        return base64.b64encode(self.manipulated_xml.encode("utf-8")).decode("utf-8")


class SAMLManipulator:
    """Manipulates SAML assertions for security testing.

    This class allows modifying SAML attributes, subjects, conditions,
    and re-signing assertions with custom keys.
    """

    def __init__(self, saml_xml: str) -> None:
        """Initialize with a SAML Response or Assertion XML.

        Args:
            saml_xml: SAML XML string (can be base64-encoded).

        Raises:
            ValueError: If XML is invalid.
        """
        # Try to decode if base64-encoded
        try:
            decoded = base64.b64decode(saml_xml)
            self.original_xml = decoded.decode("utf-8")
        except Exception:
            self.original_xml = saml_xml

        # Parse the XML
        try:
            self.doc = etree.fromstring(self.original_xml.encode("utf-8"))
        except etree.XMLSyntaxError as e:
            raise ValueError(f"Invalid XML: {e}") from e

        self.manipulations: list[SAMLManipulation] = []
        self._is_response = self.doc.tag == f"{{{SAMLP_NS}}}Response"

    def _get_assertions(self) -> list[etree._Element]:
        """Get all Assertion elements from the document."""
        return self.doc.findall(f".//{{{SAML_NS}}}Assertion")

    def _get_first_assertion(self) -> etree._Element | None:
        """Get the first Assertion element."""
        assertions = self._get_assertions()
        return assertions[0] if assertions else None

    def modify_nameid(self, new_value: str) -> SAMLManipulator:
        """Modify the NameID value in the assertion.

        Args:
            new_value: New NameID value.

        Returns:
            Self for chaining.
        """
        assertion = self._get_first_assertion()
        if assertion is None:
            raise ValueError("No assertion found in document")

        nameid = assertion.find(f".//{{{SAML_NS}}}NameID")
        if nameid is None:
            raise ValueError("No NameID found in assertion")

        original = nameid.text
        nameid.text = new_value

        self.manipulations.append(
            SAMLManipulation(
                type=SAMLManipulationType.SUBJECT_MODIFIED,
                description="Modified NameID value",
                original_value=original,
                new_value=new_value,
            )
        )
        return self

    def modify_nameid_format(self, new_format: str) -> SAMLManipulator:
        """Modify the NameID format in the assertion.

        Args:
            new_format: New NameID format URI.

        Returns:
            Self for chaining.
        """
        assertion = self._get_first_assertion()
        if assertion is None:
            raise ValueError("No assertion found in document")

        nameid = assertion.find(f".//{{{SAML_NS}}}NameID")
        if nameid is None:
            raise ValueError("No NameID found in assertion")

        original = nameid.get("Format")
        nameid.set("Format", new_format)

        self.manipulations.append(
            SAMLManipulation(
                type=SAMLManipulationType.SUBJECT_MODIFIED,
                description="Modified NameID format",
                original_value=original,
                new_value=new_format,
            )
        )
        return self

    def modify_attribute(
        self,
        attribute_name: str,
        new_value: str | list[str],
        *,
        create_if_missing: bool = False,
    ) -> SAMLManipulator:
        """Modify an attribute value in the assertion.

        Args:
            attribute_name: Name of the attribute (can be Name or FriendlyName).
            new_value: New value(s) for the attribute.
            create_if_missing: Create the attribute if it doesn't exist.

        Returns:
            Self for chaining.
        """
        assertion = self._get_first_assertion()
        if assertion is None:
            raise ValueError("No assertion found in document")

        # Find attribute by Name or FriendlyName
        attribute = None
        for attr in assertion.findall(f".//{{{SAML_NS}}}Attribute"):
            if attr.get("Name") == attribute_name or attr.get("FriendlyName") == attribute_name:
                attribute = attr
                break

        if attribute is None:
            if not create_if_missing:
                raise ValueError(f"Attribute '{attribute_name}' not found")

            # Create the attribute
            attr_statement = assertion.find(f".//{{{SAML_NS}}}AttributeStatement")
            if attr_statement is None:
                raise ValueError("No AttributeStatement found to add attribute to")

            attribute = etree.SubElement(
                attr_statement,
                f"{{{SAML_NS}}}Attribute",
                Name=attribute_name,
            )

            self.manipulations.append(
                SAMLManipulation(
                    type=SAMLManipulationType.ATTRIBUTE_ADDED,
                    description=f"Added attribute '{attribute_name}'",
                    new_value=str(new_value),
                )
            )

        # Get original values
        original_values = []
        for value_elem in attribute.findall(f"{{{SAML_NS}}}AttributeValue"):
            original_values.append(value_elem.text or "")
            attribute.remove(value_elem)

        # Add new values
        values = new_value if isinstance(new_value, list) else [new_value]
        for val in values:
            value_elem = etree.SubElement(attribute, f"{{{SAML_NS}}}AttributeValue")
            value_elem.text = val

        if original_values:
            self.manipulations.append(
                SAMLManipulation(
                    type=SAMLManipulationType.ATTRIBUTE_MODIFIED,
                    description=f"Modified attribute '{attribute_name}'",
                    original_value=", ".join(original_values),
                    new_value=", ".join(values),
                )
            )

        return self

    def add_attribute(
        self,
        name: str,
        value: str | list[str],
        friendly_name: str | None = None,
        name_format: str = "urn:oasis:names:tc:SAML:2.0:attrname-format:basic",
    ) -> SAMLManipulator:
        """Add a new attribute to the assertion.

        Args:
            name: Attribute name (typically a URI).
            value: Attribute value(s).
            friendly_name: Optional friendly name.
            name_format: Attribute name format URI.

        Returns:
            Self for chaining.
        """
        assertion = self._get_first_assertion()
        if assertion is None:
            raise ValueError("No assertion found in document")

        attr_statement = assertion.find(f".//{{{SAML_NS}}}AttributeStatement")
        if attr_statement is None:
            # Create AttributeStatement if it doesn't exist
            conditions = assertion.find(f"{{{SAML_NS}}}Conditions")
            if conditions is not None:
                idx = list(assertion).index(conditions) + 1
                attr_statement = etree.Element(f"{{{SAML_NS}}}AttributeStatement")
                assertion.insert(idx, attr_statement)
            else:
                attr_statement = etree.SubElement(assertion, f"{{{SAML_NS}}}AttributeStatement")

        # Create attribute
        attribs = {"Name": name, "NameFormat": name_format}
        if friendly_name:
            attribs["FriendlyName"] = friendly_name

        attribute = etree.SubElement(attr_statement, f"{{{SAML_NS}}}Attribute", **attribs)

        values = value if isinstance(value, list) else [value]
        for val in values:
            value_elem = etree.SubElement(attribute, f"{{{SAML_NS}}}AttributeValue")
            value_elem.text = val

        self.manipulations.append(
            SAMLManipulation(
                type=SAMLManipulationType.ATTRIBUTE_ADDED,
                description=f"Added attribute '{friendly_name or name}'",
                new_value=", ".join(values),
            )
        )
        return self

    def remove_attribute(self, attribute_name: str) -> SAMLManipulator:
        """Remove an attribute from the assertion.

        Args:
            attribute_name: Name of the attribute to remove.

        Returns:
            Self for chaining.
        """
        assertion = self._get_first_assertion()
        if assertion is None:
            raise ValueError("No assertion found in document")

        for attr in assertion.findall(f".//{{{SAML_NS}}}Attribute"):
            if attr.get("Name") == attribute_name or attr.get("FriendlyName") == attribute_name:
                # Get original values
                original_values = [v.text or "" for v in attr.findall(f"{{{SAML_NS}}}AttributeValue")]

                parent = attr.getparent()
                if parent is not None:
                    parent.remove(attr)

                self.manipulations.append(
                    SAMLManipulation(
                        type=SAMLManipulationType.ATTRIBUTE_REMOVED,
                        description=f"Removed attribute '{attribute_name}'",
                        original_value=", ".join(original_values),
                    )
                )
                return self

        raise ValueError(f"Attribute '{attribute_name}' not found")

    def modify_issuer(self, new_issuer: str) -> SAMLManipulator:
        """Modify the Issuer value.

        Args:
            new_issuer: New issuer value.

        Returns:
            Self for chaining.
        """
        # Modify Response issuer
        if self._is_response:
            response_issuer = self.doc.find(f"{{{SAML_NS}}}Issuer")
            if response_issuer is not None:
                original = response_issuer.text
                response_issuer.text = new_issuer
                self.manipulations.append(
                    SAMLManipulation(
                        type=SAMLManipulationType.ISSUER_MODIFIED,
                        description="Modified Response Issuer",
                        original_value=original,
                        new_value=new_issuer,
                    )
                )

        # Modify Assertion issuer
        assertion = self._get_first_assertion()
        if assertion is not None:
            assertion_issuer = assertion.find(f"{{{SAML_NS}}}Issuer")
            if assertion_issuer is not None:
                original = assertion_issuer.text
                assertion_issuer.text = new_issuer
                self.manipulations.append(
                    SAMLManipulation(
                        type=SAMLManipulationType.ISSUER_MODIFIED,
                        description="Modified Assertion Issuer",
                        original_value=original,
                        new_value=new_issuer,
                    )
                )

        return self

    def extend_conditions(self, hours: int = 24) -> SAMLManipulator:
        """Extend the assertion validity period.

        Args:
            hours: Number of hours to extend the validity.

        Returns:
            Self for chaining.
        """
        assertion = self._get_first_assertion()
        if assertion is None:
            raise ValueError("No assertion found in document")

        conditions = assertion.find(f"{{{SAML_NS}}}Conditions")
        if conditions is None:
            raise ValueError("No Conditions found in assertion")

        now = datetime.now(UTC)
        new_not_before = (now - timedelta(minutes=5)).strftime("%Y-%m-%dT%H:%M:%SZ")
        new_not_after = (now + timedelta(hours=hours)).strftime("%Y-%m-%dT%H:%M:%SZ")

        original_not_before = conditions.get("NotBefore")
        original_not_after = conditions.get("NotOnOrAfter")

        conditions.set("NotBefore", new_not_before)
        conditions.set("NotOnOrAfter", new_not_after)

        self.manipulations.append(
            SAMLManipulation(
                type=SAMLManipulationType.CONDITION_MODIFIED,
                description="Extended validity period",
                original_value=f"NotBefore: {original_not_before}, NotOnOrAfter: {original_not_after}",
                new_value=f"NotBefore: {new_not_before}, NotOnOrAfter: {new_not_after}",
            )
        )
        return self

    def modify_audience(self, new_audience: str) -> SAMLManipulator:
        """Modify the audience restriction.

        Args:
            new_audience: New audience URI (SP entity ID).

        Returns:
            Self for chaining.
        """
        assertion = self._get_first_assertion()
        if assertion is None:
            raise ValueError("No assertion found in document")

        audience = assertion.find(f".//{{{SAML_NS}}}Audience")
        if audience is None:
            raise ValueError("No Audience found in assertion")

        original = audience.text
        audience.text = new_audience

        self.manipulations.append(
            SAMLManipulation(
                type=SAMLManipulationType.CONDITION_MODIFIED,
                description="Modified Audience restriction",
                original_value=original,
                new_value=new_audience,
            )
        )
        return self

    def strip_signature(self) -> ManipulatedAssertion:
        """Remove all signatures from the document.

        This tests if applications properly validate SAML signatures.

        Returns:
            ManipulatedAssertion with signatures stripped.
        """
        # Remove all Signature elements
        for sig in self.doc.findall(f".//{{{DSIG_NS}}}Signature"):
            parent = sig.getparent()
            if parent is not None:
                parent.remove(sig)

        self.manipulations.append(
            SAMLManipulation(
                type=SAMLManipulationType.SIGNATURE_STRIPPED,
                description="Removed all signatures from document",
            )
        )

        return ManipulatedAssertion(
            original_xml=self.original_xml,
            manipulated_xml=etree.tostring(self.doc, encoding="unicode"),
            manipulations=self.manipulations.copy(),
            signed_with="none (unsigned)",
        )

    def sign_with_key(
        self,
        private_key: rsa.RSAPrivateKey,
        certificate: Certificate | None = None,
        key_description: str = "Custom RSA key",
        sign_assertion: bool = True,
        sign_response: bool = False,
    ) -> ManipulatedAssertion:
        """Re-sign the SAML document with a custom key.

        Args:
            private_key: RSA private key for signing.
            certificate: Optional X.509 certificate to embed in signature.
            key_description: Description of the key for labeling.
            sign_assertion: Sign the Assertion element.
            sign_response: Sign the Response element (if present).

        Returns:
            ManipulatedAssertion signed with the provided key.
        """
        if not SIGNXML_AVAILABLE:
            raise RuntimeError("signxml library is required for re-signing. Install with: pip install signxml")

        # First remove existing signatures
        for sig in self.doc.findall(f".//{{{DSIG_NS}}}Signature"):
            parent = sig.getparent()
            if parent is not None:
                parent.remove(sig)

        # Convert private key to PEM for signxml
        key_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )

        # Convert certificate to PEM if provided
        cert_pem = None
        if certificate:
            cert_pem = certificate.public_bytes(serialization.Encoding.PEM)

        # Create signer
        signer = XMLSigner(
            method=SignatureMethod.RSA_SHA256,
            digest_algorithm=DigestAlgorithm.SHA256,
        )

        signed_doc = self.doc

        # Sign assertion
        if sign_assertion:
            assertion = self._get_first_assertion()
            if assertion is not None:
                # The assertion needs an ID attribute for reference
                assertion_id = assertion.get("ID")
                if assertion_id:
                    signed_doc = signer.sign(
                        signed_doc,
                        key=key_pem,
                        cert=cert_pem,
                        reference_uri=f"#{assertion_id}",
                    )

        # Sign response
        if sign_response and self._is_response:
            response_id = self.doc.get("ID")
            if response_id:
                signed_doc = signer.sign(
                    signed_doc,
                    key=key_pem,
                    cert=cert_pem,
                    reference_uri=f"#{response_id}",
                )

        self.manipulations.append(
            SAMLManipulation(
                type=SAMLManipulationType.CUSTOM_SIGNED,
                description=f"Re-signed with {key_description}",
            )
        )

        return ManipulatedAssertion(
            original_xml=self.original_xml,
            manipulated_xml=etree.tostring(signed_doc, encoding="unicode"),
            manipulations=self.manipulations.copy(),
            signed_with=key_description,
        )

    def build_unsigned(self) -> ManipulatedAssertion:
        """Build manipulated assertion without re-signing.

        NOTE: If signatures exist, they will be INVALID since the content
        has been modified. Use this to test signature validation.

        Returns:
            ManipulatedAssertion with original (invalid) signatures.
        """
        return ManipulatedAssertion(
            original_xml=self.original_xml,
            manipulated_xml=etree.tostring(self.doc, encoding="unicode"),
            manipulations=self.manipulations.copy(),
            signed_with="Original signature (INVALID - content modified)",
        )


def parse_saml_attributes(saml_xml: str) -> dict[str, list[str]]:
    """Parse attributes from a SAML assertion.

    Args:
        saml_xml: SAML XML string (can be base64-encoded).

    Returns:
        Dictionary of attribute names to their values.
    """
    # Try to decode if base64-encoded
    try:
        decoded = base64.b64decode(saml_xml)
        saml_xml = decoded.decode("utf-8")
    except Exception:
        pass

    doc = etree.fromstring(saml_xml.encode("utf-8"))
    attributes: dict[str, list[str]] = {}

    for attr in doc.findall(f".//{{{SAML_NS}}}Attribute"):
        name = attr.get("FriendlyName") or attr.get("Name") or "unknown"
        values = [v.text or "" for v in attr.findall(f"{{{SAML_NS}}}AttributeValue")]
        attributes[name] = values

    return attributes


def get_nameid_from_assertion(saml_xml: str) -> tuple[str | None, str | None]:
    """Extract NameID and its format from a SAML assertion.

    Args:
        saml_xml: SAML XML string (can be base64-encoded).

    Returns:
        Tuple of (nameid_value, nameid_format).
    """
    # Try to decode if base64-encoded
    try:
        decoded = base64.b64decode(saml_xml)
        saml_xml = decoded.decode("utf-8")
    except Exception:
        pass

    doc = etree.fromstring(saml_xml.encode("utf-8"))
    nameid = doc.find(f".//{{{SAML_NS}}}NameID")

    if nameid is not None:
        return nameid.text, nameid.get("Format")

    return None, None
