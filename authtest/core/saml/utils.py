"""SAML utility functions."""

from __future__ import annotations

from xml.dom import minidom


def pretty_print_xml(xml_string: str, indent: str = "  ") -> str:
    """Pretty-print an XML string with proper indentation.

    Args:
        xml_string: Raw XML string.
        indent: Indentation string (default: 2 spaces).

    Returns:
        Formatted XML string with proper indentation.
    """
    try:
        # Parse and pretty-print using minidom
        dom = minidom.parseString(xml_string.encode("utf-8"))
        pretty = dom.toprettyxml(indent=indent)
        # Remove the XML declaration if we want just the content
        # and remove blank lines
        lines = pretty.split("\n")
        # Skip first line (xml declaration) and remove empty lines
        result_lines = []
        for line in lines[1:]:  # Skip XML declaration
            if line.strip():
                result_lines.append(line)
        return "\n".join(result_lines)
    except Exception:
        # If parsing fails, return original
        return xml_string


# Common SAML attribute names and their descriptions
# Organized by category for easier lookup
SAML_ATTRIBUTE_DESCRIPTIONS: dict[str, dict[str, str]] = {
    # Core identity attributes
    "urn:oid:0.9.2342.19200300.100.1.1": {
        "name": "uid",
        "description": "User ID - unique identifier for the user",
    },
    "urn:oid:0.9.2342.19200300.100.1.3": {
        "name": "mail",
        "description": "Email address",
    },
    "urn:oid:2.5.4.3": {
        "name": "cn",
        "description": "Common Name - full name of the user",
    },
    "urn:oid:2.5.4.4": {
        "name": "sn",
        "description": "Surname - family name / last name",
    },
    "urn:oid:2.5.4.42": {
        "name": "givenName",
        "description": "Given Name - first name",
    },
    "urn:oid:2.16.840.1.113730.3.1.241": {
        "name": "displayName",
        "description": "Display Name - preferred name for display",
    },
    # eduPerson attributes (common in academic/enterprise)
    "urn:oid:1.3.6.1.4.1.5923.1.1.1.1": {
        "name": "eduPersonAffiliation",
        "description": "Affiliation type (e.g., faculty, student, staff)",
    },
    "urn:oid:1.3.6.1.4.1.5923.1.1.1.6": {
        "name": "eduPersonPrincipalName",
        "description": "Principal name - unique identifier within scope",
    },
    "urn:oid:1.3.6.1.4.1.5923.1.1.1.7": {
        "name": "eduPersonEntitlement",
        "description": "Entitlement - rights granted to the user",
    },
    "urn:oid:1.3.6.1.4.1.5923.1.1.1.9": {
        "name": "eduPersonScopedAffiliation",
        "description": "Scoped affiliation (e.g., student@example.edu)",
    },
    "urn:oid:1.3.6.1.4.1.5923.1.1.1.10": {
        "name": "eduPersonTargetedID",
        "description": "Targeted ID - persistent pseudonymous identifier",
    },
    # Commonly used friendly names
    "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress": {
        "name": "emailaddress",
        "description": "Email address (Microsoft/WS-Federation style)",
    },
    "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name": {
        "name": "name",
        "description": "Full name (Microsoft/WS-Federation style)",
    },
    "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname": {
        "name": "givenname",
        "description": "First name (Microsoft/WS-Federation style)",
    },
    "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname": {
        "name": "surname",
        "description": "Last name (Microsoft/WS-Federation style)",
    },
    "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/upn": {
        "name": "upn",
        "description": "User Principal Name (Microsoft/Active Directory)",
    },
    "http://schemas.microsoft.com/ws/2008/06/identity/claims/groups": {
        "name": "groups",
        "description": "Group memberships (Microsoft/Azure AD)",
    },
    "http://schemas.microsoft.com/ws/2008/06/identity/claims/role": {
        "name": "role",
        "description": "Role assignments (Microsoft/Azure AD)",
    },
    # Okta-style attributes
    "firstName": {
        "name": "firstName",
        "description": "First name (Okta style)",
    },
    "lastName": {
        "name": "lastName",
        "description": "Last name (Okta style)",
    },
    "email": {
        "name": "email",
        "description": "Email address (simple name)",
    },
    "login": {
        "name": "login",
        "description": "Login identifier / username",
    },
    "groups": {
        "name": "groups",
        "description": "Group memberships",
    },
    "department": {
        "name": "department",
        "description": "Department / organizational unit",
    },
    "title": {
        "name": "title",
        "description": "Job title",
    },
    "manager": {
        "name": "manager",
        "description": "Manager reference",
    },
    "employeeNumber": {
        "name": "employeeNumber",
        "description": "Employee ID number",
    },
}

# NameID format descriptions
NAMEID_FORMAT_DESCRIPTIONS: dict[str, str] = {
    "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress": "Email Address - uses the user's email as identifier",
    "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified": "Unspecified - format left to IdP discretion",
    "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent": "Persistent - stable pseudonymous identifier across sessions",
    "urn:oasis:names:tc:SAML:2.0:nameid-format:transient": "Transient - temporary identifier for this session only",
    "urn:oasis:names:tc:SAML:1.1:nameid-format:X509SubjectName": "X.509 Subject Name - distinguished name format",
    "urn:oasis:names:tc:SAML:1.1:nameid-format:WindowsDomainQualifiedName": "Windows Domain - DOMAIN\\username format",
    "urn:oasis:names:tc:SAML:2.0:nameid-format:kerberos": "Kerberos Principal - name@REALM format",
    "urn:oasis:names:tc:SAML:2.0:nameid-format:entity": "Entity - entityID reference",
}

# Authentication context class descriptions
AUTHN_CONTEXT_DESCRIPTIONS: dict[str, str] = {
    "urn:oasis:names:tc:SAML:2.0:ac:classes:unspecified": "Unspecified authentication method",
    "urn:oasis:names:tc:SAML:2.0:ac:classes:Password": "Password-based authentication",
    "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport": "Password over protected transport (HTTPS)",
    "urn:oasis:names:tc:SAML:2.0:ac:classes:X509": "X.509 certificate authentication",
    "urn:oasis:names:tc:SAML:2.0:ac:classes:Kerberos": "Kerberos authentication",
    "urn:oasis:names:tc:SAML:2.0:ac:classes:TLSClient": "TLS client certificate authentication",
    "urn:oasis:names:tc:SAML:2.0:ac:classes:SmartcardPKI": "Smartcard PKI authentication",
    "urn:oasis:names:tc:SAML:2.0:ac:classes:TimeSyncToken": "Time-synchronized OTP token",
    "urn:oasis:names:tc:SAML:2.0:ac:classes:MobileTwoFactorUnregistered": "Mobile two-factor (unregistered device)",
    "urn:oasis:names:tc:SAML:2.0:ac:classes:MobileTwoFactorContract": "Mobile two-factor (registered device)",
    "urn:federation:authentication:windows": "Windows Integrated Authentication",
}


def get_attribute_info(attr_name: str) -> dict[str, str]:
    """Get friendly name and description for a SAML attribute.

    Args:
        attr_name: The attribute name/OID.

    Returns:
        Dictionary with 'name' and 'description' keys.
    """
    if attr_name in SAML_ATTRIBUTE_DESCRIPTIONS:
        return SAML_ATTRIBUTE_DESCRIPTIONS[attr_name]

    # If not in our map, extract a friendly name from the attribute
    friendly_name = attr_name
    if "/" in attr_name:
        friendly_name = attr_name.rsplit("/", 1)[-1]
    elif ":" in attr_name:
        friendly_name = attr_name.rsplit(":", 1)[-1]

    return {
        "name": friendly_name,
        "description": "Custom attribute",
    }


def get_nameid_format_description(format_uri: str) -> str:
    """Get human-readable description for a NameID format.

    Args:
        format_uri: The NameID format URI.

    Returns:
        Human-readable description.
    """
    return NAMEID_FORMAT_DESCRIPTIONS.get(format_uri, f"Custom format: {format_uri}")


def get_authn_context_description(context_uri: str) -> str:
    """Get human-readable description for an authentication context.

    Args:
        context_uri: The AuthnContext class reference URI.

    Returns:
        Human-readable description.
    """
    return AUTHN_CONTEXT_DESCRIPTIONS.get(context_uri, f"Custom: {context_uri}")
