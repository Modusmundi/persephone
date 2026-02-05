"""SAML authentication flow implementations."""

from authtest.core.saml.signature import (
    SignatureInfo,
    SignatureLocation,
    SignatureStatus,
    SignatureValidationResult,
    get_signature_summary,
    validate_signature,
)
from authtest.core.saml.sp import (
    SAMLAssertion,
    SAMLRequest,
    SAMLResponse,
    SAMLServiceProvider,
)

__all__ = [
    "SAMLAssertion",
    "SAMLRequest",
    "SAMLResponse",
    "SAMLServiceProvider",
    "SignatureInfo",
    "SignatureLocation",
    "SignatureStatus",
    "SignatureValidationResult",
    "get_signature_summary",
    "validate_signature",
]
