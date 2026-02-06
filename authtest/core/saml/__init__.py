"""SAML authentication flow implementations."""

from authtest.core.saml.artifact import (
    ArtifactResolver,
    ArtifactResolveRequest,
    ArtifactResolveResponse,
    SAMLArtifact,
)
from authtest.core.saml.logout import (
    LogoutSessionInfo,
    LogoutStatus,
    LogoutValidationCheck,
    LogoutValidationResult,
    SAMLLogoutHandler,
    SAMLLogoutRequest,
    SAMLLogoutResponse,
    get_logout_status_description,
    validate_logout_response,
)
from authtest.core.saml.signature import (
    SignatureInfo,
    SignatureLocation,
    SignatureStatus,
    SignatureValidationResult,
    get_signature_summary,
    validate_signature,
)
from authtest.core.saml.sp import (
    BINDING_HTTP_ARTIFACT,
    BINDING_HTTP_POST,
    BINDING_HTTP_REDIRECT,
    SAMLAssertion,
    SAMLRequest,
    SAMLResponse,
    SAMLServiceProvider,
)
from authtest.core.saml.manipulation import (
    ManipulatedAssertion,
    SAMLManipulation,
    SAMLManipulationType,
    SAMLManipulator,
    get_nameid_from_assertion,
    parse_saml_attributes,
)

__all__ = [
    # Artifact binding
    "ArtifactResolveRequest",
    "ArtifactResolveResponse",
    "ArtifactResolver",
    "SAMLArtifact",
    # Logout (SLO)
    "LogoutSessionInfo",
    "LogoutStatus",
    "LogoutValidationCheck",
    "LogoutValidationResult",
    "SAMLLogoutHandler",
    "SAMLLogoutRequest",
    "SAMLLogoutResponse",
    "get_logout_status_description",
    "validate_logout_response",
    # Manipulation
    "ManipulatedAssertion",
    "SAMLManipulation",
    "SAMLManipulationType",
    "SAMLManipulator",
    "get_nameid_from_assertion",
    "parse_saml_attributes",
    # SP
    "BINDING_HTTP_ARTIFACT",
    "BINDING_HTTP_POST",
    "BINDING_HTTP_REDIRECT",
    "SAMLAssertion",
    "SAMLRequest",
    "SAMLResponse",
    "SAMLServiceProvider",
    # Signature
    "SignatureInfo",
    "SignatureLocation",
    "SignatureStatus",
    "SignatureValidationResult",
    "get_signature_summary",
    "validate_signature",
]
