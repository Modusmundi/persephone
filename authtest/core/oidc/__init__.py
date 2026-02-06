"""OIDC authentication flow implementations."""

from authtest.core.oidc.client import (
    AuthorizationRequest,
    DeviceAuthorizationResponse,
    OIDCClient,
    OIDCClientConfig,
    TokenResponse,
    UserInfoResponse,
    generate_code_challenge,
    generate_code_verifier,
)
from authtest.core.oidc.flows import (
    AuthorizationCodeFlow,
    ClientCredentialsFlow,
    DeviceCodeFlow,
    DeviceCodeFlowState,
    ImplicitFlow,
    OIDCFlowResult,
    OIDCFlowState,
    OIDCFlowStatus,
    PreflightCheck,
    PreflightResult,
    TestOutcome,
)
from authtest.core.oidc.utils import (
    DecodedToken,
    decode_jwt,
    format_token_claims,
    get_algorithm_description,
    get_token_type_description,
)
from authtest.core.oidc.validation import (
    JWKSManager,
    TokenValidationResult,
    TokenValidator,
    ValidationCheck,
    ValidationStatus,
    validate_id_token,
)

__all__ = [
    # Client
    "AuthorizationRequest",
    "DeviceAuthorizationResponse",
    "OIDCClient",
    "OIDCClientConfig",
    "TokenResponse",
    "UserInfoResponse",
    "generate_code_challenge",
    "generate_code_verifier",
    # Flows
    "AuthorizationCodeFlow",
    "ClientCredentialsFlow",
    "DeviceCodeFlow",
    "DeviceCodeFlowState",
    "ImplicitFlow",
    "OIDCFlowResult",
    "OIDCFlowState",
    "OIDCFlowStatus",
    "PreflightCheck",
    "PreflightResult",
    "TestOutcome",
    # Utils
    "DecodedToken",
    "decode_jwt",
    "format_token_claims",
    "get_algorithm_description",
    "get_token_type_description",
    # Validation
    "JWKSManager",
    "TokenValidationResult",
    "TokenValidator",
    "ValidationCheck",
    "ValidationStatus",
    "validate_id_token",
]
