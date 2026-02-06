"""OIDC authentication flow implementations."""

from authtest.core.oidc.client import (
    AuthorizationRequest,
    OIDCClient,
    OIDCClientConfig,
    TokenResponse,
    UserInfoResponse,
)
from authtest.core.oidc.flows import (
    AuthorizationCodeFlow,
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

__all__ = [
    # Client
    "AuthorizationRequest",
    "OIDCClient",
    "OIDCClientConfig",
    "TokenResponse",
    "UserInfoResponse",
    # Flows
    "AuthorizationCodeFlow",
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
]
