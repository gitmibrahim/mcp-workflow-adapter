from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Any, Final

import jwt
from jwt import PyJWK, PyJWKSet

from workflow_adapter.errors import AdapterError, ErrorCode, generate_correlation_id

DISCOVERY_RPC_METHODS: Final[frozenset[str]] = frozenset(
    {
        "initialize",
        "notifications/initialized",
        "ping",
        "tools/list",
    }
)


class AuthProfile(StrEnum):
    ALEXA_CATEGORY_MCP = "ALEXA_CATEGORY_MCP"
    ALEXA_MCP_TOOLKIT = "ALEXA_MCP_TOOLKIT"
    COMPATIBLE_BOTH = "COMPATIBLE_BOTH"


@dataclass(frozen=True)
class AuthenticatedCaller:
    """Verified identity extracted from an OAuth 2.1 Bearer JWT."""

    subject: str
    scopes: frozenset[str]
    is_service_token: bool
    issuer: str
    audience: str

    @property
    def principal_id(self) -> str:
        if self.is_service_token or not self.subject:
            raise AdapterError(
                ErrorCode.FORBIDDEN,
                "User principal_id is unavailable on a service-tier token.",
                retryable=False,
            )
        return self.subject


class OAuth2TokenVerifier:
    """Verifies RS256 OAuth 2.1 JWTs, canonical resource audience, and two-tier MCP scopes."""

    def __init__(
        self,
        *,
        issuer_url: str,
        resource_uri: str,
        jwks_json: str,
        profile: AuthProfile = AuthProfile.ALEXA_CATEGORY_MCP,
        allowed_algorithms: tuple[str, ...] = ("RS256",),
    ) -> None:
        if not issuer_url or not resource_uri:
            raise ValueError("issuer_url and resource_uri must be non-empty.")
        if not jwks_json:
            raise ValueError("jwks_json must be provided for signature verification.")
        self._issuer_url = issuer_url.rstrip("/")
        self._resource_uri = resource_uri
        self._jwk_set = PyJWKSet.from_json(jwks_json)
        self._profile = profile
        self._algorithms = list(allowed_algorithms)

    @property
    def issuer_url(self) -> str:
        return self._issuer_url

    @property
    def resource_uri(self) -> str:
        return self._resource_uri

    @property
    def profile(self) -> AuthProfile:
        return self._profile

    def _resolve_signing_key(self, token: str, correlation_id: str) -> PyJWK:
        try:
            unverified_header = jwt.get_unverified_header(token)
        except jwt.PyJWTError as exc:
            raise AdapterError(
                ErrorCode.UNAUTHORIZED,
                "Malformed Bearer token header.",
                retryable=True,
                correlation_id=correlation_id,
            ) from exc

        alg = unverified_header.get("alg")
        if alg not in self._algorithms:
            raise AdapterError(
                ErrorCode.UNAUTHORIZED,
                f"Unsupported JWT signing algorithm '{alg}'.",
                retryable=True,
                correlation_id=correlation_id,
            )

        kid = unverified_header.get("kid")
        for key in self._jwk_set.keys:
            if kid is None or key.key_id == kid:
                return key

        raise AdapterError(
            ErrorCode.UNAUTHORIZED,
            "Token signing key ID (kid) not found in trusted JWKS.",
            retryable=True,
            correlation_id=correlation_id,
        )

    def authenticate_bearer_header(
        self, authorization_header: str | None, *, correlation_id: str | None = None
    ) -> AuthenticatedCaller:
        corr_id = correlation_id or generate_correlation_id()
        if not authorization_header:
            raise AdapterError(
                ErrorCode.UNAUTHORIZED,
                "Missing Authorization Bearer header.",
                retryable=True,
                correlation_id=corr_id,
            )

        parts = authorization_header.strip().split(" ", 1)
        if len(parts) != 2 or parts[0].lower() != "bearer" or not parts[1].strip():
            raise AdapterError(
                ErrorCode.UNAUTHORIZED,
                "Authorization header must use Bearer token scheme.",
                retryable=True,
                correlation_id=corr_id,
            )

        raw_token = parts[1].strip()
        signing_key = self._resolve_signing_key(raw_token, corr_id)

        try:
            claims: dict[str, Any] = jwt.decode(
                raw_token,
                signing_key.key,
                algorithms=self._algorithms,
                audience=self._resource_uri,
                options={
                    "require": ["exp", "iss", "sub"],
                    "verify_signature": True,
                    "verify_exp": True,
                    "verify_aud": True,
                },
            )
        except jwt.ExpiredSignatureError as exc:
            raise AdapterError(
                ErrorCode.UNAUTHORIZED,
                "Bearer token has expired.",
                retryable=True,
                correlation_id=corr_id,
            ) from exc
        except jwt.InvalidAudienceError as exc:
            raise AdapterError(
                ErrorCode.UNAUTHORIZED,
                "Bearer token audience does not match this MCP resource URI.",
                retryable=True,
                correlation_id=corr_id,
            ) from exc
        except jwt.PyJWTError as exc:
            raise AdapterError(
                ErrorCode.UNAUTHORIZED,
                "Bearer token cryptographic verification failed.",
                retryable=True,
                correlation_id=corr_id,
            ) from exc

        token_iss = str(claims.get("iss", "")).rstrip("/")
        if token_iss != self._issuer_url:
            raise AdapterError(
                ErrorCode.UNAUTHORIZED,
                "Bearer token issuer is not trusted.",
                retryable=True,
                correlation_id=corr_id,
            )

        # Verify optional RFC 8707 'resource' claim if present alongside 'aud'
        resource_claim = claims.get("resource")
        if resource_claim is not None and resource_claim != self._resource_uri:
            raise AdapterError(
                ErrorCode.UNAUTHORIZED,
                "Bearer token resource claim does not match canonical MCP resource URI.",
                retryable=True,
                correlation_id=corr_id,
            )

        raw_scope = claims.get("scope", "")
        scopes: set[str] = set()
        if isinstance(raw_scope, str):
            scopes.update(s for s in raw_scope.split() if s)
        elif isinstance(claims.get("scp"), list):
            scopes.update(str(s) for s in claims["scp"] if s)

        subject = str(claims.get("sub", "")).strip()
        if not subject:
            raise AdapterError(
                ErrorCode.UNAUTHORIZED,
                "Bearer token is missing a non-empty 'sub' claim.",
                retryable=True,
                correlation_id=corr_id,
            )

        grant_type = str(claims.get("grant_type", "")).lower()
        token_use = str(claims.get("token_use", "")).lower()
        is_service = (
            grant_type == "client_credentials"
            or token_use == "service"
            or ("mcp:service" in scopes and "mcp:tools" not in scopes)
        )

        return AuthenticatedCaller(
            subject=subject,
            scopes=frozenset(scopes),
            is_service_token=is_service,
            issuer=token_iss,
            audience=self._resource_uri,
        )

    def authorize_rpc_method(
        self, caller: AuthenticatedCaller, rpc_method: str, *, correlation_id: str | None = None
    ) -> None:
        corr_id = correlation_id or generate_correlation_id()

        if rpc_method in DISCOVERY_RPC_METHODS:
            if self._profile == AuthProfile.ALEXA_MCP_TOOLKIT:
                if "mcp:tools" not in caller.scopes and "mcp:service" not in caller.scopes:
                    raise AdapterError(
                        ErrorCode.FORBIDDEN,
                        f"Method '{rpc_method}' requires 'mcp:tools' or 'mcp:service' scope.",
                        retryable=False,
                        correlation_id=corr_id,
                    )
            else:
                if "mcp:service" not in caller.scopes and "mcp:tools" not in caller.scopes:
                    raise AdapterError(
                        ErrorCode.FORBIDDEN,
                        f"Discovery method '{rpc_method}' requires 'mcp:service' or 'mcp:tools' scope.",
                        retryable=False,
                        correlation_id=corr_id,
                    )
            return

        if rpc_method == "tools/call":
            if caller.is_service_token:
                raise AdapterError(
                    ErrorCode.FORBIDDEN,
                    "Service-only token ('mcp:service' / client_credentials) cannot invoke 'tools/call'. "
                    "User-delegated 'mcp:tools' token is required.",
                    retryable=False,
                    correlation_id=corr_id,
                )
            if "mcp:tools" not in caller.scopes:
                raise AdapterError(
                    ErrorCode.FORBIDDEN,
                    "Invoking 'tools/call' requires 'mcp:tools' scope.",
                    retryable=False,
                    correlation_id=corr_id,
                )
            return

        raise AdapterError(
            ErrorCode.INVALID_INPUT,
            f"Unsupported MCP JSON-RPC method '{rpc_method}'.",
            retryable=False,
            correlation_id=corr_id,
        )
