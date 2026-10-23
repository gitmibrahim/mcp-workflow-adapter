from __future__ import annotations

import base64
import hashlib
import json
import secrets
import time
from dataclasses import dataclass
from typing import Any

import jwt
from cryptography.hazmat.primitives.asymmetric import rsa
from jwt.algorithms import RSAAlgorithm

from workflow_adapter.errors import AdapterError, ErrorCode


@dataclass
class PendingAuthCode:
    code: str
    client_id: str
    principal_id: str
    redirect_uri: str
    code_challenge: str
    code_challenge_method: str
    scope: str
    resource: str
    expires_at: float


class EphemeralOAuth2TestIssuer:
    """In-memory RS256 OAuth 2.1 + PKCE (S256) issuer fixture for contract testing ONLY."""

    def __init__(
        self,
        *,
        issuer_url: str = "https://test-issuer.checkpoint.local",
        default_resource_uri: str = "https://mcp.checkpoint.local/mcp",
        kid: str = "test-rs256-key-1",
    ) -> None:
        self.issuer_url = issuer_url.rstrip("/")
        self.default_resource_uri = default_resource_uri
        self.kid = kid
        self._private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self._public_key = self._private_key.public_key()
        self._untrusted_private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self._auth_codes: dict[str, PendingAuthCode] = {}

    def get_jwks_json(self) -> str:
        jwk_dict = json.loads(RSAAlgorithm.to_jwk(self._public_key))
        jwk_dict["kid"] = self.kid
        jwk_dict["use"] = "sig"
        jwk_dict["alg"] = "RS256"
        return json.dumps({"keys": [jwk_dict]})

    @staticmethod
    def generate_pkce_pair() -> tuple[str, str]:
        """Return (code_verifier, s256_code_challenge)."""
        verifier = secrets.token_urlsafe(48)
        digest = hashlib.sha256(verifier.encode("ascii")).digest()
        challenge = base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
        return verifier, challenge

    def create_authorization_code(
        self,
        *,
        client_id: str,
        principal_id: str,
        redirect_uri: str,
        code_challenge: str,
        code_challenge_method: str = "S256",
        scope: str = "mcp:tools",
        resource: str | None = None,
    ) -> str:
        if code_challenge_method != "S256" or not code_challenge:
            raise AdapterError(
                ErrorCode.INVALID_INPUT, "PKCE code_challenge_method 'S256' is required."
            )
        code = f"code_{secrets.token_urlsafe(24)}"
        self._auth_codes[code] = PendingAuthCode(
            code=code,
            client_id=client_id,
            principal_id=principal_id,
            redirect_uri=redirect_uri,
            code_challenge=code_challenge,
            code_challenge_method=code_challenge_method,
            scope=scope,
            resource=resource or self.default_resource_uri,
            expires_at=time.time() + 300.0,
        )
        return code

    def exchange_authorization_code(
        self,
        *,
        code: str,
        client_id: str,
        redirect_uri: str,
        code_verifier: str,
        resource: str | None = None,
    ) -> str:
        pending = self._auth_codes.pop(code, None)
        if pending is None or time.time() > pending.expires_at:
            raise AdapterError(ErrorCode.UNAUTHORIZED, "Invalid or expired authorization code.")
        if pending.client_id != client_id or pending.redirect_uri != redirect_uri:
            raise AdapterError(ErrorCode.UNAUTHORIZED, "Client ID or redirect URI mismatch.")

        expected_digest = hashlib.sha256(code_verifier.encode("ascii")).digest()
        expected_challenge = base64.urlsafe_b64encode(expected_digest).rstrip(b"=").decode("ascii")
        if not secrets.compare_digest(expected_challenge, pending.code_challenge):
            raise AdapterError(ErrorCode.UNAUTHORIZED, "PKCE S256 verification failed.")

        target_resource = resource or pending.resource
        if target_resource != pending.resource:
            raise AdapterError(
                ErrorCode.UNAUTHORIZED, "Target resource mismatch during code exchange."
            )

        return self.issue_user_token(
            principal_id=pending.principal_id,
            scope=pending.scope,
            resource_uri=target_resource,
        )

    def issue_service_token(
        self,
        *,
        client_id: str = "alexa-plus-service-client",
        scope: str = "mcp:service",
        resource_uri: str | None = None,
        expires_in_seconds: int = 3600,
    ) -> str:
        now = int(time.time())
        target_aud = resource_uri or self.default_resource_uri
        claims: dict[str, Any] = {
            "iss": self.issuer_url,
            "sub": f"service:{client_id}",
            "aud": target_aud,
            "resource": target_aud,
            "scope": scope,
            "grant_type": "client_credentials",
            "token_use": "service",
            "iat": now,
            "exp": now + expires_in_seconds,
        }
        return jwt.encode(claims, self._private_key, algorithm="RS256", headers={"kid": self.kid})

    def issue_user_token(
        self,
        *,
        principal_id: str,
        scope: str = "mcp:tools",
        resource_uri: str | None = None,
        issuer_override: str | None = None,
        expires_in_seconds: int = 3600,
        sign_with_untrusted_key: bool = False,
        kid_override: str | None = None,
    ) -> str:
        now = int(time.time())
        target_aud = resource_uri or self.default_resource_uri
        claims: dict[str, Any] = {
            "iss": issuer_override or self.issuer_url,
            "sub": principal_id,
            "aud": target_aud,
            "resource": target_aud,
            "scope": scope,
            "grant_type": "authorization_code",
            "token_use": "user",
            "iat": now,
            "exp": now + expires_in_seconds,
        }
        key = self._untrusted_private_key if sign_with_untrusted_key else self._private_key
        return jwt.encode(
            claims,
            key,
            algorithm="RS256",
            headers={"kid": kid_override or self.kid},
        )
