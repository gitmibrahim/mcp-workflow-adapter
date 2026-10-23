from __future__ import annotations

from pathlib import Path
from typing import Any

import httpx
import pytest

from fixtures.oauth_test_issuer import EphemeralOAuth2TestIssuer
from workflow_adapter.auth import AuthProfile, OAuth2TokenVerifier
from workflow_adapter.backends.local import LocalBackend
from workflow_adapter.errors import AdapterError, ErrorCode
from workflow_adapter.mcp_server import MCPWorkflowServer
from workflow_adapter.ports import DomainPolicyPort


@pytest.fixture
def oauth_issuer() -> EphemeralOAuth2TestIssuer:
    return EphemeralOAuth2TestIssuer(
        issuer_url="https://test-issuer.checkpoint.local",
        default_resource_uri="https://mcp.checkpoint.local/mcp",
    )


@pytest.fixture
def auth_verifier(oauth_issuer: EphemeralOAuth2TestIssuer) -> OAuth2TokenVerifier:
    return OAuth2TokenVerifier(
        issuer_url=oauth_issuer.issuer_url,
        resource_uri=oauth_issuer.default_resource_uri,
        jwks_json=oauth_issuer.get_jwks_json(),
        profile=AuthProfile.ALEXA_CATEGORY_MCP,
    )


@pytest.fixture
def mcp_server(
    auth_verifier: OAuth2TokenVerifier, policy: DomainPolicyPort, tmp_path: Path
) -> MCPWorkflowServer:
    db_path = tmp_path / "auth_contract_wal.db"
    backend = LocalBackend(db_path.as_posix(), policy)
    return MCPWorkflowServer(backend=backend, token_verifier=auth_verifier)


@pytest.mark.asyncio
async def test_missing_or_malformed_bearer_token_returns_headerless_401(
    mcp_server: MCPWorkflowServer,
) -> None:
    app = mcp_server.create_asgi_app()
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="https://test") as client:
        # Case 1: Missing Authorization header
        resp_missing = await client.post(
            "/mcp", json={"jsonrpc": "2.0", "id": "1", "method": "ping"}
        )
        assert resp_missing.status_code == 401
        assert "www-authenticate" not in {k.lower() for k in resp_missing.headers}
        assert resp_missing.json()["error"]["error_code"] == ErrorCode.UNAUTHORIZED.value

        # Case 2: Basic auth scheme
        resp_basic = await client.post(
            "/mcp",
            headers={"Authorization": "Basic dXNlcjpwYXNz"},
            json={"jsonrpc": "2.0", "id": "2", "method": "ping"},
        )
        assert resp_basic.status_code == 401
        assert "www-authenticate" not in {k.lower() for k in resp_basic.headers}
        assert resp_basic.json()["error"]["error_code"] == ErrorCode.UNAUTHORIZED.value

        # Case 3: Malformed JWT token
        resp_bad_jwt = await client.post(
            "/mcp",
            headers={"Authorization": "Bearer not-a-valid-jwt-token"},
            json={"jsonrpc": "2.0", "id": "3", "method": "ping"},
        )
        assert resp_bad_jwt.status_code == 401
        assert "www-authenticate" not in {k.lower() for k in resp_bad_jwt.headers}
        assert resp_bad_jwt.json()["error"]["error_code"] == ErrorCode.UNAUTHORIZED.value


@pytest.mark.asyncio
async def test_expired_wrong_aud_wrong_iss_and_untrusted_key_return_headerless_401(
    mcp_server: MCPWorkflowServer, oauth_issuer: EphemeralOAuth2TestIssuer
) -> None:
    app = mcp_server.create_asgi_app()
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="https://test") as client:
        # 1. Expired token
        expired_token = oauth_issuer.issue_user_token(
            principal_id="tech-alice",
            expires_in_seconds=-60,
        )
        r_exp = await client.post(
            "/mcp",
            headers={"Authorization": f"Bearer {expired_token}"},
            json={"jsonrpc": "2.0", "id": "1", "method": "ping"},
        )
        assert r_exp.status_code == 401
        assert "www-authenticate" not in {k.lower() for k in r_exp.headers}

        # 2. Wrong audience
        wrong_aud_token = oauth_issuer.issue_user_token(
            principal_id="tech-alice",
            resource_uri="https://wrong-service.checkpoint.local/mcp",
        )
        r_aud = await client.post(
            "/mcp",
            headers={"Authorization": f"Bearer {wrong_aud_token}"},
            json={"jsonrpc": "2.0", "id": "2", "method": "ping"},
        )
        assert r_aud.status_code == 401
        assert "www-authenticate" not in {k.lower() for k in r_aud.headers}

        # 3. Wrong issuer
        wrong_iss_token = oauth_issuer.issue_user_token(
            principal_id="tech-alice",
            issuer_override="https://evil-untrusted-issuer.example.com",
        )
        r_iss = await client.post(
            "/mcp",
            headers={"Authorization": f"Bearer {wrong_iss_token}"},
            json={"jsonrpc": "2.0", "id": "3", "method": "ping"},
        )
        assert r_iss.status_code == 401
        assert "www-authenticate" not in {k.lower() for k in r_iss.headers}

        # 4. Untrusted signing key (unknown kid or signature key)
        untrusted_key_token = oauth_issuer.issue_user_token(
            principal_id="tech-alice",
            sign_with_untrusted_key=True,
        )
        r_key = await client.post(
            "/mcp",
            headers={"Authorization": f"Bearer {untrusted_key_token}"},
            json={"jsonrpc": "2.0", "id": "4", "method": "ping"},
        )
        assert r_key.status_code == 401
        assert "www-authenticate" not in {k.lower() for k in r_key.headers}


def test_pkce_s256_authorization_code_exchange_enforced(
    oauth_issuer: EphemeralOAuth2TestIssuer,
) -> None:
    code_verifier, code_challenge = oauth_issuer.generate_pkce_pair()

    # Valid PKCE exchange
    code = oauth_issuer.create_authorization_code(
        client_id="alexa-client-1",
        principal_id="tech-alice",
        redirect_uri="https://alexa.amazon.com/api/callback",
        code_challenge=code_challenge,
        code_challenge_method="S256",
        scope="mcp:tools",
    )
    user_token = oauth_issuer.exchange_authorization_code(
        code=code,
        client_id="alexa-client-1",
        redirect_uri="https://alexa.amazon.com/api/callback",
        code_verifier=code_verifier,
    )
    assert user_token is not None and len(user_token) > 20

    # Rejected plain challenge method
    with pytest.raises(AdapterError) as exc_plain:
        oauth_issuer.create_authorization_code(
            client_id="alexa-client-1",
            principal_id="tech-alice",
            redirect_uri="https://alexa.amazon.com/api/callback",
            code_challenge="plain-string",
            code_challenge_method="plain",
        )
    assert exc_plain.value.error_code == ErrorCode.INVALID_INPUT

    # Rejected tampered code_verifier
    code2 = oauth_issuer.create_authorization_code(
        client_id="alexa-client-1",
        principal_id="tech-alice",
        redirect_uri="https://alexa.amazon.com/api/callback",
        code_challenge=code_challenge,
        code_challenge_method="S256",
    )
    with pytest.raises(AdapterError) as exc_tamper:
        oauth_issuer.exchange_authorization_code(
            code=code2,
            client_id="alexa-client-1",
            redirect_uri="https://alexa.amazon.com/api/callback",
            code_verifier="wrong-verifier-secret-key",
        )
    assert exc_tamper.value.error_code == ErrorCode.UNAUTHORIZED


@pytest.mark.asyncio
async def test_tier1_service_token_allowed_for_discovery_but_forbidden_on_tools_call(
    mcp_server: MCPWorkflowServer, oauth_issuer: EphemeralOAuth2TestIssuer
) -> None:
    app = mcp_server.create_asgi_app()
    transport = httpx.ASGITransport(app=app)
    service_token = oauth_issuer.issue_service_token(scope="mcp:service")
    headers = {"Authorization": f"Bearer {service_token}"}

    async with httpx.AsyncClient(transport=transport, base_url="https://test") as client:
        # Discovery: initialize -> 200
        r_init = await client.post(
            "/mcp",
            headers=headers,
            json={"jsonrpc": "2.0", "id": "1", "method": "initialize", "params": {}},
        )
        assert r_init.status_code == 200
        assert r_init.json()["result"]["serverInfo"]["name"] == "checkpoint-workflow-mcp"

        # Discovery: ping -> 200
        r_ping = await client.post(
            "/mcp",
            headers=headers,
            json={"jsonrpc": "2.0", "id": "2", "method": "ping"},
        )
        assert r_ping.status_code == 200

        # Discovery: tools/list -> 200 with 6 tools
        r_list = await client.post(
            "/mcp",
            headers=headers,
            json={"jsonrpc": "2.0", "id": "3", "method": "tools/list"},
        )
        assert r_list.status_code == 200
        tools = r_list.json()["result"]["tools"]
        assert len(tools) == 6

        # Forbidden: tools/call with service token returns tool error with FORBIDDEN
        r_call = await client.post(
            "/mcp",
            headers=headers,
            json={
                "jsonrpc": "2.0",
                "id": "4",
                "method": "tools/call",
                "params": {
                    "name": "start_inspection",
                    "arguments": {
                        "inspection_type": "contract_type",
                        "asset_id": "ASSET-ALPHA",
                        "idempotency_key": "srv-start-01",
                    },
                },
            },
        )
        assert r_call.status_code == 200
        res = r_call.json()["result"]
        assert res["isError"] is True
        assert res["structuredContent"]["error_code"] == ErrorCode.FORBIDDEN.value


@pytest.mark.asyncio
async def test_tier2_user_token_without_mcp_tools_scope_forbidden_on_tools_call(
    mcp_server: MCPWorkflowServer, oauth_issuer: EphemeralOAuth2TestIssuer
) -> None:
    app = mcp_server.create_asgi_app()
    transport = httpx.ASGITransport(app=app)
    # User token missing mcp:tools scope
    unscoped_token = oauth_issuer.issue_user_token(
        principal_id="tech-alice",
        scope="profile email",
    )
    headers = {"Authorization": f"Bearer {unscoped_token}"}

    async with httpx.AsyncClient(transport=transport, base_url="https://test") as client:
        r_call = await client.post(
            "/mcp",
            headers=headers,
            json={
                "jsonrpc": "2.0",
                "id": "1",
                "method": "tools/call",
                "params": {
                    "name": "start_inspection",
                    "arguments": {
                        "inspection_type": "contract_type",
                        "asset_id": "ASSET-ALPHA",
                        "idempotency_key": "unscoped-01",
                    },
                },
            },
        )
        assert r_call.status_code == 200
        res = r_call.json()["result"]
        assert res["isError"] is True
        assert res["structuredContent"]["error_code"] == ErrorCode.FORBIDDEN.value


@pytest.mark.asyncio
async def test_protected_resource_metadata_endpoint_is_authentic(
    mcp_server: MCPWorkflowServer, auth_verifier: OAuth2TokenVerifier
) -> None:
    app = mcp_server.create_asgi_app()
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="https://test") as client:
        resp = await client.get("/.well-known/oauth-protected-resource")
        assert resp.status_code == 200
        data: dict[str, Any] = resp.json()
        assert data["resource"] == auth_verifier.resource_uri
        assert data["authorization_servers"] == [auth_verifier.issuer_url]
        assert data["scopes_supported"] == ["mcp:service", "mcp:tools"]
        assert data["bearer_methods_supported"] == ["header"]


def test_no_oauth_issuer_code_shipped_in_src_package() -> None:
    src_dir = Path(__file__).resolve().parent.parent.parent / "src" / "workflow_adapter"
    assert src_dir.is_dir()

    py_files = list(src_dir.rglob("*.py"))
    assert len(py_files) > 0

    for py_file in py_files:
        content = py_file.read_text(encoding="utf-8")
        assert "EphemeralOAuth2TestIssuer" not in content, (
            f"Test issuer EphemeralOAuth2TestIssuer must not be included in production src: {py_file}"
        )


@pytest.mark.asyncio
async def test_both_alexa_category_mcp_and_toolkit_profiles_pass_contract(
    oauth_issuer: EphemeralOAuth2TestIssuer, policy: DomainPolicyPort, tmp_path: Path
) -> None:
    db_path = tmp_path / "profiles_wal.db"
    backend = LocalBackend(db_path.as_posix(), policy)

    # 1. Profile: ALEXA_CATEGORY_MCP
    v_cat = OAuth2TokenVerifier(
        issuer_url=oauth_issuer.issuer_url,
        resource_uri=oauth_issuer.default_resource_uri,
        jwks_json=oauth_issuer.get_jwks_json(),
        profile=AuthProfile.ALEXA_CATEGORY_MCP,
    )
    s_cat = MCPWorkflowServer(backend=backend, token_verifier=v_cat)
    t_cat = httpx.ASGITransport(app=s_cat.create_asgi_app())

    # 2. Profile: ALEXA_MCP_TOOLKIT
    v_tool = OAuth2TokenVerifier(
        issuer_url=oauth_issuer.issuer_url,
        resource_uri=oauth_issuer.default_resource_uri,
        jwks_json=oauth_issuer.get_jwks_json(),
        profile=AuthProfile.ALEXA_MCP_TOOLKIT,
    )
    s_tool = MCPWorkflowServer(backend=backend, token_verifier=v_tool)
    t_tool = httpx.ASGITransport(app=s_tool.create_asgi_app())

    user_token = oauth_issuer.issue_user_token(
        principal_id="tech-alice",
        scope="mcp:tools",
    )
    headers = {"Authorization": f"Bearer {user_token}"}

    async with httpx.AsyncClient(transport=t_cat, base_url="https://test") as c_cat:
        r1 = await c_cat.post(
            "/mcp",
            headers=headers,
            json={"jsonrpc": "2.0", "id": "1", "method": "initialize", "params": {}},
        )
        assert r1.status_code == 200

    async with httpx.AsyncClient(transport=t_tool, base_url="https://test") as c_tool:
        r2 = await c_tool.post(
            "/mcp",
            headers=headers,
            json={"jsonrpc": "2.0", "id": "2", "method": "initialize", "params": {}},
        )
        assert r2.status_code == 200
