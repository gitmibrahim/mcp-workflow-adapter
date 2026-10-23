from __future__ import annotations

from pathlib import Path

import httpx
import pytest

from tests.fixtures.oauth_test_issuer import EphemeralOAuth2TestIssuer
from workflow_adapter.auth import AuthProfile, OAuth2TokenVerifier
from workflow_adapter.backends.local import LocalBackend
from workflow_adapter.errors import ErrorCode
from workflow_adapter.mcp_server import MCPWorkflowServer
from workflow_adapter.models import WorkflowStatus
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
    db_path = tmp_path / "streamable_http_wal.db"
    backend = LocalBackend(db_path.as_posix(), policy)
    return MCPWorkflowServer(backend=backend, token_verifier=auth_verifier)


@pytest.mark.asyncio
async def test_full_workflow_journey_over_streamable_http(
    mcp_server: MCPWorkflowServer, oauth_issuer: EphemeralOAuth2TestIssuer
) -> None:
    app = mcp_server.create_asgi_app()
    transport = httpx.ASGITransport(app=app)
    alice_token = oauth_issuer.issue_user_token(principal_id="tech-alice", scope="mcp:tools")
    headers = {"Authorization": f"Bearer {alice_token}"}

    async with httpx.AsyncClient(transport=transport, base_url="https://test") as client:
        # 1. Initialize
        r_init = await client.post(
            "/mcp",
            headers=headers,
            json={"jsonrpc": "2.0", "id": "1", "method": "initialize", "params": {}},
        )
        assert r_init.status_code == 200
        assert r_init.json()["result"]["protocolVersion"] == "2025-03-26"

        # 2. Notifications/initialized (202 Accepted)
        r_notify = await client.post(
            "/mcp",
            headers=headers,
            json={"jsonrpc": "2.0", "method": "notifications/initialized"},
        )
        assert r_notify.status_code == 202

        # 3. Tools list
        r_list = await client.post(
            "/mcp",
            headers=headers,
            json={"jsonrpc": "2.0", "id": "2", "method": "tools/list"},
        )
        assert r_list.status_code == 200
        tools = r_list.json()["result"]["tools"]
        assert len(tools) == 6

        # 4. Start inspection
        r_start = await client.post(
            "/mcp",
            headers=headers,
            json={
                "jsonrpc": "2.0",
                "id": "3",
                "method": "tools/call",
                "params": {
                    "name": "start_inspection",
                    "arguments": {
                        "inspection_type": "contract_type",
                        "asset_id": "ASSET-ALPHA",
                        "idempotency_key": "journey-start-01",
                        "notification_prefs": {"on_pause": True, "channels": ["email"]},
                    },
                },
            },
        )
        assert r_start.status_code == 200
        start_res = r_start.json()["result"]
        assert start_res["isError"] is False
        exec_id = start_res["structuredContent"]["execution_id"]
        assert start_res["structuredContent"]["status"] == WorkflowStatus.RUNNING.value
        assert start_res["structuredContent"]["next_step"]["step_id"] == "step_a"

        # 5. Record Step A (valid)
        r_step_a = await client.post(
            "/mcp",
            headers=headers,
            json={
                "jsonrpc": "2.0",
                "id": "4",
                "method": "tools/call",
                "params": {
                    "name": "record_inspection_result",
                    "arguments": {
                        "execution_id": exec_id,
                        "step_id": "step_a",
                        "value": 25.0,
                        "unit": "unit_a",
                        "idempotency_key": "journey-step-a-01",
                    },
                },
            },
        )
        assert r_step_a.status_code == 200
        res_a = r_step_a.json()["result"]
        assert res_a["isError"] is False
        assert res_a["structuredContent"]["accepted"] is True
        assert res_a["structuredContent"]["next_step"]["step_id"] == "step_b"

        # 6. Record Step B (valid)
        r_step_b = await client.post(
            "/mcp",
            headers=headers,
            json={
                "jsonrpc": "2.0",
                "id": "5",
                "method": "tools/call",
                "params": {
                    "name": "record_inspection_result",
                    "arguments": {
                        "execution_id": exec_id,
                        "step_id": "step_b",
                        "value": 150.0,
                        "unit": "unit_b",
                        "idempotency_key": "journey-step-b-01",
                    },
                },
            },
        )
        assert r_step_b.status_code == 200
        res_b = r_step_b.json()["result"]
        assert res_b["isError"] is False
        assert res_b["structuredContent"]["accepted"] is True
        assert res_b["structuredContent"]["next_step"]["step_id"] == "step_c"

        # 7. Configure notifications with pause_session=True
        r_pause = await client.post(
            "/mcp",
            headers=headers,
            json={
                "jsonrpc": "2.0",
                "id": "6",
                "method": "tools/call",
                "params": {
                    "name": "configure_notifications",
                    "arguments": {
                        "execution_id": exec_id,
                        "pause_session": True,
                        "idempotency_key": "journey-pause-01",
                    },
                },
            },
        )
        assert r_pause.status_code == 200
        assert r_pause.json()["result"]["isError"] is False

        # 8. Resume inspection status with execution_id=None
        r_resume = await client.post(
            "/mcp",
            headers=headers,
            json={
                "jsonrpc": "2.0",
                "id": "7",
                "method": "tools/call",
                "params": {
                    "name": "get_inspection_status",
                    "arguments": {},
                },
            },
        )
        assert r_resume.status_code == 200
        status_res = r_resume.json()["result"]["structuredContent"]
        assert status_res["execution_id"] == exec_id
        assert status_res["status"] == WorkflowStatus.RUNNING.value
        assert len(status_res["completed_steps"]) == 2
        assert status_res["pending_step"]["step_id"] == "step_c"

        # 9. Idempotent replay of Step A
        r_replay = await client.post(
            "/mcp",
            headers=headers,
            json={
                "jsonrpc": "2.0",
                "id": "8",
                "method": "tools/call",
                "params": {
                    "name": "record_inspection_result",
                    "arguments": {
                        "execution_id": exec_id,
                        "step_id": "step_a",
                        "value": 25.0,
                        "unit": "unit_a",
                        "idempotency_key": "journey-step-a-01",
                    },
                },
            },
        )
        assert r_replay.status_code == 200
        res_replay = r_replay.json()["result"]["structuredContent"]
        assert res_replay["accepted"] is True
        assert res_replay["duplicate"] is True

        # 10. Out-of-range reading on Step C -> transitions to BLOCKED
        r_oor = await client.post(
            "/mcp",
            headers=headers,
            json={
                "jsonrpc": "2.0",
                "id": "9",
                "method": "tools/call",
                "params": {
                    "name": "record_inspection_result",
                    "arguments": {
                        "execution_id": exec_id,
                        "step_id": "step_c",
                        "value": 999.0,
                        "unit": "unit_c",
                        "idempotency_key": "journey-step-c-oor",
                    },
                },
            },
        )
        assert r_oor.status_code == 200
        res_oor = r_oor.json()["result"]["structuredContent"]
        assert res_oor["accepted"] is False
        assert res_oor["status"] == WorkflowStatus.BLOCKED.value
        assert res_oor["active_exception"] is not None
        assert "ADVANCE_C" in res_oor["active_exception"]["allowed_resolutions"]
        exc_id = res_oor["active_exception"]["exception_id"]

        # 11. Complete inspection while BLOCKED -> rejected
        r_bad_comp = await client.post(
            "/mcp",
            headers=headers,
            json={
                "jsonrpc": "2.0",
                "id": "10",
                "method": "tools/call",
                "params": {
                    "name": "complete_inspection",
                    "arguments": {
                        "execution_id": exec_id,
                        "idempotency_key": "bad-comp-01",
                    },
                },
            },
        )
        assert r_bad_comp.status_code == 200
        res_bad_comp = r_bad_comp.json()["result"]
        assert res_bad_comp["isError"] is True
        assert res_bad_comp["structuredContent"]["error_code"] == ErrorCode.WORKFLOW_BLOCKED.value

        # 12. Resolve exception with whitelisted resolution
        r_resolve = await client.post(
            "/mcp",
            headers=headers,
            json={
                "jsonrpc": "2.0",
                "id": "11",
                "method": "tools/call",
                "params": {
                    "name": "resolve_inspection_exception",
                    "arguments": {
                        "execution_id": exec_id,
                        "exception_id": exc_id,
                        "resolution": "ADVANCE_C",
                        "idempotency_key": "journey-resolve-01",
                    },
                },
            },
        )
        assert r_resolve.status_code == 200
        res_resolve = r_resolve.json()["result"]["structuredContent"]
        assert res_resolve["status"] == WorkflowStatus.RUNNING.value
        assert res_resolve["resolution_recorded"] == "ADVANCE_C"

        # 13. Complete inspection
        r_comp = await client.post(
            "/mcp",
            headers=headers,
            json={
                "jsonrpc": "2.0",
                "id": "12",
                "method": "tools/call",
                "params": {
                    "name": "complete_inspection",
                    "arguments": {
                        "execution_id": exec_id,
                        "idempotency_key": "journey-comp-01",
                    },
                },
            },
        )
        assert r_comp.status_code == 200
        res_comp = r_comp.json()["result"]["structuredContent"]
        assert res_comp["status"] == WorkflowStatus.COMPLETED.value
        assert res_comp["summary"]["total_steps"] == 3
        assert res_comp["summary"]["metadata"]["contract_certified"] is True


@pytest.mark.asyncio
async def test_ac11_cross_principal_access_denied_over_http(
    mcp_server: MCPWorkflowServer, oauth_issuer: EphemeralOAuth2TestIssuer
) -> None:
    app = mcp_server.create_asgi_app()
    transport = httpx.ASGITransport(app=app)
    alice_token = oauth_issuer.issue_user_token(principal_id="tech-alice", scope="mcp:tools")
    bob_token = oauth_issuer.issue_user_token(principal_id="tech-bob", scope="mcp:tools")

    async with httpx.AsyncClient(transport=transport, base_url="https://test") as client:
        # Alice starts inspection
        r_start = await client.post(
            "/mcp",
            headers={"Authorization": f"Bearer {alice_token}"},
            json={
                "jsonrpc": "2.0",
                "id": "1",
                "method": "tools/call",
                "params": {
                    "name": "start_inspection",
                    "arguments": {
                        "inspection_type": "contract_type",
                        "asset_id": "ASSET-ALPHA",
                        "idempotency_key": "alice-start-01",
                    },
                },
            },
        )
        exec_id = r_start.json()["result"]["structuredContent"]["execution_id"]

        # Bob attempts all 5 mutating and reading methods on Alice's execution_id
        bob_headers = {"Authorization": f"Bearer {bob_token}"}
        calls = [
            ("get_inspection_status", {"execution_id": exec_id}),
            (
                "record_inspection_result",
                {
                    "execution_id": exec_id,
                    "step_id": "step_a",
                    "value": 25.0,
                    "idempotency_key": "bob-step-01",
                },
            ),
            (
                "resolve_inspection_exception",
                {
                    "execution_id": exec_id,
                    "exception_id": "exc_01",
                    "resolution": "ADVANCE_A",
                    "idempotency_key": "bob-res-01",
                },
            ),
            (
                "configure_notifications",
                {"execution_id": exec_id, "idempotency_key": "bob-cfg-01"},
            ),
            (
                "complete_inspection",
                {"execution_id": exec_id, "idempotency_key": "bob-comp-01"},
            ),
        ]

        for method_name, args in calls:
            resp = await client.post(
                "/mcp",
                headers=bob_headers,
                json={
                    "jsonrpc": "2.0",
                    "id": f"bob-{method_name}",
                    "method": "tools/call",
                    "params": {"name": method_name, "arguments": args},
                },
            )
            assert resp.status_code == 200
            res = resp.json()["result"]
            assert res["isError"] is True
            assert res["structuredContent"]["error_code"] == ErrorCode.FORBIDDEN.value


@pytest.mark.asyncio
async def test_ac17_multi_session_disambiguation_and_asset_lock_over_http(
    mcp_server: MCPWorkflowServer, oauth_issuer: EphemeralOAuth2TestIssuer
) -> None:
    app = mcp_server.create_asgi_app()
    transport = httpx.ASGITransport(app=app)
    alice_token = oauth_issuer.issue_user_token(principal_id="tech-alice", scope="mcp:tools")
    headers = {"Authorization": f"Bearer {alice_token}"}

    async with httpx.AsyncClient(transport=transport, base_url="https://test") as client:
        # Start Session 1 on ASSET-ALPHA
        r1 = await client.post(
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
                        "idempotency_key": "multi-start-01",
                    },
                },
            },
        )
        assert r1.json()["result"]["isError"] is False

        # Start Session 2 on ASSET-BETA
        r2 = await client.post(
            "/mcp",
            headers=headers,
            json={
                "jsonrpc": "2.0",
                "id": "2",
                "method": "tools/call",
                "params": {
                    "name": "start_inspection",
                    "arguments": {
                        "inspection_type": "contract_type",
                        "asset_id": "ASSET-BETA",
                        "idempotency_key": "multi-start-02",
                    },
                },
            },
        )
        assert r2.json()["result"]["isError"] is False

        # Attempt to start a second inspection on ASSET-ALPHA -> CONFLICT
        r_lock = await client.post(
            "/mcp",
            headers=headers,
            json={
                "jsonrpc": "2.0",
                "id": "3",
                "method": "tools/call",
                "params": {
                    "name": "start_inspection",
                    "arguments": {
                        "inspection_type": "contract_type",
                        "asset_id": "ASSET-ALPHA",
                        "idempotency_key": "conflict-start-03",
                    },
                },
            },
        )
        assert r_lock.status_code == 200
        lock_res = r_lock.json()["result"]
        assert lock_res["isError"] is True
        assert (
            lock_res["structuredContent"]["error_code"] == ErrorCode.INVALID_STATE_TRANSITION.value
        )

        # Ambiguous resume with no execution_id
        r_ambig = await client.post(
            "/mcp",
            headers=headers,
            json={
                "jsonrpc": "2.0",
                "id": "4",
                "method": "tools/call",
                "params": {
                    "name": "get_inspection_status",
                    "arguments": {},
                },
            },
        )
        assert r_ambig.status_code == 200
        ambig_res = r_ambig.json()["result"]
        assert ambig_res["isError"] is True
        assert ambig_res["structuredContent"]["error_code"] == ErrorCode.INVALID_INPUT.value
        assert ambig_res["structuredContent"]["details"]["reason"] == "AMBIGUOUS_ACTIVE_SESSION"
        assert len(ambig_res["structuredContent"]["details"]["active_executions"]) == 2


@pytest.mark.asyncio
async def test_ac16_error_responses_redact_tokens_arns_and_stack_traces_over_http(
    mcp_server: MCPWorkflowServer, oauth_issuer: EphemeralOAuth2TestIssuer
) -> None:
    app = mcp_server.create_asgi_app()
    transport = httpx.ASGITransport(app=app)
    alice_token = oauth_issuer.issue_user_token(principal_id="tech-alice", scope="mcp:tools")
    headers = {"Authorization": f"Bearer {alice_token}"}

    secret_key = "AKIAIOSFODNN7EXAMPLE"
    secret_arn = "arn:aws:states:us-east-1:123456789012:execution:state-machine:exec-123"
    synthetic_jwt = (
        "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9."
        "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIn0."
        "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
    )

    async with httpx.AsyncClient(transport=transport, base_url="https://test") as client:
        # Pass secrets and ARNs inside invalid arguments
        r = await client.post(
            "/mcp",
            headers=headers,
            json={
                "jsonrpc": "2.0",
                "id": "redact-test",
                "method": "tools/call",
                "params": {
                    "name": "start_inspection",
                    "arguments": {
                        "inspection_type": f"bad_type {secret_key} {secret_arn}",
                        "asset_id": f"bad_asset {synthetic_jwt}",
                        "idempotency_key": "redact-start-01",
                    },
                },
            },
        )
        assert r.status_code == 200
        text = r.text
        # Assert raw secrets and ARNs are strictly absent from HTTP output
        assert secret_key not in text
        assert secret_arn not in text
        assert synthetic_jwt not in text
        # Redaction placeholders should be present
        assert "[REDACTED" in text


@pytest.mark.asyncio
async def test_get_mcp_returns_405_method_not_allowed(
    mcp_server: MCPWorkflowServer,
) -> None:
    app = mcp_server.create_asgi_app()
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="https://test") as client:
        resp = await client.get("/mcp")
        assert resp.status_code == 405
        assert resp.headers.get("allow") == "POST"


@pytest.mark.asyncio
async def test_health_endpoint_returns_200_ok(
    mcp_server: MCPWorkflowServer,
) -> None:
    app = mcp_server.create_asgi_app()
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="https://test") as client:
        resp = await client.get("/health")
        assert resp.status_code == 200
        assert resp.json()["status"] == "ok"
