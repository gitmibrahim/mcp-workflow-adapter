from __future__ import annotations

import json
import logging
from typing import Any, Final

from pydantic import ValidationError
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.routing import Route

from workflow_adapter.auth import AuthenticatedCaller, OAuth2TokenVerifier
from workflow_adapter.errors import AdapterError, ErrorCode, generate_correlation_id
from workflow_adapter.models import NotificationPreferences
from workflow_adapter.ports import StorageBackendPort
from workflow_adapter.redaction import redact_sensitive_data
from workflow_adapter.well_known import OAuthProtectedResourceConfig

logger = logging.getLogger(__name__)

SUPPORTED_MCP_PROTOCOL_VERSION: Final[str] = "2025-03-26"

MCP_TOOLS_CATALOG: Final[list[dict[str, Any]]] = [
    {
        "name": "start_inspection",
        "description": (
            "Start a new stateful workflow execution for an approved asset_id and inspection_type. "
            "Acquires an active asset exclusivity lock and commits initial RUNNING state atomically."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "inspection_type": {"type": "string", "description": "Workflow type identifier."},
                "asset_id": {
                    "type": "string",
                    "description": "Target asset or flow-cell identifier.",
                },
                "idempotency_key": {
                    "type": "string",
                    "minLength": 1,
                    "maxLength": 128,
                    "description": "Unique client retry key for idempotent start execution.",
                },
                "notification_prefs": {
                    "type": "object",
                    "properties": {
                        "on_pause": {"type": "boolean"},
                        "on_revision": {"type": "boolean"},
                        "on_blocked": {"type": "boolean"},
                        "on_status": {"type": "boolean"},
                        "on_completion": {"type": "boolean"},
                        "channels": {"type": "array", "items": {"type": "string"}},
                    },
                    "additionalProperties": False,
                },
            },
            "required": ["inspection_type", "asset_id", "idempotency_key"],
            "additionalProperties": False,
        },
    },
    {
        "name": "get_inspection_status",
        "description": (
            "Retrieve authoritative workflow execution state from durable storage. "
            "If execution_id and asset_id are omitted, auto-resolves a single active session "
            "or returns disambiguation metadata if multiple active sessions exist."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "execution_id": {"type": "string"},
                "asset_id": {"type": "string"},
                "emit_notification": {"type": "boolean", "default": False},
            },
            "additionalProperties": False,
        },
    },
    {
        "name": "record_inspection_result",
        "description": (
            "Record and validate a numeric measurement for the current pending workflow step. "
            "Out-of-range values transition the workflow deterministically to BLOCKED."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "execution_id": {"type": "string"},
                "step_id": {"type": "string"},
                "value": {"type": "number"},
                "unit": {"type": "string"},
                "idempotency_key": {"type": "string", "minLength": 1, "maxLength": 128},
            },
            "required": ["execution_id", "step_id", "value", "idempotency_key"],
            "additionalProperties": False,
        },
    },
    {
        "name": "resolve_inspection_exception",
        "description": (
            "Resolve an active out-of-range exception on a BLOCKED workflow using an explicitly "
            "whitelisted domain policy resolution."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "execution_id": {"type": "string"},
                "exception_id": {"type": "string"},
                "resolution": {"type": "string"},
                "idempotency_key": {"type": "string", "minLength": 1, "maxLength": 128},
            },
            "required": ["execution_id", "exception_id", "resolution", "idempotency_key"],
            "additionalProperties": False,
        },
    },
    {
        "name": "complete_inspection",
        "description": (
            "Finalize and complete a workflow execution once all required steps and exceptions "
            "are satisfied, releasing the active asset lock and returning an audit summary."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "execution_id": {"type": "string"},
                "idempotency_key": {"type": "string", "minLength": 1, "maxLength": 128},
            },
            "required": ["execution_id", "idempotency_key"],
            "additionalProperties": False,
        },
    },
    {
        "name": "configure_notifications",
        "description": (
            "Update live workflow notification preferences and optionally mark the active session "
            "as paused (emitting an immediate resume-checkpoint notification)."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "execution_id": {"type": "string"},
                "preferences": {
                    "type": "object",
                    "properties": {
                        "on_pause": {"type": "boolean"},
                        "on_revision": {"type": "boolean"},
                        "on_blocked": {"type": "boolean"},
                        "on_status": {"type": "boolean"},
                        "on_completion": {"type": "boolean"},
                        "channels": {"type": "array", "items": {"type": "string"}},
                    },
                    "additionalProperties": False,
                },
                "pause_session": {"type": "boolean", "default": False},
                "idempotency_key": {"type": "string", "minLength": 1, "maxLength": 128},
            },
            "required": ["execution_id", "idempotency_key"],
            "additionalProperties": False,
        },
    },
]


class MCPWorkflowServer:
    """MCP Streamable HTTP server enforcing headerless 401 and two-tier OAuth 2.1 security."""

    def __init__(
        self,
        *,
        backend: StorageBackendPort,
        token_verifier: OAuth2TokenVerifier,
        server_name: str = "checkpoint-workflow-mcp",
        server_version: str = "0.1.0",
    ) -> None:
        self._backend = backend
        self._verifier = token_verifier
        self._server_name = server_name
        self._server_version = server_version
        self._resource_config = OAuthProtectedResourceConfig(
            resource_uri=token_verifier.resource_uri,
            issuer_url=token_verifier.issuer_url,
        )

    def create_asgi_app(self) -> Starlette:
        return Starlette(
            debug=False,
            routes=[
                Route("/health", self._handle_health, methods=["GET"]),
                Route(
                    "/.well-known/oauth-protected-resource",
                    self._handle_protected_resource_metadata,
                    methods=["GET"],
                ),
                Route("/mcp", self._handle_mcp_post, methods=["POST"]),
                Route("/mcp", self._handle_mcp_get_not_allowed, methods=["GET"]),
            ],
        )

    async def _handle_health(self, _request: Request) -> JSONResponse:
        return JSONResponse({"status": "ok", "server": self._server_name})

    async def _handle_protected_resource_metadata(self, _request: Request) -> JSONResponse:
        return JSONResponse(self._resource_config.to_metadata_dict())

    async def _handle_mcp_get_not_allowed(self, _request: Request) -> Response:
        return Response(status_code=405, headers={"Allow": "POST"})

    @staticmethod
    def _headerless_401_response(err: AdapterError) -> JSONResponse:
        """Return HTTP 401 Unauthorized strictly WITHOUT a WWW-Authenticate header."""
        sanitized = redact_sensitive_data(err.to_dict())
        response = JSONResponse(
            status_code=401,
            content={"error": sanitized},
        )
        if "www-authenticate" in response.headers:
            del response.headers["www-authenticate"]
        return response

    @staticmethod
    def _format_tool_result(payload: dict[str, Any], *, is_error: bool) -> dict[str, Any]:
        sanitized = redact_sensitive_data(payload)
        return {
            "content": [
                {
                    "type": "text",
                    "text": json.dumps(sanitized, sort_keys=True),
                }
            ],
            "structuredContent": sanitized,
            "isError": is_error,
        }

    def _dispatch_tool_call(
        self, caller: AuthenticatedCaller, params: dict[str, Any], correlation_id: str
    ) -> dict[str, Any]:
        tool_name = params.get("name")
        raw_args = params.get("arguments")
        if not isinstance(tool_name, str) or not tool_name:
            raise AdapterError(
                ErrorCode.INVALID_INPUT,
                "tools/call requires a non-empty string 'name'.",
                correlation_id=correlation_id,
            )
        if raw_args is None:
            args: dict[str, Any] = {}
        elif isinstance(raw_args, dict):
            args = raw_args
        else:
            raise AdapterError(
                ErrorCode.INVALID_INPUT,
                "tools/call 'arguments' must be a JSON object.",
                correlation_id=correlation_id,
            )

        principal_id = caller.principal_id

        try:
            if tool_name == "start_inspection":
                prefs_raw = args.get("notification_prefs")
                prefs = (
                    NotificationPreferences.model_validate(prefs_raw)
                    if prefs_raw is not None
                    else None
                )
                res_start = self._backend.start_inspection(
                    principal_id=principal_id,
                    inspection_type=str(args["inspection_type"]),
                    asset_id=str(args["asset_id"]),
                    idempotency_key=str(args["idempotency_key"]),
                    notification_prefs=prefs,
                    correlation_id=correlation_id,
                )
                return self._format_tool_result(res_start.model_dump(mode="json"), is_error=False)

            if tool_name == "get_inspection_status":
                res_status = self._backend.get_inspection_status(
                    principal_id=principal_id,
                    execution_id=args.get("execution_id"),
                    asset_id=args.get("asset_id"),
                    emit_notification=bool(args.get("emit_notification", False)),
                    correlation_id=correlation_id,
                )
                return self._format_tool_result(res_status.model_dump(mode="json"), is_error=False)

            if tool_name == "record_inspection_result":
                raw_val = args.get("value")
                if isinstance(raw_val, bool) or not isinstance(raw_val, (int, float)):
                    raise AdapterError(
                        ErrorCode.INVALID_INPUT,
                        "Parameter 'value' must be a numeric float or integer.",
                        correlation_id=correlation_id,
                    )
                res_record = self._backend.record_inspection_result(
                    principal_id=principal_id,
                    execution_id=str(args["execution_id"]),
                    step_id=str(args["step_id"]),
                    value=float(raw_val),
                    unit=args.get("unit"),
                    idempotency_key=str(args["idempotency_key"]),
                    correlation_id=correlation_id,
                )
                return self._format_tool_result(res_record.model_dump(mode="json"), is_error=False)

            if tool_name == "resolve_inspection_exception":
                res_resolve = self._backend.resolve_inspection_exception(
                    principal_id=principal_id,
                    execution_id=str(args["execution_id"]),
                    exception_id=str(args["exception_id"]),
                    resolution=str(args["resolution"]),
                    idempotency_key=str(args["idempotency_key"]),
                    correlation_id=correlation_id,
                )
                return self._format_tool_result(res_resolve.model_dump(mode="json"), is_error=False)

            if tool_name == "complete_inspection":
                res_complete = self._backend.complete_inspection(
                    principal_id=principal_id,
                    execution_id=str(args["execution_id"]),
                    idempotency_key=str(args["idempotency_key"]),
                    correlation_id=correlation_id,
                )
                return self._format_tool_result(
                    res_complete.model_dump(mode="json"), is_error=False
                )

            if tool_name == "configure_notifications":
                prefs_raw = args.get("preferences")
                prefs = (
                    NotificationPreferences.model_validate(prefs_raw)
                    if prefs_raw is not None
                    else None
                )
                res_cfg = self._backend.configure_notifications(
                    principal_id=principal_id,
                    execution_id=str(args["execution_id"]),
                    preferences=prefs,
                    pause_session=bool(args.get("pause_session", False)),
                    idempotency_key=str(args["idempotency_key"]),
                    correlation_id=correlation_id,
                )
                return self._format_tool_result(res_cfg.model_dump(mode="json"), is_error=False)

            raise AdapterError(
                ErrorCode.INVALID_INPUT,
                f"Unknown tool '{tool_name}'.",
                correlation_id=correlation_id,
            )
        except (KeyError, ValidationError, TypeError) as exc:
            raise AdapterError(
                ErrorCode.INVALID_INPUT,
                f"Invalid arguments for tool '{tool_name}': {exc}",
                correlation_id=correlation_id,
            ) from exc

    async def _handle_mcp_post(self, request: Request) -> Response:
        correlation_id = generate_correlation_id()

        # Step 1: Verify Bearer JWT before processing body; return headerless 401 on auth failure
        try:
            caller = self._verifier.authenticate_bearer_header(
                request.headers.get("authorization"),
                correlation_id=correlation_id,
            )
        except AdapterError as auth_err:
            logger.warning(
                "Unauthorized MCP request rejected",
                extra={"structured_data": auth_err.to_dict()},
            )
            return self._headerless_401_response(auth_err)

        # Step 2: Parse JSON-RPC 2.0 body
        try:
            body = await request.json()
        except (json.JSONDecodeError, ValueError, UnicodeDecodeError):
            err = AdapterError(
                ErrorCode.INVALID_INPUT,
                "Request body must be valid JSON.",
                correlation_id=correlation_id,
            )
            return JSONResponse(
                status_code=400,
                content={
                    "jsonrpc": "2.0",
                    "id": None,
                    "error": {"code": -32700, "message": "Parse error", "data": err.to_dict()},
                },
            )

        if not isinstance(body, dict) or body.get("jsonrpc") != "2.0":
            err = AdapterError(
                ErrorCode.INVALID_INPUT,
                "Request must be a JSON-RPC 2.0 object.",
                correlation_id=correlation_id,
            )
            return JSONResponse(
                status_code=400,
                content={
                    "jsonrpc": "2.0",
                    "id": body.get("id") if isinstance(body, dict) else None,
                    "error": {"code": -32600, "message": "Invalid Request", "data": err.to_dict()},
                },
            )

        rpc_id = body.get("id")
        is_notification = "id" not in body
        rpc_method = str(body.get("method", ""))
        params = body.get("params") or {}

        # Step 3: Authorize method against Tier 1 (mcp:service) / Tier 2 (mcp:tools)
        try:
            self._verifier.authorize_rpc_method(caller, rpc_method, correlation_id=correlation_id)
        except AdapterError as authz_err:
            if rpc_method == "tools/call" and not is_notification:
                return JSONResponse(
                    status_code=200,
                    content={
                        "jsonrpc": "2.0",
                        "id": rpc_id,
                        "result": self._format_tool_result(authz_err.to_dict(), is_error=True),
                    },
                )
            return JSONResponse(
                status_code=403,
                content={
                    "jsonrpc": "2.0",
                    "id": rpc_id,
                    "error": {
                        "code": -32003,
                        "message": authz_err.message,
                        "data": redact_sensitive_data(authz_err.to_dict()),
                    },
                },
            )

        # Step 4: Execute JSON-RPC method
        try:
            if is_notification or rpc_method == "notifications/initialized":
                return Response(status_code=202)

            if rpc_method == "initialize":
                return JSONResponse(
                    status_code=200,
                    content={
                        "jsonrpc": "2.0",
                        "id": rpc_id,
                        "result": {
                            "protocolVersion": SUPPORTED_MCP_PROTOCOL_VERSION,
                            "capabilities": {"tools": {"listChanged": False}},
                            "serverInfo": {
                                "name": self._server_name,
                                "version": self._server_version,
                            },
                        },
                    },
                )

            if rpc_method == "ping":
                return JSONResponse(
                    status_code=200,
                    content={"jsonrpc": "2.0", "id": rpc_id, "result": {}},
                )

            if rpc_method == "tools/list":
                return JSONResponse(
                    status_code=200,
                    content={
                        "jsonrpc": "2.0",
                        "id": rpc_id,
                        "result": {"tools": MCP_TOOLS_CATALOG},
                    },
                )

            if rpc_method == "tools/call":
                tool_result = self._dispatch_tool_call(caller, params, correlation_id)
                return JSONResponse(
                    status_code=200,
                    content={"jsonrpc": "2.0", "id": rpc_id, "result": tool_result},
                )

            raise AdapterError(
                ErrorCode.INVALID_INPUT,
                f"Unsupported method '{rpc_method}'.",
                correlation_id=correlation_id,
            )

        except AdapterError as domain_err:
            logger.info(
                "Structured workflow tool error returned",
                extra={"structured_data": domain_err.to_dict()},
            )
            return JSONResponse(
                status_code=200,
                content={
                    "jsonrpc": "2.0",
                    "id": rpc_id,
                    "result": self._format_tool_result(domain_err.to_dict(), is_error=True),
                },
            )
        except Exception as unexpected_exc:
            logger.error(
                "Unhandled exception in MCP server",
                exc_info=unexpected_exc,
                extra={"structured_data": {"correlation_id": correlation_id}},
            )
            safe_err = AdapterError(
                ErrorCode.INTERNAL_ERROR,
                "An unexpected internal error occurred.",
                retryable=False,
                correlation_id=correlation_id,
            )
            return JSONResponse(
                status_code=200,
                content={
                    "jsonrpc": "2.0",
                    "id": rpc_id,
                    "result": self._format_tool_result(safe_err.to_dict(), is_error=True),
                },
            )
