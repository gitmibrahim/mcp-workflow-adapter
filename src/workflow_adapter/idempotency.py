from __future__ import annotations

import hashlib
import json
import math
import secrets
from typing import Any, TypeVar

from pydantic import BaseModel

from workflow_adapter.errors import AdapterError, ErrorCode

TOutcome = TypeVar("TOutcome", bound=BaseModel)
TResponse = TypeVar("TResponse", bound=BaseModel)


def generate_execution_id() -> str:
    """Generate a 128-bit CSPRNG execution identifier in the service/backend layer."""
    return f"exec_{secrets.token_hex(16)}"


def generate_exception_id() -> str:
    return f"exc_{secrets.token_hex(8)}"


def generate_event_id(prefix: str = "evt") -> str:
    return f"{prefix}_{secrets.token_hex(8)}"


def validate_idempotency_key(idempotency_key: str) -> str:
    cleaned = idempotency_key.strip() if isinstance(idempotency_key, str) else ""
    if not cleaned or len(cleaned) > 128:
        raise AdapterError(
            ErrorCode.INVALID_INPUT,
            "idempotency_key must be a non-empty string between 1 and 128 characters.",
        )
    return cleaned


def _canonicalize_value(value: Any) -> Any:
    if isinstance(value, dict):
        return {
            str(k): _canonicalize_value(v)
            for k, v in sorted(value.items())
            if k != "idempotency_key"
        }
    if isinstance(value, (list, tuple)):
        return [_canonicalize_value(v) for v in value]
    if isinstance(value, float):
        if not math.isfinite(value):
            raise AdapterError(ErrorCode.INVALID_INPUT, "Numeric values must be finite.")
        # Normalize -0.0 to 0.0 and round to 8 decimal places for canonical stability
        return 0.0 if value == 0.0 else round(value, 8)
    if isinstance(value, BaseModel):
        return _canonicalize_value(value.model_dump(mode="json"))
    return value


def compute_payload_hash(operation: str, payload: dict[str, Any]) -> str:
    """Compute a deterministic SHA-256 hex digest of the canonicalized request payload."""
    canonical_obj = {
        "operation": operation,
        "payload": _canonicalize_value(payload),
    }
    canonical_json = json.dumps(
        canonical_obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    )
    return hashlib.sha256(canonical_json.encode("utf-8")).hexdigest()


def verify_or_raise_idempotency_conflict(
    *,
    idempotency_key: str,
    operation: str,
    stored_payload_hash: str,
    incoming_payload_hash: str,
) -> None:
    if stored_payload_hash != incoming_payload_hash:
        raise AdapterError(
            ErrorCode.IDEMPOTENCY_CONFLICT,
            f"Idempotency key '{idempotency_key}' for operation '{operation}' was already used with a different request payload.",
        )


def derive_client_request_token(
    principal_id: str, scope_id: str, operation: str, idempotency_key: str
) -> str:
    """Derive a deterministic 32-char token (<= 36 chars required by DynamoDB ClientRequestToken)."""
    raw = f"{principal_id}:{scope_id}:{operation}:{idempotency_key}".encode()
    return hashlib.sha256(raw).hexdigest()[:32]


def build_response_from_outcome(
    outcome_json: str,
    outcome_cls: type[TOutcome],
    response_cls: type[TResponse],
    *,
    duplicate: bool,
) -> TResponse:
    outcome_instance = outcome_cls.model_validate_json(outcome_json)
    data = outcome_instance.model_dump()
    data["duplicate"] = duplicate
    return response_cls.model_validate(data)
