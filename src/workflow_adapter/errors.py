from __future__ import annotations

import uuid
from enum import StrEnum
from typing import Any, Final


class ErrorCode(StrEnum):
    INVALID_INPUT = "INVALID_INPUT"
    UNAUTHORIZED = "UNAUTHORIZED"
    FORBIDDEN = "FORBIDDEN"
    NOT_FOUND = "NOT_FOUND"
    INVALID_STATE_TRANSITION = "INVALID_STATE_TRANSITION"
    IDEMPOTENCY_CONFLICT = "IDEMPOTENCY_CONFLICT"
    WORKFLOW_BLOCKED = "WORKFLOW_BLOCKED"
    BACKEND_UNAVAILABLE = "BACKEND_UNAVAILABLE"
    INTERNAL_ERROR = "INTERNAL_ERROR"


DEFAULT_RETRYABLE_BY_CODE: Final[dict[ErrorCode, bool]] = {
    ErrorCode.INVALID_INPUT: False,
    ErrorCode.UNAUTHORIZED: True,
    ErrorCode.FORBIDDEN: False,
    ErrorCode.NOT_FOUND: False,
    ErrorCode.INVALID_STATE_TRANSITION: False,
    ErrorCode.IDEMPOTENCY_CONFLICT: False,
    ErrorCode.WORKFLOW_BLOCKED: False,
    ErrorCode.BACKEND_UNAVAILABLE: True,
    ErrorCode.INTERNAL_ERROR: False,
}


def generate_correlation_id() -> str:
    return f"corr_{uuid.uuid4().hex[:16]}"


class AdapterError(Exception):
    """Structured domain and infrastructure exception with safe client serialization."""

    def __init__(
        self,
        error_code: ErrorCode | str,
        message: str,
        *,
        retryable: bool | None = None,
        correlation_id: str | None = None,
        details: dict[str, Any] | None = None,
    ) -> None:
        resolved_code = ErrorCode(error_code)
        super().__init__(message)
        self.error_code: ErrorCode = resolved_code
        self.message: str = message
        self.retryable: bool = (
            DEFAULT_RETRYABLE_BY_CODE[resolved_code] if retryable is None else retryable
        )
        self.correlation_id: str = correlation_id or generate_correlation_id()
        self.details: dict[str, Any] = details or {}

    def to_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "error_code": self.error_code.value,
            "message": self.message,
            "retryable": self.retryable,
            "correlation_id": self.correlation_id,
        }
        if self.details:
            payload["details"] = self.details
        return payload
