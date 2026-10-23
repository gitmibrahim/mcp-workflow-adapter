from __future__ import annotations

import json
import logging
import re
from typing import Any, Final

BEARER_TOKEN_PATTERN: Final[re.Pattern[str]] = re.compile(r"(?i)\bBearer\s+[A-Za-z0-9\-._~+/]+=*")
RAW_JWT_PATTERN: Final[re.Pattern[str]] = re.compile(
    r"\beyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\b"
)
AWS_ACCESS_KEY_PATTERN: Final[re.Pattern[str]] = re.compile(
    r"\b(?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16}\b"
)
AWS_ARN_PATTERN: Final[re.Pattern[str]] = re.compile(
    r"\barn:aws[a-zA-Z-]*:[a-zA-Z0-9-]+:[a-zA-Z0-9-]*:\d{12}:[^\s\"',}]+"
)
TRACEBACK_BLOCK_PATTERN: Final[re.Pattern[str]] = re.compile(
    r"Traceback \(most recent call last\):[\s\S]*"
)
FILE_LINE_FRAME_PATTERN: Final[re.Pattern[str]] = re.compile(r'File "[^"]+", line \d+, in [^\n]+')

SENSITIVE_DICT_KEYS: Final[frozenset[str]] = frozenset(
    {
        "authorization",
        "access_token",
        "refresh_token",
        "id_token",
        "token",
        "client_secret",
        "password",
        "secret",
        "aws_secret_access_key",
        "aws_session_token",
        "sfn_task_token",
        "task_token",
        "sfn_execution_arn",
    }
)


def redact_string(value: str) -> str:
    redacted = TRACEBACK_BLOCK_PATTERN.sub("[REDACTED_STACK_TRACE]", value)
    redacted = FILE_LINE_FRAME_PATTERN.sub("[REDACTED_FRAME]", redacted)
    redacted = BEARER_TOKEN_PATTERN.sub("Bearer [REDACTED_TOKEN]", redacted)
    redacted = RAW_JWT_PATTERN.sub("[REDACTED_JWT]", redacted)
    redacted = AWS_ACCESS_KEY_PATTERN.sub("[REDACTED_AWS_KEY]", redacted)
    return AWS_ARN_PATTERN.sub("[REDACTED_AWS_ARN]", redacted)


def redact_sensitive_data(data: Any) -> Any:
    if isinstance(data, str):
        return redact_string(data)
    if isinstance(data, dict):
        sanitized: dict[str, Any] = {}
        for k, v in data.items():
            key_lower = str(k).lower()
            if key_lower.endswith("_arn"):
                sanitized[k] = "[REDACTED_AWS_ARN]"
            elif (
                key_lower in SENSITIVE_DICT_KEYS
                or key_lower.endswith("_secret")
                or key_lower.endswith("_token")
            ):
                sanitized[k] = "[REDACTED]"
            else:
                sanitized[k] = redact_sensitive_data(v)
        return sanitized
    if isinstance(data, list):
        return [redact_sensitive_data(item) for item in data]
    if isinstance(data, tuple):
        return tuple(redact_sensitive_data(item) for item in data)
    return data


class RedactingJsonFormatter(logging.Formatter):
    """Structured JSON log formatter that automatically scrubs sensitive fields and substrings."""

    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "timestamp": self.formatTime(record, self.datefmt),
            "level": record.levelname,
            "logger": record.name,
            "message": redact_string(record.getMessage()),
        }
        if hasattr(record, "structured_data"):
            payload["event"] = redact_sensitive_data(record.structured_data)
        if record.exc_info:
            payload["exception"] = "[REDACTED_STACK_TRACE]"
        return json.dumps(payload, sort_keys=True)
