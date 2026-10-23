from __future__ import annotations

import json
import logging

from workflow_adapter.redaction import (
    RedactingJsonFormatter,
    redact_sensitive_data,
    redact_string,
)


def test_redact_bearer_tokens() -> None:
    sample = "Authorization failed for Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.e30.secret_sig123 with error."
    redacted = redact_string(sample)
    assert "Bearer [REDACTED_TOKEN]" in redacted
    assert "secret_sig123" not in redacted


def test_redact_raw_jwt() -> None:
    raw_jwt = (
        "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c2VyXzEyMyJ9.signature_part_here_abcdef"
    )
    sample = f"Token received: {raw_jwt}"
    redacted = redact_string(sample)
    assert "[REDACTED_JWT]" in redacted
    assert "signature_part" not in redacted


def test_redact_aws_access_keys() -> None:
    sample = "Failed to access S3 with key AKIAIOSFODNN7EXAMPLE and session ASIAIOSFODNN7EXAMPL2."
    redacted = redact_string(sample)
    assert "[REDACTED_AWS_KEY]" in redacted
    assert "AKIAIOSFODNN7EXAMPLE" not in redacted
    assert "ASIAIOSFODNN7EXAMPL2" not in redacted


def test_redact_aws_arns() -> None:
    arn = "arn:aws:states:us-east-1:123456789012:execution:CheckpointStateMachine:exec_123"
    sample = f"Executing step function at {arn} failed."
    redacted = redact_string(sample)
    assert "[REDACTED_AWS_ARN]" in redacted
    assert "CheckpointStateMachine" not in redacted


def test_redact_stack_trace_and_frame() -> None:
    trace = (
        "Traceback (most recent call last):\n"
        '  File "/var/task/app.py", line 42, in handler\n'
        '    raise ValueError("Sensitive internal error message")'
    )
    redacted = redact_string(trace)
    assert "[REDACTED_STACK_TRACE]" in redacted
    assert "Sensitive internal error message" not in redacted

    single_frame = 'File "/var/task/module.py", line 10, in execute_action'
    redacted_frame = redact_string(single_frame)
    assert "[REDACTED_FRAME]" in redacted_frame


def test_redact_sensitive_data_nested_structures() -> None:
    sensitive_dict = {
        "execution_id": "exec_123",
        "authorization": "Bearer eyJhbGci.secret.token",
        "client_secret": "my_super_secret_key",
        "custom_token": "token_abc123",
        "sfn_task_token": "AAAAKgAAAAIAAAAAAAAAAY...",
        "sfn_execution_arn": "arn:aws:states:us-east-1:123456789012:execution:sfn:exec_1",
        "nested": {
            "password": "p@ssword123",
            "safe_field": 42,
            "aws_secret_access_key": "secret456",
        },
        "items": [
            "Normal item",
            "AKIAIOSFODNN7EXAMPLE",
            {"api_secret": "hidden_secret"},
        ],
    }

    sanitized = redact_sensitive_data(sensitive_dict)
    assert sanitized["execution_id"] == "exec_123"
    assert sanitized["authorization"] == "[REDACTED]"
    assert sanitized["client_secret"] == "[REDACTED]"
    assert sanitized["custom_token"] == "[REDACTED]"
    assert sanitized["sfn_task_token"] == "[REDACTED]"
    assert sanitized["sfn_execution_arn"] == "[REDACTED_AWS_ARN]"
    assert sanitized["nested"]["password"] == "[REDACTED]"
    assert sanitized["nested"]["safe_field"] == 42
    assert sanitized["nested"]["aws_secret_access_key"] == "[REDACTED]"
    assert sanitized["items"][0] == "Normal item"
    assert sanitized["items"][1] == "[REDACTED_AWS_KEY]"
    assert sanitized["items"][2]["api_secret"] == "[REDACTED]"


def test_redacting_json_formatter() -> None:
    formatter = RedactingJsonFormatter()
    logger = logging.getLogger("test_redaction_logger")

    record = logger.makeRecord(
        name="test_logger",
        level=logging.ERROR,
        fn="test_fn",
        lno=10,
        msg="Error contacting arn:aws:states:us-east-1:123456789012:execution:sfn:exec_1 with AKIAIOSFODNN7EXAMPLE",
        args=(),
        exc_info=None,
    )
    record.structured_data = {  # type: ignore[attr-defined]
        "client_secret": "super_secret",
        "token": "secret_token",
    }

    formatted_str = formatter.format(record)
    parsed = json.loads(formatted_str)

    assert "[REDACTED_AWS_ARN]" in parsed["message"]
    assert "[REDACTED_AWS_KEY]" in parsed["message"]
    assert "AKIAIOSFODNN7EXAMPLE" not in formatted_str
    assert "super_secret" not in formatted_str
    assert parsed["event"]["client_secret"] == "[REDACTED]"
    assert parsed["event"]["token"] == "[REDACTED]"
