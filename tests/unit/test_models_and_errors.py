from __future__ import annotations

import ast
from pathlib import Path

import pytest
from pydantic import ValidationError

from workflow_adapter.errors import (
    DEFAULT_RETRYABLE_BY_CODE,
    AdapterError,
    ErrorCode,
)
from workflow_adapter.models import (
    CompletedStepRecord,
    NotificationEventType,
    NotificationPreferences,
    ResolutionBehavior,
    StepDefinition,
    StepOutcome,
    StepSummary,
    WorkflowStatus,
    utc_now_iso,
)


def test_zero_aws_sdk_imports_in_core_modules() -> None:
    """NFR-2: Verify zero AWS SDK (boto3, botocore, aws_cdk) or domain imports in core adapter modules."""
    src_dir = Path(__file__).resolve().parent.parent.parent / "src" / "workflow_adapter"
    core_files = [
        src_dir / "__init__.py",
        src_dir / "models.py",
        src_dir / "errors.py",
        src_dir / "ports.py",
        src_dir / "redaction.py",
    ]

    # Optional core modules if present
    for optional_module in [
        "state_machine.py",
        "idempotency.py",
        "auth.py",
        "well_known.py",
        "mcp_server.py",
        "backends/local.py",
    ]:
        p = src_dir / optional_module
        if p.exists():
            core_files.append(p)

    forbidden_prefixes = (
        "boto3",
        "botocore",
        "aws_cdk",
        "genomics_assistant",
        "alexa_plus_genomics_workflow_assistant",
    )

    for file_path in core_files:
        assert file_path.exists(), f"Core module {file_path} must exist."
        tree = ast.parse(file_path.read_text(encoding="utf-8"), filename=str(file_path))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    for forbidden in forbidden_prefixes:
                        assert not alias.name.startswith(forbidden), (
                            f"Illegal import '{alias.name}' detected in {file_path.name} (line {node.lineno})"
                        )
            elif isinstance(node, ast.ImportFrom) and node.module:
                for forbidden in forbidden_prefixes:
                    assert not node.module.startswith(forbidden), (
                        f"Illegal from-import '{node.module}' detected in {file_path.name} (line {node.lineno})"
                    )


def test_workflow_status_has_exact_four_mvp_states() -> None:
    expected_states = {
        WorkflowStatus.CREATED,
        WorkflowStatus.RUNNING,
        WorkflowStatus.BLOCKED,
        WorkflowStatus.COMPLETED,
    }
    assert set(WorkflowStatus) == expected_states
    assert len(WorkflowStatus) == 4
    all_values = [s.value for s in WorkflowStatus]
    assert "FAILED" not in all_values
    assert "CANCELLED" not in all_values
    assert "AWAITING_APPROVAL" not in all_values


def test_error_codes_and_retryability() -> None:
    expected_codes = {
        "INVALID_INPUT",
        "UNAUTHORIZED",
        "FORBIDDEN",
        "NOT_FOUND",
        "INVALID_STATE_TRANSITION",
        "IDEMPOTENCY_CONFLICT",
        "WORKFLOW_BLOCKED",
        "BACKEND_UNAVAILABLE",
        "INTERNAL_ERROR",
    }
    assert {c.value for c in ErrorCode} == expected_codes
    assert len(ErrorCode) == 9

    # Retryable defaults
    assert DEFAULT_RETRYABLE_BY_CODE[ErrorCode.UNAUTHORIZED] is True
    assert DEFAULT_RETRYABLE_BY_CODE[ErrorCode.BACKEND_UNAVAILABLE] is True
    assert DEFAULT_RETRYABLE_BY_CODE[ErrorCode.INVALID_INPUT] is False
    assert DEFAULT_RETRYABLE_BY_CODE[ErrorCode.FORBIDDEN] is False
    assert DEFAULT_RETRYABLE_BY_CODE[ErrorCode.NOT_FOUND] is False
    assert DEFAULT_RETRYABLE_BY_CODE[ErrorCode.INVALID_STATE_TRANSITION] is False
    assert DEFAULT_RETRYABLE_BY_CODE[ErrorCode.IDEMPOTENCY_CONFLICT] is False
    assert DEFAULT_RETRYABLE_BY_CODE[ErrorCode.WORKFLOW_BLOCKED] is False
    assert DEFAULT_RETRYABLE_BY_CODE[ErrorCode.INTERNAL_ERROR] is False


def test_adapter_error_structure_and_dict() -> None:
    err = AdapterError(ErrorCode.INVALID_INPUT, "Test invalid input")
    assert err.error_code == ErrorCode.INVALID_INPUT
    assert err.retryable is False
    assert err.correlation_id.startswith("corr_")
    d = err.to_dict()
    assert d["error_code"] == "INVALID_INPUT"
    assert d["message"] == "Test invalid input"
    assert d["retryable"] is False
    assert "correlation_id" in d

    # Test override retryable and custom details
    err2 = AdapterError(
        ErrorCode.BACKEND_UNAVAILABLE,
        "Database locked",
        retryable=True,
        correlation_id="corr_custom123",
        details={"db": "sqlite"},
    )
    d2 = err2.to_dict()
    assert d2["retryable"] is True
    assert d2["correlation_id"] == "corr_custom123"
    assert d2["details"] == {"db": "sqlite"}


def test_step_definition_and_summary() -> None:
    step = StepDefinition(
        step_id="step_1",
        title="Sample Step",
        unit="ng/uL",
        accepted_units=("ng/ul", "ng_ul"),
        min_value=10.0,
        max_value=50.0,
        resolution_policies={"RETEST": ResolutionBehavior.RETEST},
    )
    summary = step.to_summary()
    assert isinstance(summary, StepSummary)
    assert summary.step_id == "step_1"
    assert summary.min_value == 10.0
    assert summary.max_value == 50.0

    assert step.accepts_unit("ng/uL") is True
    assert step.accepts_unit("ng/ul") is True
    assert step.accepts_unit("NG_UL") is True
    assert step.accepts_unit(None) is True
    assert step.accepts_unit("ug/uL") is False


def test_notification_preferences_enabled_mapping() -> None:
    prefs = NotificationPreferences(
        on_pause=True,
        on_revision=False,
        on_blocked=True,
        on_status=False,
        on_completion=True,
    )
    assert prefs.is_enabled_for(NotificationEventType.ON_PAUSE_INTERRUPTION) is True
    assert prefs.is_enabled_for(NotificationEventType.ON_STEP_REVISION) is False
    assert prefs.is_enabled_for(NotificationEventType.ON_EXCEPTION_BLOCKED) is True
    assert prefs.is_enabled_for(NotificationEventType.ON_STATUS_REQUESTED) is False
    assert prefs.is_enabled_for(NotificationEventType.ON_INSPECTION_COMPLETED) is True


def test_models_are_frozen() -> None:
    summary = StepSummary(step_id="s1", title="Title", unit="u", min_value=1.0, max_value=2.0)
    with pytest.raises(ValidationError):
        # Attempt mutation on frozen Pydantic model
        summary.step_id = "s2"

    rec = CompletedStepRecord(
        step_id="s1",
        title="Title",
        value=1.5,
        unit="u",
        outcome=StepOutcome.NORMAL,
        recorded_at=utc_now_iso(),
    )
    with pytest.raises(ValidationError):
        rec.value = 2.0
