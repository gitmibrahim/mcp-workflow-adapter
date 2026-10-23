from __future__ import annotations

import pytest

from workflow_adapter.errors import AdapterError, ErrorCode
from workflow_adapter.idempotency import (
    build_response_from_outcome,
    compute_payload_hash,
    derive_client_request_token,
    generate_event_id,
    generate_exception_id,
    generate_execution_id,
    validate_idempotency_key,
    verify_or_raise_idempotency_conflict,
)
from workflow_adapter.models import (
    NotificationPreferences,
    StartInspectionOutcome,
    StartInspectionResponse,
    StepSummary,
    WorkflowStatus,
)


def test_id_generation_formats() -> None:
    exec_id = generate_execution_id()
    assert exec_id.startswith("exec_")
    assert len(exec_id) == 37  # "exec_" (5) + 32 hex chars

    exc_id = generate_exception_id()
    assert exc_id.startswith("exc_")
    assert len(exc_id) == 20  # "exc_" (4) + 16 hex chars

    evt_id = generate_event_id("audit")
    assert evt_id.startswith("audit_")


def test_validate_idempotency_key() -> None:
    assert validate_idempotency_key("my-key-123") == "my-key-123"

    with pytest.raises(AdapterError) as exc_empty:
        validate_idempotency_key("")
    assert exc_empty.value.error_code == ErrorCode.INVALID_INPUT

    with pytest.raises(AdapterError) as exc_too_long:
        validate_idempotency_key("a" * 129)
    assert exc_too_long.value.error_code == ErrorCode.INVALID_INPUT


def test_canonical_payload_hashing_key_order_invariance() -> None:
    payload_a = {"b": 2, "a": 1, "nested": {"y": 20, "x": 10}}
    payload_b = {"a": 1, "nested": {"x": 10, "y": 20}, "b": 2}
    hash_a = compute_payload_hash("record_result", payload_a)
    hash_b = compute_payload_hash("record_result", payload_b)
    assert hash_a == hash_b


def test_canonical_payload_hashing_excludes_idempotency_key() -> None:
    payload_1 = {"value": 42.0, "step_id": "step_1", "idempotency_key": "k1"}
    payload_2 = {"value": 42.0, "step_id": "step_1", "idempotency_key": "k2"}
    assert compute_payload_hash("record_result", payload_1) == compute_payload_hash(
        "record_result", payload_2
    )


def test_canonical_payload_hashing_normalizes_zero() -> None:
    payload_neg = {"reading": -0.0}
    payload_pos = {"reading": 0.0}
    assert compute_payload_hash("step", payload_neg) == compute_payload_hash("step", payload_pos)


def test_verify_or_raise_idempotency_conflict() -> None:
    # No conflict when hashes match
    verify_or_raise_idempotency_conflict(
        idempotency_key="key-1",
        operation="record_result",
        stored_payload_hash="hash_abc",
        incoming_payload_hash="hash_abc",
    )

    # Conflict raises IDEMPOTENCY_CONFLICT
    with pytest.raises(AdapterError) as exc_info:
        verify_or_raise_idempotency_conflict(
            idempotency_key="key-1",
            operation="record_result",
            stored_payload_hash="hash_abc",
            incoming_payload_hash="hash_different",
        )
    assert exc_info.value.error_code == ErrorCode.IDEMPOTENCY_CONFLICT


def test_derive_client_request_token() -> None:
    t1 = derive_client_request_token("u1", "s1", "start", "k1")
    t2 = derive_client_request_token("u1", "s1", "start", "k1")
    t3 = derive_client_request_token("u1", "s1", "start", "k2")

    assert t1 == t2
    assert t1 != t3
    assert len(t1) == 32


def test_build_response_from_outcome() -> None:
    outcome = StartInspectionOutcome(
        execution_id="exec_1",
        asset_id="ASSET-1",
        inspection_type="type-1",
        status=WorkflowStatus.RUNNING,
        next_step=StepSummary(step_id="s1", title="Title", unit="u", min_value=1.0, max_value=2.0),
        notification_prefs=NotificationPreferences(),
        message="Started",
    )
    outcome_json = outcome.model_dump_json()

    # Initial commit (duplicate=False)
    resp_first = build_response_from_outcome(
        outcome_json,
        StartInspectionOutcome,
        StartInspectionResponse,
        duplicate=False,
    )
    assert resp_first.duplicate is False
    assert resp_first.execution_id == "exec_1"

    # Replay commit (duplicate=True)
    resp_replay = build_response_from_outcome(
        outcome_json,
        StartInspectionOutcome,
        StartInspectionResponse,
        duplicate=True,
    )
    assert resp_replay.duplicate is True
    assert resp_replay.execution_id == "exec_1"
