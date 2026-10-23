from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from workflow_adapter.backends.local import LocalBackend
from workflow_adapter.errors import AdapterError, ErrorCode
from workflow_adapter.models import (
    ResolutionBehavior,
    WorkflowStatus,
)
from workflow_adapter.ports import DomainPolicyPort


@pytest.fixture
def backend(tmp_path: Path, policy: DomainPolicyPort) -> LocalBackend:
    db_file = tmp_path / "contract_local.db"
    return LocalBackend(db_file, policy)


def test_ac1_start_inspection_returns_stable_id(backend: LocalBackend) -> None:
    resp = backend.start_inspection(
        principal_id="tech-1",
        inspection_type="contract_type",
        asset_id="ASSET-ALPHA",
        idempotency_key="start-key-01",
    )
    assert resp.execution_id.startswith("exec_")
    assert len(resp.execution_id) == 37
    assert resp.status == WorkflowStatus.RUNNING
    assert resp.duplicate is False
    assert resp.next_step.step_id == "step_a"

    # Status matches initial state
    status = backend.get_inspection_status(
        principal_id="tech-1",
        execution_id=resp.execution_id,
    )
    assert status.status == WorkflowStatus.RUNNING
    assert status.desired_state_version == 1
    assert status.pending_step is not None
    assert status.pending_step.step_id == "step_a"


def test_ac2_record_two_valid_readings_persists(backend: LocalBackend) -> None:
    start_resp = backend.start_inspection(
        principal_id="tech-1",
        inspection_type="contract_type",
        asset_id="ASSET-ALPHA",
        idempotency_key="start-key-02",
    )
    exec_id = start_resp.execution_id

    # Record step_a
    r1 = backend.record_inspection_result(
        principal_id="tech-1",
        execution_id=exec_id,
        step_id="step_a",
        value=25.0,
        unit="unit_a",
        idempotency_key="step-a-key",
    )
    assert r1.accepted is True
    assert r1.next_step is not None
    assert r1.next_step.step_id == "step_b"

    # Record step_b
    r2 = backend.record_inspection_result(
        principal_id="tech-1",
        execution_id=exec_id,
        step_id="step_b",
        value=150.0,
        unit="unit_b",
        idempotency_key="step-b-key",
    )
    assert r2.accepted is True
    assert r2.next_step is not None
    assert r2.next_step.step_id == "step_c"

    # Query status
    status = backend.get_inspection_status(principal_id="tech-1", execution_id=exec_id)
    assert len(status.completed_steps) == 2
    assert status.desired_state_version == 3
    assert status.pending_step is not None
    assert status.pending_step.step_id == "step_c"


def test_ac5_idempotent_replay_preserves_outcome(backend: LocalBackend) -> None:
    # 1. Start replay
    s1 = backend.start_inspection(
        principal_id="tech-1",
        inspection_type="contract_type",
        asset_id="ASSET-ALPHA",
        idempotency_key="idemp-key-s",
    )
    assert s1.duplicate is False
    s2 = backend.start_inspection(
        principal_id="tech-1",
        inspection_type="contract_type",
        asset_id="ASSET-ALPHA",
        idempotency_key="idemp-key-s",
    )
    assert s2.duplicate is True
    assert s2.execution_id == s1.execution_id

    # 2. Step replay
    m1 = backend.record_inspection_result(
        principal_id="tech-1",
        execution_id=s1.execution_id,
        step_id="step_a",
        value=30.0,
        unit="unit_a",
        idempotency_key="idemp-key-m",
    )
    assert m1.duplicate is False
    m2 = backend.record_inspection_result(
        principal_id="tech-1",
        execution_id=s1.execution_id,
        step_id="step_a",
        value=30.0,
        unit="unit_a",
        idempotency_key="idemp-key-m",
    )
    assert m2.duplicate is True
    assert m2.accepted == m1.accepted


def test_ac6_idempotency_key_payload_mismatch_conflicts(backend: LocalBackend) -> None:
    start_resp = backend.start_inspection(
        principal_id="tech-1",
        inspection_type="contract_type",
        asset_id="ASSET-ALPHA",
        idempotency_key="unique-start-key",
    )
    exec_id = start_resp.execution_id

    backend.record_inspection_result(
        principal_id="tech-1",
        execution_id=exec_id,
        step_id="step_a",
        value=35.0,
        unit="unit_a",
        idempotency_key="step-key-conflict",
    )

    # Replay with same key but different value (40.0 instead of 35.0)
    with pytest.raises(AdapterError) as exc_info:
        backend.record_inspection_result(
            principal_id="tech-1",
            execution_id=exec_id,
            step_id="step_a",
            value=40.0,
            unit="unit_a",
            idempotency_key="step-key-conflict",
        )
    assert exc_info.value.error_code == ErrorCode.IDEMPOTENCY_CONFLICT


def test_ac8_out_of_range_reading_blocks_workflow(backend: LocalBackend) -> None:
    start_resp = backend.start_inspection(
        principal_id="tech-1",
        inspection_type="contract_type",
        asset_id="ASSET-ALPHA",
        idempotency_key="block-test-start",
    )
    exec_id = start_resp.execution_id

    # 5.0 is below min 10.0 for step_a
    r_block = backend.record_inspection_result(
        principal_id="tech-1",
        execution_id=exec_id,
        step_id="step_a",
        value=5.0,
        unit="unit_a",
        idempotency_key="block-step-key",
    )
    assert r_block.accepted is False
    assert r_block.status == WorkflowStatus.BLOCKED
    assert r_block.active_exception is not None

    status = backend.get_inspection_status(principal_id="tech-1", execution_id=exec_id)
    assert status.status == WorkflowStatus.BLOCKED
    assert status.active_exception is not None
    assert status.active_exception.reason == "OUT_OF_RANGE_LOW"


def test_ac9_complete_rejected_when_incomplete_or_blocked(backend: LocalBackend) -> None:
    start_resp = backend.start_inspection(
        principal_id="tech-1",
        inspection_type="contract_type",
        asset_id="ASSET-ALPHA",
        idempotency_key="ac9-start",
    )
    exec_id = start_resp.execution_id

    # Reject complete when steps pending
    with pytest.raises(AdapterError) as exc_pending:
        backend.complete_inspection(
            principal_id="tech-1",
            execution_id=exec_id,
            idempotency_key="complete-key-fail",
        )
    assert exc_pending.value.error_code == ErrorCode.INVALID_STATE_TRANSITION

    # Block on step_a
    backend.record_inspection_result(
        principal_id="tech-1",
        execution_id=exec_id,
        step_id="step_a",
        value=2.0,
        unit="unit_a",
        idempotency_key="step-a-block",
    )

    # Reject complete when BLOCKED
    with pytest.raises(AdapterError) as exc_blocked:
        backend.complete_inspection(
            principal_id="tech-1",
            execution_id=exec_id,
            idempotency_key="complete-key-fail2",
        )
    assert exc_blocked.value.error_code == ErrorCode.WORKFLOW_BLOCKED


def test_ac10_only_whitelisted_resolutions_accepted(backend: LocalBackend) -> None:
    start_resp = backend.start_inspection(
        principal_id="tech-1",
        inspection_type="contract_type",
        asset_id="ASSET-ALPHA",
        idempotency_key="ac10-start",
    )
    exec_id = start_resp.execution_id

    block_resp = backend.record_inspection_result(
        principal_id="tech-1",
        execution_id=exec_id,
        step_id="step_a",
        value=2.0,
        unit="unit_a",
        idempotency_key="step-a-block-ac10",
    )
    assert block_resp.active_exception is not None
    exc_id = block_resp.active_exception.exception_id

    # Reject non-whitelisted resolution FORCE_PASS
    with pytest.raises(AdapterError) as exc_unapproved:
        backend.resolve_inspection_exception(
            principal_id="tech-1",
            execution_id=exec_id,
            exception_id=exc_id,
            resolution="FORCE_PASS",
            idempotency_key="res-key-force",
        )
    assert exc_unapproved.value.error_code == ErrorCode.INVALID_INPUT

    # Accept whitelisted RETEST_A
    retest_resp = backend.resolve_inspection_exception(
        principal_id="tech-1",
        execution_id=exec_id,
        exception_id=exc_id,
        resolution="RETEST_A",
        idempotency_key="res-key-retest",
    )
    assert retest_resp.status == WorkflowStatus.RUNNING
    assert retest_resp.resolution_behavior == ResolutionBehavior.RETEST


def test_ac11_cross_principal_access_denied(backend: LocalBackend) -> None:
    start_resp = backend.start_inspection(
        principal_id="user-a",
        inspection_type="contract_type",
        asset_id="ASSET-ALPHA",
        idempotency_key="user-a-start",
    )
    exec_id = start_resp.execution_id

    # user-b attempts to query status
    with pytest.raises(AdapterError) as exc_status:
        backend.get_inspection_status(principal_id="user-b", execution_id=exec_id)
    assert exc_status.value.error_code == ErrorCode.FORBIDDEN

    # user-b attempts mutation
    with pytest.raises(AdapterError) as exc_mutation:
        backend.record_inspection_result(
            principal_id="user-b",
            execution_id=exec_id,
            step_id="step_a",
            value=25.0,
            unit="unit_a",
            idempotency_key="user-b-step",
        )
    assert exc_mutation.value.error_code == ErrorCode.FORBIDDEN


def test_transient_backend_unavailable_preserves_committed_state(backend: LocalBackend) -> None:
    start_resp = backend.start_inspection(
        principal_id="tech-1",
        inspection_type="contract_type",
        asset_id="ASSET-ALPHA",
        idempotency_key="transient-start",
    )
    exec_id = start_resp.execution_id

    # Record step_a
    backend.record_inspection_result(
        principal_id="tech-1",
        execution_id=exec_id,
        step_id="step_a",
        value=20.0,
        unit="unit_a",
        idempotency_key="transient-step1",
    )

    # Simulate storage failure
    backend.set_simulate_unavailable(True)

    with pytest.raises(AdapterError) as exc_info:
        backend.record_inspection_result(
            principal_id="tech-1",
            execution_id=exec_id,
            step_id="step_b",
            value=120.0,
            unit="unit_b",
            idempotency_key="transient-step2",
        )
    assert exc_info.value.error_code == ErrorCode.BACKEND_UNAVAILABLE
    assert exc_info.value.retryable is True

    # Restore storage and verify state is intact at step_b
    backend.set_simulate_unavailable(False)
    status = backend.get_inspection_status(principal_id="tech-1", execution_id=exec_id)
    assert len(status.completed_steps) == 1
    assert status.desired_state_version == 2
    assert status.pending_step is not None
    assert status.pending_step.step_id == "step_b"


def test_corrupt_persisted_json_raises_internal_error_without_mutating_row(
    backend: LocalBackend,
) -> None:
    start_resp = backend.start_inspection(
        principal_id="tech-1",
        inspection_type="contract_type",
        asset_id="ASSET-ALPHA",
        idempotency_key="corrupt-test-start",
    )
    exec_id = start_resp.execution_id

    # Corrupt execution_json in SQLite
    conn = sqlite3.connect(str(backend.db_path))
    conn.execute(
        "UPDATE executions SET execution_json = '{bad json}' WHERE execution_id = ?;",
        (exec_id,),
    )
    conn.commit()
    conn.close()

    # get_inspection_status raises INTERNAL_ERROR
    with pytest.raises(AdapterError) as exc_info:
        backend.get_inspection_status(principal_id="tech-1", execution_id=exec_id)
    assert exc_info.value.error_code == ErrorCode.INTERNAL_ERROR
    assert exc_info.value.retryable is False

    # Row is still '{bad json}' and was not mutated
    conn = sqlite3.connect(str(backend.db_path))
    row = conn.execute(
        "SELECT execution_json FROM executions WHERE execution_id = ?;", (exec_id,)
    ).fetchone()
    assert row[0] == "{bad json}"
    conn.close()
