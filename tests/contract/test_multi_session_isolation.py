from pathlib import Path

import pytest

from workflow_adapter.backends.local import LocalBackend
from workflow_adapter.errors import AdapterError, ErrorCode
from workflow_adapter.models import WorkflowStatus
from workflow_adapter.ports import DomainPolicyPort


@pytest.fixture
def backend(tmp_path: Path, policy: DomainPolicyPort) -> LocalBackend:
    db_file = tmp_path / "multi_session_test.db"
    return LocalBackend(db_file, policy)


def test_active_asset_exclusivity_lock_rejects_duplicate_start(backend: LocalBackend) -> None:
    # 1. Start execution on ASSET-ALPHA
    resp1 = backend.start_inspection(
        principal_id="tech-1",
        inspection_type="contract_type",
        asset_id="ASSET-ALPHA",
        idempotency_key="start-asset-alpha-1",
    )
    exec_id_1 = resp1.execution_id

    # 2. Attempt duplicate start on same asset with different key by same principal
    with pytest.raises(AdapterError) as exc_info:
        backend.start_inspection(
            principal_id="tech-1",
            inspection_type="contract_type",
            asset_id="ASSET-ALPHA",
            idempotency_key="start-asset-alpha-2",
        )
    err = exc_info.value
    assert err.error_code == ErrorCode.INVALID_STATE_TRANSITION
    assert err.details["reason"] == "ASSET_ALREADY_UNDER_INSPECTION"
    assert err.details["owned_by_caller"] is True
    assert err.details["active_execution_id"] == exec_id_1


def test_cross_principal_asset_lock_masks_execution_id(backend: LocalBackend) -> None:
    # 1. User A locks ASSET-ALPHA
    backend.start_inspection(
        principal_id="user-a",
        inspection_type="contract_type",
        asset_id="ASSET-ALPHA",
        idempotency_key="user-a-start",
    )

    # 2. User B tries to start on ASSET-ALPHA
    with pytest.raises(AdapterError) as exc_info:
        backend.start_inspection(
            principal_id="user-b",
            inspection_type="contract_type",
            asset_id="ASSET-ALPHA",
            idempotency_key="user-b-start",
        )
    err = exc_info.value
    assert err.error_code == ErrorCode.INVALID_STATE_TRANSITION
    assert err.details["reason"] == "ASSET_ALREADY_UNDER_INSPECTION"
    assert err.details["owned_by_caller"] is False
    assert "active_execution_id" not in err.details
    assert "user-a" not in err.message


def test_complete_inspection_releases_asset_lock(backend: LocalBackend) -> None:
    resp1 = backend.start_inspection(
        principal_id="tech-1",
        inspection_type="contract_type",
        asset_id="ASSET-ALPHA",
        idempotency_key="run1-start",
    )
    exec_id_1 = resp1.execution_id

    # Complete all 3 steps
    backend.record_inspection_result(
        principal_id="tech-1",
        execution_id=exec_id_1,
        step_id="step_a",
        value=20.0,
        unit="unit_a",
        idempotency_key="r1-s1",
    )
    backend.record_inspection_result(
        principal_id="tech-1",
        execution_id=exec_id_1,
        step_id="step_b",
        value=150.0,
        unit="unit_b",
        idempotency_key="r1-s2",
    )
    backend.record_inspection_result(
        principal_id="tech-1",
        execution_id=exec_id_1,
        step_id="step_c",
        value=10.0,
        unit="unit_c",
        idempotency_key="r1-s3",
    )
    complete_resp = backend.complete_inspection(
        principal_id="tech-1",
        execution_id=exec_id_1,
        idempotency_key="r1-complete",
    )
    assert complete_resp.status == WorkflowStatus.COMPLETED

    # Now a new execution can be started on ASSET-ALPHA
    resp2 = backend.start_inspection(
        principal_id="tech-1",
        inspection_type="contract_type",
        asset_id="ASSET-ALPHA",
        idempotency_key="run2-start",
    )
    assert resp2.execution_id != exec_id_1
    assert resp2.status == WorkflowStatus.RUNNING


def test_multi_session_disambiguation(backend: LocalBackend) -> None:
    # Zero active executions -> NOT_FOUND
    with pytest.raises(AdapterError) as exc_zero:
        backend.get_inspection_status(principal_id="tech-1", execution_id=None, asset_id=None)
    assert exc_zero.value.error_code == ErrorCode.NOT_FOUND

    # Start 1 execution on ASSET-ALPHA -> auto resolves
    r1 = backend.start_inspection(
        principal_id="tech-1",
        inspection_type="contract_type",
        asset_id="ASSET-ALPHA",
        idempotency_key="alpha-start",
    )
    status_single = backend.get_inspection_status(
        principal_id="tech-1", execution_id=None, asset_id=None
    )
    assert status_single.execution_id == r1.execution_id
    assert status_single.asset_id == "ASSET-ALPHA"

    # Start 2nd active execution on ASSET-BETA
    r2 = backend.start_inspection(
        principal_id="tech-1",
        inspection_type="contract_type",
        asset_id="ASSET-BETA",
        idempotency_key="beta-start",
    )

    # Calling with neither execution_id nor asset_id -> raises AMBIGUOUS_ACTIVE_SESSION
    with pytest.raises(AdapterError) as exc_ambiguous:
        backend.get_inspection_status(principal_id="tech-1", execution_id=None, asset_id=None)
    assert exc_ambiguous.value.error_code == ErrorCode.INVALID_INPUT
    assert exc_ambiguous.value.details["reason"] == "AMBIGUOUS_ACTIVE_SESSION"
    assert len(exc_ambiguous.value.details["active_executions"]) == 2

    # Calling with asset_id="ASSET-BETA" disambiguates successfully
    status_beta = backend.get_inspection_status(
        principal_id="tech-1", execution_id=None, asset_id="ASSET-BETA"
    )
    assert status_beta.execution_id == r2.execution_id
    assert status_beta.asset_id == "ASSET-BETA"

    # list_active_executions returns both briefs
    briefs = backend.list_active_executions(principal_id="tech-1")
    assert len(briefs) == 2
    assert {b.asset_id for b in briefs} == {"ASSET-ALPHA", "ASSET-BETA"}
