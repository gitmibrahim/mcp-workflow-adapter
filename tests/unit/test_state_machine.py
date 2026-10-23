from __future__ import annotations

from typing import Any

import pytest

from workflow_adapter.errors import AdapterError, ErrorCode
from workflow_adapter.models import (
    NotificationEventType,
    NotificationPreferences,
    ResolutionBehavior,
    StepDefinition,
    StepOutcome,
    WorkflowExecution,
    WorkflowStatus,
    utc_now_iso,
)
from workflow_adapter.ports import DomainPolicyPort
from workflow_adapter.state_machine import (
    apply_complete_inspection,
    apply_configure_notifications,
    apply_record_reading,
    apply_resolve_exception,
    build_notification_record,
    build_status_response,
    compute_next_allowed_actions,
    create_initial_execution,
)


class DummyDomainPolicy(DomainPolicyPort):
    """Simple 2-step test policy with RETEST and ANNOTATE_AND_ADVANCE resolution policies."""

    def __init__(self) -> None:
        self.steps = (
            StepDefinition(
                step_id="step_1",
                title="Step 1 Title",
                unit="ng/uL",
                accepted_units=("ng/ul", "ng_ul"),
                min_value=15.0,
                max_value=60.0,
                resolution_policies={
                    "RETEST_DILUTED": ResolutionBehavior.RETEST,
                    "ESCALATE_AND_OVERRIDE": ResolutionBehavior.ANNOTATE_AND_ADVANCE,
                },
            ),
            StepDefinition(
                step_id="step_2",
                title="Step 2 Title",
                unit="pM",
                accepted_units=("pm",),
                min_value=180.0,
                max_value=250.0,
                resolution_policies={
                    "RETEST_MOLARITY": ResolutionBehavior.RETEST,
                },
            ),
        )

    def validate_asset_and_type(self, inspection_type: str, asset_id: str) -> dict[str, Any]:
        if inspection_type != "test_type":
            raise AdapterError(
                ErrorCode.INVALID_INPUT, f"Unknown inspection type {inspection_type}"
            )
        if asset_id != "ASSET-01":
            raise AdapterError(ErrorCode.INVALID_INPUT, f"Unknown asset {asset_id}")
        return {"asset_id": asset_id, "type": inspection_type}

    def get_steps(self, inspection_type: str) -> tuple[StepDefinition, ...]:
        return self.steps

    def get_step(self, inspection_type: str, step_id: str) -> StepDefinition:
        for s in self.steps:
            if s.step_id == step_id:
                return s
        raise AdapterError(ErrorCode.INVALID_INPUT, f"Step '{step_id}' not found.")

    def validate_reading(
        self, inspection_type: str, step_id: str, value: float, unit: str | None = None
    ) -> tuple[bool, str | None]:
        step = self.get_step(inspection_type, step_id)
        if value < step.min_value:
            return False, "OUT_OF_RANGE_LOW"
        if value > step.max_value:
            return False, "OUT_OF_RANGE_HIGH"
        return True, None

    def resolve_exception_behavior(
        self, inspection_type: str, step_id: str, resolution: str
    ) -> ResolutionBehavior:
        step = self.get_step(inspection_type, step_id)
        if resolution not in step.resolution_policies:
            raise AdapterError(
                ErrorCode.INVALID_INPUT,
                f"Resolution '{resolution}' is not whitelisted for step '{step_id}'.",
            )
        return step.resolution_policies[resolution]

    def build_completion_metadata(self, execution: WorkflowExecution) -> dict[str, Any]:
        return {"domain_completion_status": "RELEASED"}


@pytest.fixture
def policy() -> DummyDomainPolicy:
    return DummyDomainPolicy()


def test_create_initial_execution(policy: DummyDomainPolicy) -> None:
    now = utc_now_iso()
    exec_state, outcome = create_initial_execution(
        execution_id="exec_1",
        principal_id="user_1",
        inspection_type="test_type",
        asset_id="ASSET-01",
        policy=policy,
        now_iso=now,
    )
    assert exec_state.execution_id == "exec_1"
    assert exec_state.status == WorkflowStatus.RUNNING
    assert exec_state.desired_state_version == 1
    assert exec_state.pending_step_id == "step_1"
    assert outcome.status == WorkflowStatus.RUNNING
    assert outcome.next_step.step_id == "step_1"

    allowed = compute_next_allowed_actions(exec_state)
    assert "record_inspection_result" in allowed
    assert "get_inspection_status" in allowed


def test_record_in_range_reading_advances_step(policy: DummyDomainPolicy) -> None:
    now = utc_now_iso()
    exec_state, _ = create_initial_execution(
        execution_id="exec_1",
        principal_id="user_1",
        inspection_type="test_type",
        asset_id="ASSET-01",
        policy=policy,
        now_iso=now,
    )

    updated_exec, outcome = apply_record_reading(
        execution=exec_state,
        step_id="step_1",
        value=30.0,
        unit="ng/uL",
        policy=policy,
        new_exception_id="exc_1",
        now_iso=now,
    )

    assert outcome.accepted is True
    assert outcome.status == WorkflowStatus.RUNNING
    assert outcome.next_step is not None
    assert outcome.next_step.step_id == "step_2"
    assert updated_exec.desired_state_version == 2
    assert updated_exec.pending_step_id == "step_2"
    assert len(updated_exec.completed_steps) == 1
    assert updated_exec.completed_steps[0].outcome == StepOutcome.NORMAL


def test_record_out_of_range_reading_blocks_workflow(policy: DummyDomainPolicy) -> None:
    now = utc_now_iso()
    exec_state, _ = create_initial_execution(
        execution_id="exec_1",
        principal_id="user_1",
        inspection_type="test_type",
        asset_id="ASSET-01",
        policy=policy,
        now_iso=now,
    )

    # 10.0 is below min 15.0
    blocked_exec, outcome = apply_record_reading(
        execution=exec_state,
        step_id="step_1",
        value=10.0,
        unit="ng/uL",
        policy=policy,
        new_exception_id="exc_101",
        now_iso=now,
    )

    assert outcome.accepted is False
    assert outcome.status == WorkflowStatus.BLOCKED
    assert blocked_exec.status == WorkflowStatus.BLOCKED
    assert blocked_exec.active_exception is not None
    assert blocked_exec.active_exception.exception_id == "exc_101"
    assert blocked_exec.active_exception.reason == "OUT_OF_RANGE_LOW"
    assert blocked_exec.pending_step_id == "step_1"

    allowed = compute_next_allowed_actions(blocked_exec)
    assert "resolve_inspection_exception" in allowed
    assert "record_inspection_result" not in allowed

    # AC8/AC9: Recording while BLOCKED must raise WORKFLOW_BLOCKED
    with pytest.raises(AdapterError) as exc_info:
        apply_record_reading(
            execution=blocked_exec,
            step_id="step_1",
            value=25.0,
            unit="ng/uL",
            policy=policy,
            new_exception_id="exc_102",
            now_iso=now,
        )
    assert exc_info.value.error_code == ErrorCode.WORKFLOW_BLOCKED


def test_resolve_exception_retest_and_annotate(policy: DummyDomainPolicy) -> None:
    now = utc_now_iso()
    exec_state, _ = create_initial_execution(
        execution_id="exec_1",
        principal_id="user_1",
        inspection_type="test_type",
        asset_id="ASSET-01",
        policy=policy,
        now_iso=now,
    )
    blocked_exec, _ = apply_record_reading(
        execution=exec_state,
        step_id="step_1",
        value=10.0,
        unit="ng/uL",
        policy=policy,
        new_exception_id="exc_101",
        now_iso=now,
    )

    # AC10: Reject non-whitelisted resolution
    with pytest.raises(AdapterError) as exc_info:
        apply_resolve_exception(
            execution=blocked_exec,
            exception_id="exc_101",
            resolution="FORCE_PASS_OVERRIDE",
            policy=policy,
            now_iso=now,
        )
    assert exc_info.value.error_code == ErrorCode.INVALID_INPUT

    # Test RETEST behavior
    res_exec, res_outcome = apply_resolve_exception(
        execution=blocked_exec,
        exception_id="exc_101",
        resolution="RETEST_DILUTED",
        policy=policy,
        now_iso=now,
    )
    assert res_outcome.status == WorkflowStatus.RUNNING
    assert res_outcome.resolution_behavior == ResolutionBehavior.RETEST
    assert res_exec.status == WorkflowStatus.RUNNING
    assert res_exec.active_exception is None
    assert res_exec.pending_step_id == "step_1"
    assert len(res_exec.completed_steps) == 0

    # Re-block and test ANNOTATE_AND_ADVANCE
    reblocked_exec, _ = apply_record_reading(
        execution=res_exec,
        step_id="step_1",
        value=12.0,
        unit="ng/uL",
        policy=policy,
        new_exception_id="exc_102",
        now_iso=now,
    )
    advanced_exec, adv_outcome = apply_resolve_exception(
        execution=reblocked_exec,
        exception_id="exc_102",
        resolution="ESCALATE_AND_OVERRIDE",
        policy=policy,
        now_iso=now,
    )
    assert adv_outcome.resolution_behavior == ResolutionBehavior.ANNOTATE_AND_ADVANCE
    assert advanced_exec.status == WorkflowStatus.RUNNING
    assert advanced_exec.pending_step_id == "step_2"
    assert len(advanced_exec.completed_steps) == 1
    assert advanced_exec.completed_steps[0].outcome == StepOutcome.EXCEPTION_RESOLVED_ANNOTATED


def test_complete_inspection_guards_and_success(policy: DummyDomainPolicy) -> None:
    now = utc_now_iso()
    exec_state, _ = create_initial_execution(
        execution_id="exec_1",
        principal_id="user_1",
        inspection_type="test_type",
        asset_id="ASSET-01",
        policy=policy,
        now_iso=now,
    )

    # AC9: Attempting complete when step 1 is pending
    with pytest.raises(AdapterError) as exc_info:
        apply_complete_inspection(
            execution=exec_state,
            policy=policy,
            audit_reference="AUDIT-123",
            now_iso=now,
        )
    assert exc_info.value.error_code == ErrorCode.INVALID_STATE_TRANSITION

    # Complete step 1
    step1_exec, _ = apply_record_reading(
        execution=exec_state,
        step_id="step_1",
        value=30.0,
        unit="ng/uL",
        policy=policy,
        new_exception_id="exc_1",
        now_iso=now,
    )

    # Complete step 2
    step2_exec, _ = apply_record_reading(
        execution=step1_exec,
        step_id="step_2",
        value=200.0,
        unit="pM",
        policy=policy,
        new_exception_id="exc_2",
        now_iso=now,
    )
    assert step2_exec.pending_step_id is None

    # Now completion succeeds
    completed_exec, outcome = apply_complete_inspection(
        execution=step2_exec,
        policy=policy,
        audit_reference="AUDIT-123",
        now_iso=now,
    )
    assert outcome.status == WorkflowStatus.COMPLETED
    assert completed_exec.status == WorkflowStatus.COMPLETED
    assert completed_exec.audit_summary is not None
    assert completed_exec.audit_summary.audit_reference == "AUDIT-123"
    assert completed_exec.audit_summary.normal_steps == 2

    # Cannot record reading or complete again once completed
    with pytest.raises(AdapterError) as exc_complete_again:
        apply_complete_inspection(
            execution=completed_exec,
            policy=policy,
            audit_reference="AUDIT-124",
            now_iso=now,
        )
    assert exc_complete_again.value.error_code == ErrorCode.INVALID_STATE_TRANSITION


def test_configure_notifications_and_pause(policy: DummyDomainPolicy) -> None:
    now = utc_now_iso()
    exec_state, _ = create_initial_execution(
        execution_id="exec_1",
        principal_id="user_1",
        inspection_type="test_type",
        asset_id="ASSET-01",
        policy=policy,
        now_iso=now,
    )

    new_prefs = NotificationPreferences(on_pause=True, on_revision=True)
    paused_exec, outcome = apply_configure_notifications(
        execution=exec_state,
        preferences=new_prefs,
        pause_session=True,
        now_iso=now,
    )
    assert paused_exec.session_paused is True
    assert outcome.session_paused is True
    assert outcome.notification_queued is True

    # Build pause notification record
    notif = build_notification_record(
        notification_id="notif_1",
        execution=paused_exec,
        event_type=NotificationEventType.ON_PAUSE_INTERRUPTION,
        summary_message="Session paused for incubation.",
        now_iso=now,
    )
    assert notif is not None
    assert notif.event_type == NotificationEventType.ON_PAUSE_INTERRUPTION
    assert notif.payload["session_paused"] is True

    # Test status response builder
    status_resp = build_status_response(paused_exec, policy)
    assert status_resp.session_paused is True
    assert status_resp.pending_step is not None
    assert status_resp.pending_step.step_id == "step_1"
