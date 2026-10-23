from __future__ import annotations

import math
from typing import Any

from workflow_adapter.errors import AdapterError, ErrorCode
from workflow_adapter.models import (
    CompletedStepRecord,
    CompleteInspectionOutcome,
    ConfigureNotificationsOutcome,
    ExceptionDetail,
    InspectionAuditSummary,
    InspectionStatusResponse,
    NotificationEventType,
    NotificationPreferences,
    NotificationRecord,
    RecordResultOutcome,
    ResolutionBehavior,
    ResolveExceptionOutcome,
    StartInspectionOutcome,
    StepOutcome,
    WorkflowExecution,
    WorkflowStatus,
)
from workflow_adapter.ports import DomainPolicyPort


def compute_next_allowed_actions(execution: WorkflowExecution) -> list[str]:
    """Pure mapping of execution state to allowed tool actions."""
    if execution.status == WorkflowStatus.BLOCKED:
        return ["resolve_inspection_exception", "get_inspection_status", "configure_notifications"]
    if execution.status == WorkflowStatus.RUNNING and execution.pending_step_id is not None:
        return ["record_inspection_result", "get_inspection_status", "configure_notifications"]
    if execution.status == WorkflowStatus.RUNNING and execution.pending_step_id is None:
        return ["complete_inspection", "get_inspection_status", "configure_notifications"]
    if execution.status == WorkflowStatus.COMPLETED:
        return ["get_inspection_status"]
    return ["get_inspection_status"]


def create_initial_execution(
    *,
    execution_id: str,
    principal_id: str,
    inspection_type: str,
    asset_id: str,
    policy: DomainPolicyPort,
    notification_prefs: NotificationPreferences | None = None,
    now_iso: str,
) -> tuple[WorkflowExecution, StartInspectionOutcome]:
    """Initialize a brand-new workflow execution in state RUNNING."""
    policy.validate_asset_and_type(inspection_type, asset_id)
    steps = policy.get_steps(inspection_type)
    if not steps:
        raise AdapterError(
            ErrorCode.INTERNAL_ERROR,
            f"No steps configured for inspection type '{inspection_type}'.",
        )

    initial_prefs = notification_prefs or NotificationPreferences()
    initial_step = steps[0]

    execution = WorkflowExecution(
        execution_id=execution_id,
        principal_id=principal_id,
        inspection_type=inspection_type,
        asset_id=asset_id,
        status=WorkflowStatus.RUNNING,
        desired_state_version=1,
        completed_steps=[],
        pending_step_id=initial_step.step_id,
        active_exception=None,
        blocked_reason=None,
        session_paused=False,
        notification_prefs=initial_prefs,
        created_at=now_iso,
        updated_at=now_iso,
        acked_sfn_version=0,
    )

    outcome = StartInspectionOutcome(
        execution_id=execution_id,
        asset_id=asset_id,
        inspection_type=inspection_type,
        status=WorkflowStatus.RUNNING,
        next_step=initial_step.to_summary(),
        notification_prefs=initial_prefs,
        message=f"Workflow started for asset {asset_id}.",
    )
    return execution, outcome


def apply_record_reading(
    *,
    execution: WorkflowExecution,
    step_id: str,
    value: float,
    unit: str | None,
    policy: DomainPolicyPort,
    new_exception_id: str,
    now_iso: str,
) -> tuple[WorkflowExecution, RecordResultOutcome]:
    """Pure transition for recording a step measurement."""
    if execution.status == WorkflowStatus.COMPLETED:
        raise AdapterError(
            ErrorCode.INVALID_STATE_TRANSITION,
            "Cannot record results on a completed workflow.",
        )
    if execution.status == WorkflowStatus.BLOCKED:
        raise AdapterError(
            ErrorCode.WORKFLOW_BLOCKED,
            f"Workflow is BLOCKED: {execution.blocked_reason}. Resolve active exception first.",
        )
    if execution.pending_step_id is None:
        raise AdapterError(
            ErrorCode.INVALID_STATE_TRANSITION,
            "All required steps are already completed; call complete_inspection.",
        )
    if step_id != execution.pending_step_id:
        raise AdapterError(
            ErrorCode.INVALID_INPUT,
            f"Expected pending step '{execution.pending_step_id}', got '{step_id}'.",
        )
    if not math.isfinite(value):
        raise AdapterError(
            ErrorCode.INVALID_INPUT,
            "Reading value must be a finite number.",
        )

    step_def = policy.get_step(execution.inspection_type, step_id)
    if not step_def.accepts_unit(unit):
        raise AdapterError(
            ErrorCode.INVALID_INPUT,
            f"Invalid unit '{unit}' for step '{step_id}'. Expected '{step_def.unit}'.",
        )

    is_valid, out_of_range_reason = policy.validate_reading(
        execution.inspection_type, step_id, value, unit
    )

    all_steps = policy.get_steps(execution.inspection_type)
    step_index = next(
        (i for i, s in enumerate(all_steps) if s.step_id == step_id),
        -1,
    )

    new_version = execution.desired_state_version + 1

    if is_valid:
        # Normal step completion
        recorded_step = CompletedStepRecord(
            step_id=step_def.step_id,
            title=step_def.title,
            value=value,
            unit=unit or step_def.unit,
            outcome=StepOutcome.NORMAL,
            recorded_at=now_iso,
        )

        next_step_def = all_steps[step_index + 1] if step_index + 1 < len(all_steps) else None
        next_step_id = next_step_def.step_id if next_step_def else None

        updated_execution = execution.model_copy(
            update={
                "completed_steps": [*execution.completed_steps, recorded_step],
                "pending_step_id": next_step_id,
                "session_paused": False,
                "desired_state_version": new_version,
                "updated_at": now_iso,
            }
        )

        queued = execution.notification_prefs.is_enabled_for(NotificationEventType.ON_STEP_REVISION)
        outcome = RecordResultOutcome(
            execution_id=execution.execution_id,
            step_id=step_id,
            accepted=True,
            status=WorkflowStatus.RUNNING,
            next_step=next_step_def.to_summary() if next_step_def else None,
            active_exception=None,
            blocked_reason=None,
            next_allowed_actions=compute_next_allowed_actions(updated_execution),
            notification_queued=queued,
            message=f"Step '{step_id}' accepted.",
        )
        return updated_execution, outcome

    # Out-of-range measurement -> Transition to BLOCKED
    reason_code = out_of_range_reason or "OUT_OF_RANGE"
    exc_detail = ExceptionDetail(
        exception_id=new_exception_id,
        step_id=step_id,
        step_title=step_def.title,
        value=value,
        unit=unit or step_def.unit,
        min_value=step_def.min_value,
        max_value=step_def.max_value,
        reason=reason_code,
        allowed_resolutions=list(step_def.resolution_policies.keys()),
        created_at=now_iso,
    )
    blocked_msg = (
        f"Step '{step_id}' value {value} {unit or step_def.unit} outside allowed range "
        f"[{step_def.min_value}, {step_def.max_value}] ({reason_code})"
    )

    updated_execution = execution.model_copy(
        update={
            "status": WorkflowStatus.BLOCKED,
            "active_exception": exc_detail,
            "blocked_reason": blocked_msg,
            "session_paused": False,
            "desired_state_version": new_version,
            "updated_at": now_iso,
        }
    )

    queued = execution.notification_prefs.is_enabled_for(NotificationEventType.ON_EXCEPTION_BLOCKED)
    outcome = RecordResultOutcome(
        execution_id=execution.execution_id,
        step_id=step_id,
        accepted=False,
        status=WorkflowStatus.BLOCKED,
        next_step=None,
        active_exception=exc_detail,
        blocked_reason=blocked_msg,
        next_allowed_actions=compute_next_allowed_actions(updated_execution),
        notification_queued=queued,
        message="Reading outside normal limits. Workflow is BLOCKED.",
    )
    return updated_execution, outcome


def apply_resolve_exception(
    *,
    execution: WorkflowExecution,
    exception_id: str,
    resolution: str,
    policy: DomainPolicyPort,
    now_iso: str,
) -> tuple[WorkflowExecution, ResolveExceptionOutcome]:
    """Pure transition for applying a whitelisted exception resolution."""
    if execution.status != WorkflowStatus.BLOCKED or execution.active_exception is None:
        raise AdapterError(
            ErrorCode.INVALID_STATE_TRANSITION,
            "Workflow does not have an active exception to resolve.",
        )
    if execution.active_exception.exception_id != exception_id:
        raise AdapterError(
            ErrorCode.NOT_FOUND,
            f"Active exception '{exception_id}' not found on execution.",
        )

    behavior = policy.resolve_exception_behavior(
        execution.inspection_type, execution.active_exception.step_id, resolution
    )

    new_version = execution.desired_state_version + 1
    step_def = policy.get_step(execution.inspection_type, execution.active_exception.step_id)

    if behavior == ResolutionBehavior.RETEST:
        updated_execution = execution.model_copy(
            update={
                "status": WorkflowStatus.RUNNING,
                "active_exception": None,
                "blocked_reason": None,
                "pending_step_id": execution.active_exception.step_id,
                "desired_state_version": new_version,
                "session_paused": False,
                "updated_at": now_iso,
            }
        )

        queued = execution.notification_prefs.is_enabled_for(NotificationEventType.ON_STEP_REVISION)
        outcome = ResolveExceptionOutcome(
            execution_id=execution.execution_id,
            exception_id=exception_id,
            status=WorkflowStatus.RUNNING,
            resolution_recorded=resolution,
            resolution_behavior=ResolutionBehavior.RETEST,
            pending_step=step_def.to_summary(),
            next_allowed_actions=compute_next_allowed_actions(updated_execution),
            notification_queued=queued,
            message=f"Exception resolved with RETEST. Please re-record reading for step '{step_def.step_id}'.",
        )
        return updated_execution, outcome

    # ANNOTATE_AND_ADVANCE
    annotated_record = CompletedStepRecord(
        step_id=step_def.step_id,
        title=step_def.title,
        value=execution.active_exception.value,
        unit=execution.active_exception.unit,
        outcome=StepOutcome.EXCEPTION_RESOLVED_ANNOTATED,
        recorded_at=now_iso,
        exception_resolution=resolution,
    )

    all_steps = policy.get_steps(execution.inspection_type)
    step_index = next(
        (i for i, s in enumerate(all_steps) if s.step_id == step_def.step_id),
        -1,
    )
    next_step_def = all_steps[step_index + 1] if step_index + 1 < len(all_steps) else None
    next_step_id = next_step_def.step_id if next_step_def else None

    updated_execution = execution.model_copy(
        update={
            "status": WorkflowStatus.RUNNING,
            "completed_steps": [*execution.completed_steps, annotated_record],
            "active_exception": None,
            "blocked_reason": None,
            "pending_step_id": next_step_id,
            "desired_state_version": new_version,
            "session_paused": False,
            "updated_at": now_iso,
        }
    )

    queued = execution.notification_prefs.is_enabled_for(NotificationEventType.ON_STEP_REVISION)
    outcome = ResolveExceptionOutcome(
        execution_id=execution.execution_id,
        exception_id=exception_id,
        status=WorkflowStatus.RUNNING,
        resolution_recorded=resolution,
        resolution_behavior=ResolutionBehavior.ANNOTATE_AND_ADVANCE,
        pending_step=next_step_def.to_summary() if next_step_def else None,
        next_allowed_actions=compute_next_allowed_actions(updated_execution),
        notification_queued=queued,
        message=f"Exception resolved and step '{step_def.step_id}' annotated and advanced.",
    )
    return updated_execution, outcome


def apply_complete_inspection(
    *,
    execution: WorkflowExecution,
    policy: DomainPolicyPort,
    audit_reference: str,
    now_iso: str,
) -> tuple[WorkflowExecution, CompleteInspectionOutcome]:
    """Pure transition for completing an inspection."""
    if execution.status == WorkflowStatus.BLOCKED:
        raise AdapterError(
            ErrorCode.WORKFLOW_BLOCKED,
            f"Cannot complete while workflow is BLOCKED: {execution.blocked_reason}",
        )
    if execution.status != WorkflowStatus.RUNNING:
        raise AdapterError(
            ErrorCode.INVALID_STATE_TRANSITION,
            f"Cannot complete workflow in state '{execution.status}'.",
        )

    all_steps = policy.get_steps(execution.inspection_type)
    if execution.pending_step_id is not None or len(execution.completed_steps) < len(all_steps):
        raise AdapterError(
            ErrorCode.INVALID_STATE_TRANSITION,
            f"Cannot complete workflow while step '{execution.pending_step_id}' is still pending.",
        )

    normal_count = sum(1 for s in execution.completed_steps if s.outcome == StepOutcome.NORMAL)
    exc_count = sum(
        1
        for s in execution.completed_steps
        if s.outcome == StepOutcome.EXCEPTION_RESOLVED_ANNOTATED
    )
    domain_meta = policy.build_completion_metadata(execution)

    audit_summary = InspectionAuditSummary(
        execution_id=execution.execution_id,
        asset_id=execution.asset_id,
        inspection_type=execution.inspection_type,
        total_steps=len(execution.completed_steps),
        normal_steps=normal_count,
        exception_resolved_steps=exc_count,
        audit_reference=audit_reference,
        completed_at=now_iso,
        metadata=domain_meta,
    )

    new_version = execution.desired_state_version + 1
    updated_execution = execution.model_copy(
        update={
            "status": WorkflowStatus.COMPLETED,
            "audit_summary": audit_summary,
            "completed_at": now_iso,
            "session_paused": False,
            "desired_state_version": new_version,
            "updated_at": now_iso,
        }
    )

    queued = execution.notification_prefs.is_enabled_for(
        NotificationEventType.ON_INSPECTION_COMPLETED
    )
    outcome = CompleteInspectionOutcome(
        execution_id=execution.execution_id,
        status=WorkflowStatus.COMPLETED,
        completed_at=now_iso,
        summary=audit_summary,
        notification_queued=queued,
        message=f"Workflow completed successfully for asset {execution.asset_id}.",
    )
    return updated_execution, outcome


def apply_configure_notifications(
    *,
    execution: WorkflowExecution,
    preferences: NotificationPreferences | None,
    pause_session: bool,
    now_iso: str,
) -> tuple[WorkflowExecution, ConfigureNotificationsOutcome]:
    """Pure state transition for updating notification preferences and/or pausing an active session."""
    if pause_session and execution.status == WorkflowStatus.COMPLETED:
        raise AdapterError(
            ErrorCode.INVALID_STATE_TRANSITION,
            "Cannot pause a workflow execution that is already COMPLETED.",
        )

    updated_prefs = preferences if preferences is not None else execution.notification_prefs
    new_version = execution.desired_state_version + 1

    will_queue_pause_notification = bool(
        pause_session and updated_prefs.is_enabled_for(NotificationEventType.ON_PAUSE_INTERRUPTION)
    )

    updated_execution = execution.model_copy(
        update={
            "notification_prefs": updated_prefs,
            "session_paused": pause_session,
            "desired_state_version": new_version,
            "updated_at": now_iso,
        }
    )

    action_desc = (
        "Session paused and notification preferences updated."
        if pause_session
        else "Notification preferences updated."
    )
    outcome = ConfigureNotificationsOutcome(
        execution_id=updated_execution.execution_id,
        status=updated_execution.status,
        preferences=updated_prefs,
        session_paused=updated_execution.session_paused,
        notification_queued=will_queue_pause_notification,
        message=action_desc,
    )
    return updated_execution, outcome


def build_notification_record(
    *,
    notification_id: str,
    execution: WorkflowExecution,
    event_type: NotificationEventType,
    summary_message: str,
    extra_payload: dict[str, Any] | None = None,
    now_iso: str,
    force_emit: bool = False,
) -> NotificationRecord | None:
    """Construct a deterministic NotificationRecord if enabled by preferences or force_emit=True."""
    if not force_emit and not execution.notification_prefs.is_enabled_for(event_type):
        return None

    payload: dict[str, Any] = {
        "execution_id": execution.execution_id,
        "asset_id": execution.asset_id,
        "inspection_type": execution.inspection_type,
        "status": execution.status.value,
        "state_version": execution.desired_state_version,
        "session_paused": execution.session_paused,
        "completed_steps_count": len(execution.completed_steps),
        "pending_step_id": execution.pending_step_id,
        "blocked_reason": execution.blocked_reason,
        "resume_voice_prompt": f"Resume my inspection for {execution.asset_id}",
    }
    if execution.active_exception is not None:
        payload["active_exception"] = execution.active_exception.model_dump(mode="json")
    if execution.audit_summary is not None:
        payload["audit_summary"] = execution.audit_summary.model_dump(mode="json")
    if extra_payload:
        payload.update(extra_payload)

    return NotificationRecord(
        notification_id=notification_id,
        execution_id=execution.execution_id,
        principal_id=execution.principal_id,
        asset_id=execution.asset_id,
        state_version=execution.desired_state_version,
        event_type=event_type,
        channels=list(execution.notification_prefs.channels),
        summary_message=summary_message,
        payload=payload,
        created_at=now_iso,
        dispatched=False,
    )


def build_status_response(
    execution: WorkflowExecution,
    policy: DomainPolicyPort,
) -> InspectionStatusResponse:
    """Build a strongly typed status response from authoritative execution state."""
    pending_step_summary = None
    if execution.pending_step_id is not None:
        step_def = policy.get_step(execution.inspection_type, execution.pending_step_id)
        pending_step_summary = step_def.to_summary()

    return InspectionStatusResponse(
        execution_id=execution.execution_id,
        asset_id=execution.asset_id,
        inspection_type=execution.inspection_type,
        status=execution.status,
        desired_state_version=execution.desired_state_version,
        acked_sfn_version=execution.acked_sfn_version,
        session_paused=execution.session_paused,
        completed_steps=execution.completed_steps,
        pending_step=pending_step_summary,
        active_exception=execution.active_exception,
        blocked_reason=execution.blocked_reason,
        next_allowed_actions=compute_next_allowed_actions(execution),
        notification_prefs=execution.notification_prefs,
        last_updated_at=execution.updated_at,
    )
