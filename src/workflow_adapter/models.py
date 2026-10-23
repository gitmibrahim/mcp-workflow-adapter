from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field


def utc_now_iso() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


class WorkflowStatus(StrEnum):
    """4-state MVP business state machine. Infrastructure errors never add a FAILED state."""

    CREATED = "CREATED"
    RUNNING = "RUNNING"
    BLOCKED = "BLOCKED"
    COMPLETED = "COMPLETED"


class ResolutionBehavior(StrEnum):
    """Deterministic state-machine behavior when an exception resolution is applied."""

    RETEST = "RETEST"
    ANNOTATE_AND_ADVANCE = "ANNOTATE_AND_ADVANCE"


class StepOutcome(StrEnum):
    NORMAL = "NORMAL"
    EXCEPTION_RESOLVED_ANNOTATED = "EXCEPTION_RESOLVED_ANNOTATED"


class NotificationEventType(StrEnum):
    ON_PAUSE_INTERRUPTION = "ON_PAUSE_INTERRUPTION"
    ON_STEP_REVISION = "ON_STEP_REVISION"
    ON_EXCEPTION_BLOCKED = "ON_EXCEPTION_BLOCKED"
    ON_STATUS_REQUESTED = "ON_STATUS_REQUESTED"
    ON_INSPECTION_COMPLETED = "ON_INSPECTION_COMPLETED"


class TokenLifecycleStatus(StrEnum):
    NONE = "NONE"
    AVAILABLE = "AVAILABLE"
    IN_FLIGHT = "IN_FLIGHT"
    CONSUMED = "CONSUMED"


class OutboxStatus(StrEnum):
    PENDING = "PENDING"
    ACKNOWLEDGED = "ACKNOWLEDGED"


class StepSummary(BaseModel):
    model_config = ConfigDict(frozen=True)

    step_id: str
    title: str
    unit: str
    min_value: float
    max_value: float


class StepDefinition(BaseModel):
    model_config = ConfigDict(frozen=True)

    step_id: str
    title: str
    unit: str
    accepted_units: tuple[str, ...] = ()
    min_value: float
    max_value: float
    resolution_policies: dict[str, ResolutionBehavior]

    def to_summary(self) -> StepSummary:
        return StepSummary(
            step_id=self.step_id,
            title=self.title,
            unit=self.unit,
            min_value=self.min_value,
            max_value=self.max_value,
        )

    def accepts_unit(self, candidate_unit: str | None) -> bool:
        if candidate_unit is None:
            return True
        normalized = candidate_unit.strip().lower()
        allowed = {self.unit.lower(), *(u.lower() for u in self.accepted_units)}
        return normalized in allowed


class CompletedStepRecord(BaseModel):
    model_config = ConfigDict(frozen=True)

    step_id: str
    title: str
    value: float
    unit: str
    outcome: StepOutcome
    recorded_at: str
    exception_resolution: str | None = None


class ExceptionDetail(BaseModel):
    model_config = ConfigDict(frozen=True)

    exception_id: str
    step_id: str
    step_title: str
    value: float
    unit: str
    min_value: float
    max_value: float
    reason: str
    allowed_resolutions: list[str]
    created_at: str


class NotificationPreferences(BaseModel):
    model_config = ConfigDict(frozen=True)

    on_pause: bool = True
    on_revision: bool = False
    on_blocked: bool = True
    on_status: bool = False
    on_completion: bool = True
    channels: list[str] = Field(default_factory=lambda: ["voice_summary"])

    def is_enabled_for(self, event_type: NotificationEventType) -> bool:
        mapping = {
            NotificationEventType.ON_PAUSE_INTERRUPTION: self.on_pause,
            NotificationEventType.ON_STEP_REVISION: self.on_revision,
            NotificationEventType.ON_EXCEPTION_BLOCKED: self.on_blocked,
            NotificationEventType.ON_STATUS_REQUESTED: self.on_status,
            NotificationEventType.ON_INSPECTION_COMPLETED: self.on_completion,
        }
        return mapping.get(event_type, False)


class NotificationRecord(BaseModel):
    model_config = ConfigDict(frozen=True)

    notification_id: str
    execution_id: str
    principal_id: str
    asset_id: str
    state_version: int
    event_type: NotificationEventType
    channels: list[str]
    summary_message: str
    payload: dict[str, Any]
    created_at: str
    dispatched: bool = False


class ExecutionBrief(BaseModel):
    """Returned during multi-session disambiguation or active session listings."""

    model_config = ConfigDict(frozen=True)

    execution_id: str
    asset_id: str
    inspection_type: str
    status: WorkflowStatus
    pending_step_id: str | None
    session_paused: bool
    updated_at: str


class InspectionAuditSummary(BaseModel):
    model_config = ConfigDict(frozen=True)

    execution_id: str
    asset_id: str
    inspection_type: str
    total_steps: int
    normal_steps: int
    exception_resolved_steps: int
    audit_reference: str
    completed_at: str
    metadata: dict[str, Any] = Field(default_factory=dict)


class WorkflowExecution(BaseModel):
    """Authoritative business and orchestration state persisted in SQLite or DynamoDB."""

    model_config = ConfigDict(frozen=True)

    execution_id: str
    principal_id: str
    inspection_type: str
    asset_id: str
    status: WorkflowStatus
    desired_state_version: int = Field(ge=1)
    completed_steps: list[CompletedStepRecord] = Field(default_factory=list)
    pending_step_id: str | None = None
    active_exception: ExceptionDetail | None = None
    blocked_reason: str | None = None
    session_paused: bool = False
    notification_prefs: NotificationPreferences = Field(default_factory=NotificationPreferences)
    completed_at: str | None = None
    audit_summary: InspectionAuditSummary | None = None
    created_at: str
    updated_at: str

    # Step Functions orchestration tracking fields (authoritative in DynamoDB METADATA)
    acked_sfn_version: int = Field(default=0, ge=0)
    sfn_execution_arn: str | None = None
    sfn_recovery_epoch: int = Field(default=0, ge=0)
    sfn_recovery_lease_until_ms: int = Field(default=0, ge=0)
    sfn_token_status: TokenLifecycleStatus = TokenLifecycleStatus.NONE
    sfn_task_token: str | None = None
    sfn_token_version: int = Field(default=0, ge=0)
    sfn_lease_seq: int = Field(default=0, ge=0)
    sfn_inflight_target_version: int | None = None
    sfn_token_lease_until_ms: int = Field(default=0, ge=0)
    sfn_token_expires_at_ms: int = Field(default=0, ge=0)


class AuditEvent(BaseModel):
    model_config = ConfigDict(frozen=True)

    event_id: str
    execution_id: str
    principal_id: str
    state_version: int
    event_type: str
    step_id: str | None = None
    details: dict[str, Any] = Field(default_factory=dict)
    correlation_id: str
    recorded_at: str


class OutboxRecord(BaseModel):
    model_config = ConfigDict(frozen=True)

    execution_id: str
    target_version: int
    outbox_status: OutboxStatus
    operation: str
    snapshot_json: str
    created_at: str
    acked_at: str | None = None
    acked_by_version: int | None = None
    acked_by_exec_arn: str | None = None


# Immutable Business Outcomes vs. Replay Response Envelopes (AC5)


class StartInspectionOutcome(BaseModel):
    model_config = ConfigDict(frozen=True)

    execution_id: str
    asset_id: str
    inspection_type: str
    status: Literal[WorkflowStatus.RUNNING]
    next_step: StepSummary
    notification_prefs: NotificationPreferences
    message: str


class StartInspectionResponse(StartInspectionOutcome):
    duplicate: bool = False


class InspectionStatusResponse(BaseModel):
    model_config = ConfigDict(frozen=True)

    execution_id: str
    asset_id: str
    inspection_type: str
    status: WorkflowStatus
    desired_state_version: int
    acked_sfn_version: int
    session_paused: bool
    completed_steps: list[CompletedStepRecord]
    pending_step: StepSummary | None
    active_exception: ExceptionDetail | None
    blocked_reason: str | None
    next_allowed_actions: list[str]
    notification_prefs: NotificationPreferences
    last_updated_at: str


class RecordResultOutcome(BaseModel):
    model_config = ConfigDict(frozen=True)

    execution_id: str
    step_id: str
    accepted: bool
    status: Literal[WorkflowStatus.RUNNING, WorkflowStatus.BLOCKED]
    next_step: StepSummary | None
    active_exception: ExceptionDetail | None
    blocked_reason: str | None
    next_allowed_actions: list[str]
    notification_queued: bool
    message: str


class RecordResultResponse(RecordResultOutcome):
    duplicate: bool = False


class ResolveExceptionOutcome(BaseModel):
    model_config = ConfigDict(frozen=True)

    execution_id: str
    exception_id: str
    status: Literal[WorkflowStatus.RUNNING]
    resolution_recorded: str
    resolution_behavior: ResolutionBehavior
    pending_step: StepSummary | None
    next_allowed_actions: list[str]
    notification_queued: bool
    message: str


class ResolveExceptionResponse(ResolveExceptionOutcome):
    duplicate: bool = False


class CompleteInspectionOutcome(BaseModel):
    model_config = ConfigDict(frozen=True)

    execution_id: str
    status: Literal[WorkflowStatus.COMPLETED]
    completed_at: str
    summary: InspectionAuditSummary
    notification_queued: bool
    message: str


class CompleteInspectionResponse(CompleteInspectionOutcome):
    duplicate: bool = False


class ConfigureNotificationsOutcome(BaseModel):
    model_config = ConfigDict(frozen=True)

    execution_id: str
    status: WorkflowStatus
    preferences: NotificationPreferences
    session_paused: bool
    notification_queued: bool
    message: str


class ConfigureNotificationsResponse(ConfigureNotificationsOutcome):
    duplicate: bool = False
