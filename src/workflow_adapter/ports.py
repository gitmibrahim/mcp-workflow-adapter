from __future__ import annotations

from typing import Any, Protocol, runtime_checkable

from workflow_adapter.models import (
    AuditEvent,
    CompleteInspectionResponse,
    ConfigureNotificationsResponse,
    ExecutionBrief,
    InspectionStatusResponse,
    NotificationPreferences,
    NotificationRecord,
    OutboxRecord,
    RecordResultResponse,
    ResolutionBehavior,
    ResolveExceptionResponse,
    StartInspectionResponse,
    StepDefinition,
    WorkflowExecution,
)


@runtime_checkable
class DomainPolicyPort(Protocol):
    """Injects domain-specific workflow definitions, bounds, and escalation policies."""

    def validate_asset_and_type(self, inspection_type: str, asset_id: str) -> dict[str, Any]:
        """Return asset metadata dict or raise AdapterError(INVALID_INPUT)."""
        ...

    def get_steps(self, inspection_type: str) -> tuple[StepDefinition, ...]:
        """Return ordered step definitions for inspection_type."""
        ...

    def get_step(self, inspection_type: str, step_id: str) -> StepDefinition:
        """Return StepDefinition or raise AdapterError(INVALID_INPUT)."""
        ...

    def validate_reading(
        self, inspection_type: str, step_id: str, value: float, unit: str | None = None
    ) -> tuple[bool, str | None]:
        """Validate unit and numeric range. Returns (is_within_range, out_of_range_reason)."""
        ...

    def resolve_exception_behavior(
        self, inspection_type: str, step_id: str, resolution: str
    ) -> ResolutionBehavior:
        """Return ResolutionBehavior for whitelisted resolution or raise AdapterError(INVALID_INPUT)."""
        ...

    def build_completion_metadata(self, execution: WorkflowExecution) -> dict[str, Any]:
        """Build domain-specific completion/release metadata for InspectionAuditSummary."""
        ...


@runtime_checkable
class NotificationPort(Protocol):
    """Dispatches committed workflow notification records to local or cloud sinks."""

    def dispatch(self, record: NotificationRecord) -> bool:
        """Deliver notification record. Must not raise unhandled exceptions to caller."""
        ...


@runtime_checkable
class OrchestratorPort(Protocol):
    """Synchronizes committed authoritative state with asynchronous orchestration (Step Functions)."""

    def reconcile_execution(self, execution_id: str) -> None:
        """Advance orchestration state toward desired_state_version safely."""
        ...


@runtime_checkable
class StorageBackendPort(Protocol):
    """Authoritative transactional workflow backend interface."""

    def start_inspection(
        self,
        *,
        principal_id: str,
        inspection_type: str,
        asset_id: str,
        idempotency_key: str,
        notification_prefs: NotificationPreferences | None = None,
        correlation_id: str | None = None,
    ) -> StartInspectionResponse: ...

    def get_inspection_status(
        self,
        *,
        principal_id: str,
        execution_id: str | None = None,
        asset_id: str | None = None,
        emit_notification: bool = False,
        correlation_id: str | None = None,
    ) -> InspectionStatusResponse: ...

    def record_inspection_result(
        self,
        *,
        principal_id: str,
        execution_id: str,
        step_id: str,
        value: float,
        unit: str | None = None,
        idempotency_key: str,
        correlation_id: str | None = None,
    ) -> RecordResultResponse: ...

    def resolve_inspection_exception(
        self,
        *,
        principal_id: str,
        execution_id: str,
        exception_id: str,
        resolution: str,
        idempotency_key: str,
        correlation_id: str | None = None,
    ) -> ResolveExceptionResponse: ...

    def complete_inspection(
        self,
        *,
        principal_id: str,
        execution_id: str,
        idempotency_key: str,
        correlation_id: str | None = None,
    ) -> CompleteInspectionResponse: ...

    def configure_notifications(
        self,
        *,
        principal_id: str,
        execution_id: str,
        preferences: NotificationPreferences | None = None,
        pause_session: bool = False,
        idempotency_key: str,
        correlation_id: str | None = None,
    ) -> ConfigureNotificationsResponse: ...

    def list_active_executions(self, *, principal_id: str) -> list[ExecutionBrief]: ...

    def get_audit_trail(self, *, principal_id: str, execution_id: str) -> list[AuditEvent]: ...

    def get_outbox_records(self, *, principal_id: str, execution_id: str) -> list[OutboxRecord]: ...

    def get_notifications(
        self, *, principal_id: str, execution_id: str
    ) -> list[NotificationRecord]: ...
