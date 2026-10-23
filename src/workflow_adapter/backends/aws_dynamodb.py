from __future__ import annotations

import contextlib
import logging
from typing import Any

from botocore.exceptions import BotoCoreError, ClientError  # type: ignore[import-untyped]
from pydantic import ValidationError

from workflow_adapter.errors import AdapterError, ErrorCode, generate_correlation_id
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
    AuditEvent,
    CompleteInspectionOutcome,
    CompleteInspectionResponse,
    ConfigureNotificationsOutcome,
    ConfigureNotificationsResponse,
    ExecutionBrief,
    InspectionStatusResponse,
    NotificationEventType,
    NotificationPreferences,
    NotificationRecord,
    OutboxRecord,
    OutboxStatus,
    RecordResultOutcome,
    RecordResultResponse,
    ResolveExceptionOutcome,
    ResolveExceptionResponse,
    StartInspectionOutcome,
    StartInspectionResponse,
    TokenLifecycleStatus,
    WorkflowExecution,
    WorkflowStatus,
    utc_now_iso,
)
from workflow_adapter.ports import (
    DomainPolicyPort,
    NotificationPort,
    OrchestratorPort,
    StorageBackendPort,
)
from workflow_adapter.state_machine import (
    apply_complete_inspection,
    apply_configure_notifications,
    apply_record_reading,
    apply_resolve_exception,
    build_notification_record,
    build_status_response,
    create_initial_execution,
)

logger = logging.getLogger(__name__)


def _pad_ver(version: int) -> str:
    return f"{version:06d}"


class DynamoDBWorkflowStore(StorageBackendPort):
    """Authoritative single-table DynamoDB store using multi-item TransactWriteItems."""

    def __init__(
        self,
        *,
        ddb_client: Any,
        table_name: str,
        policy: DomainPolicyPort,
        notification_port: NotificationPort | None = None,
        orchestrator_port: OrchestratorPort | None = None,
    ) -> None:
        if not table_name:
            raise ValueError("table_name must be non-empty.")
        self._ddb = ddb_client
        self._table = table_name
        self._policy = policy
        self._notification_port = notification_port
        self._orchestrator_port = orchestrator_port

    def set_orchestrator_port(self, orchestrator_port: OrchestratorPort) -> None:
        self._orchestrator_port = orchestrator_port

    def set_notification_port(self, notification_port: NotificationPort) -> None:
        self._notification_port = notification_port

    # ─── DynamoDB Attribute Helpers ───────────────────────────────────────

    @staticmethod
    def _s(value: str) -> dict[str, str]:
        return {"S": value}

    @staticmethod
    def _n(value: int | float) -> dict[str, str]:
        return {"N": str(value)}

    @staticmethod
    def _bool(value: bool) -> dict[str, bool]:
        return {"BOOL": bool(value)}

    # ─── Serialization ────────────────────────────────────────────────────

    def _serialize_metadata_item(self, execution: WorkflowExecution) -> dict[str, Any]:
        item: dict[str, Any] = {
            "PK": self._s(f"EXEC#{execution.execution_id}"),
            "SK": self._s("METADATA"),
            "item_type": self._s("METADATA"),
            "execution_id": self._s(execution.execution_id),
            "principal_id": self._s(execution.principal_id),
            "inspection_type": self._s(execution.inspection_type),
            "asset_id": self._s(execution.asset_id),
            "status": self._s(execution.status.value),
            "desired_state_version": self._n(execution.desired_state_version),
            "pending_step_id": self._s(execution.pending_step_id or ""),
            "session_paused": self._bool(execution.session_paused),
            "execution_json": self._s(execution.model_dump_json()),
            "created_at": self._s(execution.created_at),
            "updated_at": self._s(execution.updated_at),
            "acked_sfn_version": self._n(execution.acked_sfn_version),
            "sfn_execution_arn": self._s(execution.sfn_execution_arn or ""),
            "sfn_recovery_epoch": self._n(execution.sfn_recovery_epoch),
            "sfn_recovery_lease_until_ms": self._n(execution.sfn_recovery_lease_until_ms),
            "sfn_token_status": self._s(execution.sfn_token_status.value),
            "sfn_task_token": self._s(execution.sfn_task_token or ""),
            "sfn_token_version": self._n(execution.sfn_token_version),
            "sfn_lease_seq": self._n(execution.sfn_lease_seq),
            "sfn_inflight_target_version": self._n(execution.sfn_inflight_target_version or 0),
            "sfn_token_lease_until_ms": self._n(execution.sfn_token_lease_until_ms),
            "sfn_token_expires_at_ms": self._n(execution.sfn_token_expires_at_ms),
        }
        return item

    def _serialize_principal_exec_item(self, execution: WorkflowExecution) -> dict[str, Any]:
        return {
            "PK": self._s(f"PRINCIPAL#{execution.principal_id}"),
            "SK": self._s(f"EXEC#{execution.execution_id}"),
            "item_type": self._s("PRINCIPAL_EXEC"),
            "principal_id": self._s(execution.principal_id),
            "execution_id": self._s(execution.execution_id),
            "asset_id": self._s(execution.asset_id),
            "inspection_type": self._s(execution.inspection_type),
            "status": self._s(execution.status.value),
            "pending_step_id": self._s(execution.pending_step_id or ""),
            "session_paused": self._bool(execution.session_paused),
            "desired_state_version": self._n(execution.desired_state_version),
            "updated_at": self._s(execution.updated_at),
        }

    # ─── Deserialization ──────────────────────────────────────────────────

    @staticmethod
    def _deserialize_metadata_item(item: dict[str, Any], correlation_id: str) -> WorkflowExecution:
        try:
            raw_json = item["execution_json"]["S"]
            base_exec = WorkflowExecution.model_validate_json(raw_json)
            sfn_arn = item.get("sfn_execution_arn", {}).get("S") or None
            sfn_token = item.get("sfn_task_token", {}).get("S") or None
            inflight_v = int(item.get("sfn_inflight_target_version", {}).get("N", "0"))
            return base_exec.model_copy(
                update={
                    "desired_state_version": int(item["desired_state_version"]["N"]),
                    "acked_sfn_version": int(item.get("acked_sfn_version", {}).get("N", "0")),
                    "sfn_execution_arn": sfn_arn,
                    "sfn_recovery_epoch": int(item.get("sfn_recovery_epoch", {}).get("N", "0")),
                    "sfn_recovery_lease_until_ms": int(
                        item.get("sfn_recovery_lease_until_ms", {}).get("N", "0")
                    ),
                    "sfn_token_status": TokenLifecycleStatus(
                        item.get("sfn_token_status", {}).get("S", "NONE")
                    ),
                    "sfn_task_token": sfn_token,
                    "sfn_token_version": int(item.get("sfn_token_version", {}).get("N", "0")),
                    "sfn_lease_seq": int(item.get("sfn_lease_seq", {}).get("N", "0")),
                    "sfn_inflight_target_version": inflight_v if inflight_v > 0 else None,
                    "sfn_token_lease_until_ms": int(
                        item.get("sfn_token_lease_until_ms", {}).get("N", "0")
                    ),
                    "sfn_token_expires_at_ms": int(
                        item.get("sfn_token_expires_at_ms", {}).get("N", "0")
                    ),
                }
            )
        except (KeyError, ValueError, ValidationError) as exc:
            raise AdapterError(
                ErrorCode.INTERNAL_ERROR,
                "Persisted DynamoDB workflow execution failed schema integrity validation.",
                retryable=False,
                correlation_id=correlation_id,
            ) from exc

    # ─── Error Mapping ────────────────────────────────────────────────────

    def _map_client_error(self, exc: Exception, correlation_id: str) -> AdapterError:
        if isinstance(exc, AdapterError):
            return exc
        if isinstance(exc, ClientError):
            code = exc.response.get("Error", {}).get("Code", "")
            if code in {
                "ProvisionedThroughputExceededException",
                "RequestLimitExceeded",
                "InternalServerError",
                "ServiceUnavailable",
                "ThrottlingException",
                "TransactionInProgressException",
            }:
                return AdapterError(
                    ErrorCode.BACKEND_UNAVAILABLE,
                    f"DynamoDB service transiently unavailable ({code}).",
                    retryable=True,
                    correlation_id=correlation_id,
                )
        if isinstance(exc, BotoCoreError):
            return AdapterError(
                ErrorCode.BACKEND_UNAVAILABLE,
                "AWS transport error communicating with DynamoDB.",
                retryable=True,
                correlation_id=correlation_id,
            )
        return AdapterError(
            ErrorCode.BACKEND_UNAVAILABLE,
            "Unexpected storage error communicating with DynamoDB.",
            retryable=True,
            correlation_id=correlation_id,
        )

    # ─── Load Helpers ─────────────────────────────────────────────────────

    def load_execution_metadata(
        self, execution_id: str, *, correlation_id: str | None = None
    ) -> WorkflowExecution:
        corr_id = correlation_id or generate_correlation_id()
        try:
            resp = self._ddb.get_item(
                TableName=self._table,
                Key={"PK": self._s(f"EXEC#{execution_id}"), "SK": self._s("METADATA")},
                ConsistentRead=True,
            )
        except (ClientError, BotoCoreError) as exc:
            raise self._map_client_error(exc, corr_id) from exc

        item = resp.get("Item")
        if not item:
            raise AdapterError(
                ErrorCode.NOT_FOUND,
                f"Workflow execution '{execution_id}' not found.",
                correlation_id=corr_id,
            )
        return self._deserialize_metadata_item(item, corr_id)

    def _get_start_idemp(
        self, principal_id: str, idempotency_key: str, corr_id: str
    ) -> dict[str, Any] | None:
        try:
            resp = self._ddb.get_item(
                TableName=self._table,
                Key={
                    "PK": self._s(f"PRINCIPAL#{principal_id}"),
                    "SK": self._s(f"START_IDEMP#{idempotency_key}"),
                },
                ConsistentRead=True,
            )
            return resp.get("Item")
        except (ClientError, BotoCoreError) as exc:
            raise self._map_client_error(exc, corr_id) from exc

    def _get_asset_lock(self, asset_id: str, corr_id: str) -> dict[str, Any] | None:
        try:
            resp = self._ddb.get_item(
                TableName=self._table,
                Key={"PK": self._s(f"ASSET#{asset_id}"), "SK": self._s("ACTIVE_LOCK")},
                ConsistentRead=True,
            )
            return resp.get("Item")
        except (ClientError, BotoCoreError) as exc:
            raise self._map_client_error(exc, corr_id) from exc

    def _get_mutation_idemp(
        self, execution_id: str, operation: str, idempotency_key: str, corr_id: str
    ) -> dict[str, Any] | None:
        try:
            resp = self._ddb.get_item(
                TableName=self._table,
                Key={
                    "PK": self._s(f"EXEC#{execution_id}"),
                    "SK": self._s(f"IDEMP#{operation}#{idempotency_key}"),
                },
                ConsistentRead=True,
            )
            return resp.get("Item")
        except (ClientError, BotoCoreError) as exc:
            raise self._map_client_error(exc, corr_id) from exc

    def _raise_asset_lock_conflict(
        self, asset_id: str, caller_principal_id: str, lock_item: dict[str, Any], corr_id: str
    ) -> None:
        owner_id = lock_item["principal_id"]["S"]
        active_exec_id = lock_item["execution_id"]["S"]
        if owner_id == caller_principal_id:
            raise AdapterError(
                ErrorCode.INVALID_STATE_TRANSITION,
                f"Asset '{asset_id}' already has an active workflow execution ({active_exec_id}). "
                "Resume or complete the existing execution before starting a new one.",
                retryable=False,
                correlation_id=corr_id,
                details={
                    "reason": "ASSET_ALREADY_UNDER_INSPECTION",
                    "asset_id": asset_id,
                    "active_execution_id": active_exec_id,
                    "owned_by_caller": True,
                },
            )
        raise AdapterError(
            ErrorCode.INVALID_STATE_TRANSITION,
            f"Asset '{asset_id}' is currently locked by another active workflow execution.",
            retryable=False,
            correlation_id=corr_id,
            details={
                "reason": "ASSET_ALREADY_UNDER_INSPECTION",
                "asset_id": asset_id,
                "owned_by_caller": False,
            },
        )

    # ─── Post-Commit Side Effects ─────────────────────────────────────────

    def _post_commit_side_effects(self, execution_id: str) -> None:
        """Best-effort reconciler trigger + notification flush after a successful commit."""
        if self._orchestrator_port:
            try:
                self._orchestrator_port.reconcile_execution(execution_id)
            except Exception:
                logger.debug("Reconciler side-effect suppressed", exc_info=True)
        self._flush_pending_notifications(execution_id)

    def _flush_pending_notifications(self, execution_id: str) -> None:
        """Best-effort dispatch of committed but undispatched NOTIFY items."""
        if not self._notification_port:
            return
        try:
            records = self.get_notifications(
                principal_id="__system__", execution_id=execution_id
            )
            for rec in records:
                if not rec.dispatched:
                    try:
                        self._notification_port.dispatch(rec)
                    except Exception:
                        logger.debug("Notification dispatch suppressed", exc_info=True)
        except Exception:
            logger.debug("Notification flush suppressed", exc_info=True)

    # ─── start_inspection ─────────────────────────────────────────────────

    def start_inspection(
        self,
        *,
        principal_id: str,
        inspection_type: str,
        asset_id: str,
        idempotency_key: str,
        notification_prefs: NotificationPreferences | None = None,
        correlation_id: str | None = None,
    ) -> StartInspectionResponse:
        corr_id = correlation_id or generate_correlation_id()
        clean_key = validate_idempotency_key(idempotency_key)
        prefs = notification_prefs or NotificationPreferences()
        payload_hash = compute_payload_hash(
            "start_inspection",
            {
                "inspection_type": inspection_type,
                "asset_id": asset_id,
                "notification_prefs": prefs.model_dump(mode="json"),
            },
        )

        # 1. Pre-check start idempotency
        existing_idemp = self._get_start_idemp(principal_id, clean_key, corr_id)
        if existing_idemp is not None:
            verify_or_raise_idempotency_conflict(
                idempotency_key=clean_key,
                operation="start_inspection",
                stored_payload_hash=existing_idemp["payload_hash"]["S"],
                incoming_payload_hash=payload_hash,
            )
            exec_id = existing_idemp["execution_id"]["S"]
            self._post_commit_side_effects(exec_id)
            return build_response_from_outcome(
                existing_idemp["outcome_json"]["S"],
                StartInspectionOutcome,
                StartInspectionResponse,
                duplicate=True,
            )

        # 2. Validate domain catalog and check active asset lock
        self._policy.validate_asset_and_type(inspection_type, asset_id)
        existing_lock = self._get_asset_lock(asset_id, corr_id)
        if existing_lock is not None:
            self._raise_asset_lock_conflict(asset_id, principal_id, existing_lock, corr_id)

        # 3. Build initial execution & atomic items
        execution_id = generate_execution_id()
        now_iso = utc_now_iso()
        execution, outcome = create_initial_execution(
            execution_id=execution_id,
            principal_id=principal_id,
            inspection_type=inspection_type,
            asset_id=asset_id,
            notification_prefs=prefs,
            policy=self._policy,
            now_iso=now_iso,
        )

        audit_event = AuditEvent(
            event_id=generate_event_id("aud"),
            execution_id=execution_id,
            principal_id=principal_id,
            state_version=1,
            event_type="WORKFLOW_STARTED",
            step_id=execution.pending_step_id,
            details={"asset_id": asset_id, "inspection_type": inspection_type},
            correlation_id=corr_id,
            recorded_at=now_iso,
        )
        outbox_record = OutboxRecord(
            execution_id=execution_id,
            target_version=1,
            outbox_status=OutboxStatus.PENDING,
            operation="start_inspection",
            snapshot_json=execution.model_dump_json(),
            created_at=now_iso,
        )

        client_token = derive_client_request_token(
            principal_id, "START", "start_inspection", clean_key
        )

        transact_items: list[dict[str, Any]] = [
            {
                "Put": {
                    "TableName": self._table,
                    "Item": {
                        "PK": self._s(f"PRINCIPAL#{principal_id}"),
                        "SK": self._s(f"START_IDEMP#{clean_key}"),
                        "item_type": self._s("START_IDEMP"),
                        "principal_id": self._s(principal_id),
                        "idempotency_key": self._s(clean_key),
                        "payload_hash": self._s(payload_hash),
                        "execution_id": self._s(execution_id),
                        "outcome_json": self._s(outcome.model_dump_json()),
                        "created_at": self._s(now_iso),
                    },
                    "ConditionExpression": "attribute_not_exists(PK)",
                }
            },
            {
                "Put": {
                    "TableName": self._table,
                    "Item": {
                        "PK": self._s(f"ASSET#{asset_id}"),
                        "SK": self._s("ACTIVE_LOCK"),
                        "item_type": self._s("ASSET_LOCK"),
                        "asset_id": self._s(asset_id),
                        "execution_id": self._s(execution_id),
                        "principal_id": self._s(principal_id),
                        "inspection_type": self._s(inspection_type),
                        "acquired_at": self._s(now_iso),
                    },
                    "ConditionExpression": "attribute_not_exists(PK)",
                }
            },
            {
                "Put": {
                    "TableName": self._table,
                    "Item": self._serialize_metadata_item(execution),
                    "ConditionExpression": "attribute_not_exists(PK)",
                }
            },
            {
                "Put": {
                    "TableName": self._table,
                    "Item": self._serialize_principal_exec_item(execution),
                }
            },
            {
                "Put": {
                    "TableName": self._table,
                    "Item": {
                        "PK": self._s(f"EXEC#{execution_id}"),
                        "SK": self._s(f"AUDIT#{_pad_ver(1)}#{audit_event.event_id}"),
                        "item_type": self._s("AUDIT"),
                        "execution_id": self._s(execution_id),
                        "state_version": self._n(1),
                        "event_id": self._s(audit_event.event_id),
                        "principal_id": self._s(principal_id),
                        "event_type": self._s(audit_event.event_type),
                        "audit_json": self._s(audit_event.model_dump_json()),
                        "recorded_at": self._s(now_iso),
                    },
                }
            },
            {
                "Put": {
                    "TableName": self._table,
                    "Item": {
                        "PK": self._s(f"EXEC#{execution_id}"),
                        "SK": self._s(f"OUTBOX#{_pad_ver(1)}"),
                        "item_type": self._s("OUTBOX"),
                        "execution_id": self._s(execution_id),
                        "target_version": self._n(1),
                        "outbox_status": self._s(OutboxStatus.PENDING.value),
                        "operation": self._s("start_inspection"),
                        "snapshot_json": self._s(outbox_record.snapshot_json),
                        "created_at": self._s(now_iso),
                    },
                }
            },
        ]

        try:
            self._ddb.transact_write_items(
                TransactItems=transact_items,
                ClientRequestToken=client_token,
            )
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") == "TransactionCanceledException":
                # Re-check START_IDEMP first (concurrent duplicate start race AC7)
                raced_idemp = self._get_start_idemp(principal_id, clean_key, corr_id)
                if raced_idemp is not None:
                    verify_or_raise_idempotency_conflict(
                        idempotency_key=clean_key,
                        operation="start_inspection",
                        stored_payload_hash=raced_idemp["payload_hash"]["S"],
                        incoming_payload_hash=payload_hash,
                    )
                    raced_exec_id = raced_idemp["execution_id"]["S"]
                    self._post_commit_side_effects(raced_exec_id)
                    return build_response_from_outcome(
                        raced_idemp["outcome_json"]["S"],
                        StartInspectionOutcome,
                        StartInspectionResponse,
                        duplicate=True,
                    )
                # Otherwise check if ASSET_LOCK caused the cancellation (AC17)
                raced_lock = self._get_asset_lock(asset_id, corr_id)
                if raced_lock is not None:
                    self._raise_asset_lock_conflict(asset_id, principal_id, raced_lock, corr_id)
            raise self._map_client_error(exc, corr_id) from exc
        except BotoCoreError as exc:
            raise self._map_client_error(exc, corr_id) from exc

        self._post_commit_side_effects(execution_id)
        return StartInspectionResponse(**outcome.model_dump(), duplicate=False)

    # ─── get_inspection_status ────────────────────────────────────────────

    def get_inspection_status(
        self,
        *,
        principal_id: str,
        execution_id: str | None = None,
        asset_id: str | None = None,
        emit_notification: bool = False,
        correlation_id: str | None = None,
    ) -> InspectionStatusResponse:
        corr_id = correlation_id or generate_correlation_id()

        if execution_id:
            execution = self.load_execution_metadata(execution_id, correlation_id=corr_id)
            if execution.principal_id != principal_id:
                raise AdapterError(
                    ErrorCode.FORBIDDEN,
                    f"Principal '{principal_id}' does not own execution '{execution_id}'.",
                    correlation_id=corr_id,
                )
        else:
            # Find by principal - strongly consistent query
            active = self.list_active_executions(principal_id=principal_id)
            if not active:
                raise AdapterError(
                    ErrorCode.NOT_FOUND,
                    f"No active workflow executions found for principal '{principal_id}'.",
                    correlation_id=corr_id,
                )
            # Pick the most recently updated
            best = max(active, key=lambda b: b.updated_at)
            execution = self.load_execution_metadata(best.execution_id, correlation_id=corr_id)

        response = build_status_response(execution, self._policy)

        if emit_notification:
            notification = build_notification_record(
                notification_id=generate_event_id("notif"),
                execution=execution,
                event_type=NotificationEventType.ON_STATUS_REQUESTED,
                summary_message=f"Status check for {execution.asset_id}",
                now_iso=utc_now_iso(),
                force_emit=True,
            )
            if notification:
                self._emit_notification_item(execution, notification, corr_id)

        return response

    # ─── record_inspection_result ─────────────────────────────────────────

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
    ) -> RecordResultResponse:
        corr_id = correlation_id or generate_correlation_id()
        clean_key = validate_idempotency_key(idempotency_key)
        operation = "record_inspection_result"
        payload_hash = compute_payload_hash(
            operation,
            {"step_id": step_id, "value": value, "unit": unit or ""},
        )

        # 1. Idempotency pre-check
        existing_idemp = self._get_mutation_idemp(execution_id, operation, clean_key, corr_id)
        if existing_idemp is not None:
            verify_or_raise_idempotency_conflict(
                idempotency_key=clean_key,
                operation=operation,
                stored_payload_hash=existing_idemp["payload_hash"]["S"],
                incoming_payload_hash=payload_hash,
            )
            self._post_commit_side_effects(execution_id)
            return build_response_from_outcome(
                existing_idemp["outcome_json"]["S"],
                RecordResultOutcome,
                RecordResultResponse,
                duplicate=True,
            )

        # 2. Load current state
        execution = self.load_execution_metadata(execution_id, correlation_id=corr_id)
        if execution.principal_id != principal_id:
            raise AdapterError(
                ErrorCode.FORBIDDEN,
                f"Principal '{principal_id}' does not own execution '{execution_id}'.",
                correlation_id=corr_id,
            )

        # 3. Apply state machine transition
        now_iso = utc_now_iso()
        new_version = execution.desired_state_version + 1
        new_execution, outcome = apply_record_reading(
            execution=execution,
            step_id=step_id,
            value=value,
            unit=unit,
            policy=self._policy,
            now_iso=now_iso,
            new_exception_id=generate_exception_id(),
        )

        new_version = new_execution.desired_state_version
        audit_event = AuditEvent(
            event_id=generate_event_id("aud"),
            execution_id=execution_id,
            principal_id=principal_id,
            state_version=new_version,
            event_type="RESULT_RECORDED" if outcome.accepted else "EXCEPTION_RAISED",
            step_id=step_id,
            details={"value": value, "unit": unit or "", "accepted": outcome.accepted},
            correlation_id=corr_id,
            recorded_at=now_iso,
        )
        outbox_record = OutboxRecord(
            execution_id=execution_id,
            target_version=new_version,
            outbox_status=OutboxStatus.PENDING,
            operation=operation,
            snapshot_json=new_execution.model_dump_json(),
            created_at=now_iso,
        )

        client_token = derive_client_request_token(
            principal_id, execution_id, operation, clean_key
        )

        transact_items: list[dict[str, Any]] = [
            {
                "Put": {
                    "TableName": self._table,
                    "Item": self._serialize_metadata_item(new_execution),
                    "ConditionExpression": "desired_state_version = :expected_v AND principal_id = :pid",
                    "ExpressionAttributeValues": {
                        ":expected_v": self._n(execution.desired_state_version),
                        ":pid": self._s(principal_id),
                    },
                }
            },
            {
                "Put": {
                    "TableName": self._table,
                    "Item": self._serialize_principal_exec_item(new_execution),
                }
            },
            {
                "Put": {
                    "TableName": self._table,
                    "Item": {
                        "PK": self._s(f"EXEC#{execution_id}"),
                        "SK": self._s(f"IDEMP#{operation}#{clean_key}"),
                        "item_type": self._s("IDEMP"),
                        "execution_id": self._s(execution_id),
                        "operation": self._s(operation),
                        "idempotency_key": self._s(clean_key),
                        "principal_id": self._s(principal_id),
                        "payload_hash": self._s(payload_hash),
                        "state_version_after": self._n(new_version),
                        "outcome_json": self._s(outcome.model_dump_json()),
                        "created_at": self._s(now_iso),
                    },
                    "ConditionExpression": "attribute_not_exists(PK)",
                }
            },
            {
                "Put": {
                    "TableName": self._table,
                    "Item": {
                        "PK": self._s(f"EXEC#{execution_id}"),
                        "SK": self._s(f"AUDIT#{_pad_ver(new_version)}#{audit_event.event_id}"),
                        "item_type": self._s("AUDIT"),
                        "execution_id": self._s(execution_id),
                        "state_version": self._n(new_version),
                        "event_id": self._s(audit_event.event_id),
                        "principal_id": self._s(principal_id),
                        "event_type": self._s(audit_event.event_type),
                        "audit_json": self._s(audit_event.model_dump_json()),
                        "recorded_at": self._s(now_iso),
                    },
                }
            },
            {
                "Put": {
                    "TableName": self._table,
                    "Item": {
                        "PK": self._s(f"EXEC#{execution_id}"),
                        "SK": self._s(f"OUTBOX#{_pad_ver(new_version)}"),
                        "item_type": self._s("OUTBOX"),
                        "execution_id": self._s(execution_id),
                        "target_version": self._n(new_version),
                        "outbox_status": self._s(OutboxStatus.PENDING.value),
                        "operation": self._s(operation),
                        "snapshot_json": self._s(outbox_record.snapshot_json),
                        "created_at": self._s(now_iso),
                    },
                }
            },
        ]

        # Notification item if applicable
        notification = build_notification_record(
            notification_id=generate_event_id("notif"),
            execution=new_execution,
            event_type=(
                NotificationEventType.ON_EXCEPTION_BLOCKED
                if not outcome.accepted
                else NotificationEventType.ON_STEP_REVISION
            ),
            summary_message=outcome.message,
            now_iso=now_iso,
        )
        if notification:
            transact_items.append(
                {
                    "Put": {
                        "TableName": self._table,
                        "Item": {
                            "PK": self._s(f"EXEC#{execution_id}"),
                            "SK": self._s(f"NOTIFY#{_pad_ver(new_version)}#{notification.notification_id}"),
                            "item_type": self._s("NOTIFY"),
                            "notification_id": self._s(notification.notification_id),
                            "execution_id": self._s(execution_id),
                            "principal_id": self._s(principal_id),
                            "state_version": self._n(new_version),
                            "event_type": self._s(notification.event_type.value),
                            "dispatched": self._bool(False),
                            "notification_json": self._s(notification.model_dump_json()),
                            "created_at": self._s(now_iso),
                        },
                    }
                }
            )

        try:
            self._ddb.transact_write_items(
                TransactItems=transact_items,
                ClientRequestToken=client_token,
            )
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") == "TransactionCanceledException":
                raced_idemp = self._get_mutation_idemp(execution_id, operation, clean_key, corr_id)
                if raced_idemp is not None:
                    verify_or_raise_idempotency_conflict(
                        idempotency_key=clean_key,
                        operation=operation,
                        stored_payload_hash=raced_idemp["payload_hash"]["S"],
                        incoming_payload_hash=payload_hash,
                    )
                    self._post_commit_side_effects(execution_id)
                    return build_response_from_outcome(
                        raced_idemp["outcome_json"]["S"],
                        RecordResultOutcome,
                        RecordResultResponse,
                        duplicate=True,
                    )
            raise self._map_client_error(exc, corr_id) from exc
        except BotoCoreError as exc:
            raise self._map_client_error(exc, corr_id) from exc

        self._post_commit_side_effects(execution_id)
        return RecordResultResponse(**outcome.model_dump(), duplicate=False)

    # ─── resolve_inspection_exception ─────────────────────────────────────

    def resolve_inspection_exception(
        self,
        *,
        principal_id: str,
        execution_id: str,
        exception_id: str,
        resolution: str,
        idempotency_key: str,
        correlation_id: str | None = None,
    ) -> ResolveExceptionResponse:
        corr_id = correlation_id or generate_correlation_id()
        clean_key = validate_idempotency_key(idempotency_key)
        operation = "resolve_inspection_exception"
        payload_hash = compute_payload_hash(
            operation,
            {"exception_id": exception_id, "resolution": resolution},
        )

        existing_idemp = self._get_mutation_idemp(execution_id, operation, clean_key, corr_id)
        if existing_idemp is not None:
            verify_or_raise_idempotency_conflict(
                idempotency_key=clean_key,
                operation=operation,
                stored_payload_hash=existing_idemp["payload_hash"]["S"],
                incoming_payload_hash=payload_hash,
            )
            self._post_commit_side_effects(execution_id)
            return build_response_from_outcome(
                existing_idemp["outcome_json"]["S"],
                ResolveExceptionOutcome,
                ResolveExceptionResponse,
                duplicate=True,
            )

        execution = self.load_execution_metadata(execution_id, correlation_id=corr_id)
        if execution.principal_id != principal_id:
            raise AdapterError(
                ErrorCode.FORBIDDEN,
                f"Principal '{principal_id}' does not own execution '{execution_id}'.",
                correlation_id=corr_id,
            )

        now_iso = utc_now_iso()
        new_execution, outcome = apply_resolve_exception(
            execution=execution,
            exception_id=exception_id,
            resolution=resolution,
            policy=self._policy,
            now_iso=now_iso,
        )

        new_version = new_execution.desired_state_version
        audit_event = AuditEvent(
            event_id=generate_event_id("aud"),
            execution_id=execution_id,
            principal_id=principal_id,
            state_version=new_version,
            event_type="EXCEPTION_RESOLVED",
            step_id=new_execution.pending_step_id,
            details={"exception_id": exception_id, "resolution": resolution},
            correlation_id=corr_id,
            recorded_at=now_iso,
        )
        outbox_record = OutboxRecord(
            execution_id=execution_id,
            target_version=new_version,
            outbox_status=OutboxStatus.PENDING,
            operation=operation,
            snapshot_json=new_execution.model_dump_json(),
            created_at=now_iso,
        )

        client_token = derive_client_request_token(
            principal_id, execution_id, operation, clean_key
        )

        transact_items: list[dict[str, Any]] = [
            {
                "Put": {
                    "TableName": self._table,
                    "Item": self._serialize_metadata_item(new_execution),
                    "ConditionExpression": "desired_state_version = :expected_v AND principal_id = :pid",
                    "ExpressionAttributeValues": {
                        ":expected_v": self._n(execution.desired_state_version),
                        ":pid": self._s(principal_id),
                    },
                }
            },
            {
                "Put": {
                    "TableName": self._table,
                    "Item": self._serialize_principal_exec_item(new_execution),
                }
            },
            {
                "Put": {
                    "TableName": self._table,
                    "Item": {
                        "PK": self._s(f"EXEC#{execution_id}"),
                        "SK": self._s(f"IDEMP#{operation}#{clean_key}"),
                        "item_type": self._s("IDEMP"),
                        "execution_id": self._s(execution_id),
                        "operation": self._s(operation),
                        "idempotency_key": self._s(clean_key),
                        "principal_id": self._s(principal_id),
                        "payload_hash": self._s(payload_hash),
                        "state_version_after": self._n(new_version),
                        "outcome_json": self._s(outcome.model_dump_json()),
                        "created_at": self._s(now_iso),
                    },
                    "ConditionExpression": "attribute_not_exists(PK)",
                }
            },
            {
                "Put": {
                    "TableName": self._table,
                    "Item": {
                        "PK": self._s(f"EXEC#{execution_id}"),
                        "SK": self._s(f"AUDIT#{_pad_ver(new_version)}#{audit_event.event_id}"),
                        "item_type": self._s("AUDIT"),
                        "execution_id": self._s(execution_id),
                        "state_version": self._n(new_version),
                        "event_id": self._s(audit_event.event_id),
                        "principal_id": self._s(principal_id),
                        "event_type": self._s(audit_event.event_type),
                        "audit_json": self._s(audit_event.model_dump_json()),
                        "recorded_at": self._s(now_iso),
                    },
                }
            },
            {
                "Put": {
                    "TableName": self._table,
                    "Item": {
                        "PK": self._s(f"EXEC#{execution_id}"),
                        "SK": self._s(f"OUTBOX#{_pad_ver(new_version)}"),
                        "item_type": self._s("OUTBOX"),
                        "execution_id": self._s(execution_id),
                        "target_version": self._n(new_version),
                        "outbox_status": self._s(OutboxStatus.PENDING.value),
                        "operation": self._s(operation),
                        "snapshot_json": self._s(outbox_record.snapshot_json),
                        "created_at": self._s(now_iso),
                    },
                }
            },
        ]

        try:
            self._ddb.transact_write_items(
                TransactItems=transact_items,
                ClientRequestToken=client_token,
            )
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") == "TransactionCanceledException":
                raced_idemp = self._get_mutation_idemp(execution_id, operation, clean_key, corr_id)
                if raced_idemp is not None:
                    verify_or_raise_idempotency_conflict(
                        idempotency_key=clean_key,
                        operation=operation,
                        stored_payload_hash=raced_idemp["payload_hash"]["S"],
                        incoming_payload_hash=payload_hash,
                    )
                    self._post_commit_side_effects(execution_id)
                    return build_response_from_outcome(
                        raced_idemp["outcome_json"]["S"],
                        ResolveExceptionOutcome,
                        ResolveExceptionResponse,
                        duplicate=True,
                    )
            raise self._map_client_error(exc, corr_id) from exc
        except BotoCoreError as exc:
            raise self._map_client_error(exc, corr_id) from exc

        self._post_commit_side_effects(execution_id)
        return ResolveExceptionResponse(**outcome.model_dump(), duplicate=False)

    # ─── configure_notifications ──────────────────────────────────────────

    def configure_notifications(
        self,
        *,
        principal_id: str,
        execution_id: str,
        preferences: NotificationPreferences | None = None,
        pause_session: bool = False,
        idempotency_key: str,
        correlation_id: str | None = None,
    ) -> ConfigureNotificationsResponse:
        corr_id = correlation_id or generate_correlation_id()
        clean_key = validate_idempotency_key(idempotency_key)
        operation = "configure_notifications"
        payload_hash = compute_payload_hash(
            operation,
            {
                "preferences": (preferences or NotificationPreferences()).model_dump(mode="json"),
                "pause_session": pause_session,
            },
        )

        existing_idemp = self._get_mutation_idemp(execution_id, operation, clean_key, corr_id)
        if existing_idemp is not None:
            verify_or_raise_idempotency_conflict(
                idempotency_key=clean_key,
                operation=operation,
                stored_payload_hash=existing_idemp["payload_hash"]["S"],
                incoming_payload_hash=payload_hash,
            )
            self._post_commit_side_effects(execution_id)
            return build_response_from_outcome(
                existing_idemp["outcome_json"]["S"],
                ConfigureNotificationsOutcome,
                ConfigureNotificationsResponse,
                duplicate=True,
            )

        execution = self.load_execution_metadata(execution_id, correlation_id=corr_id)
        if execution.principal_id != principal_id:
            raise AdapterError(
                ErrorCode.FORBIDDEN,
                f"Principal '{principal_id}' does not own execution '{execution_id}'.",
                correlation_id=corr_id,
            )

        now_iso = utc_now_iso()
        new_execution, outcome = apply_configure_notifications(
            execution=execution,
            preferences=preferences,
            pause_session=pause_session,
            now_iso=now_iso,
        )

        new_version = new_execution.desired_state_version
        audit_event = AuditEvent(
            event_id=generate_event_id("aud"),
            execution_id=execution_id,
            principal_id=principal_id,
            state_version=new_version,
            event_type="NOTIFICATIONS_CONFIGURED",
            details={"pause_session": pause_session},
            correlation_id=corr_id,
            recorded_at=now_iso,
        )
        outbox_record = OutboxRecord(
            execution_id=execution_id,
            target_version=new_version,
            outbox_status=OutboxStatus.PENDING,
            operation=operation,
            snapshot_json=new_execution.model_dump_json(),
            created_at=now_iso,
        )

        client_token = derive_client_request_token(
            principal_id, execution_id, operation, clean_key
        )

        transact_items: list[dict[str, Any]] = [
            {
                "Put": {
                    "TableName": self._table,
                    "Item": self._serialize_metadata_item(new_execution),
                    "ConditionExpression": "desired_state_version = :expected_v AND principal_id = :pid",
                    "ExpressionAttributeValues": {
                        ":expected_v": self._n(execution.desired_state_version),
                        ":pid": self._s(principal_id),
                    },
                }
            },
            {
                "Put": {
                    "TableName": self._table,
                    "Item": self._serialize_principal_exec_item(new_execution),
                }
            },
            {
                "Put": {
                    "TableName": self._table,
                    "Item": {
                        "PK": self._s(f"EXEC#{execution_id}"),
                        "SK": self._s(f"IDEMP#{operation}#{clean_key}"),
                        "item_type": self._s("IDEMP"),
                        "execution_id": self._s(execution_id),
                        "operation": self._s(operation),
                        "idempotency_key": self._s(clean_key),
                        "principal_id": self._s(principal_id),
                        "payload_hash": self._s(payload_hash),
                        "state_version_after": self._n(new_version),
                        "outcome_json": self._s(outcome.model_dump_json()),
                        "created_at": self._s(now_iso),
                    },
                    "ConditionExpression": "attribute_not_exists(PK)",
                }
            },
            {
                "Put": {
                    "TableName": self._table,
                    "Item": {
                        "PK": self._s(f"EXEC#{execution_id}"),
                        "SK": self._s(f"AUDIT#{_pad_ver(new_version)}#{audit_event.event_id}"),
                        "item_type": self._s("AUDIT"),
                        "execution_id": self._s(execution_id),
                        "state_version": self._n(new_version),
                        "event_id": self._s(audit_event.event_id),
                        "principal_id": self._s(principal_id),
                        "event_type": self._s(audit_event.event_type),
                        "audit_json": self._s(audit_event.model_dump_json()),
                        "recorded_at": self._s(now_iso),
                    },
                }
            },
            {
                "Put": {
                    "TableName": self._table,
                    "Item": {
                        "PK": self._s(f"EXEC#{execution_id}"),
                        "SK": self._s(f"OUTBOX#{_pad_ver(new_version)}"),
                        "item_type": self._s("OUTBOX"),
                        "execution_id": self._s(execution_id),
                        "target_version": self._n(new_version),
                        "outbox_status": self._s(OutboxStatus.PENDING.value),
                        "operation": self._s(operation),
                        "snapshot_json": self._s(outbox_record.snapshot_json),
                        "created_at": self._s(now_iso),
                    },
                }
            },
        ]

        # Notification if pause/resume
        if pause_session:
            notification = build_notification_record(
                notification_id=generate_event_id("notif"),
                execution=new_execution,
                event_type=NotificationEventType.ON_PAUSE_INTERRUPTION,
                summary_message=f"Session paused for {new_execution.asset_id}",
                now_iso=now_iso,
            )
            if notification:
                transact_items.append(
                    {
                        "Put": {
                            "TableName": self._table,
                            "Item": {
                                "PK": self._s(f"EXEC#{execution_id}"),
                                "SK": self._s(f"NOTIFY#{_pad_ver(new_version)}#{notification.notification_id}"),
                                "item_type": self._s("NOTIFY"),
                                "notification_id": self._s(notification.notification_id),
                                "execution_id": self._s(execution_id),
                                "principal_id": self._s(principal_id),
                                "state_version": self._n(new_version),
                                "event_type": self._s(notification.event_type.value),
                                "dispatched": self._bool(False),
                                "notification_json": self._s(notification.model_dump_json()),
                                "created_at": self._s(now_iso),
                            },
                        }
                    }
                )

        try:
            self._ddb.transact_write_items(
                TransactItems=transact_items,
                ClientRequestToken=client_token,
            )
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") == "TransactionCanceledException":
                raced_idemp = self._get_mutation_idemp(execution_id, operation, clean_key, corr_id)
                if raced_idemp is not None:
                    verify_or_raise_idempotency_conflict(
                        idempotency_key=clean_key,
                        operation=operation,
                        stored_payload_hash=raced_idemp["payload_hash"]["S"],
                        incoming_payload_hash=payload_hash,
                    )
                    self._post_commit_side_effects(execution_id)
                    return build_response_from_outcome(
                        raced_idemp["outcome_json"]["S"],
                        ConfigureNotificationsOutcome,
                        ConfigureNotificationsResponse,
                        duplicate=True,
                    )
            raise self._map_client_error(exc, corr_id) from exc
        except BotoCoreError as exc:
            raise self._map_client_error(exc, corr_id) from exc

        self._post_commit_side_effects(execution_id)
        return ConfigureNotificationsResponse(**outcome.model_dump(), duplicate=False)

    # ─── complete_inspection ──────────────────────────────────────────────

    def complete_inspection(
        self,
        *,
        principal_id: str,
        execution_id: str,
        idempotency_key: str,
        correlation_id: str | None = None,
    ) -> CompleteInspectionResponse:
        corr_id = correlation_id or generate_correlation_id()
        clean_key = validate_idempotency_key(idempotency_key)
        operation = "complete_inspection"
        payload_hash = compute_payload_hash(operation, {})

        existing_idemp = self._get_mutation_idemp(execution_id, operation, clean_key, corr_id)
        if existing_idemp is not None:
            verify_or_raise_idempotency_conflict(
                idempotency_key=clean_key,
                operation=operation,
                stored_payload_hash=existing_idemp["payload_hash"]["S"],
                incoming_payload_hash=payload_hash,
            )
            self._post_commit_side_effects(execution_id)
            return build_response_from_outcome(
                existing_idemp["outcome_json"]["S"],
                CompleteInspectionOutcome,
                CompleteInspectionResponse,
                duplicate=True,
            )

        execution = self.load_execution_metadata(execution_id, correlation_id=corr_id)
        if execution.principal_id != principal_id:
            raise AdapterError(
                ErrorCode.FORBIDDEN,
                f"Principal '{principal_id}' does not own execution '{execution_id}'.",
                correlation_id=corr_id,
            )

        now_iso = utc_now_iso()
        audit_ref = f"AUDIT-{execution.asset_id}-{execution.execution_id[:8]}"
        new_execution, outcome = apply_complete_inspection(
            execution=execution,
            audit_reference=audit_ref,
            policy=self._policy,
            now_iso=now_iso,
        )

        new_version = new_execution.desired_state_version
        audit_event = AuditEvent(
            event_id=generate_event_id("aud"),
            execution_id=execution_id,
            principal_id=principal_id,
            state_version=new_version,
            event_type="INSPECTION_COMPLETED",
            details={},
            correlation_id=corr_id,
            recorded_at=now_iso,
        )
        outbox_record = OutboxRecord(
            execution_id=execution_id,
            target_version=new_version,
            outbox_status=OutboxStatus.PENDING,
            operation=operation,
            snapshot_json=new_execution.model_dump_json(),
            created_at=now_iso,
        )

        client_token = derive_client_request_token(
            principal_id, execution_id, operation, clean_key
        )

        transact_items: list[dict[str, Any]] = [
            {
                "Put": {
                    "TableName": self._table,
                    "Item": self._serialize_metadata_item(new_execution),
                    "ConditionExpression": "desired_state_version = :expected_v AND principal_id = :pid",
                    "ExpressionAttributeValues": {
                        ":expected_v": self._n(execution.desired_state_version),
                        ":pid": self._s(principal_id),
                    },
                }
            },
            {
                "Put": {
                    "TableName": self._table,
                    "Item": self._serialize_principal_exec_item(new_execution),
                }
            },
            {
                "Put": {
                    "TableName": self._table,
                    "Item": {
                        "PK": self._s(f"EXEC#{execution_id}"),
                        "SK": self._s(f"IDEMP#{operation}#{clean_key}"),
                        "item_type": self._s("IDEMP"),
                        "execution_id": self._s(execution_id),
                        "operation": self._s(operation),
                        "idempotency_key": self._s(clean_key),
                        "principal_id": self._s(principal_id),
                        "payload_hash": self._s(payload_hash),
                        "state_version_after": self._n(new_version),
                        "outcome_json": self._s(outcome.model_dump_json()),
                        "created_at": self._s(now_iso),
                    },
                    "ConditionExpression": "attribute_not_exists(PK)",
                }
            },
            {
                "Put": {
                    "TableName": self._table,
                    "Item": {
                        "PK": self._s(f"EXEC#{execution_id}"),
                        "SK": self._s(f"AUDIT#{_pad_ver(new_version)}#{audit_event.event_id}"),
                        "item_type": self._s("AUDIT"),
                        "execution_id": self._s(execution_id),
                        "state_version": self._n(new_version),
                        "event_id": self._s(audit_event.event_id),
                        "principal_id": self._s(principal_id),
                        "event_type": self._s(audit_event.event_type),
                        "audit_json": self._s(audit_event.model_dump_json()),
                        "recorded_at": self._s(now_iso),
                    },
                }
            },
            {
                "Put": {
                    "TableName": self._table,
                    "Item": {
                        "PK": self._s(f"EXEC#{execution_id}"),
                        "SK": self._s(f"OUTBOX#{_pad_ver(new_version)}"),
                        "item_type": self._s("OUTBOX"),
                        "execution_id": self._s(execution_id),
                        "target_version": self._n(new_version),
                        "outbox_status": self._s(OutboxStatus.PENDING.value),
                        "operation": self._s(operation),
                        "snapshot_json": self._s(outbox_record.snapshot_json),
                        "created_at": self._s(now_iso),
                    },
                }
            },
            # AC17: Delete ASSET_LOCK atomically on complete
            {
                "Delete": {
                    "TableName": self._table,
                    "Key": {
                        "PK": self._s(f"ASSET#{execution.asset_id}"),
                        "SK": self._s("ACTIVE_LOCK"),
                    },
                    "ConditionExpression": "execution_id = :eid",
                    "ExpressionAttributeValues": {
                        ":eid": self._s(execution_id),
                    },
                }
            },
        ]

        # Notification for completion
        notification = build_notification_record(
            notification_id=generate_event_id("notif"),
            execution=new_execution,
            event_type=NotificationEventType.ON_INSPECTION_COMPLETED,
            summary_message=f"Inspection completed for {new_execution.asset_id}",
            now_iso=now_iso,
        )
        if notification:
            transact_items.append(
                {
                    "Put": {
                        "TableName": self._table,
                        "Item": {
                            "PK": self._s(f"EXEC#{execution_id}"),
                            "SK": self._s(f"NOTIFY#{_pad_ver(new_version)}#{notification.notification_id}"),
                            "item_type": self._s("NOTIFY"),
                            "notification_id": self._s(notification.notification_id),
                            "execution_id": self._s(execution_id),
                            "principal_id": self._s(principal_id),
                            "state_version": self._n(new_version),
                            "event_type": self._s(notification.event_type.value),
                            "dispatched": self._bool(False),
                            "notification_json": self._s(notification.model_dump_json()),
                            "created_at": self._s(now_iso),
                        },
                    }
                }
            )

        try:
            self._ddb.transact_write_items(
                TransactItems=transact_items,
                ClientRequestToken=client_token,
            )
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") == "TransactionCanceledException":
                raced_idemp = self._get_mutation_idemp(execution_id, operation, clean_key, corr_id)
                if raced_idemp is not None:
                    verify_or_raise_idempotency_conflict(
                        idempotency_key=clean_key,
                        operation=operation,
                        stored_payload_hash=raced_idemp["payload_hash"]["S"],
                        incoming_payload_hash=payload_hash,
                    )
                    self._post_commit_side_effects(execution_id)
                    return build_response_from_outcome(
                        raced_idemp["outcome_json"]["S"],
                        CompleteInspectionOutcome,
                        CompleteInspectionResponse,
                        duplicate=True,
                    )
            raise self._map_client_error(exc, corr_id) from exc
        except BotoCoreError as exc:
            raise self._map_client_error(exc, corr_id) from exc

        self._post_commit_side_effects(execution_id)
        return CompleteInspectionResponse(**outcome.model_dump(), duplicate=False)

    # ─── Read-Only Queries ────────────────────────────────────────────────

    def list_active_executions(self, *, principal_id: str) -> list[ExecutionBrief]:
        """Strongly consistent principal-scoped query for active executions."""
        corr_id = generate_correlation_id()
        try:
            resp = self._ddb.query(
                TableName=self._table,
                KeyConditionExpression="PK = :pk AND begins_with(SK, :prefix)",
                ExpressionAttributeValues={
                    ":pk": self._s(f"PRINCIPAL#{principal_id}"),
                    ":prefix": self._s("EXEC#"),
                },
                ConsistentRead=True,
            )
        except (ClientError, BotoCoreError) as exc:
            raise self._map_client_error(exc, corr_id) from exc

        briefs: list[ExecutionBrief] = []
        for item in resp.get("Items", []):
            status_str = item.get("status", {}).get("S", "")
            try:
                status = WorkflowStatus(status_str)
            except ValueError:
                continue
            briefs.append(
                ExecutionBrief(
                    execution_id=item["execution_id"]["S"],
                    asset_id=item["asset_id"]["S"],
                    inspection_type=item["inspection_type"]["S"],
                    status=status,
                    pending_step_id=item.get("pending_step_id", {}).get("S") or None,
                    session_paused=item.get("session_paused", {}).get("BOOL", False),
                    updated_at=item.get("updated_at", {}).get("S", ""),
                )
            )
        return briefs

    def get_audit_trail(self, *, principal_id: str, execution_id: str) -> list[AuditEvent]:
        corr_id = generate_correlation_id()
        # Verify ownership
        execution = self.load_execution_metadata(execution_id, correlation_id=corr_id)
        if execution.principal_id != principal_id:
            raise AdapterError(
                ErrorCode.FORBIDDEN,
                f"Principal '{principal_id}' does not own execution '{execution_id}'.",
                correlation_id=corr_id,
            )

        try:
            resp = self._ddb.query(
                TableName=self._table,
                KeyConditionExpression="PK = :pk AND begins_with(SK, :prefix)",
                ExpressionAttributeValues={
                    ":pk": self._s(f"EXEC#{execution_id}"),
                    ":prefix": self._s("AUDIT#"),
                },
                ConsistentRead=True,
            )
        except (ClientError, BotoCoreError) as exc:
            raise self._map_client_error(exc, corr_id) from exc

        events: list[AuditEvent] = []
        for item in resp.get("Items", []):
            raw = item.get("audit_json", {}).get("S")
            if raw:
                with contextlib.suppress(Exception):
                    events.append(AuditEvent.model_validate_json(raw))
        return events

    def get_outbox_records(self, *, principal_id: str, execution_id: str) -> list[OutboxRecord]:
        corr_id = generate_correlation_id()
        execution = self.load_execution_metadata(execution_id, correlation_id=corr_id)
        if execution.principal_id != principal_id:
            raise AdapterError(
                ErrorCode.FORBIDDEN,
                f"Principal '{principal_id}' does not own execution '{execution_id}'.",
                correlation_id=corr_id,
            )

        try:
            resp = self._ddb.query(
                TableName=self._table,
                KeyConditionExpression="PK = :pk AND begins_with(SK, :prefix)",
                ExpressionAttributeValues={
                    ":pk": self._s(f"EXEC#{execution_id}"),
                    ":prefix": self._s("OUTBOX#"),
                },
                ConsistentRead=True,
            )
        except (ClientError, BotoCoreError) as exc:
            raise self._map_client_error(exc, corr_id) from exc

        records: list[OutboxRecord] = []
        for item in resp.get("Items", []):
            with contextlib.suppress(Exception):
                records.append(
                    OutboxRecord(
                        execution_id=item["execution_id"]["S"],
                        target_version=int(item["target_version"]["N"]),
                        outbox_status=OutboxStatus(item["outbox_status"]["S"]),
                        operation=item["operation"]["S"],
                        snapshot_json=item.get("snapshot_json", {}).get("S", "{}"),
                        created_at=item.get("created_at", {}).get("S", ""),
                        acked_at=item.get("acked_at", {}).get("S") or None,
                        acked_by_version=int(item["acked_by_version"]["N"]) if item.get("acked_by_version", {}).get("N") else None,
                        acked_by_exec_arn=item.get("acked_by_exec_arn", {}).get("S") or None,
                    )
                )
        return records

    def get_notifications(
        self, *, principal_id: str, execution_id: str
    ) -> list[NotificationRecord]:
        corr_id = generate_correlation_id()
        # Skip ownership check for __system__ internal calls
        if principal_id != "__system__":
            execution = self.load_execution_metadata(execution_id, correlation_id=corr_id)
            if execution.principal_id != principal_id:
                raise AdapterError(
                    ErrorCode.FORBIDDEN,
                    f"Principal '{principal_id}' does not own execution '{execution_id}'.",
                    correlation_id=corr_id,
                )

        try:
            resp = self._ddb.query(
                TableName=self._table,
                KeyConditionExpression="PK = :pk AND begins_with(SK, :prefix)",
                ExpressionAttributeValues={
                    ":pk": self._s(f"EXEC#{execution_id}"),
                    ":prefix": self._s("NOTIFY#"),
                },
                ConsistentRead=True,
            )
        except (ClientError, BotoCoreError) as exc:
            raise self._map_client_error(exc, corr_id) from exc

        records: list[NotificationRecord] = []
        for item in resp.get("Items", []):
            raw = item.get("notification_json", {}).get("S")
            if raw:
                with contextlib.suppress(Exception):
                    records.append(NotificationRecord.model_validate_json(raw))
        return records

    # ─── Helper: Emit a single notification item ──────────────────────────

    def _emit_notification_item(
        self, execution: WorkflowExecution, notification: NotificationRecord, corr_id: str
    ) -> None:
        """Write a single NOTIFY item outside a transaction (best-effort for status checks)."""
        try:
            self._ddb.put_item(
                TableName=self._table,
                Item={
                    "PK": self._s(f"EXEC#{execution.execution_id}"),
                    "SK": self._s(f"NOTIFY#{_pad_ver(execution.desired_state_version)}#{notification.notification_id}"),
                    "item_type": self._s("NOTIFY"),
                    "notification_id": self._s(notification.notification_id),
                    "execution_id": self._s(execution.execution_id),
                    "principal_id": self._s(execution.principal_id),
                    "state_version": self._n(execution.desired_state_version),
                    "event_type": self._s(notification.event_type.value),
                    "dispatched": self._bool(False),
                    "notification_json": self._s(notification.model_dump_json()),
                    "created_at": self._s(notification.created_at),
                },
            )
        except Exception:
            logger.debug("Failed to emit notification item", exc_info=True)
