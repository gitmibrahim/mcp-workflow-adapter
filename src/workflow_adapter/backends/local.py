from __future__ import annotations

import json
import logging
import sqlite3
import threading
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any

from pydantic import ValidationError

from workflow_adapter.errors import AdapterError, ErrorCode, generate_correlation_id
from workflow_adapter.idempotency import (
    build_response_from_outcome,
    compute_payload_hash,
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

SCHEMA_DDL = """
CREATE TABLE IF NOT EXISTS schema_migrations (
    version INTEGER PRIMARY KEY,
    applied_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS start_idempotency (
    principal_id TEXT NOT NULL,
    idempotency_key TEXT NOT NULL,
    payload_hash TEXT NOT NULL,
    execution_id TEXT NOT NULL,
    outcome_json TEXT NOT NULL,
    created_at TEXT NOT NULL,
    PRIMARY KEY (principal_id, idempotency_key)
);

CREATE TABLE IF NOT EXISTS asset_locks (
    asset_id TEXT PRIMARY KEY,
    execution_id TEXT NOT NULL UNIQUE,
    principal_id TEXT NOT NULL,
    inspection_type TEXT NOT NULL,
    acquired_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS executions (
    execution_id TEXT PRIMARY KEY,
    principal_id TEXT NOT NULL,
    inspection_type TEXT NOT NULL,
    asset_id TEXT NOT NULL,
    status TEXT NOT NULL,
    desired_state_version INTEGER NOT NULL,
    pending_step_id TEXT,
    session_paused INTEGER NOT NULL DEFAULT 0,
    execution_json TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_executions_principal_status_updated
    ON executions (principal_id, status, updated_at DESC, execution_id ASC);

CREATE INDEX IF NOT EXISTS idx_executions_principal_asset_updated
    ON executions (principal_id, asset_id, updated_at DESC, execution_id ASC);

CREATE TABLE IF NOT EXISTS mutation_idempotency (
    execution_id TEXT NOT NULL,
    operation TEXT NOT NULL,
    idempotency_key TEXT NOT NULL,
    principal_id TEXT NOT NULL,
    payload_hash TEXT NOT NULL,
    state_version_after INTEGER NOT NULL,
    outcome_json TEXT NOT NULL,
    created_at TEXT NOT NULL,
    PRIMARY KEY (execution_id, operation, idempotency_key)
);

CREATE TABLE IF NOT EXISTS audit_events (
    execution_id TEXT NOT NULL,
    state_version INTEGER NOT NULL,
    event_id TEXT NOT NULL,
    principal_id TEXT NOT NULL,
    event_type TEXT NOT NULL,
    audit_json TEXT NOT NULL,
    recorded_at TEXT NOT NULL,
    PRIMARY KEY (execution_id, state_version, event_id)
);

CREATE TABLE IF NOT EXISTS outbox_events (
    execution_id TEXT NOT NULL,
    target_version INTEGER NOT NULL,
    outbox_status TEXT NOT NULL,
    operation TEXT NOT NULL,
    snapshot_json TEXT NOT NULL,
    created_at TEXT NOT NULL,
    acked_at TEXT,
    acked_by_version INTEGER,
    acked_by_exec_arn TEXT,
    PRIMARY KEY (execution_id, target_version)
);

CREATE TABLE IF NOT EXISTS notification_outbox (
    notification_id TEXT PRIMARY KEY,
    execution_id TEXT NOT NULL,
    principal_id TEXT NOT NULL,
    state_version INTEGER NOT NULL,
    event_type TEXT NOT NULL,
    dispatched INTEGER NOT NULL DEFAULT 0,
    notification_json TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_notification_outbox_exec_version
    ON notification_outbox (execution_id, state_version ASC, created_at ASC);
"""


class InMemoryNotificationSink(NotificationPort):
    """Thread-safe local NotificationPort implementation with fault injection."""

    def __init__(self, *, fail_next_n: int = 0) -> None:
        self._lock = threading.Lock()
        self._delivered: list[NotificationRecord] = []
        self._delivered_ids: set[str] = set()
        self._fail_remaining: int = fail_next_n

    def set_fail_next_n(self, count: int) -> None:
        with self._lock:
            self._fail_remaining = max(0, count)

    def dispatch(self, record: NotificationRecord) -> bool:
        with self._lock:
            if self._fail_remaining > 0:
                self._fail_remaining -= 1
                return False
            if record.notification_id not in self._delivered_ids:
                self._delivered.append(record.model_copy(update={"dispatched": True}))
                self._delivered_ids.add(record.notification_id)
            return True

    @property
    def delivered_records(self) -> list[NotificationRecord]:
        with self._lock:
            return list(self._delivered)

    def clear(self) -> None:
        with self._lock:
            self._delivered.clear()
            self._delivered_ids.clear()
            self._fail_remaining = 0


class LocalBackend(StorageBackendPort):
    """File-backed SQLite WAL persistence backend with atomic BEGIN IMMEDIATE transactions."""

    def __init__(
        self,
        db_path: str | Path,
        policy: DomainPolicyPort,
        *,
        notification_port: NotificationPort | None = None,
        orchestrator_port: OrchestratorPort | None = None,
        busy_timeout_ms: int = 5000,
    ) -> None:
        self._db_path = Path(db_path).expanduser().resolve()
        self._db_path.parent.mkdir(parents=True, exist_ok=True)
        self._policy = policy
        self._notification_port = notification_port
        self._orchestrator_port = orchestrator_port
        self._busy_timeout_ms = busy_timeout_ms
        self._simulate_unavailable: bool = False
        self._init_schema()

    @property
    def db_path(self) -> Path:
        return self._db_path

    def set_simulate_unavailable(self, unavailable: bool) -> None:
        """Fault-injection hook for testing BACKEND_UNAVAILABLE isolation."""
        self._simulate_unavailable = unavailable

    def _open_connection(self) -> sqlite3.Connection:
        if self._simulate_unavailable:
            raise AdapterError(
                ErrorCode.BACKEND_UNAVAILABLE,
                "Simulated local storage unavailability.",
                retryable=True,
            )
        try:
            conn = sqlite3.connect(
                str(self._db_path),
                timeout=max(0.1, self._busy_timeout_ms / 1000.0),
                isolation_level=None,
                check_same_thread=False,
            )
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA journal_mode=WAL;")
            conn.execute("PRAGMA synchronous=NORMAL;")
            conn.execute("PRAGMA foreign_keys=ON;")
            conn.execute(f"PRAGMA busy_timeout={int(self._busy_timeout_ms)};")
            return conn
        except sqlite3.Error as exc:
            raise AdapterError(
                ErrorCode.BACKEND_UNAVAILABLE,
                f"Failed to open SQLite WAL database: {exc}",
                retryable=True,
            ) from exc

    @contextmanager
    def _write_transaction(self, correlation_id: str) -> Iterator[sqlite3.Connection]:
        conn = self._open_connection()
        try:
            conn.execute("BEGIN IMMEDIATE;")
            yield conn
            if conn.in_transaction:
                conn.execute("COMMIT;")
        except AdapterError:
            self._safe_rollback(conn)
            raise
        except sqlite3.OperationalError as exc:
            self._safe_rollback(conn)
            raise AdapterError(
                ErrorCode.BACKEND_UNAVAILABLE,
                f"SQLite transaction lock or operational timeout: {exc}",
                retryable=True,
                correlation_id=correlation_id,
            ) from exc
        except sqlite3.Error as exc:
            self._safe_rollback(conn)
            raise AdapterError(
                ErrorCode.BACKEND_UNAVAILABLE,
                f"SQLite storage error during transaction: {exc}",
                retryable=True,
                correlation_id=correlation_id,
            ) from exc
        finally:
            conn.close()

    @contextmanager
    def _read_connection(self, correlation_id: str) -> Iterator[sqlite3.Connection]:
        conn = self._open_connection()
        try:
            yield conn
        except AdapterError:
            raise
        except sqlite3.Error as exc:
            raise AdapterError(
                ErrorCode.BACKEND_UNAVAILABLE,
                f"SQLite read error: {exc}",
                retryable=True,
                correlation_id=correlation_id,
            ) from exc
        finally:
            conn.close()

    @staticmethod
    def _safe_rollback(conn: sqlite3.Connection) -> None:
        try:
            if conn.in_transaction:
                conn.execute("ROLLBACK;")
        except sqlite3.Error:
            pass

    def _init_schema(self) -> None:
        conn = self._open_connection()
        try:
            conn.executescript(SCHEMA_DDL)
            conn.execute(
                "INSERT OR IGNORE INTO schema_migrations (version, applied_at) VALUES (1, ?);",
                (utc_now_iso(),),
            )
        finally:
            conn.close()

    @staticmethod
    def _deserialize_execution(raw_json: str, correlation_id: str) -> WorkflowExecution:
        try:
            return WorkflowExecution.model_validate_json(raw_json)
        except (ValidationError, ValueError, json.JSONDecodeError) as exc:
            raise AdapterError(
                ErrorCode.INTERNAL_ERROR,
                "Persisted workflow record failed integrity validation.",
                retryable=False,
                correlation_id=correlation_id,
            ) from exc

    def _load_execution_in_tx(
        self, conn: sqlite3.Connection, execution_id: str, correlation_id: str
    ) -> WorkflowExecution:
        row = conn.execute(
            "SELECT execution_json FROM executions WHERE execution_id = ?;",
            (execution_id,),
        ).fetchone()
        if row is None:
            raise AdapterError(
                ErrorCode.NOT_FOUND,
                f"Workflow execution '{execution_id}' not found.",
                correlation_id=correlation_id,
            )
        return self._deserialize_execution(str(row["execution_json"]), correlation_id)

    def _flush_pending_notifications(self, execution_id: str) -> None:
        """Deliver queued outbox notifications outside the main transaction without raising."""
        if self._notification_port is None:
            return
        corr_id = generate_correlation_id()
        try:
            with self._open_connection() as conn:
                rows = conn.execute(
                    "SELECT notification_id, notification_json FROM notification_outbox "
                    "WHERE execution_id = ? AND dispatched = 0 ORDER BY state_version ASC, created_at ASC;",
                    (execution_id,),
                ).fetchall()
                for row in rows:
                    notif_id = str(row["notification_id"])
                    try:
                        record = NotificationRecord.model_validate_json(row["notification_json"])
                        success = self._notification_port.dispatch(record)
                        if success:
                            conn.execute(
                                "UPDATE notification_outbox SET dispatched = 1 WHERE notification_id = ?;",
                                (notif_id,),
                            )
                    except Exception as exc:  # noqa: BLE001
                        logger.warning(
                            "Failed to dispatch notification %s for execution %s: %s",
                            notif_id,
                            execution_id,
                            exc,
                        )
        except Exception as exc:  # noqa: BLE001
            logger.warning(
                "Error during notification outbox flush: %s", exc, extra={"correlation_id": corr_id}
            )

    def _resolve_target_execution(
        self,
        conn: sqlite3.Connection,
        principal_id: str,
        execution_id: str | None,
        asset_id: str | None,
        correlation_id: str,
    ) -> WorkflowExecution:
        # Case A: execution_id provided
        if execution_id:
            execution = self._load_execution_in_tx(conn, execution_id, correlation_id)
            if execution.principal_id != principal_id:
                raise AdapterError(
                    ErrorCode.FORBIDDEN,
                    "Principal does not own this execution.",
                    correlation_id=correlation_id,
                )
            if asset_id and execution.asset_id != asset_id:
                raise AdapterError(
                    ErrorCode.INVALID_INPUT,
                    f"Execution '{execution_id}' is for asset '{execution.asset_id}', not '{asset_id}'.",
                    correlation_id=correlation_id,
                )
            return execution

        # Case B: asset_id provided, execution_id is None
        if asset_id:
            rows = conn.execute(
                "SELECT execution_json FROM executions "
                "WHERE principal_id = ? AND asset_id = ? AND status IN ('RUNNING', 'BLOCKED') "
                "ORDER BY updated_at DESC, execution_id ASC;",
                (principal_id, asset_id),
            ).fetchall()
            if rows:
                return self._deserialize_execution(str(rows[0]["execution_json"]), correlation_id)

            # Check if any execution exists for asset
            prior_rows = conn.execute(
                "SELECT execution_id FROM executions WHERE principal_id = ? AND asset_id = ?;",
                (principal_id, asset_id),
            ).fetchall()
            if prior_rows:
                raise AdapterError(
                    ErrorCode.NOT_FOUND,
                    f"No active workflow execution for asset '{asset_id}'. Prior executions are completed.",
                    correlation_id=correlation_id,
                )
            raise AdapterError(
                ErrorCode.NOT_FOUND,
                f"No workflow execution found for asset '{asset_id}'.",
                correlation_id=correlation_id,
            )

        # Case C: Neither execution_id nor asset_id provided
        active_rows = conn.execute(
            "SELECT execution_id, asset_id, inspection_type, status, pending_step_id, session_paused, updated_at, execution_json "
            "FROM executions WHERE principal_id = ? AND status IN ('RUNNING', 'BLOCKED') "
            "ORDER BY updated_at DESC, execution_id ASC;",
            (principal_id,),
        ).fetchall()

        if not active_rows:
            raise AdapterError(
                ErrorCode.NOT_FOUND,
                "No active workflow execution found for principal.",
                correlation_id=correlation_id,
                details={"reason": "NO_ACTIVE_EXECUTION_FOR_PRINCIPAL"},
            )
        if len(active_rows) == 1:
            return self._deserialize_execution(
                str(active_rows[0]["execution_json"]), correlation_id
            )

        # Ambiguous multiple active sessions
        active_briefs = [
            ExecutionBrief(
                execution_id=str(r["execution_id"]),
                asset_id=str(r["asset_id"]),
                inspection_type=str(r["inspection_type"]),
                status=WorkflowStatus(r["status"]),
                pending_step_id=r["pending_step_id"],
                session_paused=bool(r["session_paused"]),
                updated_at=str(r["updated_at"]),
            ).model_dump()
            for r in active_rows
        ]
        raise AdapterError(
            ErrorCode.INVALID_INPUT,
            "Multiple active workflow executions found. Please specify an execution_id or asset_id.",
            correlation_id=correlation_id,
            details={
                "reason": "AMBIGUOUS_ACTIVE_SESSION",
                "active_count": len(active_briefs),
                "active_executions": active_briefs,
            },
        )

    # -------------------------------------------------------------------------
    # StorageBackendPort Implementation
    # -------------------------------------------------------------------------

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
        valid_key = validate_idempotency_key(idempotency_key)
        prefs = notification_prefs or NotificationPreferences()

        payload_hash = compute_payload_hash(
            "start_inspection",
            {
                "inspection_type": inspection_type,
                "asset_id": asset_id,
                "notification_prefs": prefs,
            },
        )

        with self._write_transaction(corr_id) as conn:
            # 1. Start Idempotency Check
            idemp_row = conn.execute(
                "SELECT payload_hash, execution_id, outcome_json FROM start_idempotency "
                "WHERE principal_id = ? AND idempotency_key = ?;",
                (principal_id, valid_key),
            ).fetchone()
            if idemp_row is not None:
                verify_or_raise_idempotency_conflict(
                    idempotency_key=valid_key,
                    operation="start_inspection",
                    stored_payload_hash=str(idemp_row["payload_hash"]),
                    incoming_payload_hash=payload_hash,
                )
                self._flush_pending_notifications(str(idemp_row["execution_id"]))
                return build_response_from_outcome(
                    str(idemp_row["outcome_json"]),
                    StartInspectionOutcome,
                    StartInspectionResponse,
                    duplicate=True,
                )

            # 2. Domain Asset & Type Validation
            self._policy.validate_asset_and_type(inspection_type, asset_id)

            # 3. Active Asset Exclusivity Lock Check
            lock_row = conn.execute(
                "SELECT execution_id, principal_id FROM asset_locks WHERE asset_id = ?;",
                (asset_id,),
            ).fetchone()
            if lock_row is not None:
                owned_by_caller = str(lock_row["principal_id"]) == principal_id
                details: dict[str, Any] = {
                    "reason": "ASSET_ALREADY_UNDER_INSPECTION",
                    "asset_id": asset_id,
                    "owned_by_caller": owned_by_caller,
                }
                if owned_by_caller:
                    details["active_execution_id"] = str(lock_row["execution_id"])
                    msg = (
                        f"Asset '{asset_id}' already has an active workflow execution ({lock_row['execution_id']}). "
                        "Resume or complete the existing execution before starting a new one."
                    )
                else:
                    msg = f"Asset '{asset_id}' is currently locked by another active workflow execution."
                raise AdapterError(
                    ErrorCode.INVALID_STATE_TRANSITION,
                    msg,
                    retryable=False,
                    correlation_id=corr_id,
                    details=details,
                )

            # 4. Generate New Execution State
            exec_id = generate_execution_id()
            now_iso = utc_now_iso()
            execution, outcome = create_initial_execution(
                execution_id=exec_id,
                principal_id=principal_id,
                inspection_type=inspection_type,
                asset_id=asset_id,
                policy=self._policy,
                notification_prefs=prefs,
                now_iso=now_iso,
            )

            # 5. Insert Records
            conn.execute(
                "INSERT INTO executions (execution_id, principal_id, inspection_type, asset_id, status, "
                "desired_state_version, pending_step_id, session_paused, execution_json, created_at, updated_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);",
                (
                    exec_id,
                    principal_id,
                    inspection_type,
                    asset_id,
                    execution.status.value,
                    execution.desired_state_version,
                    execution.pending_step_id,
                    1 if execution.session_paused else 0,
                    execution.model_dump_json(),
                    now_iso,
                    now_iso,
                ),
            )
            conn.execute(
                "INSERT INTO asset_locks (asset_id, execution_id, principal_id, inspection_type, acquired_at) "
                "VALUES (?, ?, ?, ?, ?);",
                (asset_id, exec_id, principal_id, inspection_type, now_iso),
            )
            conn.execute(
                "INSERT INTO start_idempotency (principal_id, idempotency_key, payload_hash, execution_id, outcome_json, created_at) "
                "VALUES (?, ?, ?, ?, ?, ?);",
                (
                    principal_id,
                    valid_key,
                    payload_hash,
                    exec_id,
                    outcome.model_dump_json(),
                    now_iso,
                ),
            )

            audit_evt = AuditEvent(
                event_id=generate_event_id("audit"),
                execution_id=exec_id,
                principal_id=principal_id,
                state_version=1,
                event_type="WORKFLOW_STARTED",
                step_id=None,
                details={"asset_id": asset_id, "inspection_type": inspection_type},
                correlation_id=corr_id,
                recorded_at=now_iso,
            )
            conn.execute(
                "INSERT INTO audit_events (execution_id, state_version, event_id, principal_id, event_type, audit_json, recorded_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?);",
                (
                    exec_id,
                    1,
                    audit_evt.event_id,
                    principal_id,
                    audit_evt.event_type,
                    audit_evt.model_dump_json(),
                    now_iso,
                ),
            )

            outbox_rec = OutboxRecord(
                execution_id=exec_id,
                target_version=1,
                outbox_status=OutboxStatus.PENDING,
                operation="start_inspection",
                snapshot_json=execution.model_dump_json(),
                created_at=now_iso,
            )
            conn.execute(
                "INSERT INTO outbox_events (execution_id, target_version, outbox_status, operation, snapshot_json, created_at) "
                "VALUES (?, ?, ?, ?, ?, ?);",
                (
                    exec_id,
                    1,
                    outbox_rec.outbox_status.value,
                    outbox_rec.operation,
                    outbox_rec.snapshot_json,
                    now_iso,
                ),
            )

        self._flush_pending_notifications(exec_id)
        if self._orchestrator_port:
            self._orchestrator_port.reconcile_execution(exec_id)

        data = outcome.model_dump()
        data["duplicate"] = False
        return StartInspectionResponse.model_validate(data)

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
        with self._open_connection() as conn:
            execution = self._resolve_target_execution(
                conn, principal_id, execution_id, asset_id, corr_id
            )

            if emit_notification and execution.notification_prefs.is_enabled_for(
                NotificationEventType.ON_STATUS_REQUESTED
            ):
                now_iso = utc_now_iso()
                notif = build_notification_record(
                    notification_id=generate_event_id("notif"),
                    execution=execution,
                    event_type=NotificationEventType.ON_STATUS_REQUESTED,
                    summary_message=f"Status snapshot requested for {execution.asset_id}.",
                    now_iso=now_iso,
                )
                if notif:
                    conn.execute(
                        "INSERT OR IGNORE INTO notification_outbox "
                        "(notification_id, execution_id, principal_id, state_version, event_type, dispatched, notification_json, created_at) "
                        "VALUES (?, ?, ?, ?, ?, 0, ?, ?);",
                        (
                            notif.notification_id,
                            execution.execution_id,
                            principal_id,
                            notif.state_version,
                            notif.event_type.value,
                            notif.model_dump_json(),
                            now_iso,
                        ),
                    )

        if emit_notification:
            self._flush_pending_notifications(execution.execution_id)

        return build_status_response(execution, self._policy)

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
        valid_key = validate_idempotency_key(idempotency_key)
        op_name = "record_inspection_result"
        payload_hash = compute_payload_hash(
            op_name, {"step_id": step_id, "value": value, "unit": unit}
        )

        with self._write_transaction(corr_id) as conn:
            execution = self._load_execution_in_tx(conn, execution_id, corr_id)
            if execution.principal_id != principal_id:
                raise AdapterError(
                    ErrorCode.FORBIDDEN,
                    "Principal does not own this execution.",
                    correlation_id=corr_id,
                )

            # Idempotency replay check
            idemp_row = conn.execute(
                "SELECT payload_hash, outcome_json FROM mutation_idempotency "
                "WHERE execution_id = ? AND operation = ? AND idempotency_key = ?;",
                (execution_id, op_name, valid_key),
            ).fetchone()
            if idemp_row is not None:
                verify_or_raise_idempotency_conflict(
                    idempotency_key=valid_key,
                    operation=op_name,
                    stored_payload_hash=str(idemp_row["payload_hash"]),
                    incoming_payload_hash=payload_hash,
                )
                self._flush_pending_notifications(execution_id)
                return build_response_from_outcome(
                    str(idemp_row["outcome_json"]),
                    RecordResultOutcome,
                    RecordResultResponse,
                    duplicate=True,
                )

            now_iso = utc_now_iso()
            new_exc_id = generate_exception_id()
            updated_execution, outcome = apply_record_reading(
                execution=execution,
                step_id=step_id,
                value=value,
                unit=unit,
                policy=self._policy,
                new_exception_id=new_exc_id,
                now_iso=now_iso,
            )

            # Commit updated execution with optimistic version check
            cur = conn.execute(
                "UPDATE executions SET status = ?, desired_state_version = ?, pending_step_id = ?, "
                "session_paused = ?, execution_json = ?, updated_at = ? "
                "WHERE execution_id = ? AND desired_state_version = ?;",
                (
                    updated_execution.status.value,
                    updated_execution.desired_state_version,
                    updated_execution.pending_step_id,
                    1 if updated_execution.session_paused else 0,
                    updated_execution.model_dump_json(),
                    now_iso,
                    execution_id,
                    execution.desired_state_version,
                ),
            )
            if cur.rowcount == 0:
                raise AdapterError(
                    ErrorCode.BACKEND_UNAVAILABLE,
                    "Optimistic concurrency conflict while updating execution.",
                    retryable=True,
                    correlation_id=corr_id,
                )

            # Record mutation idempotency
            conn.execute(
                "INSERT INTO mutation_idempotency "
                "(execution_id, operation, idempotency_key, principal_id, payload_hash, state_version_after, outcome_json, created_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?);",
                (
                    execution_id,
                    op_name,
                    valid_key,
                    principal_id,
                    payload_hash,
                    updated_execution.desired_state_version,
                    outcome.model_dump_json(),
                    now_iso,
                ),
            )

            # Audit event
            audit_evt = AuditEvent(
                event_id=generate_event_id("audit"),
                execution_id=execution_id,
                principal_id=principal_id,
                state_version=updated_execution.desired_state_version,
                event_type="READING_RECORDED",
                step_id=step_id,
                details={"value": value, "unit": unit, "accepted": outcome.accepted},
                correlation_id=corr_id,
                recorded_at=now_iso,
            )
            conn.execute(
                "INSERT INTO audit_events (execution_id, state_version, event_id, principal_id, event_type, audit_json, recorded_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?);",
                (
                    execution_id,
                    updated_execution.desired_state_version,
                    audit_evt.event_id,
                    principal_id,
                    audit_evt.event_type,
                    audit_evt.model_dump_json(),
                    now_iso,
                ),
            )

            # Outbox event
            outbox_rec = OutboxRecord(
                execution_id=execution_id,
                target_version=updated_execution.desired_state_version,
                outbox_status=OutboxStatus.PENDING,
                operation=op_name,
                snapshot_json=updated_execution.model_dump_json(),
                created_at=now_iso,
            )
            conn.execute(
                "INSERT INTO outbox_events (execution_id, target_version, outbox_status, operation, snapshot_json, created_at) "
                "VALUES (?, ?, ?, ?, ?, ?);",
                (
                    execution_id,
                    outbox_rec.target_version,
                    outbox_rec.outbox_status.value,
                    outbox_rec.operation,
                    outbox_rec.snapshot_json,
                    now_iso,
                ),
            )

            # Notification outbox
            if outcome.notification_queued:
                event_type = (
                    NotificationEventType.ON_STEP_REVISION
                    if outcome.accepted
                    else NotificationEventType.ON_EXCEPTION_BLOCKED
                )
                msg = (
                    f"Step '{step_id}' accepted."
                    if outcome.accepted
                    else f"Step '{step_id}' blocked."
                )
                notif = build_notification_record(
                    notification_id=generate_event_id("notif"),
                    execution=updated_execution,
                    event_type=event_type,
                    summary_message=msg,
                    now_iso=now_iso,
                )
                if notif:
                    conn.execute(
                        "INSERT INTO notification_outbox "
                        "(notification_id, execution_id, principal_id, state_version, event_type, dispatched, notification_json, created_at) "
                        "VALUES (?, ?, ?, ?, ?, 0, ?, ?);",
                        (
                            notif.notification_id,
                            execution_id,
                            principal_id,
                            notif.state_version,
                            notif.event_type.value,
                            notif.model_dump_json(),
                            now_iso,
                        ),
                    )

        self._flush_pending_notifications(execution_id)
        if self._orchestrator_port:
            self._orchestrator_port.reconcile_execution(execution_id)

        data = outcome.model_dump()
        data["duplicate"] = False
        return RecordResultResponse.model_validate(data)

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
        valid_key = validate_idempotency_key(idempotency_key)
        op_name = "resolve_inspection_exception"
        payload_hash = compute_payload_hash(
            op_name, {"exception_id": exception_id, "resolution": resolution}
        )

        with self._write_transaction(corr_id) as conn:
            execution = self._load_execution_in_tx(conn, execution_id, corr_id)
            if execution.principal_id != principal_id:
                raise AdapterError(
                    ErrorCode.FORBIDDEN,
                    "Principal does not own this execution.",
                    correlation_id=corr_id,
                )

            idemp_row = conn.execute(
                "SELECT payload_hash, outcome_json FROM mutation_idempotency "
                "WHERE execution_id = ? AND operation = ? AND idempotency_key = ?;",
                (execution_id, op_name, valid_key),
            ).fetchone()
            if idemp_row is not None:
                verify_or_raise_idempotency_conflict(
                    idempotency_key=valid_key,
                    operation=op_name,
                    stored_payload_hash=str(idemp_row["payload_hash"]),
                    incoming_payload_hash=payload_hash,
                )
                self._flush_pending_notifications(execution_id)
                return build_response_from_outcome(
                    str(idemp_row["outcome_json"]),
                    ResolveExceptionOutcome,
                    ResolveExceptionResponse,
                    duplicate=True,
                )

            now_iso = utc_now_iso()
            updated_execution, outcome = apply_resolve_exception(
                execution=execution,
                exception_id=exception_id,
                resolution=resolution,
                policy=self._policy,
                now_iso=now_iso,
            )

            cur = conn.execute(
                "UPDATE executions SET status = ?, desired_state_version = ?, pending_step_id = ?, "
                "session_paused = ?, execution_json = ?, updated_at = ? "
                "WHERE execution_id = ? AND desired_state_version = ?;",
                (
                    updated_execution.status.value,
                    updated_execution.desired_state_version,
                    updated_execution.pending_step_id,
                    1 if updated_execution.session_paused else 0,
                    updated_execution.model_dump_json(),
                    now_iso,
                    execution_id,
                    execution.desired_state_version,
                ),
            )
            if cur.rowcount == 0:
                raise AdapterError(
                    ErrorCode.BACKEND_UNAVAILABLE,
                    "Optimistic concurrency conflict while resolving exception.",
                    retryable=True,
                    correlation_id=corr_id,
                )

            conn.execute(
                "INSERT INTO mutation_idempotency "
                "(execution_id, operation, idempotency_key, principal_id, payload_hash, state_version_after, outcome_json, created_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?);",
                (
                    execution_id,
                    op_name,
                    valid_key,
                    principal_id,
                    payload_hash,
                    updated_execution.desired_state_version,
                    outcome.model_dump_json(),
                    now_iso,
                ),
            )

            audit_evt = AuditEvent(
                event_id=generate_event_id("audit"),
                execution_id=execution_id,
                principal_id=principal_id,
                state_version=updated_execution.desired_state_version,
                event_type="EXCEPTION_RESOLVED",
                step_id=execution.active_exception.step_id if execution.active_exception else None,
                details={"exception_id": exception_id, "resolution": resolution},
                correlation_id=corr_id,
                recorded_at=now_iso,
            )
            conn.execute(
                "INSERT INTO audit_events (execution_id, state_version, event_id, principal_id, event_type, audit_json, recorded_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?);",
                (
                    execution_id,
                    updated_execution.desired_state_version,
                    audit_evt.event_id,
                    principal_id,
                    audit_evt.event_type,
                    audit_evt.model_dump_json(),
                    now_iso,
                ),
            )

            outbox_rec = OutboxRecord(
                execution_id=execution_id,
                target_version=updated_execution.desired_state_version,
                outbox_status=OutboxStatus.PENDING,
                operation=op_name,
                snapshot_json=updated_execution.model_dump_json(),
                created_at=now_iso,
            )
            conn.execute(
                "INSERT INTO outbox_events (execution_id, target_version, outbox_status, operation, snapshot_json, created_at) "
                "VALUES (?, ?, ?, ?, ?, ?);",
                (
                    execution_id,
                    outbox_rec.target_version,
                    outbox_rec.outbox_status.value,
                    outbox_rec.operation,
                    outbox_rec.snapshot_json,
                    now_iso,
                ),
            )

            if outcome.notification_queued:
                notif = build_notification_record(
                    notification_id=generate_event_id("notif"),
                    execution=updated_execution,
                    event_type=NotificationEventType.ON_STEP_REVISION,
                    summary_message=f"Exception resolved with {resolution}.",
                    now_iso=now_iso,
                )
                if notif:
                    conn.execute(
                        "INSERT INTO notification_outbox "
                        "(notification_id, execution_id, principal_id, state_version, event_type, dispatched, notification_json, created_at) "
                        "VALUES (?, ?, ?, ?, ?, 0, ?, ?);",
                        (
                            notif.notification_id,
                            execution_id,
                            principal_id,
                            notif.state_version,
                            notif.event_type.value,
                            notif.model_dump_json(),
                            now_iso,
                        ),
                    )

        self._flush_pending_notifications(execution_id)
        if self._orchestrator_port:
            self._orchestrator_port.reconcile_execution(execution_id)

        data = outcome.model_dump()
        data["duplicate"] = False
        return ResolveExceptionResponse.model_validate(data)

    def complete_inspection(
        self,
        *,
        principal_id: str,
        execution_id: str,
        idempotency_key: str,
        correlation_id: str | None = None,
    ) -> CompleteInspectionResponse:
        corr_id = correlation_id or generate_correlation_id()
        valid_key = validate_idempotency_key(idempotency_key)
        op_name = "complete_inspection"
        payload_hash = compute_payload_hash(op_name, {"execution_id": execution_id})

        with self._write_transaction(corr_id) as conn:
            execution = self._load_execution_in_tx(conn, execution_id, corr_id)
            if execution.principal_id != principal_id:
                raise AdapterError(
                    ErrorCode.FORBIDDEN,
                    "Principal does not own this execution.",
                    correlation_id=corr_id,
                )

            idemp_row = conn.execute(
                "SELECT payload_hash, outcome_json FROM mutation_idempotency "
                "WHERE execution_id = ? AND operation = ? AND idempotency_key = ?;",
                (execution_id, op_name, valid_key),
            ).fetchone()
            if idemp_row is not None:
                verify_or_raise_idempotency_conflict(
                    idempotency_key=valid_key,
                    operation=op_name,
                    stored_payload_hash=str(idemp_row["payload_hash"]),
                    incoming_payload_hash=payload_hash,
                )
                self._flush_pending_notifications(execution_id)
                return build_response_from_outcome(
                    str(idemp_row["outcome_json"]),
                    CompleteInspectionOutcome,
                    CompleteInspectionResponse,
                    duplicate=True,
                )

            now_iso = utc_now_iso()
            audit_ref = f"AUDIT-{execution.asset_id}-{execution.execution_id[:8]}"
            updated_execution, outcome = apply_complete_inspection(
                execution=execution,
                policy=self._policy,
                audit_reference=audit_ref,
                now_iso=now_iso,
            )

            cur = conn.execute(
                "UPDATE executions SET status = ?, desired_state_version = ?, pending_step_id = ?, "
                "session_paused = ?, execution_json = ?, updated_at = ? "
                "WHERE execution_id = ? AND desired_state_version = ?;",
                (
                    updated_execution.status.value,
                    updated_execution.desired_state_version,
                    None,
                    0,
                    updated_execution.model_dump_json(),
                    now_iso,
                    execution_id,
                    execution.desired_state_version,
                ),
            )
            if cur.rowcount == 0:
                raise AdapterError(
                    ErrorCode.BACKEND_UNAVAILABLE,
                    "Optimistic concurrency conflict while completing inspection.",
                    retryable=True,
                    correlation_id=corr_id,
                )

            # Atomic release of active asset lock (AC17)
            conn.execute(
                "DELETE FROM asset_locks WHERE asset_id = ? AND execution_id = ?;",
                (execution.asset_id, execution_id),
            )

            conn.execute(
                "INSERT INTO mutation_idempotency "
                "(execution_id, operation, idempotency_key, principal_id, payload_hash, state_version_after, outcome_json, created_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?);",
                (
                    execution_id,
                    op_name,
                    valid_key,
                    principal_id,
                    payload_hash,
                    updated_execution.desired_state_version,
                    outcome.model_dump_json(),
                    now_iso,
                ),
            )

            audit_evt = AuditEvent(
                event_id=generate_event_id("audit"),
                execution_id=execution_id,
                principal_id=principal_id,
                state_version=updated_execution.desired_state_version,
                event_type="WORKFLOW_COMPLETED",
                step_id=None,
                details={"audit_reference": audit_ref},
                correlation_id=corr_id,
                recorded_at=now_iso,
            )
            conn.execute(
                "INSERT INTO audit_events (execution_id, state_version, event_id, principal_id, event_type, audit_json, recorded_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?);",
                (
                    execution_id,
                    updated_execution.desired_state_version,
                    audit_evt.event_id,
                    principal_id,
                    audit_evt.event_type,
                    audit_evt.model_dump_json(),
                    now_iso,
                ),
            )

            outbox_rec = OutboxRecord(
                execution_id=execution_id,
                target_version=updated_execution.desired_state_version,
                outbox_status=OutboxStatus.PENDING,
                operation=op_name,
                snapshot_json=updated_execution.model_dump_json(),
                created_at=now_iso,
            )
            conn.execute(
                "INSERT INTO outbox_events (execution_id, target_version, outbox_status, operation, snapshot_json, created_at) "
                "VALUES (?, ?, ?, ?, ?, ?);",
                (
                    execution_id,
                    outbox_rec.target_version,
                    outbox_rec.outbox_status.value,
                    outbox_rec.operation,
                    outbox_rec.snapshot_json,
                    now_iso,
                ),
            )

            if outcome.notification_queued:
                notif = build_notification_record(
                    notification_id=generate_event_id("notif"),
                    execution=updated_execution,
                    event_type=NotificationEventType.ON_INSPECTION_COMPLETED,
                    summary_message=f"Inspection completed for asset {execution.asset_id}.",
                    now_iso=now_iso,
                )
                if notif:
                    conn.execute(
                        "INSERT INTO notification_outbox "
                        "(notification_id, execution_id, principal_id, state_version, event_type, dispatched, notification_json, created_at) "
                        "VALUES (?, ?, ?, ?, ?, 0, ?, ?);",
                        (
                            notif.notification_id,
                            execution_id,
                            principal_id,
                            notif.state_version,
                            notif.event_type.value,
                            notif.model_dump_json(),
                            now_iso,
                        ),
                    )

        self._flush_pending_notifications(execution_id)
        if self._orchestrator_port:
            self._orchestrator_port.reconcile_execution(execution_id)

        data = outcome.model_dump()
        data["duplicate"] = False
        return CompleteInspectionResponse.model_validate(data)

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
        valid_key = validate_idempotency_key(idempotency_key)
        op_name = "configure_notifications"
        payload_hash = compute_payload_hash(
            op_name, {"preferences": preferences, "pause_session": pause_session}
        )

        with self._write_transaction(corr_id) as conn:
            execution = self._load_execution_in_tx(conn, execution_id, corr_id)
            if execution.principal_id != principal_id:
                raise AdapterError(
                    ErrorCode.FORBIDDEN,
                    "Principal does not own this execution.",
                    correlation_id=corr_id,
                )

            idemp_row = conn.execute(
                "SELECT payload_hash, outcome_json FROM mutation_idempotency "
                "WHERE execution_id = ? AND operation = ? AND idempotency_key = ?;",
                (execution_id, op_name, valid_key),
            ).fetchone()
            if idemp_row is not None:
                verify_or_raise_idempotency_conflict(
                    idempotency_key=valid_key,
                    operation=op_name,
                    stored_payload_hash=str(idemp_row["payload_hash"]),
                    incoming_payload_hash=payload_hash,
                )
                self._flush_pending_notifications(execution_id)
                return build_response_from_outcome(
                    str(idemp_row["outcome_json"]),
                    ConfigureNotificationsOutcome,
                    ConfigureNotificationsResponse,
                    duplicate=True,
                )

            now_iso = utc_now_iso()
            updated_execution, outcome = apply_configure_notifications(
                execution=execution,
                preferences=preferences,
                pause_session=pause_session,
                now_iso=now_iso,
            )

            cur = conn.execute(
                "UPDATE executions SET status = ?, desired_state_version = ?, pending_step_id = ?, "
                "session_paused = ?, execution_json = ?, updated_at = ? "
                "WHERE execution_id = ? AND desired_state_version = ?;",
                (
                    updated_execution.status.value,
                    updated_execution.desired_state_version,
                    updated_execution.pending_step_id,
                    1 if updated_execution.session_paused else 0,
                    updated_execution.model_dump_json(),
                    now_iso,
                    execution_id,
                    execution.desired_state_version,
                ),
            )
            if cur.rowcount == 0:
                raise AdapterError(
                    ErrorCode.BACKEND_UNAVAILABLE,
                    "Optimistic concurrency conflict while configuring notifications.",
                    retryable=True,
                    correlation_id=corr_id,
                )

            conn.execute(
                "INSERT INTO mutation_idempotency "
                "(execution_id, operation, idempotency_key, principal_id, payload_hash, state_version_after, outcome_json, created_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?);",
                (
                    execution_id,
                    op_name,
                    valid_key,
                    principal_id,
                    payload_hash,
                    updated_execution.desired_state_version,
                    outcome.model_dump_json(),
                    now_iso,
                ),
            )

            audit_evt = AuditEvent(
                event_id=generate_event_id("audit"),
                execution_id=execution_id,
                principal_id=principal_id,
                state_version=updated_execution.desired_state_version,
                event_type="NOTIFICATIONS_CONFIGURED",
                step_id=None,
                details={"session_paused": pause_session},
                correlation_id=corr_id,
                recorded_at=now_iso,
            )
            conn.execute(
                "INSERT INTO audit_events (execution_id, state_version, event_id, principal_id, event_type, audit_json, recorded_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?);",
                (
                    execution_id,
                    updated_execution.desired_state_version,
                    audit_evt.event_id,
                    principal_id,
                    audit_evt.event_type,
                    audit_evt.model_dump_json(),
                    now_iso,
                ),
            )

            outbox_rec = OutboxRecord(
                execution_id=execution_id,
                target_version=updated_execution.desired_state_version,
                outbox_status=OutboxStatus.PENDING,
                operation=op_name,
                snapshot_json=updated_execution.model_dump_json(),
                created_at=now_iso,
            )
            conn.execute(
                "INSERT INTO outbox_events (execution_id, target_version, outbox_status, operation, snapshot_json, created_at) "
                "VALUES (?, ?, ?, ?, ?, ?);",
                (
                    execution_id,
                    outbox_rec.target_version,
                    outbox_rec.outbox_status.value,
                    outbox_rec.operation,
                    outbox_rec.snapshot_json,
                    now_iso,
                ),
            )

            if outcome.notification_queued:
                notif = build_notification_record(
                    notification_id=generate_event_id("notif"),
                    execution=updated_execution,
                    event_type=NotificationEventType.ON_PAUSE_INTERRUPTION,
                    summary_message="Session paused for operator interruption.",
                    now_iso=now_iso,
                )
                if notif:
                    conn.execute(
                        "INSERT INTO notification_outbox "
                        "(notification_id, execution_id, principal_id, state_version, event_type, dispatched, notification_json, created_at) "
                        "VALUES (?, ?, ?, ?, ?, 0, ?, ?);",
                        (
                            notif.notification_id,
                            execution_id,
                            principal_id,
                            notif.state_version,
                            notif.event_type.value,
                            notif.model_dump_json(),
                            now_iso,
                        ),
                    )

        self._flush_pending_notifications(execution_id)
        if self._orchestrator_port:
            self._orchestrator_port.reconcile_execution(execution_id)

        data = outcome.model_dump()
        data["duplicate"] = False
        return ConfigureNotificationsResponse.model_validate(data)

    def list_active_executions(self, *, principal_id: str) -> list[ExecutionBrief]:
        corr_id = generate_correlation_id()
        with self._read_connection(corr_id) as conn:
            rows = conn.execute(
                "SELECT execution_id, asset_id, inspection_type, status, pending_step_id, session_paused, updated_at "
                "FROM executions WHERE principal_id = ? AND status IN ('RUNNING', 'BLOCKED') "
                "ORDER BY updated_at DESC, execution_id ASC;",
                (principal_id,),
            ).fetchall()
            return [
                ExecutionBrief(
                    execution_id=str(r["execution_id"]),
                    asset_id=str(r["asset_id"]),
                    inspection_type=str(r["inspection_type"]),
                    status=WorkflowStatus(r["status"]),
                    pending_step_id=r["pending_step_id"],
                    session_paused=bool(r["session_paused"]),
                    updated_at=str(r["updated_at"]),
                )
                for r in rows
            ]

    def get_audit_trail(self, *, principal_id: str, execution_id: str) -> list[AuditEvent]:
        corr_id = generate_correlation_id()
        with self._read_connection(corr_id) as conn:
            execution = self._load_execution_in_tx(conn, execution_id, corr_id)
            if execution.principal_id != principal_id:
                raise AdapterError(
                    ErrorCode.FORBIDDEN,
                    "Principal does not own this execution.",
                    correlation_id=corr_id,
                )
            rows = conn.execute(
                "SELECT audit_json FROM audit_events WHERE execution_id = ? "
                "ORDER BY state_version ASC, recorded_at ASC;",
                (execution_id,),
            ).fetchall()
            return [AuditEvent.model_validate_json(r["audit_json"]) for r in rows]

    def get_outbox_records(self, *, principal_id: str, execution_id: str) -> list[OutboxRecord]:
        corr_id = generate_correlation_id()
        with self._read_connection(corr_id) as conn:
            execution = self._load_execution_in_tx(conn, execution_id, corr_id)
            if execution.principal_id != principal_id:
                raise AdapterError(
                    ErrorCode.FORBIDDEN,
                    "Principal does not own this execution.",
                    correlation_id=corr_id,
                )
            rows = conn.execute(
                "SELECT execution_id, target_version, outbox_status, operation, snapshot_json, created_at, "
                "acked_at, acked_by_version, acked_by_exec_arn FROM outbox_events "
                "WHERE execution_id = ? ORDER BY target_version ASC;",
                (execution_id,),
            ).fetchall()
            return [
                OutboxRecord(
                    execution_id=str(r["execution_id"]),
                    target_version=int(r["target_version"]),
                    outbox_status=OutboxStatus(r["outbox_status"]),
                    operation=str(r["operation"]),
                    snapshot_json=str(r["snapshot_json"]),
                    created_at=str(r["created_at"]),
                    acked_at=r["acked_at"],
                    acked_by_version=r["acked_by_version"],
                    acked_by_exec_arn=r["acked_by_exec_arn"],
                )
                for r in rows
            ]

    def get_notifications(
        self, *, principal_id: str, execution_id: str
    ) -> list[NotificationRecord]:
        corr_id = generate_correlation_id()
        with self._read_connection(corr_id) as conn:
            execution = self._load_execution_in_tx(conn, execution_id, corr_id)
            if execution.principal_id != principal_id:
                raise AdapterError(
                    ErrorCode.FORBIDDEN,
                    "Principal does not own this execution.",
                    correlation_id=corr_id,
                )
            rows = conn.execute(
                "SELECT notification_json, dispatched FROM notification_outbox "
                "WHERE execution_id = ? ORDER BY state_version ASC, created_at ASC;",
                (execution_id,),
            ).fetchall()
            return [
                NotificationRecord.model_validate_json(r["notification_json"]).model_copy(
                    update={"dispatched": bool(r["dispatched"])}
                )
                for r in rows
            ]
