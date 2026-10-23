from __future__ import annotations

import contextlib
import json
import logging
import time
from typing import Any, Final

from botocore.exceptions import BotoCoreError, ClientError  # type: ignore[import-untyped]

from workflow_adapter.backends.aws_dynamodb import DynamoDBWorkflowStore, _pad_ver
from workflow_adapter.models import (
    OutboxStatus,
    TokenLifecycleStatus,
    WorkflowExecution,
    WorkflowStatus,
    utc_now_iso,
)
from workflow_adapter.ports import OrchestratorPort

logger = logging.getLogger(__name__)

TOKEN_LEASE_DURATION_MS: Final[int] = 5_000
RECOVERY_LEASE_DURATION_MS: Final[int] = 10_000
TERMINAL_SFN_FAILURE_STATES: Final[frozenset[str]] = frozenset({"TIMED_OUT", "ABORTED", "FAILED"})


def _now_ms() -> int:
    return int(time.time() * 1000)


class StepFunctionsReconciler(OrchestratorPort):
    """
    Fenced asynchronous reconciler synchronizing DynamoDB authoritative state with Step Functions Standard.
    Enforces the locked invariant: external reconcilers NEVER increment acked_sfn_version directly.
    """

    def __init__(
        self,
        *,
        ddb_client: Any,
        sfn_client: Any,
        table_name: str,
        state_machine_arn: str,
        store: DynamoDBWorkflowStore,
        clock_ms_fn: Any = _now_ms,
    ) -> None:
        self._ddb = ddb_client
        self._sfn = sfn_client
        self._table = table_name
        self._state_machine_arn = state_machine_arn
        self._store = store
        self._clock_ms = clock_ms_fn

    def _deterministic_execution_arn(self, execution_name: str) -> str:
        parts = self._state_machine_arn.split(":")
        parts[5] = "execution"
        return ":".join(parts) + f":{execution_name}"

    def reconcile_execution(self, execution_id: str) -> None:
        """Advance Step Functions orchestration toward METADATA.desired_state_version safely (R1-R8)."""
        if not self._state_machine_arn:
            return
        try:
            execution = self._store.load_execution_metadata(execution_id)
        except Exception as exc:  # noqa: BLE001
            logger.warning("Reconciler could not load metadata", extra={"structured_data": {"error": str(exc)}})
            return

        if execution.acked_sfn_version >= execution.desired_state_version and execution.sfn_execution_arn:
            return

        # R1: Initial startup
        if execution.sfn_execution_arn is None and execution.sfn_recovery_epoch == 0:
            self._start_initial_execution_r1(execution)
            return

        now_ms = self._clock_ms()
        if (
            execution.sfn_token_expires_at_ms > 0
            and now_ms > execution.sfn_token_expires_at_ms
            and execution.acked_sfn_version < execution.desired_state_version
        ):
            self._attempt_recovery_if_terminal_r5_r8(execution)
            return

        # R2: Token not yet registered
        if (
            execution.sfn_token_status == TokenLifecycleStatus.NONE
            or execution.sfn_token_status == TokenLifecycleStatus.CONSUMED
            or execution.sfn_token_version < execution.acked_sfn_version
            or not execution.sfn_task_token
        ):
            self._inspect_or_recover_execution(execution)
            return

        # R3, R4, R6, R7: Fenced token claim and SendTaskSuccess
        self._claim_and_deliver_callback(execution)

    def _start_initial_execution_r1(self, execution: WorkflowExecution) -> None:
        exec_name = execution.execution_id
        sfn_input = json.dumps(
            {
                "execution_id": execution.execution_id,
                "epoch": 0,
                "entry_target_version": execution.desired_state_version,
                "status": execution.status.value,
            },
            sort_keys=True,
        )
        try:
            resp = self._sfn.start_execution(
                stateMachineArn=self._state_machine_arn,
                name=exec_name,
                input=sfn_input,
            )
            exec_arn = resp["executionArn"]
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "")
            if code == "ExecutionAlreadyExists":
                exec_arn = self._deterministic_execution_arn(exec_name)
            else:
                logger.warning("StartExecution failed transiently", extra={"structured_data": {"code": code}})
                return
        except BotoCoreError:
            return

        with contextlib.suppress(ClientError, BotoCoreError):
            self._ddb.update_item(
                TableName=self._table,
                Key={"PK": {"S": f"EXEC#{execution.execution_id}"}, "SK": {"S": "METADATA"}},
                UpdateExpression="SET sfn_execution_arn = :arn",
                ConditionExpression="sfn_recovery_epoch = :zero AND (attribute_not_exists(sfn_execution_arn) OR sfn_execution_arn = :empty)",
                ExpressionAttributeValues={
                    ":arn": {"S": exec_arn},
                    ":zero": {"N": "0"},
                    ":empty": {"S": ""},
                },
            )

    def _claim_and_deliver_callback(self, execution: WorkflowExecution) -> None:
        now_ms = self._clock_ms()
        can_claim = execution.sfn_token_status == TokenLifecycleStatus.AVAILABLE or (
            execution.sfn_token_status == TokenLifecycleStatus.IN_FLIGHT
            and execution.sfn_token_lease_until_ms < now_ms
        )
        if not can_claim or not execution.sfn_task_token or not execution.sfn_execution_arn:
            return

        v_proc = execution.acked_sfn_version
        v_deliver = execution.desired_state_version
        old_seq = execution.sfn_lease_seq
        my_lease_seq = old_seq + 1
        lease_until = now_ms + TOKEN_LEASE_DURATION_MS

        try:
            self._ddb.update_item(
                TableName=self._table,
                Key={"PK": {"S": f"EXEC#{execution.execution_id}"}, "SK": {"S": "METADATA"}},
                UpdateExpression=(
                    "SET sfn_token_status = :inflight, "
                    "sfn_lease_seq = :new_seq, "
                    "sfn_inflight_target_version = :v_deliv, "
                    "sfn_token_lease_until_ms = :lease_until"
                ),
                ConditionExpression=(
                    "sfn_execution_arn = :exec_arn "
                    "AND acked_sfn_version = :v_proc "
                    "AND sfn_token_version = :v_proc "
                    "AND sfn_lease_seq = :old_seq "
                    "AND (sfn_token_status = :avail OR (sfn_token_status = :inflight AND sfn_token_lease_until_ms < :now_ms))"
                ),
                ExpressionAttributeValues={
                    ":exec_arn": {"S": execution.sfn_execution_arn},
                    ":v_proc": {"N": str(v_proc)},
                    ":old_seq": {"N": str(old_seq)},
                    ":new_seq": {"N": str(my_lease_seq)},
                    ":v_deliv": {"N": str(v_deliver)},
                    ":lease_until": {"N": str(lease_until)},
                    ":now_ms": {"N": str(now_ms)},
                    ":avail": {"S": TokenLifecycleStatus.AVAILABLE.value},
                    ":inflight": {"S": TokenLifecycleStatus.IN_FLIGHT.value},
                },
            )
        except (ClientError, BotoCoreError):
            return

        callback_output = json.dumps(
            {
                "execution_id": execution.execution_id,
                "epoch": execution.sfn_recovery_epoch,
                "from_version": v_proc,
                "delivered_version": v_deliver,
                "lease_seq": my_lease_seq,
                "status": execution.status.value,
            },
            sort_keys=True,
        )
        try:
            self._sfn.send_task_success(
                taskToken=execution.sfn_task_token,
                output=callback_output,
            )
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "")
            if code in {"TaskTimedOut", "ExecutionDoesNotExist"}:
                latest = self._store.load_execution_metadata(execution.execution_id)
                self._attempt_recovery_if_terminal_r5_r8(latest)
            elif code in {"InvalidToken", "TaskDoesNotExist"}:
                self._handle_consumed_token_r4_r7(execution.execution_id, v_proc, my_lease_seq)
        except BotoCoreError:
            pass

    def _handle_consumed_token_r4_r7(
        self, execution_id: str, expected_token_version: int, my_lease_seq: int
    ) -> None:
        try:
            latest = self._store.load_execution_metadata(execution_id)
        except Exception:  # noqa: BLE001
            return

        if latest.acked_sfn_version > expected_token_version:
            if latest.acked_sfn_version < latest.desired_state_version and latest.sfn_token_status == TokenLifecycleStatus.AVAILABLE:
                self.reconcile_execution(execution_id)
            return

        self._inspect_or_recover_execution(latest, expected_lease_seq=my_lease_seq)

    def _inspect_or_recover_execution(
        self, execution: WorkflowExecution, *, expected_lease_seq: int | None = None
    ) -> None:
        if not execution.sfn_execution_arn:
            return
        try:
            desc = self._sfn.describe_execution(executionArn=execution.sfn_execution_arn)
        except (ClientError, BotoCoreError):
            return

        sfn_status = desc.get("status", "")
        if sfn_status in TERMINAL_SFN_FAILURE_STATES:
            self._attempt_recovery_if_terminal_r5_r8(execution, confirmed_sfn_status=sfn_status)
        elif sfn_status == "SUCCEEDED" and execution.status == WorkflowStatus.COMPLETED:
            self._record_verified_terminal_succeeded(execution)
        elif sfn_status == "RUNNING" and expected_lease_seq is not None:
            with contextlib.suppress(ClientError, BotoCoreError):
                self._ddb.update_item(
                    TableName=self._table,
                    Key={"PK": {"S": f"EXEC#{execution.execution_id}"}, "SK": {"S": "METADATA"}},
                    UpdateExpression="SET sfn_token_status = :consumed, sfn_task_token = :empty",
                    ConditionExpression="sfn_lease_seq = :seq AND sfn_token_version = :tv",
                    ExpressionAttributeValues={
                        ":consumed": {"S": TokenLifecycleStatus.CONSUMED.value},
                        ":empty": {"S": ""},
                        ":seq": {"N": str(expected_lease_seq)},
                        ":tv": {"N": str(execution.sfn_token_version)},
                    },
                )

    def _record_verified_terminal_succeeded(self, execution: WorkflowExecution) -> None:
        if not execution.sfn_execution_arn:
            return
        v_target = execution.desired_state_version
        try:
            self._ddb.update_item(
                TableName=self._table,
                Key={"PK": {"S": f"EXEC#{execution.execution_id}"}, "SK": {"S": "METADATA"}},
                UpdateExpression="SET acked_sfn_version = :v, sfn_token_status = :consumed, sfn_task_token = :empty",
                ConditionExpression="sfn_execution_arn = :arn AND acked_sfn_version < :v",
                ExpressionAttributeValues={
                    ":arn": {"S": execution.sfn_execution_arn},
                    ":v": {"N": str(v_target)},
                    ":consumed": {"S": TokenLifecycleStatus.CONSUMED.value},
                    ":empty": {"S": ""},
                },
            )
            self.acknowledge_outbox_up_to(
                execution_id=execution.execution_id,
                up_to_version=v_target,
                exec_arn=execution.sfn_execution_arn,
            )
        except (ClientError, BotoCoreError):
            pass

    def _attempt_recovery_if_terminal_r5_r8(
        self, execution: WorkflowExecution, *, confirmed_sfn_status: str | None = None
    ) -> None:
        if not execution.sfn_execution_arn:
            return

        status_to_check = confirmed_sfn_status
        if status_to_check is None:
            try:
                desc = self._sfn.describe_execution(executionArn=execution.sfn_execution_arn)
                status_to_check = desc.get("status", "")
            except (ClientError, BotoCoreError):
                return

        if status_to_check not in TERMINAL_SFN_FAILURE_STATES:
            return

        now_ms = self._clock_ms()
        old_epoch = execution.sfn_recovery_epoch
        new_epoch = old_epoch + 1
        closed_arn = execution.sfn_execution_arn
        recovery_lease_until = now_ms + RECOVERY_LEASE_DURATION_MS

        try:
            self._ddb.update_item(
                TableName=self._table,
                Key={"PK": {"S": f"EXEC#{execution.execution_id}"}, "SK": {"S": "METADATA"}},
                UpdateExpression="SET sfn_recovery_lease_until_ms = :lease_until",
                ConditionExpression=(
                    "sfn_recovery_epoch = :old_epoch "
                    "AND sfn_execution_arn = :closed_arn "
                    "AND (attribute_not_exists(sfn_recovery_lease_until_ms) OR sfn_recovery_lease_until_ms < :now_ms)"
                ),
                ExpressionAttributeValues={
                    ":old_epoch": {"N": str(old_epoch)},
                    ":closed_arn": {"S": closed_arn},
                    ":now_ms": {"N": str(now_ms)},
                    ":lease_until": {"N": str(recovery_lease_until)},
                },
            )
        except (ClientError, BotoCoreError):
            return

        recovery_name = f"{execution.execution_id}-r{new_epoch}"
        sfn_input = json.dumps(
            {
                "execution_id": execution.execution_id,
                "epoch": new_epoch,
                "entry_target_version": execution.desired_state_version,
                "status": execution.status.value,
            },
            sort_keys=True,
        )
        try:
            resp = self._sfn.start_execution(
                stateMachineArn=self._state_machine_arn,
                name=recovery_name,
                input=sfn_input,
            )
            new_arn = resp["executionArn"]
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") == "ExecutionAlreadyExists":
                new_arn = self._deterministic_execution_arn(recovery_name)
            else:
                return
        except BotoCoreError:
            return

        with contextlib.suppress(ClientError, BotoCoreError):
            self._ddb.update_item(
                TableName=self._table,
                Key={"PK": {"S": f"EXEC#{execution.execution_id}"}, "SK": {"S": "METADATA"}},
                UpdateExpression=(
                    "SET sfn_recovery_epoch = :new_epoch, "
                    "sfn_execution_arn = :new_arn, "
                    "sfn_token_status = :none_status, "
                    "sfn_task_token = :empty, "
                    "sfn_recovery_lease_until_ms = :zero"
                ),
                ConditionExpression="sfn_recovery_epoch = :old_epoch AND sfn_execution_arn = :closed_arn",
                ExpressionAttributeValues={
                    ":old_epoch": {"N": str(old_epoch)},
                    ":new_epoch": {"N": str(new_epoch)},
                    ":closed_arn": {"S": closed_arn},
                    ":new_arn": {"S": new_arn},
                    ":none_status": {"S": TokenLifecycleStatus.NONE.value},
                    ":empty": {"S": ""},
                    ":zero": {"N": "0"},
                },
            )

    def acknowledge_outbox_up_to(
        self, *, execution_id: str, up_to_version: int, exec_arn: str
    ) -> None:
        """Cumulatively mark all OUTBOX#<k> records with k <= up_to_version as ACKNOWLEDGED."""
        now_iso = utc_now_iso()
        for ver in range(1, up_to_version + 1):
            with contextlib.suppress(ClientError, BotoCoreError):
                self._ddb.update_item(
                    TableName=self._table,
                    Key={
                        "PK": {"S": f"EXEC#{execution_id}"},
                        "SK": {"S": f"OUTBOX#{_pad_ver(ver)}"},
                    },
                    UpdateExpression=(
                        "SET outbox_status = :acked, "
                        "acked_at = :now, "
                        "acked_by_version = :ver, "
                        "acked_by_exec_arn = :arn"
                    ),
                    ConditionExpression="attribute_exists(PK) AND outbox_status = :pending",
                    ExpressionAttributeValues={
                        ":acked": {"S": OutboxStatus.ACKNOWLEDGED.value},
                        ":pending": {"S": OutboxStatus.PENDING.value},
                        ":now": {"S": now_iso},
                        ":ver": {"N": str(up_to_version)},
                        ":arn": {"S": exec_arn},
                    },
                )
