from __future__ import annotations

import json
import logging
from typing import Any

import boto3  # type: ignore[import-untyped]
from botocore.exceptions import BotoCoreError, ClientError  # type: ignore[import-untyped]

from workflow_adapter.backends.aws_dynamodb import DynamoDBWorkflowStore
from workflow_adapter.backends.aws_sfn_reconciler import StepFunctionsReconciler
from workflow_adapter.models import NotificationRecord
from workflow_adapter.ports import DomainPolicyPort, NotificationPort, StorageBackendPort

logger = logging.getLogger(__name__)


class SNSNotificationSink(NotificationPort):
    """Dispatches committed notification records to Amazon SNS."""

    def __init__(
        self,
        arg1: Any = None,
        arg2: Any = None,
        *,
        topic_arn: str | None = None,
        sns_client: Any | None = None,
    ) -> None:
        # Flexible signature supporting SNSNotificationSink(sns_client, topic_arn)
        # or SNSNotificationSink(topic_arn, sns_client) or keyword args
        resolved_client = sns_client
        resolved_arn = topic_arn or ""

        if arg1 is not None and isinstance(arg1, str):
            resolved_arn = arg1
            if arg2 is not None:
                resolved_client = arg2
        elif arg1 is not None:
            resolved_client = arg1
            if arg2 is not None and isinstance(arg2, str):
                resolved_arn = arg2

        self._topic_arn = resolved_arn
        self._sns = resolved_client or boto3.client("sns")

    def dispatch(self, record: NotificationRecord) -> bool:
        if not self._topic_arn:
            logger.debug("SNS topic ARN not configured; skipping notification dispatch.")
            return False
        try:
            self._sns.publish(
                TopicArn=self._topic_arn,
                Subject=f"Checkpoint: {record.event_type.value} - {record.asset_id}",
                Message=json.dumps(
                    {
                        "notification_id": record.notification_id,
                        "execution_id": record.execution_id,
                        "principal_id": record.principal_id,
                        "asset_id": record.asset_id,
                        "event_type": record.event_type.value,
                        "summary": record.summary_message,
                        "channels": record.channels,
                        "state_version": record.state_version,
                    },
                    sort_keys=True,
                ),
                MessageAttributes={
                    "event_type": {"DataType": "String", "StringValue": record.event_type.value},
                    "execution_id": {"DataType": "String", "StringValue": record.execution_id},
                },
            )
            return True
        except (ClientError, BotoCoreError) as exc:
            logger.warning("SNS publish failed", extra={"structured_data": {"error": str(exc)}})
            return False
        except Exception as exc:  # noqa: BLE001
            logger.warning("Unexpected SNS error", extra={"structured_data": {"error": str(exc)}})
            return False


class AWSBackend(StorageBackendPort):
    """Composite AWSBackend wiring DynamoDBWorkflowStore and StepFunctionsReconciler."""

    def __init__(
        self,
        *,
        store: DynamoDBWorkflowStore,
        reconciler: StepFunctionsReconciler | None = None,
    ) -> None:
        self._store = store
        self._reconciler = reconciler
        if reconciler is not None:
            self._store.set_orchestrator_port(reconciler)

    @property
    def store(self) -> DynamoDBWorkflowStore:
        return self._store

    @property
    def reconciler(self) -> StepFunctionsReconciler | None:
        return self._reconciler

    def start_inspection(self, *args: Any, **kwargs: Any) -> Any:
        return self._store.start_inspection(*args, **kwargs)

    def get_inspection_status(self, *args: Any, **kwargs: Any) -> Any:
        return self._store.get_inspection_status(*args, **kwargs)

    def record_inspection_result(self, *args: Any, **kwargs: Any) -> Any:
        return self._store.record_inspection_result(*args, **kwargs)

    def resolve_inspection_exception(self, *args: Any, **kwargs: Any) -> Any:
        return self._store.resolve_inspection_exception(*args, **kwargs)

    def configure_notifications(self, *args: Any, **kwargs: Any) -> Any:
        return self._store.configure_notifications(*args, **kwargs)

    def complete_inspection(self, *args: Any, **kwargs: Any) -> Any:
        return self._store.complete_inspection(*args, **kwargs)

    def get_audit_trail(self, *args: Any, **kwargs: Any) -> Any:
        return self._store.get_audit_trail(*args, **kwargs)

    def get_notifications(self, *args: Any, **kwargs: Any) -> Any:
        return self._store.get_notifications(*args, **kwargs)

    def get_outbox_records(self, *args: Any, **kwargs: Any) -> Any:
        return self._store.get_outbox_records(*args, **kwargs)

    def list_active_executions(self, *args: Any, **kwargs: Any) -> Any:
        return self._store.list_active_executions(*args, **kwargs)


def create_aws_backend(
    *,
    policy: DomainPolicyPort,
    table_name: str,
    state_machine_arn: str = "",
    sns_topic_arn: str | None = None,
    ddb_client: Any | None = None,
    sfn_client: Any | None = None,
    sns_client: Any | None = None,
) -> AWSBackend:
    """Factory that wires DynamoDBWorkflowStore + StepFunctionsReconciler + SNSNotificationSink into AWSBackend."""
    ddb = ddb_client or boto3.client("dynamodb")
    sfn = sfn_client or boto3.client("stepfunctions")

    sink: SNSNotificationSink | None = None
    if sns_topic_arn:
        sink = SNSNotificationSink(topic_arn=sns_topic_arn, sns_client=sns_client)

    store = DynamoDBWorkflowStore(
        ddb_client=ddb,
        table_name=table_name,
        policy=policy,
        notification_port=sink,
    )

    reconciler = StepFunctionsReconciler(
        ddb_client=ddb,
        sfn_client=sfn,
        table_name=table_name,
        state_machine_arn=state_machine_arn,
        store=store,
    )
    store.set_orchestrator_port(reconciler)

    return AWSBackend(store=store, reconciler=reconciler)
