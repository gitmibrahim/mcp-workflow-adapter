from pathlib import Path

import pytest

from workflow_adapter.backends.local import InMemoryNotificationSink, LocalBackend
from workflow_adapter.models import NotificationEventType, NotificationPreferences, WorkflowStatus
from workflow_adapter.ports import DomainPolicyPort


@pytest.fixture
def sink() -> InMemoryNotificationSink:
    return InMemoryNotificationSink()


@pytest.fixture
def backend(
    tmp_path: Path, policy: DomainPolicyPort, sink: InMemoryNotificationSink
) -> LocalBackend:
    db_file = tmp_path / "notifications_test.db"
    return LocalBackend(db_file, policy, notification_port=sink)


def test_pause_session_notification(backend: LocalBackend, sink: InMemoryNotificationSink) -> None:
    resp = backend.start_inspection(
        principal_id="tech-1",
        inspection_type="contract_type",
        asset_id="ASSET-ALPHA",
        idempotency_key="pause-start-key",
        notification_prefs=NotificationPreferences(on_pause=True),
    )
    exec_id = resp.execution_id

    # Pause session
    pause_resp = backend.configure_notifications(
        principal_id="tech-1",
        execution_id=exec_id,
        pause_session=True,
        idempotency_key="pause-key-01",
    )
    assert pause_resp.session_paused is True
    assert pause_resp.notification_queued is True

    # Verify notification delivered to sink
    delivered = sink.delivered_records
    assert len(delivered) == 1
    assert delivered[0].event_type == NotificationEventType.ON_PAUSE_INTERRUPTION
    assert delivered[0].payload["session_paused"] is True
    assert delivered[0].dispatched is True

    # Verify persisted in notification outbox
    stored_notifs = backend.get_notifications(principal_id="tech-1", execution_id=exec_id)
    assert len(stored_notifs) == 1
    assert stored_notifs[0].dispatched is True


def test_blocked_exception_notification(
    backend: LocalBackend, sink: InMemoryNotificationSink
) -> None:
    resp = backend.start_inspection(
        principal_id="tech-1",
        inspection_type="contract_type",
        asset_id="ASSET-ALPHA",
        idempotency_key="block-start-key",
        notification_prefs=NotificationPreferences(on_blocked=True),
    )
    exec_id = resp.execution_id

    # Submit out-of-range reading on step_a (< 10.0)
    backend.record_inspection_result(
        principal_id="tech-1",
        execution_id=exec_id,
        step_id="step_a",
        value=5.0,
        unit="unit_a",
        idempotency_key="block-step-key",
    )

    delivered = sink.delivered_records
    assert len(delivered) == 1
    assert delivered[0].event_type == NotificationEventType.ON_EXCEPTION_BLOCKED
    assert "active_exception" in delivered[0].payload


def test_revision_and_completion_notifications(
    backend: LocalBackend, sink: InMemoryNotificationSink
) -> None:
    resp = backend.start_inspection(
        principal_id="tech-1",
        inspection_type="contract_type",
        asset_id="ASSET-ALPHA",
        idempotency_key="rev-start-key",
        notification_prefs=NotificationPreferences(on_revision=True, on_completion=True),
    )
    exec_id = resp.execution_id

    # Valid step_a (emits revision notification)
    backend.record_inspection_result(
        principal_id="tech-1",
        execution_id=exec_id,
        step_id="step_a",
        value=20.0,
        unit="unit_a",
        idempotency_key="rev-s1",
    )

    # Valid step_b
    backend.record_inspection_result(
        principal_id="tech-1",
        execution_id=exec_id,
        step_id="step_b",
        value=150.0,
        unit="unit_b",
        idempotency_key="rev-s2",
    )

    # Valid step_c
    backend.record_inspection_result(
        principal_id="tech-1",
        execution_id=exec_id,
        step_id="step_c",
        value=10.0,
        unit="unit_c",
        idempotency_key="rev-s3",
    )

    # Complete inspection (emits completion notification)
    complete_resp = backend.complete_inspection(
        principal_id="tech-1",
        execution_id=exec_id,
        idempotency_key="rev-complete",
    )
    assert complete_resp.status == WorkflowStatus.COMPLETED

    delivered = sink.delivered_records
    # 3 step revisions + 1 completion = 4
    assert len(delivered) == 4
    assert delivered[-1].event_type == NotificationEventType.ON_INSPECTION_COMPLETED


def test_notification_sink_failure_isolation(
    backend: LocalBackend, sink: InMemoryNotificationSink
) -> None:
    resp = backend.start_inspection(
        principal_id="tech-1",
        inspection_type="contract_type",
        asset_id="ASSET-ALPHA",
        idempotency_key="fail-start-key",
        notification_prefs=NotificationPreferences(on_pause=True),
    )
    exec_id = resp.execution_id

    # Inject sink failure for next dispatch
    sink.set_fail_next_n(1)

    # Pause mutation must still commit successfully despite sink failure
    pause_resp = backend.configure_notifications(
        principal_id="tech-1",
        execution_id=exec_id,
        pause_session=True,
        idempotency_key="fail-pause-key",
    )
    assert pause_resp.session_paused is True

    # Sink did not receive the record yet
    assert len(sink.delivered_records) == 0

    # In outbox, dispatched is still False
    stored = backend.get_notifications(principal_id="tech-1", execution_id=exec_id)
    assert len(stored) == 1
    assert stored[0].dispatched is False

    # Next call (or replay) flushes outbox and delivers successfully
    backend.configure_notifications(
        principal_id="tech-1",
        execution_id=exec_id,
        pause_session=True,
        idempotency_key="fail-pause-key",  # Idempotent replay
    )
    assert len(sink.delivered_records) == 1
    assert sink.delivered_records[0].dispatched is True
