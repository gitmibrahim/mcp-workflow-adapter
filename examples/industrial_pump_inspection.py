from __future__ import annotations

import json
import tempfile
from pathlib import Path
from typing import Any

from workflow_adapter.backends.local import LocalBackend
from workflow_adapter.errors import AdapterError, ErrorCode
from workflow_adapter.models import (
    ResolutionBehavior,
    StepDefinition,
    WorkflowExecution,
    WorkflowStatus,
)
from workflow_adapter.ports import DomainPolicyPort

PUMP_ASSET_CATALOG: dict[str, dict[str, Any]] = {
    "PUMP-07": {
        "description": "Primary Coolant Circulation Pump #07",
        "allowed_type": "pump_basic",
    },
    "PUMP-08": {"description": "Auxiliary Feedwater Pump #08", "allowed_type": "pump_basic"},
}


class PumpMaintenanceDomainPolicy(DomainPolicyPort):
    """Domain policy for industrial pump inspection proving mcp-workflow-adapter reuse."""

    def __init__(self) -> None:
        self._steps = (
            StepDefinition(
                step_id="discharge_pressure_psi",
                title="Discharge Pressure Check",
                unit="psi",
                accepted_units=("psi",),
                min_value=45.0,
                max_value=65.0,
                resolution_policies={
                    "ADJUST_RELIEF_VALVE_AND_RETEST": ResolutionBehavior.RETEST,
                    "LOG_MAINTENANCE_TICKET_AND_ANNOTATE": ResolutionBehavior.ANNOTATE_AND_ADVANCE,
                },
            ),
            StepDefinition(
                step_id="bearing_temperature_c",
                title="Bearing Housing Temperature",
                unit="celsius",
                accepted_units=("celsius", "c"),
                min_value=20.0,
                max_value=75.0,
                resolution_policies={
                    "ALLOW_COOLING_CYCLE_AND_RETEST": ResolutionBehavior.RETEST,
                    "LOG_MAINTENANCE_TICKET_AND_ANNOTATE": ResolutionBehavior.ANNOTATE_AND_ADVANCE,
                },
            ),
            StepDefinition(
                step_id="vibration_velocity_mms",
                title="RMS Vibration Velocity",
                unit="mm/s",
                accepted_units=("mm/s", "mms"),
                min_value=0.5,
                max_value=7.1,
                resolution_policies={
                    "RECALIBRATE_SENSOR_AND_RETEST": ResolutionBehavior.RETEST,
                    "LOG_MAINTENANCE_TICKET_AND_ANNOTATE": ResolutionBehavior.ANNOTATE_AND_ADVANCE,
                },
            ),
        )

    def validate_asset_and_type(self, inspection_type: str, asset_id: str) -> dict[str, Any]:
        if inspection_type != "pump_basic":
            raise AdapterError(
                ErrorCode.INVALID_INPUT,
                f"Unknown inspection type '{inspection_type}'. Allowed: 'pump_basic'.",
            )
        if asset_id not in PUMP_ASSET_CATALOG:
            raise AdapterError(
                ErrorCode.INVALID_INPUT,
                f"Unknown asset '{asset_id}'. Allowed assets: {list(PUMP_ASSET_CATALOG.keys())}.",
            )
        return PUMP_ASSET_CATALOG[asset_id]

    def get_steps(self, inspection_type: str) -> tuple[StepDefinition, ...]:
        return self._steps

    def get_step(self, inspection_type: str, step_id: str) -> StepDefinition:
        for s in self._steps:
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
                f"Resolution '{resolution}' not allowed for step '{step_id}'.",
            )
        return step.resolution_policies[resolution]

    def build_completion_metadata(self, execution: WorkflowExecution) -> dict[str, Any]:
        return {
            "asset_catalog_info": PUMP_ASSET_CATALOG.get(execution.asset_id, {}),
            "maintenance_status": "CERTIFIED_SERVICEABLE",
        }


def run_industrial_pump_demo() -> dict[str, Any]:
    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp_dir:
        db_path = Path(tmp_dir) / "pump_inspection_wal.db"
        policy = PumpMaintenanceDomainPolicy()
        operator_id = "operator-chief-01"

        # 1. Instantiate LocalBackend
        backend = LocalBackend(db_path, policy)

        # 2. Start inspection on PUMP-07
        start_resp = backend.start_inspection(
            principal_id=operator_id,
            inspection_type="pump_basic",
            asset_id="PUMP-07",
            idempotency_key="pump-start-001",
        )
        exec_id = start_resp.execution_id
        assert start_resp.duplicate is False
        assert start_resp.status == WorkflowStatus.RUNNING

        # 3. Record Step 1 (discharge pressure = 55.0 psi)
        step1_resp = backend.record_inspection_result(
            principal_id=operator_id,
            execution_id=exec_id,
            step_id="discharge_pressure_psi",
            value=55.0,
            unit="psi",
            idempotency_key="pump-step1-001",
        )
        assert step1_resp.accepted is True

        # Record Step 2 (bearing temperature = 60.0 celsius)
        step2_resp = backend.record_inspection_result(
            principal_id=operator_id,
            execution_id=exec_id,
            step_id="bearing_temperature_c",
            value=60.0,
            unit="celsius",
            idempotency_key="pump-step2-001",
        )
        assert step2_resp.accepted is True

        # 4. Close & Re-open LocalBackend to verify persistence
        reopened_backend = LocalBackend(db_path, policy)
        status_resp = reopened_backend.get_inspection_status(
            principal_id=operator_id,
            execution_id=exec_id,
        )
        assert len(status_resp.completed_steps) == 2
        assert status_resp.pending_step is not None
        assert status_resp.pending_step.step_id == "vibration_velocity_mms"

        # 5. Replay Step 2 mutation idempotently
        step2_replay = reopened_backend.record_inspection_result(
            principal_id=operator_id,
            execution_id=exec_id,
            step_id="bearing_temperature_c",
            value=60.0,
            unit="celsius",
            idempotency_key="pump-step2-001",
        )
        assert step2_replay.duplicate is True

        # 6. Submit out-of-range vibration reading (14.5 mm/s > 7.1 max)
        step3_blocked = reopened_backend.record_inspection_result(
            principal_id=operator_id,
            execution_id=exec_id,
            step_id="vibration_velocity_mms",
            value=14.5,
            unit="mm/s",
            idempotency_key="pump-step3-001",
        )
        assert step3_blocked.accepted is False
        assert step3_blocked.status == WorkflowStatus.BLOCKED
        assert step3_blocked.active_exception is not None
        exc_id = step3_blocked.active_exception.exception_id

        # 7. Resolve with LOG_MAINTENANCE_TICKET_AND_ANNOTATE (ANNOTATE_AND_ADVANCE)
        resolve_resp = reopened_backend.resolve_inspection_exception(
            principal_id=operator_id,
            execution_id=exec_id,
            exception_id=exc_id,
            resolution="LOG_MAINTENANCE_TICKET_AND_ANNOTATE",
            idempotency_key="pump-resolve-001",
        )
        assert resolve_resp.status == WorkflowStatus.RUNNING
        assert resolve_resp.resolution_behavior == ResolutionBehavior.ANNOTATE_AND_ADVANCE

        # 8. Complete inspection
        complete_resp = reopened_backend.complete_inspection(
            principal_id=operator_id,
            execution_id=exec_id,
            idempotency_key="pump-complete-001",
        )
        assert complete_resp.status == WorkflowStatus.COMPLETED

        return {
            "status": complete_resp.status.value,
            "execution_id": exec_id,
            "asset_id": "PUMP-07",
            "audit_reference": complete_resp.summary.audit_reference,
            "completed_steps": complete_resp.summary.total_steps,
            "maintenance_status": complete_resp.summary.metadata.get("maintenance_status"),
        }


if __name__ == "__main__":
    summary = run_industrial_pump_demo()
    print(json.dumps(summary, indent=2))
