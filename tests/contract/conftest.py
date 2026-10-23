from __future__ import annotations

from typing import Any

import pytest

from workflow_adapter.errors import AdapterError, ErrorCode
from workflow_adapter.models import (
    ResolutionBehavior,
    StepDefinition,
    WorkflowExecution,
)
from workflow_adapter.ports import DomainPolicyPort


class ContractTestPolicy(DomainPolicyPort):
    def __init__(self) -> None:
        self.steps = (
            StepDefinition(
                step_id="step_a",
                title="Step A Title",
                unit="unit_a",
                accepted_units=("unit_a", "ua"),
                min_value=10.0,
                max_value=50.0,
                resolution_policies={
                    "RETEST_A": ResolutionBehavior.RETEST,
                    "ADVANCE_A": ResolutionBehavior.ANNOTATE_AND_ADVANCE,
                },
            ),
            StepDefinition(
                step_id="step_b",
                title="Step B Title",
                unit="unit_b",
                accepted_units=("unit_b", "ub"),
                min_value=100.0,
                max_value=200.0,
                resolution_policies={
                    "RETEST_B": ResolutionBehavior.RETEST,
                    "ADVANCE_B": ResolutionBehavior.ANNOTATE_AND_ADVANCE,
                },
            ),
            StepDefinition(
                step_id="step_c",
                title="Step C Title",
                unit="unit_c",
                accepted_units=("unit_c", "uc"),
                min_value=5.0,
                max_value=15.0,
                resolution_policies={
                    "RETEST_C": ResolutionBehavior.RETEST,
                    "ADVANCE_C": ResolutionBehavior.ANNOTATE_AND_ADVANCE,
                },
            ),
        )

    def validate_asset_and_type(self, inspection_type: str, asset_id: str) -> dict[str, Any]:
        if inspection_type != "contract_type":
            raise AdapterError(ErrorCode.INVALID_INPUT, f"Invalid type {inspection_type}")
        if asset_id not in ("ASSET-ALPHA", "ASSET-BETA"):
            raise AdapterError(ErrorCode.INVALID_INPUT, f"Invalid asset {asset_id}")
        return {"asset_id": asset_id, "type": inspection_type}

    def get_steps(self, inspection_type: str) -> tuple[StepDefinition, ...]:
        return self.steps

    def get_step(self, inspection_type: str, step_id: str) -> StepDefinition:
        for s in self.steps:
            if s.step_id == step_id:
                return s
        raise AdapterError(ErrorCode.INVALID_INPUT, f"Step {step_id} not found.")

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
            raise AdapterError(ErrorCode.INVALID_INPUT, f"Resolution {resolution} invalid.")
        return step.resolution_policies[resolution]

    def build_completion_metadata(self, execution: WorkflowExecution) -> dict[str, Any]:
        return {"contract_certified": True}


@pytest.fixture
def policy() -> ContractTestPolicy:
    return ContractTestPolicy()
