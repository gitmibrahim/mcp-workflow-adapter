from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path


def test_ac12_industrial_pump_second_consumer_runs_offline() -> None:
    example_script = (
        Path(__file__).resolve().parents[2] / "examples" / "industrial_pump_inspection.py"
    )
    clean_env = {
        k: v
        for k, v in os.environ.items()
        if k not in {"AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN", "AWS_PROFILE"}
    }
    proc = subprocess.run(
        [sys.executable, str(example_script)],
        env=clean_env,
        capture_output=True,
        text=True,
        check=True,
    )
    assert "PUMP-07" in proc.stdout
    assert "COMPLETED" in proc.stdout
