import sys
from pathlib import Path

import pytest

# Ensure tests package/modules are importable across test subdirectories
_tests_dir = str(Path(__file__).parent.resolve())
if _tests_dir not in sys.path:
    sys.path.insert(0, _tests_dir)


@pytest.fixture(autouse=True)
def clean_aws_env_for_offline_tests(
    monkeypatch: pytest.MonkeyPatch, request: pytest.FixtureRequest
) -> None:
    """Strips AWS credential environment variables for all non-aws tests (AC12 guardrail)."""
    if "aws" not in request.keywords:
        monkeypatch.delenv("AWS_ACCESS_KEY_ID", raising=False)
        monkeypatch.delenv("AWS_SECRET_ACCESS_KEY", raising=False)
        monkeypatch.delenv("AWS_SESSION_TOKEN", raising=False)
        monkeypatch.delenv("AWS_PROFILE", raising=False)
        monkeypatch.delenv("AWS_DEFAULT_REGION", raising=False)
