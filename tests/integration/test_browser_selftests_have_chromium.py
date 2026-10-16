"""Every CI job that collects tests/integration/ must install Chromium first.

The page-monitor self-tests in tests/integration/ launch a real headless Chromium, so a job that runs
them on a fresh runner without the browser fails while creating the `page` fixture, before any test
body runs. `make test`, `make test-fast` and `make test-integration` all collect that directory.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import pytest
import yaml

WORKFLOWS = Path(__file__).resolve().parents[2] / ".github" / "workflows"
COLLECTS_INTEGRATION = re.compile(r"\bmake (?:test|test-fast|test-integration)(?:\s|$)")


def _installs_chromium(run: str) -> bool:
    return "playwright" in run and "install" in run and "chromium" in run


def _jobs_missing_chromium() -> list[str]:
    missing = []
    for path in sorted(WORKFLOWS.glob("*.yml")):
        for name, job in (yaml.safe_load(path.read_text()).get("jobs") or {}).items():
            runs = [str(step.get("run", "")) for step in job.get("steps", []) if isinstance(step, dict)]
            for index, run in enumerate(runs):
                if COLLECTS_INTEGRATION.search(run) and not any(_installs_chromium(r) for r in runs[:index]):
                    missing.append(f"{path.name}:{name}")
                    break
    return missing


@pytest.mark.integration
def test_every_job_that_collects_the_integration_tests_installs_chromium_first() -> None:
    assert _jobs_missing_chromium() == []


@pytest.mark.integration
def test_the_check_sees_a_job_without_the_browser() -> None:
    job: dict[str, Any] = {"steps": [{"run": "uv sync --all-groups"}, {"run": "make test-fast"}]}
    runs = [step["run"] for step in job["steps"]]

    assert COLLECTS_INTEGRATION.search(runs[1])
    assert not any(_installs_chromium(run) for run in runs[:1])
