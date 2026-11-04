"""Native qualification must use its own harness when nightly checks older app refs."""

import os
import re
import subprocess
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]


def native_nightly_jobs() -> tuple[dict, dict]:
    jobs = yaml.safe_load((ROOT / ".github/workflows/nightly.yml").read_text())["jobs"]
    native = {
        name: job for name, job in jobs.items()
        if any("make test-native-deploy" in step.get("run", "") for step in job.get("steps", []))
    }
    assert len(native) == 1, "Every active nightly run must qualify native deployment exactly once"
    return jobs, native


def test_native_nightly_uses_workflow_harness_when_staging_predates_the_make_targets() -> None:
    jobs, native = native_nightly_jobs()
    job = next(iter(native.values()))
    checkout = next(step for step in job["steps"] if step.get("uses", "").startswith("actions/checkout@"))
    assert checkout["with"]["ref"] == "${{ github.workflow_sha }}", "Older app refs cannot supply the new native harness"
    assert "matrix" not in job.get("strategy", {}), "The native harness already qualifies all three topologies"
    assert job["if"] == jobs["nightly"]["if"], "Native qualification must run for every active nightly"


def test_native_nightly_failure_reaches_the_existing_scheduled_failure_notification() -> None:
    jobs, native = native_nightly_jobs()
    assert set(native) <= set(jobs["notify-scheduled-failure"]["needs"])


def test_required_integration_check_waits_for_parallel_native_and_general_suites() -> None:
    jobs = yaml.safe_load((ROOT / ".github/workflows/integration.yml").read_text())["jobs"]
    native = {
        name for name, job in jobs.items()
        if any("make test-native-deploy" in step.get("run", "") for step in job.get("steps", []))
    }
    general = {
        name for name, job in jobs.items()
        if any("make test-integration" in step.get("run", "") for step in job.get("steps", []))
    }
    assert native.isdisjoint(general), "Serial native qualification needlessly consumes the merge queue deadline"
    assert len(native) == len(general) == 1
    gate = jobs["integration-test"]
    assert set(gate["needs"]) == native | general
    assert gate["if"] == "always()", "Failure and skip results must reach the required gate"
    assert all(not jobs[name].get("needs") for name in native | general)
    for name in native | general:
        job = jobs[name]
        assert "if" not in job and "continue-on-error" not in job
        for step in job["steps"]:
            assert "continue-on-error" not in step
            assert step.get("if") in (None, "always()"), "Upstream work must not silently skip"


@pytest.mark.parametrize("general", ["success", "failure", "cancelled", "skipped"])
@pytest.mark.parametrize("native", ["success", "failure", "cancelled", "skipped"])
def test_required_integration_gate_only_passes_when_both_real_jobs_succeed(general: str, native: str) -> None:
    gate = yaml.safe_load((ROOT / ".github/workflows/integration.yml").read_text())["jobs"]["integration-test"]
    results = {"integration-suite": general, "native-deploy": native}
    environment = dict(os.environ)
    for name, expression in gate["env"].items():
        binding = re.fullmatch(r"\$\{\{\s*needs\.([\w-]+)\.result\s*\}\}", expression)
        assert binding is not None, "The gate must consume actual upstream job results"
        environment[name] = results[binding[1]]
    script = "\n".join(step["run"] for step in gate["steps"] if "run" in step)
    completed = subprocess.run(  # noqa: S603 -- Execute the repository-owned gate, not caller-provided shell text.
        ["/bin/bash", "-euc", script], env=environment, capture_output=True, check=False
    )
    assert (completed.returncode == 0) is (general == native == "success")
