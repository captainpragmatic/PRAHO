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
        name: job
        for name, job in jobs.items()
        if any("make test-native-deploy" in step.get("run", "") for step in job.get("steps", []))
    }
    assert len(native) == 1, "Every active nightly run must qualify native deployment exactly once"
    return jobs, native


def test_native_nightly_uses_workflow_harness_when_staging_predates_the_make_targets() -> None:
    jobs, native = native_nightly_jobs()
    job = next(iter(native.values()))
    checkout = next(step for step in job["steps"] if step.get("uses", "").startswith("actions/checkout@"))
    assert checkout["with"]["ref"] == "${{ github.workflow_sha }}", (
        "Older app refs cannot supply the new native harness"
    )
    assert "matrix" not in job.get("strategy", {}), "The native harness already qualifies all three topologies"
    assert job["if"] == jobs["nightly"]["if"], "Native qualification must run for every active nightly"


def test_native_nightly_failure_reaches_the_existing_scheduled_failure_notification() -> None:
    jobs, native = native_nightly_jobs()
    assert set(native) <= set(jobs["notify-scheduled-failure"]["needs"])


def test_required_integration_check_waits_for_parallel_native_and_general_suites() -> None:
    jobs = yaml.safe_load((ROOT / ".github/workflows/integration.yml").read_text())["jobs"]
    native = {
        name
        for name, job in jobs.items()
        if any("make test-native-deploy" in step.get("run", "") for step in job.get("steps", []))
    }
    general = {
        name
        for name, job in jobs.items()
        if any("make test-integration" in step.get("run", "") for step in job.get("steps", []))
    }
    assert native.isdisjoint(general), "Serial native qualification needlessly consumes the merge queue deadline"
    assert len(native) == len(general) == 1
    (native_job,) = native
    gate = jobs["integration-test"]
    assert set(gate["needs"]) == native | general | {"native-changes"}
    assert gate["if"] == "always()", "Failure and skip results must reach the required gate"
    assert all(not jobs[name].get("needs") for name in general)
    # The native jobs may skip only by their selection, which fails open (scripts/ci_native_needed.py).
    assert jobs[native_job]["needs"] == "native-changes"
    assert jobs[native_job]["if"] == "!cancelled() && needs.native-changes.outputs.native != 'false'"
    assert "if" not in jobs["native-changes"] and not jobs["native-changes"].get("needs")

    # The infrastructure check is not profile-specific: exactly one matrix entry runs it. Only those two
    # steps may carry that condition; the acceptance itself runs in every entry.
    def infrastructure(step: dict) -> bool:
        return step.get("run") == "make test-native-infra" or step.get("uses", "").startswith(
            "hashicorp/setup-terraform@"
        )

    for name in native | general:
        job = jobs[name]
        assert "continue-on-error" not in job
        for step in job["steps"]:
            assert "continue-on-error" not in step
            if name == native_job and infrastructure(step):
                assert step.get("if") == "matrix.profile == 'combined-prod'"
            else:
                assert step.get("if") in (None, "always()"), "Upstream work must not silently skip"
    acceptance = [step for step in jobs[native_job]["steps"] if step.get("run") == "make test-native-deploy"]
    assert len(acceptance) == 1 and "if" not in acceptance[0]


def test_native_ci_qualifies_each_topology_in_parallel_with_no_missing_profile() -> None:
    native = yaml.safe_load((ROOT / ".github/workflows/integration.yml").read_text())["jobs"]["native-deploy"]
    strategy = native.get("strategy", {})
    # The split cases run as shards; tests/deploy/test_native_profiles.py proves the matrix covers every case once.
    assert strategy.get("matrix", {}).get("profile") == [
        "split-prod-1",
        "split-prod-2",
        "split-prod-3",
        "split-prod-4",
        "combined-staging",
        "combined-prod",
    ]
    assert strategy.get("fail-fast") is False
    assert native.get("env", {}).get("PRAHO_NATIVE_ACCEPTANCE_PROFILE") == "${{ matrix.profile }}"


@pytest.mark.parametrize("workflow", ["integration.yml", "nightly.yml"])
def test_general_integration_installs_the_pinned_transport_collection_before_tests(workflow: str) -> None:
    jobs = yaml.safe_load((ROOT / ".github/workflows" / workflow).read_text())["jobs"]
    matching = [
        job
        for job in jobs.values()
        if any("make test-integration" in step.get("run", "") for step in job.get("steps", []))
    ]
    assert len(matching) == 1
    commands = [step.get("run", "") for step in matching[0]["steps"]]
    tests = next(index for index, command in enumerate(commands) if "make test-integration" in command)
    install = [
        index
        for index, command in enumerate(commands)
        if "ansible-galaxy" in command and "ansible.posix:2.2.0" in command
    ]
    assert len(install) == 1 and install[0] < tests, "A fresh runner has ansible-core but no transport collection"


@pytest.mark.parametrize("selection", ["success", "failure", "cancelled", "skipped"])
@pytest.mark.parametrize("selected", ["true", "false", ""])
@pytest.mark.parametrize("general", ["success", "failure", "cancelled", "skipped"])
@pytest.mark.parametrize("native", ["success", "failure", "cancelled", "skipped"])
def test_required_integration_gate_only_passes_when_both_real_jobs_succeed(
    general: str, native: str, selected: str, selection: str
) -> None:
    gate = yaml.safe_load((ROOT / ".github/workflows/integration.yml").read_text())["jobs"]["integration-test"]
    # The selection's status and its answer vary independently: an answer of false from a selection that
    # then failed, was cancelled or skipped can never excuse a native skip.
    results = {"integration-suite": general, "native-deploy": native, "native-changes": selection}
    outputs = {("native-changes", "native"): selected}
    environment = dict(os.environ)
    for name, expression in gate["env"].items():
        result = re.fullmatch(r"\$\{\{\s*needs\.([\w-]+)\.result\s*\}\}", expression)
        output = re.fullmatch(r"\$\{\{\s*needs\.([\w-]+)\.outputs\.([\w-]+)\s*\}\}", expression)
        assert result or output, "The gate must consume actual upstream job results"
        environment[name] = results[result[1]] if result else outputs[(output[1], output[2])]
    script = "\n".join(step["run"] for step in gate["steps"] if "run" in step)
    completed = subprocess.run(  # noqa: S603 -- Execute the repository-owned gate, not caller-provided shell text.
        ["/bin/bash", "-euc", script], env=environment, capture_output=True, check=False
    )
    deliberately_skipped = native == "skipped" and selected == "false" and selection == "success"
    assert (completed.returncode == 0) is (general == "success" and (native == "success" or deliberately_skipped))
