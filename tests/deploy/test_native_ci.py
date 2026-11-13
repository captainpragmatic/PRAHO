"""Native qualification must use its own harness when nightly checks older app refs."""

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
    assert len(native) == 1, "Every active nightly run must qualify native deployment in one job's shards"
    return jobs, native


def test_native_nightly_uses_workflow_harness_when_staging_predates_the_make_targets() -> None:
    jobs, native = native_nightly_jobs()
    job = next(iter(native.values()))
    checkout = next(step for step in job["steps"] if step.get("uses", "").startswith("actions/checkout@"))
    assert checkout["with"]["ref"] == "${{ github.workflow_sha }}", (
        "Older app refs cannot supply the new native harness"
    )
    assert job["if"] == jobs["nightly"]["if"], "Native qualification must run for every active nightly"


def test_native_nightly_runs_the_shards_in_parallel_like_the_release_candidate() -> None:
    # tests/integration/test_verify_release_candidate.py proves the shard list is the verifier's; the
    # profiles together run every case once (tests/deploy/test_native_profiles.py).
    _jobs, native = native_nightly_jobs()
    job = next(iter(native.values()))
    assert job["strategy"]["fail-fast"] is False, "one failed shard must not cancel the others' evidence"
    assert job["env"]["PRAHO_NATIVE_ACCEPTANCE_PROFILE"] == "${{ matrix.profile }}"
    assert "continue-on-error" not in job
    for step in job["steps"]:
        assert "continue-on-error" not in step
        infrastructure = step.get("run") == "make test-native-infra" or step.get("uses", "").startswith(
            "hashicorp/setup-terraform@"
        )
        assert step.get("if") == ("matrix.profile == 'combined-prod'" if infrastructure else None), step


def test_the_master_nightly_tests_exactly_the_commit_its_run_names() -> None:
    # The release candidate credits a nightly step to the run's head_sha, so the master leg must check out
    # that exact commit, not whatever the branch points at when the job starts (or is re-run).
    jobs = yaml.safe_load((ROOT / ".github/workflows/nightly.yml").read_text())["jobs"]
    checkout = next(step for step in jobs["nightly"]["steps"] if step.get("uses", "").startswith("actions/checkout@"))
    assert checkout["with"]["ref"] == "${{ matrix.branch == 'master' && github.sha || matrix.branch }}"
    # The release verifier recognises a pinned nightly by this exact text in the commit's nightly.yml.
    from scripts.verify_release_candidate import NIGHTLY_CHECKOUT_PIN  # noqa: PLC0415

    assert NIGHTLY_CHECKOUT_PIN in (ROOT / ".github/workflows/nightly.yml").read_text()


def test_native_nightly_failure_reaches_the_existing_scheduled_failure_notification() -> None:
    jobs, native = native_nightly_jobs()
    assert set(native) <= set(jobs["notify-scheduled-failure"]["needs"])


def test_native_qualification_runs_nightly_and_in_the_release_candidate_not_the_merge_queue() -> None:
    # The queue no longer carries native deploy (ADR-0036): the nightly qualifies master, and a release
    # candidate reuses that proof for its exact commit or runs the shards on the candidate (rc-native).
    integration = yaml.safe_load((ROOT / ".github/workflows/integration.yml").read_text())["jobs"]
    assert not [name for name, job in integration.items() if "test-native" in str(job.get("steps", []))]
    assert set(integration["integration-test"]["needs"]) == {"integration-suite"}

    rc = yaml.safe_load((ROOT / ".github/workflows/release-candidate.yml").read_text())["jobs"]["rc-native"]
    assert "continue-on-error" not in rc

    # The infrastructure check is not profile-specific: exactly one matrix entry runs it. Only those two
    # steps may carry that condition; the acceptance itself runs in every entry.
    def infrastructure(step: dict) -> bool:
        return step.get("run") == "make test-native-infra" or step.get("uses", "").startswith(
            "hashicorp/setup-terraform@"
        )

    for step in rc["steps"]:
        assert "continue-on-error" not in step
        if infrastructure(step):
            assert step.get("if") == "matrix.profile == 'combined-prod'"
        else:
            assert "if" not in step, "Upstream work must not silently skip"
    acceptance = [step for step in rc["steps"] if step.get("run") == "make test-native-deploy"]
    assert len(acceptance) == 1


def test_native_ci_qualifies_each_topology_in_parallel_with_no_missing_profile() -> None:
    native = yaml.safe_load((ROOT / ".github/workflows/release-candidate.yml").read_text())["jobs"]["rc-native"]
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
