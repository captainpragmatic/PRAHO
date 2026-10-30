"""The release candidate vouches only for a commit the merge queue tested with every required check.

scripts/verify_release_candidate.py decides from GitHub's run and job data; these tests drive its
decisions with fixtures shaped like that data, and its lookups with a stand-in for the GitHub API.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from scripts.verify_release_candidate import (
    VerificationError,
    check_conclusions,
    failed_checks,
    required_contexts,
    verify,
)

pytestmark = pytest.mark.integration

PLATFORM = ".github/workflows/platform.yml"
LAB = ".github/workflows/virtualmin-lab-pr.yml"
CONTEXTS = ["coverage-gate", "pull-request"]


def run(run_id: int, path: str, conclusion: str = "success", **jobs: str) -> dict[str, Any]:
    named = [{"name": name.replace("_", "-"), "conclusion": c} for name, c in jobs.items()]
    return {"id": run_id, "path": path, "conclusion": conclusion, "jobs": named}


def green_runs() -> list[dict[str, Any]]:
    return [run(1, PLATFORM, coverage_gate="success"), run(2, LAB, changes="success", pull_request="success")]


def test_every_required_check_green_passes() -> None:
    assert failed_checks(CONTEXTS, check_conclusions(green_runs())) == []


@pytest.mark.parametrize("conclusion", ["failure", "cancelled", "timed_out", "action_required", "None"])
def test_a_check_that_did_not_succeed_fails(conclusion: str) -> None:
    runs = [run(1, PLATFORM, coverage_gate=conclusion), run(2, LAB, changes="success", pull_request="success")]

    assert failed_checks(CONTEXTS, check_conclusions(runs)) == [f"coverage-gate: {conclusion} ({PLATFORM})"]


def test_a_check_that_never_reported_fails() -> None:
    runs = [run(2, LAB, changes="success", pull_request="success")]

    assert failed_checks(CONTEXTS, check_conclusions(runs)) == ["coverage-gate: never reported"]


def test_the_newest_run_of_a_workflow_decides() -> None:
    newer_failure = run(3, PLATFORM, coverage_gate="failure")
    # GitHub lists runs newest first, but the decision must not depend on the order.
    for runs in ([newer_failure, *green_runs()], [*green_runs(), newer_failure]):
        assert failed_checks(CONTEXTS, check_conclusions(runs)) == [f"coverage-gate: failure ({PLATFORM})"]


def test_the_same_check_name_from_two_workflows_is_ambiguous() -> None:
    runs = [*green_runs(), run(4, ".github/workflows/other.yml", coverage_gate="success")]

    assert failed_checks(CONTEXTS, check_conclusions(runs)) == ["coverage-gate: reported by several workflows"]


def test_the_lab_may_skip_only_when_its_own_selection_succeeded() -> None:
    skipped = [run(1, PLATFORM, coverage_gate="success"), run(2, LAB, changes="success", pull_request="skipped")]
    assert failed_checks(CONTEXTS, check_conclusions(skipped)) == []

    failed_selection = [run(1, PLATFORM, coverage_gate="success"), run(2, LAB, changes="failure", pull_request="skipped")]
    assert failed_checks(CONTEXTS, check_conclusions(failed_selection)) == [f"pull-request: skipped ({LAB})"]

    # Cancelled after `changes` chose the lab: the lab job is skipped too, and must not count as a pass.
    cancelled = [run(1, PLATFORM, coverage_gate="success"), run(2, LAB, "cancelled", changes="success", pull_request="skipped")]
    assert failed_checks(CONTEXTS, check_conclusions(cancelled)) == [f"pull-request: skipped ({LAB})"]


def test_only_the_lab_may_skip() -> None:
    runs = [run(1, PLATFORM, coverage_gate="skipped"), run(2, LAB, changes="success", pull_request="success")]

    assert failed_checks(CONTEXTS, check_conclusions(runs)) == [f"coverage-gate: skipped ({PLATFORM})"]


def test_a_ruleset_without_required_checks_refuses() -> None:
    with pytest.raises(VerificationError):
        required_contexts({"rules": [{"type": "deletion"}]})


def test_the_committed_ruleset_is_read() -> None:
    ruleset = json.loads((Path(__file__).resolve().parents[2] / ".github/rulesets/master.json").read_text())
    assert "coverage-gate" in required_contexts(ruleset)


SHA = "a" * 40
REQUIRED = required_contexts(
    json.loads((Path(__file__).resolve().parents[2] / ".github/rulesets/master.json").read_text())
)


def nightly(  # noqa: PLR0913  # One fixture field per fact a run can carry
    run_id: int,
    full: str,
    branch: str = "master",
    activity: str = "success",
    conclusion: str = "success",
    drift: str = "skipped",
    jobs: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """A completed nightly lab run: ``full`` is its nightly-full job, ``activity`` its check-activity job,
    ``drift`` its nightly-drift job (it runs only on the drift schedule), ``conclusion`` the run's own."""
    if jobs is None:
        jobs = [
            {"name": "check-activity", "conclusion": activity},
            {"name": "nightly-full", "conclusion": full},
            # Drift is a matrix job: GitHub names each leg after its runner.
            {"name": "nightly-drift (ubuntu-latest)", "conclusion": drift},
            {"name": "nightly-drift (ubuntu-24.04-arm)", "conclusion": drift},
        ]
    return {"id": run_id, "head_branch": branch, "conclusion": conclusion, "jobs": jobs}


class FakeGitHub:
    """Answers the lookups verify() makes, and records them."""

    def __init__(self, runs: list[dict[str, Any]], nightly_runs: list[dict[str, Any]] | None = None) -> None:
        self.runs = runs
        self.nightly_runs = [nightly(900, "success")] if nightly_runs is None else nightly_runs
        self.paths: list[str] = []

    def __call__(self, path: str) -> Any:
        self.paths.append(path)
        every = self.runs + self.nightly_runs
        if "/jobs?" in path:
            run_id = int(path.split("/runs/")[1].split("/")[0])
            return {"jobs": next(run["jobs"] for run in every if run["id"] == run_id)}
        if "workflows/virtualmin-lab.yml/runs" in path:
            # GitHub pages a listing; three runs a page here, so a test can reach page two.
            page = int(path.rsplit("page=", maxsplit=1)[-1]) if "&page=" in path else 1
            listed = self.nightly_runs[(page - 1) * 3 : page * 3]
        else:
            listed = self.runs
        return {"workflow_runs": [{key: value for key, value in run.items() if key != "jobs"} for run in listed]}


def all_green() -> list[dict[str, Any]]:
    jobs = [{"name": context, "conclusion": "success"} for context in REQUIRED]
    return [{"id": 7, "path": PLATFORM, "conclusion": "success", "jobs": jobs}]


def test_a_commit_the_queue_tested_green_is_vouched_for() -> None:
    github = FakeGitHub(all_green())

    assert SHA in verify(SHA, "owner/repo", github)
    # The candidate's own merge_group runs decide, not its pull request's.
    assert github.paths[0] == f"repos/owner/repo/actions/runs?head_sha={SHA}&event=merge_group&per_page=100"


def test_a_commit_merged_around_the_queue_is_refused() -> None:
    with pytest.raises(VerificationError, match="never tested"):
        verify(SHA, "owner/repo", FakeGitHub([]))


def test_a_red_check_in_the_queue_is_refused() -> None:
    runs = all_green()
    runs[0]["jobs"][0]["conclusion"] = "failure"

    with pytest.raises(VerificationError, match=f"{runs[0]['jobs'][0]['name']}: failure"):
        verify(SHA, "owner/repo", FakeGitHub(runs))


def test_the_latest_full_nightly_lab_must_have_passed() -> None:
    # The release candidate runs no lab of its own: the queue ran the lab suites on the candidate,
    # and the nightly full lab covers node deploy, faults and browser tests on master.
    with pytest.raises(VerificationError, match="full Virtualmin lab"):
        verify(SHA, "owner/repo", FakeGitHub(all_green(), [nightly(902, "failure"), nightly(901, "success")]))


def test_nightly_runs_that_skipped_the_full_lab_are_passed_over() -> None:
    # check-activity skips the full lab on a day without changes: the last run that ran it decides.
    green = FakeGitHub(all_green(), [nightly(903, "skipped"), nightly(902, "success")])
    assert SHA in verify(SHA, "owner/repo", green)
    red = FakeGitHub(all_green(), [nightly(903, "skipped"), nightly(902, "failure")])
    with pytest.raises(VerificationError, match="full Virtualmin lab"):
        verify(SHA, "owner/repo", red)


def test_a_full_lab_run_on_another_branch_does_not_count() -> None:
    github = FakeGitHub(all_green(), [nightly(904, "success", branch="feature")])
    with pytest.raises(VerificationError, match="full Virtualmin lab"):
        verify(SHA, "owner/repo", github)


def test_no_full_lab_on_record_is_refused() -> None:
    with pytest.raises(VerificationError, match="full Virtualmin lab"):
        verify(SHA, "owner/repo", FakeGitHub(all_green(), []))


def test_a_failed_selection_is_not_a_quiet_night() -> None:
    # check-activity failing skips the full lab too: that night was interrupted, not uneventful.
    for activity in ("failure", "cancelled"):
        github = FakeGitHub(all_green(), [nightly(906, "skipped", activity=activity), nightly(905, "success")])
        with pytest.raises(VerificationError, match="full Virtualmin lab"):
            verify(SHA, "owner/repo", github)


def test_a_drift_run_is_passed_over_whatever_its_outcome() -> None:
    # Drift tests the latest Virtualmin packages: informational, never a release gate.
    for drift, conclusion in (("success", "success"), ("failure", "failure")):
        run = nightly(907, "skipped", activity="skipped", drift=drift, conclusion=conclusion)
        assert SHA in verify(SHA, "owner/repo", FakeGitHub(all_green(), [run, nightly(905, "success")]))


def test_a_cancelled_night_is_not_a_quiet_one() -> None:
    cancelled_after_selection = nightly(908, "skipped", activity="success", conclusion="cancelled")
    cancelled_before_jobs = nightly(909, "skipped", conclusion="cancelled", jobs=[])
    for run in (cancelled_after_selection, cancelled_before_jobs):
        with pytest.raises(VerificationError, match="full Virtualmin lab"):
            verify(SHA, "owner/repo", FakeGitHub(all_green(), [run, nightly(905, "success")]))


def test_the_last_full_lab_is_found_beyond_the_first_page() -> None:
    quiet = [nightly(920 - n, "skipped") for n in range(4)]  # quiet nights fill page one and part of two
    github = FakeGitHub(all_green(), [*quiet, nightly(900, "success")])
    assert "run 900" in verify(SHA, "owner/repo", github)
