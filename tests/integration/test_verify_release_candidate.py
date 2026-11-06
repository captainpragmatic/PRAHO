"""The release candidate vouches only for a commit the merge queue tested with every required check.

scripts/verify_release_candidate.py decides from GitHub's run and job data; these tests drive its
decisions with fixtures shaped like that data, and its lookups with a stand-in for the GitHub API.
"""

from __future__ import annotations

import base64
import json
from pathlib import Path
from typing import Any

import pytest

from scripts.verify_release_candidate import (
    NIGHTLY_CHECKOUT_PIN,
    RELEASE_SCOPES,
    VerificationError,
    check_conclusions,
    failed_checks,
    pick_candidate,
    release_evidence,
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

    failed_selection = [
        run(1, PLATFORM, coverage_gate="success"),
        run(2, LAB, changes="failure", pull_request="skipped"),
    ]
    assert failed_checks(CONTEXTS, check_conclusions(failed_selection)) == [f"pull-request: skipped ({LAB})"]

    # Cancelled after `changes` chose the lab: the lab job is skipped too, and must not count as a pass.
    cancelled = [
        run(1, PLATFORM, coverage_gate="success"),
        run(2, LAB, "cancelled", changes="success", pull_request="skipped"),
    ]
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
OTHER = "b" * 40
REQUIRED = required_contexts(
    json.loads((Path(__file__).resolve().parents[2] / ".github/rulesets/master.json").read_text())
)
POSTGRES_STEP = "Whole platform suite on PostgreSQL"
INTEGRATION_STEP = "Integration tests"


def step(name: str, conclusion: str = "success") -> dict[str, Any]:
    return {"name": name, "conclusion": conclusion}


def nightly_run(  # noqa: PLR0913  # One fixture field per fact a nightly run can carry
    run_id: int,
    sha: str = SHA,
    *,
    branch: str = "master",
    postgres: str = "success",
    integration: str = "success",
    native: str = "success",
    full: str = "success",
) -> dict[str, Any]:
    """A nightly.yml run: the matrix job "nightly (master)" and the native job."""
    return {
        "id": run_id,
        "workflow": "nightly.yml",
        "head_sha": sha,
        "head_branch": branch,
        "conclusion": "success",
        "updated_at": f"2026-11-01T00:{run_id % 60:02d}:00Z",
        "jobs": [
            {
                "name": "nightly (master)",
                "conclusion": full,
                "steps": [step(POSTGRES_STEP, postgres), step(INTEGRATION_STEP, integration)],
            },
            {"name": "nightly-native-deploy", "conclusion": native, "steps": []},
        ],
    }


def lab_run(
    run_id: int, sha: str = SHA, *, outcome: str = "success", job: str = "nightly-containers"
) -> dict[str, Any]:
    return {
        "id": run_id,
        "workflow": "virtualmin-lab.yml",
        "head_sha": sha,
        "head_branch": "master",
        "conclusion": outcome,
        "jobs": [{"name": job, "conclusion": outcome, "steps": []}],
    }


class FakeGitHub:
    """Answers the lookups the verifier makes, and records them."""

    def __init__(
        self, runs: list[dict[str, Any]], evidence: list[dict[str, Any]] | None = None, *, pinned: bool = True
    ) -> None:
        self.runs = runs
        self.pinned = pinned
        self.evidence = [nightly_run(900), lab_run(901)] if evidence is None else evidence
        self.paths: list[str] = []

    def __call__(self, path: str) -> Any:
        self.paths.append(path)
        every = self.runs + self.evidence
        if "/contents/.github/workflows/nightly.yml" in path:
            text = NIGHTLY_CHECKOUT_PIN if self.pinned else "ref: ${{ matrix.branch }}"
            return {"encoding": "base64", "content": base64.b64encode(text.encode()).decode()}
        if "/jobs?" in path:
            run_id = int(path.split("/runs/")[1].split("/")[0])
            return {"jobs": next(run["jobs"] for run in every if run["id"] == run_id)}
        if "/actions/workflows/" in path:
            workflow = path.split("/actions/workflows/")[1].split("/")[0]
            listed = [run for run in self.evidence if run["workflow"] == workflow]
            if "head_sha=" in path:
                sha = path.split("head_sha=")[1].split("&")[0]
                listed = [run for run in listed if run["head_sha"] == sha]
            if "branch=" in path:
                branch = path.split("branch=")[1].split("&")[0]
                listed = [run for run in listed if run["head_branch"] == branch]
        else:
            # The merge_group lookup filters by commit, like GitHub's; a fixture run without one matches any.
            sha = path.split("head_sha=")[1].split("&")[0] if "head_sha=" in path else None
            listed = [run for run in self.runs if sha is None or run.get("head_sha", sha) == sha]
        return {"workflow_runs": [{key: value for key, value in run.items() if key != "jobs"} for run in listed]}


def all_green() -> list[dict[str, Any]]:
    jobs = [{"name": context, "conclusion": "success"} for context in REQUIRED]
    return [{"id": 7, "path": PLATFORM, "conclusion": "success", "jobs": jobs}]


def decisions(evidence: list[dict[str, Any]], sha: str = SHA, *, pinned: bool = True) -> dict[str, str]:
    github = FakeGitHub([], evidence, pinned=pinned)
    return {scope: answer.split()[0] for scope, answer in release_evidence(sha, "owner/repo", github).items()}


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


def test_the_queue_check_no_longer_depends_on_the_lab() -> None:
    # Release-scope suites are decided per scope by release_evidence, never by the queue verdict.
    assert SHA in verify(SHA, "owner/repo", FakeGitHub(all_green(), evidence=[]))


def test_every_scope_is_reused_from_nightly_runs_on_the_exact_candidate() -> None:
    answers = release_evidence(SHA, "owner/repo", FakeGitHub([], [nightly_run(910), lab_run(911)]))
    assert set(answers) == set(RELEASE_SCOPES) == {"postgres", "crowdsec", "native", "lab"}
    assert answers == {
        "postgres": "reuse 910",
        "crowdsec": "reuse 910",
        "native": "reuse 910",
        "lab": "reuse 911",
    }


def test_evidence_from_another_commit_or_branch_never_counts() -> None:
    assert set(decisions([nightly_run(912, OTHER), lab_run(913, OTHER)]).values()) == {"run"}
    assert set(decisions([nightly_run(914, branch="staging")]).values()) == {"run"}
    assert set(decisions([]).values()) == {"run"}


@pytest.mark.parametrize(
    ("field", "scope"), [("postgres", "postgres"), ("integration", "crowdsec"), ("native", "native")]
)
@pytest.mark.parametrize("outcome", ["failure", "cancelled", "skipped"])
def test_a_scope_whose_proof_did_not_succeed_must_run(field: str, scope: str, outcome: str) -> None:
    answers = decisions([nightly_run(915, **{field: outcome}), lab_run(916)])
    assert answers[scope] == "run"
    assert answers["lab"] == "reuse"


def test_an_unrelated_failed_step_does_not_void_a_proven_step() -> None:
    # Lint failing in the same nightly job must not throw away a passed PostgreSQL suite: the step is the proof.
    run = nightly_run(926, full="failure")
    run["jobs"][0]["steps"].insert(0, step("Full lint (every make lint phase)", "failure"))
    answers = decisions([run, lab_run(927)])
    assert answers["postgres"] == "reuse" and answers["crowdsec"] == "reuse"


def test_a_whole_job_scope_still_needs_the_job_to_succeed() -> None:
    assert decisions([nightly_run(928, native="failure"), lab_run(929)])["native"] == "run"


def test_a_missing_step_is_no_proof() -> None:
    run = nightly_run(917)
    run["jobs"][0]["steps"] = [step(INTEGRATION_STEP)]
    answers = decisions([run, lab_run(918)])
    assert answers["postgres"] == "run" and answers["crowdsec"] == "reuse"


def test_a_failed_lab_run_on_the_candidate_must_run() -> None:
    for outcome in ("failure", "cancelled", "skipped"):
        assert decisions([nightly_run(919), lab_run(920, outcome=outcome)])["lab"] == "run"


def test_an_older_run_of_the_same_commit_can_still_prove_a_scope() -> None:
    # A later dispatch on the same commit that skipped the job says nothing, so the earlier proof stands.
    newer = nightly_run(922, native="skipped")
    older = nightly_run(921)
    assert decisions([newer, older, lab_run(923)])["native"] == "reuse"


def test_the_newest_run_that_ran_a_scope_decides() -> None:
    # A later run on the same commit that failed the scope outweighs an earlier pass.
    newer = nightly_run(936, postgres="failure")
    older = nightly_run(935)
    assert decisions([newer, older, lab_run(937)])["postgres"] == "run"
    newer_lab, older_lab = lab_run(939, outcome="failure"), lab_run(938)
    assert decisions([nightly_run(940), newer_lab, older_lab])["lab"] == "run"


def test_a_rerun_that_failed_after_a_newer_pass_decides() -> None:
    # Run 945 passed; run 944 was then re-run and failed: the latest execution decides, not the run ID.
    passed = nightly_run(945)
    rerun = {**nightly_run(944, postgres="failure"), "updated_at": "2026-11-02T09:00:00Z"}
    assert decisions([passed, rerun, lab_run(946)])["postgres"] == "run"


@pytest.mark.parametrize("order", ["pass first", "fail first"])
def test_any_failed_execution_on_the_commit_means_run(order: str) -> None:
    # No ordering decides: an older run that finished last with an earlier pass cannot hide a failure.
    passed = {**nightly_run(950), "updated_at": "2026-11-02T10:00:00Z"}
    failed = {**nightly_run(951, postgres="failure"), "updated_at": "2026-11-02T09:30:00Z"}
    runs = [passed, failed] if order == "pass first" else [failed, passed]
    assert decisions([*runs, lab_run(952)])["postgres"] == "run"


def test_step_evidence_needs_the_pinned_nightly_checkout() -> None:
    # Before the master leg checked out github.sha, a nightly could test a later master than its head_sha.
    answers = decisions([nightly_run(947), lab_run(948)], pinned=False)
    assert answers["postgres"] == "run" and answers["crowdsec"] == "run"
    assert answers["native"] == "reuse" and answers["lab"] == "reuse"


def test_the_lab_under_its_earlier_job_name_still_counts() -> None:
    assert decisions([nightly_run(924), lab_run(925, job="nightly-full")])["lab"] == "reuse"


def test_the_newest_fully_proven_master_commit_is_picked() -> None:
    evidence = [nightly_run(931, OTHER, native="failure"), lab_run(932, OTHER), nightly_run(929), lab_run(930)]
    assert pick_candidate("owner/repo", FakeGitHub(all_green(), evidence)) == SHA


def test_a_proven_commit_the_queue_did_not_vouch_for_is_skipped() -> None:
    # OTHER is fully proven but has no merge_group runs (merged around the queue); SHA is next.
    evidence = [nightly_run(942, OTHER), lab_run(943, OTHER), nightly_run(940), lab_run(941)]
    queue = [{**run, "head_sha": SHA} for run in all_green()]
    assert pick_candidate("owner/repo", FakeGitHub(queue, evidence)) == SHA


def test_no_fully_proven_commit_refuses_to_pick() -> None:
    with pytest.raises(VerificationError, match="nightly"):
        pick_candidate("owner/repo", FakeGitHub([], [nightly_run(933, native="failure"), lab_run(934)]))
