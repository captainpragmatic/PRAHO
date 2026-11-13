"""The release candidate vouches only for a commit the merge queue tested with every required check.

scripts/verify_release_candidate.py decides from GitHub's run and job data; these tests drive its
decisions with fixtures shaped like that data, and its lookups with a stand-in for the GitHub API.
"""

from __future__ import annotations

import base64
import json
import re
import shlex
from pathlib import Path
from typing import Any

import pytest
import yaml

from scripts.verify_release_candidate import (
    NATIVE_PROFILES,
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
    shards: dict[str, str] | None = None,
) -> dict[str, Any]:
    """A nightly.yml run: the matrix job "nightly (master)" and the native shard jobs.

    ``shards`` maps a profile to its outcome, overriding ``native``; ``None`` as an outcome leaves it out."""
    outcomes = dict.fromkeys(NATIVE_PROFILES, native) | (shards or {})
    native_jobs = [
        {"name": f"nightly-native-deploy ({profile})", "conclusion": outcome, "steps": []}
        for profile, outcome in outcomes.items()
        if outcome is not None
    ]
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
            *native_jobs,
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
            run = next(run for run in every if run["id"] == run_id)
            # GitHub's filter=latest hides earlier attempts of a re-run; filter=all lists them too.
            jobs = run.get("earlier_attempts", []) + run["jobs"] if "filter=all" in path else run["jobs"]
            return {"total_count": run.get("total_jobs", len(jobs)), "jobs": jobs}
        if "/actions/workflows/" in path:
            workflow = path.split("/actions/workflows/")[1].split("/")[0]
            listed = [run for run in self.evidence if run["workflow"] == workflow]
            if "head_sha=" in path:
                sha = path.split("head_sha=")[1].split("&")[0]
                listed = [run for run in listed if run["head_sha"] == sha]
            if "branch=" in path:
                branch = path.split("branch=")[1].split("&")[0]
                listed = [run for run in listed if run["head_branch"] == branch]
            if "status=" in path:
                status = path.split("status=")[1].split("&")[0]
                listed = [run for run in listed if run.get("status", "completed") == status]
            if "per_page=" in path:
                listed = sorted(listed, key=lambda run: int(run["id"]), reverse=True)
                listed = listed[: int(path.split("per_page=")[1].split("&")[0])]
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


def test_a_failed_earlier_attempt_of_a_rerun_still_counts() -> None:
    rerun = nightly_run(953)
    rerun["earlier_attempts"] = [
        {"name": "nightly (master)", "conclusion": "failure", "steps": [step(POSTGRES_STEP, "failure")]}
    ]
    assert decisions([rerun, lab_run(954)])["postgres"] == "run"


def test_a_truncated_history_is_no_proof(monkeypatch: pytest.MonkeyPatch) -> None:
    # A full page may hide an older failure on the commit beyond it, so a full page answers `run`.
    monkeypatch.setattr("scripts.verify_release_candidate._EVIDENCE_RUNS", 2)
    evidence = [nightly_run(957), nightly_run(956), nightly_run(955, postgres="failure"), lab_run(958)]
    assert decisions(evidence)["postgres"] == "run"
    assert decisions([nightly_run(959), lab_run(960)])["postgres"] == "reuse"


def test_a_run_still_in_progress_on_the_commit_is_no_proof() -> None:
    # A re-run in progress keeps its failed earlier attempt; a finished green run must not outvote it.
    rerun = {**nightly_run(963, postgres="failure"), "status": "in_progress"}
    answers = decisions([rerun, nightly_run(964), lab_run(965)])
    assert answers["postgres"] == "run" and answers["native"] == "run" and answers["lab"] == "reuse"


def test_an_incomplete_job_history_is_no_proof() -> None:
    # More jobs than one page returned: a failed attempt may sit on a page not read.
    run = {**nightly_run(961), "total_jobs": 150}
    answers = decisions([run, lab_run(962)])
    assert answers["postgres"] == "run" and answers["native"] == "run" and answers["lab"] == "reuse"


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


def test_pick_runs_from_a_local_checkout_without_the_actions_environment(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    # Outside Actions, GITHUB_REPOSITORY is unset: gh resolves {owner}/{repo} from the checkout's remote.
    import scripts.verify_release_candidate as module  # noqa: PLC0415  # patch the name main() calls

    monkeypatch.delenv("GITHUB_REPOSITORY", raising=False)
    seen: list[str] = []
    monkeypatch.setattr(module, "pick_candidate", lambda repo: seen.append(repo) or SHA)
    assert module.main(["verify_release_candidate.py", "--pick"]) == 0
    assert seen == ["{owner}/{repo}"] and capsys.readouterr().out.strip() == SHA


def test_native_is_reused_only_when_every_shard_of_one_run_passed() -> None:
    assert decisions([nightly_run(970), lab_run(971)])["native"] == "reuse"
    for profile in NATIVE_PROFILES:
        # One shard missing (a smaller matrix covers less) or failed: the native scope must run.
        assert decisions([nightly_run(972, shards={profile: None}), lab_run(973)])["native"] == "run", profile
        assert decisions([nightly_run(974, shards={profile: "failure"}), lab_run(975)])["native"] == "run", profile
        assert decisions([nightly_run(976, shards={profile: "skipped"}), lab_run(977)])["native"] == "run", profile


def test_native_shards_split_across_two_runs_prove_nothing() -> None:
    first, second = NATIVE_PROFILES[:3], NATIVE_PROFILES[3:]
    older = nightly_run(978, shards=dict.fromkeys(second))
    newer = nightly_run(979, shards=dict.fromkeys(first))
    assert decisions([newer, older, lab_run(980)])["native"] == "run"


def test_the_unsharded_native_job_of_an_older_nightly_still_counts() -> None:
    run = nightly_run(981, shards=dict.fromkeys(NATIVE_PROFILES))
    run["jobs"].append({"name": "nightly-native-deploy", "conclusion": "success", "steps": []})
    assert decisions([run, lab_run(982)])["native"] == "reuse"
    run["jobs"][-1]["conclusion"] = "failure"
    assert decisions([run, lab_run(983)])["native"] == "run"


# --- The nightly still produces every scope a release candidate reuses ------------------------------------

REPO = Path(__file__).resolve().parents[2]
WORKFLOWS = REPO / ".github" / "workflows"


def _workflow(name: str) -> dict[str, Any]:
    # Quote GitHub's event key so YAML 1.1 does not read a bare `on` as True.
    text = (WORKFLOWS / name).read_text(encoding="utf-8")
    return yaml.safe_load(re.sub(r"^on:", '"on":', text, flags=re.MULTILINE))


def _produced_job_names(workflow: dict[str, Any]) -> set[str]:
    """The job names a scheduled run on master reports: `<id> (<value>)` for a one-key matrix."""
    names: set[str] = set()
    for job_id, job in workflow["jobs"].items():
        assert "name" not in job, f"{job_id}: a name override would change what the verifier must match"
        matrix = job.get("strategy", {}).get("matrix", {})
        if not matrix:
            names.add(job_id)
            continue
        ((key, values),) = matrix.items()
        # The nightly's branch matrix comes from check-activity; master is the leg a release reuses.
        values = ["master"] if key == "branch" else values
        assert isinstance(values, list), f"{job_id}: the matrix must list its values for the verifier to match"
        names.update(f"{job_id} ({value})" for value in values)
    return names


def _job(workflow: dict[str, Any], produced_name: str) -> dict[str, Any]:
    return workflow["jobs"][produced_name.split(" (", maxsplit=1)[0]]


@pytest.mark.parametrize("scope", sorted(RELEASE_SCOPES))
def test_the_nightly_still_produces_every_scope_a_release_reuses(scope: str) -> None:
    name, job_sets, step_name = RELEASE_SCOPES[scope]
    workflow = _workflow(name)
    assert "schedule" in workflow["on"], f"{name} must run on a schedule to leave evidence for the candidate"
    # The first set is what today's workflow produces; the others match runs from before a rename.
    current = job_sets[0]
    produced = _produced_job_names(workflow)
    assert current <= produced, f"{scope}: {sorted(current - produced)} no longer run in {name}"
    if step_name is not None:
        for job_name in current:
            steps = [step for step in _job(workflow, job_name)["steps"] if step.get("name") == step_name]
            assert len(steps) == 1, f"{scope}: {job_name} must run the step {step_name!r} exactly once"
            assert "if" not in steps[0] and "continue-on-error" not in steps[0]


def test_the_nightly_tests_exactly_the_commit_a_release_credits() -> None:
    # A step scope is credited to the run's head_sha only when nightly.yml carries this pin.
    assert NIGHTLY_CHECKOUT_PIN in (WORKFLOWS / "nightly.yml").read_text(encoding="utf-8")


def test_the_proof_steps_run_what_their_scope_names() -> None:
    nightly = _workflow("nightly.yml")["jobs"]["nightly"]
    steps = {step.get("name"): step for step in nightly["steps"]}
    postgres = steps[RELEASE_SCOPES["postgres"][2]]
    assert "manage.py test tests" in postgres["run"] and "--settings=config.settings.ci" in postgres["run"]

    # The crowdsec scope is proven by the integration step, so it must collect CrowdSec's Docker suites: the
    # target's default (CROWDSEC_DOCKER=1), never the queue's CROWDSEC_DOCKER=0, on the line or through env
    # (make's `?=` reads the environment). tests/integration/test_crowdsec_test_artifacts.py runs both.
    integration = steps[RELEASE_SCOPES["crowdsec"][2]]
    assert integration["run"] == "make test-integration"
    workflow = _workflow("nightly.yml")
    for scope in (workflow, nightly, integration):
        environment = scope.get("env", {})
        assert "PYTEST_ADDOPTS" not in environment and "CROWDSEC_DOCKER" not in environment
    makefile = (REPO / "Makefile").read_text(encoding="utf-8")
    assert re.search(r"^CROWDSEC_DOCKER \?= 1$", makefile, re.MULTILINE), "the default must keep CrowdSec"
    recipe = re.search(r"^test-integration:[^\n]*\n((?:\t[^\n]*\n)+)", makefile, re.MULTILINE)
    assert recipe is not None
    collected = shlex.split(recipe.group(1).replace("\\\n", " "))
    assert "tests/deploy/" in collected, "the integration target must collect tests/deploy"
    assert not [arg for arg in collected if "crowdsec" in arg.lower() and arg.startswith("--ignore")]
    assert list(REPO.glob("tests/deploy/test_crowdsec*_docker.py")), "CrowdSec's Docker suites must exist"


def test_the_native_shards_are_one_list_for_the_verifier_the_nightly_and_the_candidate() -> None:
    nightly = _workflow("nightly.yml")["jobs"]["nightly-native-deploy"]["strategy"]["matrix"]["profile"]
    candidate = _workflow("release-candidate.yml")["jobs"]["rc-native"]["strategy"]["matrix"]["profile"]
    assert tuple(nightly) == tuple(candidate) == NATIVE_PROFILES


def test_five_of_six_shards_all_green_is_no_proof() -> None:
    # Exactly the expected profiles, each present and green on the exact commit: anything less runs native.
    run = nightly_run(984, shards={NATIVE_PROFILES[-1]: None})
    assert len([job for job in run["jobs"] if job["name"].startswith("nightly-native-deploy")]) == 5
    assert decisions([run, lab_run(985)])["native"] == "run"


@pytest.mark.parametrize("outcome", ["success", "failure", "cancelled", "skipped"])
def test_a_shard_the_verifier_does_not_expect_is_no_proof(outcome: str) -> None:
    # A matrix that grew or renamed a profile no longer matches the verifier's list: run, never reuse.
    run = nightly_run(986)
    run["jobs"].append({"name": "nightly-native-deploy (split-prod-5)", "conclusion": outcome, "steps": []})
    assert decisions([run, lab_run(987)])["native"] == "run"


@pytest.mark.parametrize("outcome", ["cancelled", "skipped", "failure", "timed_out"])
def test_every_shard_outcome_but_success_means_run(outcome: str) -> None:
    for profile in NATIVE_PROFILES:
        assert decisions([nightly_run(988, shards={profile: outcome}), lab_run(989)])["native"] == "run", profile
