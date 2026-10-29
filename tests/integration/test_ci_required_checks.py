"""Master's required checks are real, always reported, and cannot pass without running.

`.github/rulesets/master.json` names the checks a pull request needs before it can merge. Each fact
below is read from source:

- every required context is a job of a workflow that every pull request to master starts (a workflow
  skipped by a paths filter never reports, and a required check that never reports blocks forever),
  and that every merge group starts too: the merge queue waits for the same checks on its own commit;
- the merge queue waits longer than the slowest required job may run;
- no required job tolerates its own failure (`continue-on-error`), which would let a red job pass;
- the one job allowed to skip itself, the Virtualmin lab, skips on a pull request and, in the queue,
  fails open;
- the release-candidate workflow tests exactly the commit it vouches for, and only it may vouch.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
from pathlib import Path
from typing import Any

import pytest
import yaml

from scripts.ci_lab_needed import lab_needed

pytestmark = pytest.mark.integration

REPO = Path(__file__).resolve().parents[2]
WORKFLOWS = REPO / ".github" / "workflows"
RULESETS = REPO / ".github" / "rulesets"
GITHUB_ACTIONS_APP_ID = 15368

# Jobs allowed an `if:` because skipping them is the selection itself, and it fails open.
SELECTIVE_JOBS = {"pull-request": "!cancelled() && needs.changes.outputs.lab != 'false'"}
# A required job whose steps branch on the event: the PR runs a focused subset first, then everything.
STEP_CONDITIONS_ALLOWED = {"platform-test"}
STEP_CONDITIONS_ALWAYS_OK = {"always()", "failure()"}


def load_workflow(path: Path) -> dict[str, Any]:
    # Quote GitHub's event key so YAML 1.1 does not read a bare `on` as True.
    return yaml.safe_load(re.sub(r"^on:", '"on":', path.read_text(encoding="utf-8"), flags=re.MULTILINE))


def required_checks() -> list[dict[str, Any]]:
    ruleset = json.loads((RULESETS / "master.json").read_text(encoding="utf-8"))
    (rule,) = [rule for rule in ruleset["rules"] if rule["type"] == "required_status_checks"]
    return rule["parameters"]["required_status_checks"]


def pull_request_jobs() -> dict[str, tuple[str, dict[str, Any]]]:
    """Every job of a workflow that every pull request to master starts, by job id."""
    jobs: dict[str, tuple[str, dict[str, Any]]] = {}
    for path in sorted(WORKFLOWS.glob("*.yml")):
        workflow = load_workflow(path)
        trigger = (workflow["on"] or {}).get("pull_request") if isinstance(workflow["on"], dict) else None
        if trigger is None and "pull_request" not in (workflow["on"] or []):
            continue
        trigger = trigger or {}
        if "paths" in trigger or "paths-ignore" in trigger:
            continue
        if "master" not in trigger.get("branches", ["master"]):
            continue
        types = trigger.get("types")
        assert types is None or "synchronize" in types, f"{path.name}: a new push must re-run its checks"
        for job_id, job in workflow["jobs"].items():
            name = job.get("name", job_id)
            assert name not in jobs, f"check {name} appears in two PR workflows: it is ambiguous"
            jobs[name] = (path.name, job)
    return jobs


def ruleset_rule(rule_type: str) -> dict[str, Any]:
    ruleset = json.loads((RULESETS / "master.json").read_text(encoding="utf-8"))
    (rule,) = [rule for rule in ruleset["rules"] if rule["type"] == rule_type]
    return rule


def test_the_ruleset_requires_the_core_checks() -> None:
    contexts = {check["context"] for check in required_checks()}

    # Canary: a ruleset that lost its checks would make every other test here pass vacuously.
    for needed in ("coverage-gate", "portal-test", "lint-and-quality", "integration-test", "browser-e2e", "dco"):
        assert needed in contexts, needed


def test_only_github_actions_can_satisfy_a_required_check() -> None:
    # Without the app id, anyone allowed to post a commit status could post a green one by name.
    for check in required_checks():
        assert check.get("integration_id") == GITHUB_ACTIONS_APP_ID, check["context"]


@pytest.mark.parametrize("context", [check["context"] for check in required_checks()])
def test_every_required_check_runs_on_every_pull_request(context: str) -> None:
    jobs = pull_request_jobs()

    assert context in jobs, (
        f"{context} is required but no workflow that every pull request starts has that job: "
        "it would never report and every merge would wait forever"
    )
    workflow, job = jobs[context]
    assert "continue-on-error" not in job, f"{workflow}:{context} may fail and still pass"
    for step in job.get("steps", []):
        assert "continue-on-error" not in step, f"{workflow}:{context} step {step.get('name')} may fail silently"
    assert "strategy" not in job, f"{workflow}:{context}: a matrix renames the check, which then never reports"
    if context in SELECTIVE_JOBS:
        assert job["if"] == SELECTIVE_JOBS[context], f"{workflow}:{context} must skip only on an explicit 'false'"
    else:
        assert "if" not in job, f"{workflow}:{context} can be skipped, and a skipped job reports success"
    if context not in STEP_CONDITIONS_ALLOWED:
        for step in job.get("steps", []):
            condition = step.get("if")
            assert condition is None or condition in STEP_CONDITIONS_ALWAYS_OK, (
                f"{workflow}:{context} step {step.get('name')} runs only `if: {condition}`: the check can pass without it"
            )


@pytest.mark.parametrize("workflow", sorted({workflow for workflow, _ in pull_request_jobs().values()}))
def test_every_required_workflow_runs_in_the_merge_queue(workflow: str) -> None:
    required = {check["context"] for check in required_checks()}
    if not required & {name for name, (path, _) in pull_request_jobs().items() if path == workflow}:
        return
    triggers = load_workflow(WORKFLOWS / workflow)["on"]
    assert isinstance(triggers, dict) and "merge_group" in triggers, (
        f"{workflow} has a required check but does not run on merge_group: every queued pull request would "
        "wait for it until the queue times out"
    )
    types = (triggers["merge_group"] or {}).get("types")
    assert types is None or "checks_requested" in types, workflow


def test_the_merge_queue_squashes_and_outwaits_the_slowest_job() -> None:
    queue = ruleset_rule("merge_queue")["parameters"]
    assert queue["merge_method"] == "SQUASH"
    assert queue["grouping_strategy"] == "ALLGREEN", "HEADGREEN lands an entry whose own group never passed"
    # A required job still running when the queue stops waiting fails the group. The lab is the slowest and
    # declares the longest limit; the queue must outwait every limit a required job declares.
    required = {check["context"] for check in required_checks()}
    declared = [
        int(job["timeout-minutes"])
        for name, (_, job) in pull_request_jobs().items()
        if name in required and "timeout-minutes" in job
    ]
    assert declared, "no required job declares a time limit: this comparison would check nothing"
    assert queue["check_response_timeout_minutes"] > max(declared)


def _lab_decision(repo: Path, event: str, base: str) -> str:
    """Run the lab workflow's own decision step in ``repo`` and return what it wrote to its output."""
    (step,) = [
        step
        for step in load_workflow(WORKFLOWS / "virtualmin-lab-pr.yml")["jobs"]["changes"]["steps"]
        if step.get("id") == "decide"
    ]
    output = repo / "github_output"
    output.write_text("")
    env = {**os.environ, "EVENT": event, "BASE_SHA": base, "GITHUB_OUTPUT": str(output)}
    subprocess.run(["bash", "-c", step["run"]], cwd=repo, env=env, check=True, capture_output=True)  # noqa: S603, S607
    return output.read_text().strip()


def _git(repo: Path, *args: str) -> str:
    return subprocess.run(["git", *args], cwd=repo, check=True, capture_output=True, text=True).stdout.strip()  # noqa: S603, S607


def test_the_lab_runs_in_the_queue_only_and_fails_open_there(tmp_path: Path) -> None:
    _git(tmp_path, "init", "--quiet")
    _git(tmp_path, "config", "user.email", "ci@example.com")
    _git(tmp_path, "config", "user.name", "CI")
    (tmp_path / "scripts").mkdir()
    (tmp_path / "scripts" / "ci_lab_needed.py").write_text((REPO / "scripts" / "ci_lab_needed.py").read_text())
    _git(tmp_path, "add", ".")
    _git(tmp_path, "commit", "--quiet", "-m", "base")
    base = _git(tmp_path, "rev-parse", "HEAD")
    (tmp_path / "docs").mkdir()
    (tmp_path / "docs" / "note.md").write_text("prose\n")
    _git(tmp_path, "add", ".")
    _git(tmp_path, "commit", "--quiet", "-m", "docs only")

    # A push to a pull request never runs the lab, whatever it changes.
    assert _lab_decision(tmp_path, "pull_request", "") == "lab=false"
    # In the queue the base branch's rules decide: prose cannot reach the lab.
    assert _lab_decision(tmp_path, "merge_group", base) == "lab=false"
    # A base the step cannot read gives no diff, and no diff runs the lab.
    assert _lab_decision(tmp_path, "merge_group", "") == "lab=true"
    (tmp_path / "services" / "platform").mkdir(parents=True)
    (tmp_path / "services" / "platform" / "x.py").write_text("x = 1\n")
    _git(tmp_path, "add", ".")
    _git(tmp_path, "commit", "--quiet", "-m", "platform code")
    assert _lab_decision(tmp_path, "merge_group", base) == "lab=true"


def _dco(repo: Path, event: str, base: str, head: str, body: str = "") -> int:
    """Run the DCO job's own sign-off step in ``repo`` and return its exit status."""
    (job,) = [job for name, (_, job) in pull_request_jobs().items() if name == "dco"]
    (step,) = [step for step in job["steps"] if "Signed-off-by" in step.get("run", "")]
    env = {**os.environ, "EVENT": event, "BASE_SHA": base, "HEAD_SHA": head, "PR_BODY": body}
    return subprocess.run(["bash", "-c", step["run"]], cwd=repo, env=env, capture_output=True, check=False).returncode  # noqa: S603, S607


def _commit(repo: Path, message: str) -> str:
    _git(repo, "commit", "--quiet", "--allow-empty", "-m", message)
    return _git(repo, "rev-parse", "HEAD")


def test_the_dco_check_reads_the_queues_real_squash_and_the_description(tmp_path: Path) -> None:
    _git(tmp_path, "init", "--quiet")
    _git(tmp_path, "config", "user.email", "ci@example.com")
    _git(tmp_path, "config", "user.name", "CI")
    base = _commit(tmp_path, "base")
    signed = _commit(tmp_path, "feat: a change (#1)\n\nSigned-off-by: A <a@example.com>")
    unsigned = _commit(tmp_path, "feat: another change (#2)\n\nNo trailer here.")

    # In the queue, the range is the queue's own squash commits, whose message is the description.
    assert _dco(tmp_path, "merge_group", base, signed) == 0
    assert _dco(tmp_path, "merge_group", base, unsigned) != 0
    # On the pull request, signed commits are not enough: the description becomes the squash message.
    assert _dco(tmp_path, "pull_request", base, signed, body="Summary.\n\nSigned-off-by: A <a@example.com>") == 0
    assert _dco(tmp_path, "pull_request", base, signed, body="Summary only.") != 0


def test_a_changed_description_is_checked_again() -> None:
    triggers = load_workflow(WORKFLOWS / "dco-check.yml")["on"]
    assert "edited" in triggers["pull_request"]["types"]


def test_no_other_job_can_stand_in_for_a_required_check() -> None:
    # A same-named job in another workflow (a dispatch, a schedule, the release candidate) adds a check
    # run with that name to the commit, and a skipped one reads as success.
    owners = {name: workflow for name, (workflow, _) in pull_request_jobs().items()}
    for path in WORKFLOWS.glob("*.yml"):
        for job_id, job in load_workflow(path)["jobs"].items():
            name = job.get("name", job_id)
            if name in owners:
                assert owners[name] == path.name, f"{path.name}:{job_id} shares the required check name {name}"


def test_no_workflow_runs_pull_request_code_on_a_comment() -> None:
    # The removed /full-test ran a PR's code with write permissions when a trusted person commented.
    for path in WORKFLOWS.glob("*.yml"):
        triggers = load_workflow(path)["on"]
        names = triggers if isinstance(triggers, list) else list(triggers or {})
        assert "issue_comment" not in names, path.name
        assert "pull_request_target" not in names, path.name


@pytest.mark.parametrize(
    ("changed", "expected"),
    [
        ([], True),  # the diff could not be computed: run
        (["", "  "], True),
        (["services/platform/apps/infrastructure/ansible_service.py"], True),
        (["services/platform/apps/provisioning/services.py"], True),
        (["services/platform/config/settings/base.py"], True),
        # The lab bootstrap creates currencies, customers and staff users.
        (["services/platform/apps/billing/models.py"], True),
        (["services/platform/apps/customers/models.py"], True),
        (["services/platform/apps/users/models.py"], True),
        (["docs/ADRs/ADR-0036-tiered-ci-testing-strategy.md"], False),
        (["services/portal/apps/billing/views.py", "README.md"], False),
        (["README.md", "deploy/virtualmin-lab/compose.yml"], True),
        # Imported by provisioning, and nobody had listed them: an allowlist of what reaches the lab goes stale.
        (["services/platform/apps/orders/tasks.py", "services/platform/apps/tickets/models.py"], True),
        (["services/platform/tests/billing/test_x.py", "tests/integration/test_y.py", ".github/rulesets/master.json"], False),
    ],
)
def test_the_lab_selection_fails_open(changed: list[str], expected: bool) -> None:
    assert lab_needed(changed) is expected


class TestReleaseCandidate:
    workflow = load_workflow(WORKFLOWS / "release-candidate.yml")
    jobs: dict[str, Any] = workflow["jobs"]

    def test_only_a_master_dispatch_may_vouch_for_a_commit(self) -> None:
        assert list(self.workflow["on"]) == ["workflow_dispatch"]
        script = str(self.jobs["resolve"]["steps"])
        assert 'refs/heads/master' in script and "merge-base --is-ancestor" in script

    def test_the_candidate_is_verified_by_the_tested_script(self) -> None:
        # tests/integration/test_verify_release_candidate.py drives the script's decisions.
        runs = [step.get("run", "") for step in self.jobs["resolve"]["steps"]]
        assert 'python3 scripts/verify_release_candidate.py "$SHA"' in runs

    def test_every_job_tests_the_resolved_candidate(self) -> None:
        for job_id, job in self.jobs.items():
            if job_id in ("resolve", "record"):
                continue
            if "uses" in job:  # a called workflow gets the commit as its `ref` input
                assert job["with"]["ref"] == "${{ needs.resolve.outputs.sha }}", job_id
                continue
            checkouts = [step for step in job["steps"] if str(step.get("uses", "")).startswith("actions/checkout")]
            assert checkouts, job_id
            for step in checkouts:
                assert step["with"]["ref"] == "${{ needs.resolve.outputs.sha }}", job_id

    def test_the_status_is_posted_only_after_every_check(self) -> None:
        record = self.jobs["record"]
        assert set(record["needs"]) == set(self.jobs) - {"record"}
        assert "if" not in record, "an `always()` here would vouch for a failed run"
        assert record["permissions"] == {"statuses": "write"}
        assert self.workflow["permissions"] == {"contents": "read"}


def test_a_failing_credential_check_fails_the_security_lint() -> None:
    makefile = (REPO / "Makefile").read_text(encoding="utf-8")
    assert "$(MAKE) lint-credentials || exit $$?;" in makefile


@pytest.mark.parametrize("job_id", ["browser-e2e", "browser-csp"])
def test_browser_jobs_always_stop_their_stack(job_id: str) -> None:
    steps = load_workflow(WORKFLOWS / "browser.yml")["jobs"][job_id]["steps"]
    stops = [step for step in steps if step.get("run") == "make stop-e2e"]

    assert len(stops) == 1 and stops[0]["if"] == "always()", job_id
