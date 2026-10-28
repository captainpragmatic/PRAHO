"""Master's required checks are real, always reported, and cannot pass without running.

`.github/rulesets/master.json` names the checks a pull request needs before it can merge. Each fact
below is read from source:

- every required context is a job of a workflow that every pull request to master starts (a workflow
  skipped by a paths filter never reports, and a required check that never reports blocks forever);
- no required job tolerates its own failure (`continue-on-error`), which would let a red job pass;
- the one job allowed to skip itself, the Virtualmin lab, fails open;
- the release-candidate workflow tests exactly the commit it vouches for, and only it may vouch.
"""

from __future__ import annotations

import json
import re
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
