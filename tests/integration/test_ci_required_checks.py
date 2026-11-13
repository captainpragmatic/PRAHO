"""Master's required checks are real, always reported, and cannot pass without running.

`.github/rulesets/master.json` names the checks a pull request needs before it can merge. Each fact
below is read from source:

- every required context is a job of a workflow that every pull request to master starts (a workflow
  skipped by a paths filter never reports, and a required check that never reports blocks forever),
  and that every merge group starts too: the merge queue waits for the same checks on its own commit;
- the merge queue waits longer than the slowest required job may run;
- no required job tolerates its own failure (`continue-on-error`), which would let a red job pass;
- a required job skips only on a pull request, and only the queue-tier jobs do (ADR-0036's fast tier): a
  skipped job reports success, so the merge queue must run every one of them, and a gate that waits on a
  skippable job must still run and judge it;
- the release-candidate workflow tests exactly the commit it vouches for, and only it may vouch.
"""

from __future__ import annotations

import json
import os
import re
import shlex
import subprocess
from pathlib import Path
from typing import Any, ClassVar

import pytest
import yaml

pytestmark = pytest.mark.integration

REPO = Path(__file__).resolve().parents[2]
WORKFLOWS = REPO / ".github" / "workflows"
RULESETS = REPO / ".github" / "rulesets"
GITHUB_ACTIONS_APP_ID = 15368

# The queue tier (ADR-0036): these jobs skip on a pull request, which runs the fast tier, and run in the merge
# queue and on master. Exactly these jobs may skip, and only with exactly this condition.
PR_SKIP = "github.event_name != 'pull_request'"
SELECTIVE_JOBS: dict[str, str] = {
    "coverage-gate": PR_SKIP,
    "portal-server": PR_SKIP,
    "browser-csp": PR_SKIP,
    "browser-hosting-checkout": PR_SKIP,
    # A gate over another job: always() lets it judge a failed or cancelled dependency instead of skipping.
    "browser-e2e": f"always() && {PR_SKIP}",
    "integration-suite": PR_SKIP,
}
# A required job whose steps branch on the event: the PR runs the affected modules only.
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
        assert job.get("if") == SELECTIVE_JOBS[context], f"{workflow}:{context} must skip on a pull request only"
    else:
        # always() forces a dependency gate to run even when an upstream job fails or skips.
        assert job.get("if") in (None, "always()"), (
            f"{workflow}:{context} can be skipped, and a skipped job reports success"
        )
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


def _evaluate(condition: str, event: str) -> bool:
    """Evaluate a job condition of the shapes used here (always(), event comparisons, &&) for one event."""
    expression = condition.replace("always()", "True").replace("&&", " and ").replace("||", " or ")
    expression = expression.replace("github.event_name", repr(event))
    assert re.fullmatch(r"[\w\s'()!=]+", expression), f"unsupported condition: {condition}"
    return bool(eval(expression, {"__builtins__": {}}, {"True": True}))  # noqa: S307 -- the fixed table above


def pull_request_and_queue_jobs() -> dict[str, tuple[str, dict[str, Any]]]:
    """Every job of the pull request workflows, required or not (a dependency can decide a required one)."""
    jobs: dict[str, tuple[str, dict[str, Any]]] = {}
    for workflow in sorted({workflow for workflow, _ in pull_request_jobs().values()}):
        for job_id, job in load_workflow(WORKFLOWS / workflow)["jobs"].items():
            jobs[job_id] = (workflow, job)
    return jobs


@pytest.mark.parametrize("name", sorted(SELECTIVE_JOBS))
def test_a_queue_tier_job_skips_on_a_pull_request_and_runs_everywhere_else(name: str) -> None:
    for event in ("merge_group", "push", "workflow_dispatch", "schedule"):
        assert _evaluate(SELECTIVE_JOBS[name], event), f"{name} would skip on {event}: a skip reads as success"
    assert not _evaluate(SELECTIVE_JOBS[name], "pull_request")


def test_exactly_the_queue_tier_jobs_skip_on_a_pull_request() -> None:
    jobs = pull_request_and_queue_jobs()
    assert set(SELECTIVE_JOBS) <= set(jobs), set(SELECTIVE_JOBS) - set(jobs)
    for name, (workflow, job) in jobs.items():
        condition = str(job.get("if", ""))
        if name in SELECTIVE_JOBS:
            assert condition == SELECTIVE_JOBS[name], f"{workflow}:{name}"
        else:
            assert "event_name" not in condition, f"{workflow}:{name} branches on the event but is not listed"


def test_a_job_that_waits_on_a_queue_tier_job_still_judges_it() -> None:
    # Without always(), a job whose dependency failed in the queue is skipped, and a skipped job reads as success.
    for name, (workflow, job) in pull_request_and_queue_jobs().items():
        needs = job.get("needs", [])
        needs = [needs] if isinstance(needs, str) else needs
        if set(needs) & set(SELECTIVE_JOBS):
            assert str(job.get("if", "")).startswith("always()"), f"{workflow}:{name}"


def test_crowdsec_qualification_is_not_in_the_merge_queue() -> None:
    # CrowdSec's Docker qualification runs nightly (make test-integration) and in a release candidate that
    # cannot reuse the nightly's proof (rc-crowdsec); the queue runs neither it nor its suites by another name.
    workflow = load_workflow(WORKFLOWS / "integration.yml")
    job = workflow["jobs"]["integration-suite"]
    steps = job["steps"]
    assert not [step for step in steps if "crowdsec" in str(step).lower() and "PYTEST_ADDOPTS" not in str(step)]
    (aggregate,) = [step for step in steps if step.get("run") == "make test-integration"]
    assert "if" not in aggregate and "continue-on-error" not in aggregate

    # Derive the CrowdSec files from the actual Make recipe so a stale exclusion cannot silently miss new
    # suites or suppress unrelated Docker coverage.
    makefile = (REPO / "Makefile").read_text(encoding="utf-8")
    recipe = re.search(r"^test-crowdsec-docker:[^\n]*\n((?:\t[^\n]*\n)+)", makefile, re.MULTILINE)
    assert recipe is not None
    (native_glob,) = re.findall(r"tests/deploy/[^\s]+_docker\.py", recipe.group(1))
    native_files = set(REPO.glob(native_glob))
    assert native_files, "the CrowdSec target must collect real files"

    options = shlex.split(aggregate.get("env", {}).get("PYTEST_ADDOPTS", ""))
    assert options == [f"--ignore-glob={native_glob}"], "the aggregate must exclude exactly the CrowdSec suites"
    ignored_files = set(REPO.glob(options[0].split("=", 1)[1]))
    assert ignored_files == native_files
    assert "PYTEST_ADDOPTS" not in workflow.get("env", {})
    assert "PYTEST_ADDOPTS" not in job.get("env", {})

    other_native_files = set(REPO.glob("tests/deploy/test_*_docker.py")) - native_files
    assert other_native_files, "unrelated Docker suites must remain in the aggregate"
    for relative in ("tests/deploy/test_caddy_routing.py", "tests/deploy/test_ssh_hardening_docker.py"):
        path = REPO / relative
        assert path.is_file() and path not in ignored_files
    assert not other_native_files & ignored_files


def test_native_deploy_is_not_in_the_merge_queue() -> None:
    # Native deploy acceptance runs nightly and in a release candidate that cannot reuse it (rc-native).
    for workflow in sorted({workflow for workflow, _ in pull_request_jobs().values()}):
        assert "test-native-deploy" not in (WORKFLOWS / workflow).read_text(encoding="utf-8"), workflow
    assert not (REPO / "scripts" / "ci_native_needed.py").exists()


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


def _git(repo: Path, *args: str) -> str:
    return subprocess.run(["git", *args], cwd=repo, check=True, capture_output=True, text=True).stdout.strip()  # noqa: S603, S607


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


@pytest.mark.parametrize(
    "body",
    [
        (REPO / ".github" / "pull_request_template.md").read_text(encoding="utf-8"),  # unchanged template
        "We use Signed-off-by: trailers on every commit.",  # the word in prose
        "Summary.\n\nSigned-off-by:",  # a trailer with nobody in it
        "Summary.\n\nSigned-off-by: A",  # no address
    ],
)
def test_only_a_real_trailer_signs_a_description_or_a_squash(tmp_path: Path, body: str) -> None:
    _git(tmp_path, "init", "--quiet")
    _git(tmp_path, "config", "user.email", "ci@example.com")
    _git(tmp_path, "config", "user.name", "CI")
    base = _commit(tmp_path, "base")
    squash = _commit(tmp_path, f"feat: a change (#1)\n\n{body}")
    signed = _commit(tmp_path, "feat: a change (#1)\n\nSigned-off-by: A <a@example.com>")

    assert _dco(tmp_path, "pull_request", signed, signed, body=body) != 0
    assert _dco(tmp_path, "merge_group", base, squash) != 0
    # GitHub keeps the carriage returns of a description typed in the browser.
    assert (
        _dco(tmp_path, "pull_request", signed, signed, body="Summary.\r\n\r\nSigned-off-by: A <a@example.com>\r\n") == 0
    )


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


def _integration_gate(event: str, general: str) -> int:
    job = load_workflow(WORKFLOWS / "integration.yml")["jobs"]["integration-test"]
    assert job["needs"] == ["integration-suite"] and job["if"] == "always()"
    assert job["env"] == {
        "EVENT": "${{ github.event_name }}",
        "GENERAL_RESULT": "${{ needs.integration-suite.result }}",
    }
    (step,) = job["steps"]
    env = {**os.environ, "EVENT": event, "GENERAL_RESULT": general}
    # GitHub runs a `run:` step with `bash -e {0}`.
    return subprocess.run(["bash", "-e", "-c", step["run"]], env=env, capture_output=True, check=False).returncode  # noqa: S603, S607


@pytest.mark.parametrize("event", ["pull_request", "merge_group", "push", "workflow_dispatch"])
@pytest.mark.parametrize("general", ["success", "skipped", "failure", "cancelled", ""])
def test_the_integration_gate_accepts_a_skipped_suite_only_on_a_pull_request(event: str, general: str) -> None:
    passes = general == "success" or (general == "skipped" and event == "pull_request")
    assert (_integration_gate(event, general) == 0) is passes


class TestReleaseCandidate:
    workflow = load_workflow(WORKFLOWS / "release-candidate.yml")
    jobs: dict[str, Any] = workflow["jobs"]

    def test_only_a_master_dispatch_may_vouch_for_a_commit(self) -> None:
        assert list(self.workflow["on"]) == ["workflow_dispatch"]
        script = str(self.jobs["resolve"]["steps"])
        assert "refs/heads/master" in script and "merge-base --is-ancestor" in script

    def test_the_candidate_is_verified_by_the_tested_script(self) -> None:
        # tests/integration/test_verify_release_candidate.py drives the script's decisions.
        runs = [step.get("run", "") for step in self.jobs["resolve"]["steps"]]
        assert any(run.startswith('python3 scripts/verify_release_candidate.py "$SHA" |') for run in runs)

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

    SCOPE_JOBS: ClassVar[dict[str, str]] = {
        "postgres": "rc-platform-postgres",
        "crowdsec": "rc-crowdsec",
        "native": "rc-native",
        "lab": "rc-lab",
    }

    def test_each_release_scope_runs_only_when_no_nightly_proved_it(self) -> None:
        # scripts/verify_release_candidate.py answers reuse/run per scope; tests/integration/
        # test_verify_release_candidate.py drives those answers.
        from scripts.verify_release_candidate import RELEASE_SCOPES  # noqa: PLC0415

        assert set(self.SCOPE_JOBS) == set(RELEASE_SCOPES)
        outputs = self.jobs["resolve"]["outputs"]
        for scope, job_id in self.SCOPE_JOBS.items():
            assert outputs[scope] == f"${{{{ steps.verify.outputs.{scope} }}}}"
            assert self.jobs[job_id]["needs"] == "resolve"
            assert self.jobs[job_id]["if"] == f"needs.resolve.outputs.{scope} == 'run'"

    def test_the_lab_scope_calls_the_lab_on_the_candidate(self) -> None:
        lab = self.jobs["rc-lab"]
        assert lab["uses"] == "./.github/workflows/virtualmin-lab.yml"
        assert lab["with"] == {"suite": "containers", "ref": "${{ needs.resolve.outputs.sha }}"}

    def test_the_lab_caller_grants_every_permission_the_lab_asks_for(self) -> None:
        # A called workflow cannot raise the caller's token: GitHub refuses the call at validation.
        called = yaml.safe_load((WORKFLOWS / "virtualmin-lab.yml").read_text(encoding="utf-8"))
        asked = [called.get("permissions", {})] + [job.get("permissions", {}) for job in called["jobs"].values()]
        needed = {(scope, level) for permissions in asked for scope, level in permissions.items()}
        granted = self.jobs["rc-lab"]["permissions"]
        assert ("pull-requests", "read") in needed
        for scope, level in needed:
            assert granted.get(scope) in ({level, "write"} if level == "read" else {level}), scope

    def test_the_run_title_names_the_candidate_promote_looks_for(self) -> None:
        # promote_staging.sh finds the approved run by the title "Release candidate <sha>".
        assert self.workflow["run-name"] == "Release candidate ${{ inputs.candidate_sha || github.sha }}"
        script = str(self.jobs["resolve"]["steps"])
        assert 'sha="${CANDIDATE:-$DISPATCH_SHA}"' in script and "--pick" not in script

    def test_a_piped_step_runs_with_pipefail(self) -> None:
        # GitHub adds `-o pipefail` only for an explicit `shell: bash`; the default is `bash -e {0}`.
        for job_id, job in self.jobs.items():
            for step in job.get("steps", []):
                if " | " in step.get("run", ""):
                    assert step.get("shell") == "bash", (job_id, step.get("name"))

    def test_the_status_is_posted_only_after_every_check(self) -> None:
        record = self.jobs["record"]
        assert set(record["needs"]) == set(self.jobs) - {"record"}
        assert record["if"] == "always()", "the gate step below decides; a skipped reuse scope must reach it"
        assert record["permissions"] == {"statuses": "write"}
        assert self.workflow["permissions"] == {"contents": "read"}
        _gate, post = record["steps"]
        assert "if" not in post, "the status is posted only when the gate step passed"


SCOPES = ("postgres", "crowdsec", "native", "lab")


def _record_gate(resolve: str, decisions: dict[str, str], results: dict[str, str]) -> int:
    record = load_workflow(WORKFLOWS / "release-candidate.yml")["jobs"]["record"]
    gate = record["steps"][0]
    env = {**os.environ, "RESOLVE_RESULT": resolve}
    for scope in SCOPES:
        env[f"{scope.upper()}_DECISION"] = decisions[scope]
        env[f"{scope.upper()}_RESULT"] = results[scope]
    for name, expression in record["env"].items():
        assert "needs." in expression, name
    assert set(record["env"]) == set(env) - set(os.environ), "the table must exercise every input the gate reads"
    # GitHub runs a `run:` step with `bash -eo pipefail {0}`.
    completed = subprocess.run(  # noqa: S603 -- the repository's own gate script
        ["bash", "-eo", "pipefail", "-c", gate["run"]],  # noqa: S607
        env=env,
        capture_output=True,
        check=False,
    )
    return completed.returncode


@pytest.mark.parametrize("resolve", ["success", "failure"])
@pytest.mark.parametrize("decision", ["reuse", "run", ""])
@pytest.mark.parametrize("result", ["success", "skipped", "failure", "cancelled"])
def test_the_release_record_accepts_only_proven_scopes(resolve: str, decision: str, result: str) -> None:
    # One scope varies; the others are cleanly reused, so the varied scope alone decides.
    decisions = dict.fromkeys(SCOPES, "reuse")
    results = dict.fromkeys(SCOPES, "skipped")
    decisions["native"], results["native"] = decision, result
    proven = result == "success" or (result == "skipped" and decision == "reuse")
    assert (_record_gate(resolve, decisions, results) == 0) is (resolve == "success" and proven)


def test_a_failing_credential_check_fails_the_security_lint() -> None:
    makefile = (REPO / "Makefile").read_text(encoding="utf-8")
    assert "$(MAKE) lint-credentials || exit $$?;" in makefile


@pytest.mark.parametrize("job_id", ["browser-e2e", "browser-csp"])
def test_browser_jobs_always_stop_their_stack(job_id: str) -> None:
    steps = load_workflow(WORKFLOWS / "browser.yml")["jobs"][job_id]["steps"]
    stops = [step for step in steps if step.get("run") == "make stop-e2e"]

    assert len(stops) == 1 and stops[0]["if"] == "always()", job_id


def test_full_hosting_checkout_is_a_required_browser_dependency() -> None:
    jobs = load_workflow(WORKFLOWS / "browser.yml")["jobs"]
    assert set(jobs) == {"browser-e2e", "browser-csp", "browser-hosting-checkout"}
    full = jobs["browser-hosting-checkout"]  # Final-job canary: inventory must include the new gate.
    assert full["env"]["DB_PORT"] == "5432"
    makefile = (REPO / "Makefile").read_text()
    assert "DB_PORT=$(HOSTING_BROWSER_DB_PORT)" in makefile
    assert "DB_NAME=hosting_browser DB_HOST=127.0.0.1" in makefile
    assert any(
        step.get("run") == 'make test-hosting-plan-checkout-full HOSTING_BROWSER_DB_PORT="$DB_PORT"'
        for step in full["steps"]
    )
    stops = [step for step in full["steps"] if step.get("run") == "make ci-postgres-stop"]
    assert len(stops) == 1 and stops[0]["if"] == "always()"
    assert any("make test-hosting-plan-checkout-full" in step.get("run", "") for step in full["steps"])
    assert any("make ci-postgres-start CI_POSTGRES_IMAGE_TAG=16" in step.get("run", "") for step in full["steps"])
    assert full.get("continue-on-error") is not True
    assert all(step.get("continue-on-error") is not True for step in full["steps"])
    required = jobs["browser-e2e"]
    assert required["needs"] == ["browser-hosting-checkout"]
    assert required["if"] == "always() && github.event_name != 'pull_request'"
    guard = required["steps"][0]
    assert guard["env"]["HOSTING_CHECKOUT_RESULT"] == "${{ needs.browser-hosting-checkout.result }}"
    assert "if" not in guard


def test_hosting_warning_browser_matrix_is_a_required_step() -> None:
    steps = load_workflow(WORKFLOWS / "browser.yml")["jobs"]["browser-e2e"]["steps"]
    matches = [step for step in steps if step.get("run") == "make test-portal-hosting-warnings-browser"]
    assert len(matches) == 1
    assert "if" not in matches[0] and not matches[0].get("continue-on-error")
    makefile = (REPO / "Makefile").read_text()
    assert "test-portal-hosting-warnings-browser: build-css" in makefile
    assert "tests/browser/test_hosting_warning_surfaces.py $(HOSTING_WARNING_BROWSER_ARGS)" in makefile
    uploads = [step for step in steps if str(step.get("uses", "")).startswith("actions/upload-artifact@")]
    assert len(uploads) == 1
    assert "output/playwright/hosting-warning-boundary/" in uploads[0]["with"]["path"]


@pytest.mark.parametrize("upstream", ["success", "failure", "cancelled", "skipped"])
def test_required_browser_guard_rejects_every_unsuccessful_full_checkout(upstream: str) -> None:
    guard = load_workflow(WORKFLOWS / "browser.yml")["jobs"]["browser-e2e"]["steps"][0]
    completed = subprocess.run(  # noqa: S603 -- Execute the actual fixed CI guard against synthetic job results.
        ["/bin/bash", "-c", guard["run"]],
        check=False,
        env={**os.environ, "HOSTING_CHECKOUT_RESULT": upstream},
        capture_output=True,
        text=True,
    )
    assert (completed.returncode == 0) is (upstream == "success"), completed.stderr
