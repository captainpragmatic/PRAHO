"""Contract tests for PostgreSQL-only concurrency coverage in nightly CI."""

from __future__ import annotations

import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any, ClassVar, cast

import yaml
from django.test import SimpleTestCase

_REPOSITORY_ROOT = Path(__file__).resolve().parents[4]
_NIGHTLY_WORKFLOW = _REPOSITORY_ROOT / ".github" / "workflows" / "nightly.yml"
_INTEGRATION_WORKFLOW = _REPOSITORY_ROOT / ".github" / "workflows" / "integration.yml"
_API_TOKEN_STEP_NAME = "API token and registrar intent tests (PostgreSQL)"
_WHOLE_SUITE_STEP_NAME = "Whole platform suite on PostgreSQL"
_BILLING_CONCURRENCY_TEST_CLASS = (
    "tests.billing.test_payment_intent_security.DirectPaymentIntentPostgresConcurrencyTests"
)
_PROMOTION_CONCURRENCY_TEST_CLASS = (
    "tests.promotions.test_order_discount_concurrency.PromotionOrderPostgresConcurrencyTests"
)
_RECURRING_COLLECTION_CONCURRENCY_TEST_CLASS = (
    "tests.billing.test_recurring_collection_concurrency.RecurringCollectionPostgresConcurrencyTests"
)
_API_TOKEN_CONCURRENCY_TEST_CLASS = "tests.api.test_api_token_concurrency.APITokenPostgresConcurrencyTests"


class NightlyPostgresConcurrencyWorkflowTests(SimpleTestCase):
    """Keep the money-safety concurrency regressions wired to real PostgreSQL."""

    workflow: ClassVar[dict[str, Any]]
    nightly_job: ClassVar[dict[str, Any]]
    integration_job: ClassVar[dict[str, Any]]
    integration_gate: ClassVar[dict[str, Any]]

    @classmethod
    def setUpClass(cls) -> None:
        super().setUpClass()
        cls.workflow = yaml.safe_load(_NIGHTLY_WORKFLOW.read_text(encoding="utf-8"))
        cls.nightly_job = cls.workflow["jobs"]["nightly"]
        integration_workflow = yaml.safe_load(_INTEGRATION_WORKFLOW.read_text(encoding="utf-8"))
        cls.integration_job = integration_workflow["jobs"]["integration-suite"]
        cls.integration_gate = integration_workflow["jobs"]["integration-test"]

    def test_the_nightly_runs_the_whole_suite_on_postgresql_after_a_real_bootstrap(self) -> None:
        startup = next(
            step for step in self.nightly_job["steps"] if step.get("name") == "Start PostgreSQL (registry fallback)"
        )
        self.assertIn("16-alpine", startup["run"])
        self.assertIn("github.workflow_sha", startup["run"])
        self.assertEqual(startup["env"], {"CI_POSTGRES_USER": "test", "POSTGRES_PASSWORD": "test"})

        step_names = [step.get("name") for step in self.nightly_job["steps"]]
        self.assertLess(
            step_names.index("Start PostgreSQL (registry fallback)"), step_names.index(_WHOLE_SUITE_STEP_NAME)
        )
        whole = next(step for step in self.nightly_job["steps"] if step.get("name") == _WHOLE_SUITE_STEP_NAME)
        self.assertNotIn("continue-on-error", whole)
        self.assertIn("manage.py test tests", whole["run"])
        self.assertIn("--settings=config.settings.ci", whole["run"])

    def test_the_money_safety_concurrency_classes_run_serially_in_the_merge_queue(self) -> None:
        # The nightly no longer names them: the PostgreSQL-gated scan finds their modules, and the merge
        # queue's platform-postgres runs every gated module serially (tests/integration/
        # test_postgres_gated_tests_run_in_ci.py owns that wiring).
        scan = subprocess.run(  # noqa: S603 -- the repository's own scan, by the running interpreter
            [sys.executable, str(_REPOSITORY_ROOT / "scripts" / "pg_gated_test_modules.py")],
            capture_output=True,
            text=True,
            check=True,
            timeout=60,
        )
        modules = set(scan.stdout.split())
        for test_class in (
            _BILLING_CONCURRENCY_TEST_CLASS,
            _PROMOTION_CONCURRENCY_TEST_CLASS,
            _RECURRING_COLLECTION_CONCURRENCY_TEST_CLASS,
            _API_TOKEN_CONCURRENCY_TEST_CLASS,
        ):
            self.assertIn(test_class.rsplit(".", 1)[0], modules)

    def test_api_token_concurrency_runs_on_postgresql_in_the_merge_queue(self) -> None:
        self.assertIn("integration-suite", self.integration_gate["needs"])
        self.assertEqual(self.integration_gate["if"], "always()")
        startup = next(
            step for step in self.integration_job["steps"] if step.get("name") == "Start PostgreSQL (registry fallback)"
        )
        self.assertEqual(startup["run"], "make ci-postgres-start CI_POSTGRES_IMAGE_TAG=16")
        steps_by_name = {step.get("name"): step for step in self.integration_job["steps"]}
        api_token_step = steps_by_name[_API_TOKEN_STEP_NAME]
        self.assertEqual(api_token_step["timeout-minutes"], 15)
        self.assertNotIn("continue-on-error", api_token_step)
        self.assertEqual(api_token_step["env"]["DJANGO_SETTINGS_MODULE"], "config.settings.ci")
        command = api_token_step["run"]
        self.assertIn(_API_TOKEN_CONCURRENCY_TEST_CLASS, command)
        self.assertIn("tests.domains.test_durable_operations", command)
        # Migration-only database objects: the trigger and the PostgreSQL indexes.
        self.assertIn("tests.customers.test_payment_method_encryption_trigger", command)
        self.assertIn("tests.common.test_migration_db_objects", command)
        # Login second-factor races and the audit savepoint: only a real row lock shows them.
        self.assertIn("tests.users.test_lockout_counter_concurrency", command)
        self.assertIn("tests.users.test_staff_login_second_factor_concurrency", command)
        self.assertIn("tests.users.test_staff_login_enrollment_race", command)
        self.assertIn("tests.users.test_login_audit_failure_keeps_the_login", command)
        self.assertIn("tests.users.test_mfa_audit_isolation", command)
        self.assertIn("tests.api.test_token_second_factor_concurrency", command)
        # Fiscal correction recording: one row per command under racing legs, and the savepoint
        # that keeps a recording failure from aborting settlement.
        self.assertIn("tests.billing.test_fiscal_correction_concurrency", command)
        # Built-in storno issuance: two workers on one correction issue one note and spend one number.
        self.assertIn("tests.billing.test_builtin_storno_concurrency", command)
        self.assertIn("--settings=config.settings.ci", command)
        self.assertNotIn("config.settings.test", command)
        self.assertNotIn("--parallel", command)


def _mapping(value: object) -> dict[str, object]:
    if not isinstance(value, dict):
        raise AssertionError(f"Expected a YAML mapping, got {type(value).__name__}")
    return cast(dict[str, object], value)


def _steps(job: dict[str, object]) -> list[dict[str, object]]:
    value = job["steps"]
    if not isinstance(value, list):
        raise AssertionError("Expected a YAML step list")
    return [_mapping(step) for step in value]


def _commands(job: dict[str, object]) -> str:
    return "\n".join(str(step["run"]) for step in _steps(job) if "run" in step)


class CoverageGateWorkflowTests(SimpleTestCase):
    def _workflow(self, name: str) -> dict[str, object]:
        text = (_REPOSITORY_ROOT / ".github" / "workflows" / name).read_text(encoding="utf-8")
        # Quote GitHub's event key so YAML 1.1 does not coerce it to True.
        return _mapping(yaml.safe_load(re.sub(r"^on:", '"on":', text, flags=re.MULTILINE)))

    def _assert_unfiltered_pr(self, workflow: dict[str, object], job: dict[str, object]) -> None:
        trigger = _mapping(_mapping(workflow["on"])["pull_request"])
        for scope in (trigger, job):
            self.assertNotIn("paths", scope)
            self.assertNotIn("paths-ignore", scope)
        for key in ("if", "needs", "continue-on-error"):
            self.assertNotIn(key, job)
        for step in _steps(job):
            if "run" in step:
                self.assertNotIn("if", step)
                self.assertNotIn("continue-on-error", step)

    def _make_variable(self, name: str) -> str:
        text = (_REPOSITORY_ROOT / "Makefile").read_text(encoding="utf-8")
        match = re.search(rf"^{name}\s*(?:\?=|:=|=)\s*(.+)$", text, re.MULTILINE)
        self.assertIsNotNone(match, f"Missing Makefile variable {name}")
        if match is None:
            self.fail(f"Missing Makefile variable {name}")
        return match.group(1).strip()

    def test_platform_coverage_gate_runs_full_suite_and_package_floors_in_the_merge_queue(self) -> None:
        workflow = self._workflow("platform.yml")
        jobs = _mapping(workflow["jobs"])
        self.assertIn("coverage-gate", jobs)
        job = _mapping(jobs["coverage-gate"])
        # The queue tier (ADR-0036): a pull request skips it and runs the affected modules in platform-test;
        # the merge queue and master run it. tests/integration/test_ci_required_checks.py owns that condition.
        self.assertEqual(job.get("if"), "github.event_name != 'pull_request'")
        self._assert_unfiltered_pr(workflow, {key: value for key, value in job.items() if key != "if"})
        commands = _commands(job).splitlines()
        self.assertIn("make coverage-platform", commands)
        self.assertIn("make coverage-platform-packages", commands)
        self.assertLess(commands.index("make coverage-platform"), commands.index("make coverage-platform-packages"))

    def test_portal_coverage_job_has_no_pr_path_filters(self) -> None:
        workflow = self._workflow("portal.yml")
        job = _mapping(_mapping(workflow["jobs"])["portal-test"])
        self._assert_unfiltered_pr(workflow, job)

    def test_portal_pr_uses_the_unit_floor_target_without_the_browser_union(self) -> None:
        workflow = self._workflow("portal.yml")
        job = _mapping(_mapping(workflow["jobs"])["portal-test"])
        commands = _commands(job)
        self.assertIn("make coverage-portal-unit", commands.splitlines())
        self.assertNotIn("coverage-portal-union", commands)

    def test_every_change_starts_the_required_workflows_and_master_is_not_tested_again(self) -> None:
        for name in ("platform.yml", "portal.yml", "integration.yml"):
            with self.subTest(workflow=name):
                triggers = _mapping(self._workflow(name)["on"])
                # Required checks: a pull request and a merge group must start them whatever they change.
                for event in ("pull_request", "merge_group"):
                    trigger = _mapping(triggers[event])
                    self.assertNotIn("paths", trigger)
                    self.assertNotIn("paths-ignore", trigger)
                # The queue tested exactly the commit it lands on master; a push re-run proves nothing new.
                self.assertNotIn("push", triggers)

    def test_the_nightly_keeps_only_the_portal_union_floor(self) -> None:
        # SQLite coverage and its floors run in the merge queue (coverage-gate); the nightly keeps the portal
        # union, which needs the browser suite's coverage.
        jobs = _mapping(self._workflow("nightly.yml")["jobs"])
        self.assertIn("make coverage-portal-union", _commands(_mapping(jobs["nightly-e2e"])))
        everything = "\n".join(_commands(_mapping(job)) for job in jobs.values())
        for gone in ("coverage-platform", "PLATFORM_COVERAGE_FLOOR", "make lint", "check-types", "lint-security"):
            self.assertNotIn(gone, everything)

    def test_platform_global_floor_is_78(self) -> None:
        self.assertEqual(self._make_variable("PLATFORM_COVERAGE_FLOOR"), "78")

    def test_critical_package_floors_include_provisioning_80(self) -> None:
        floors: dict[str, str] = {}
        for pair in self._make_variable("PLATFORM_PACKAGE_FLOORS").split():
            name, floor = pair.split(":")
            floors[name] = floor
        self.assertEqual(floors, {"billing": "85", "settings": "75", "users": "70", "provisioning": "80"})

    def test_portal_unit_floor_is_79(self) -> None:
        self.assertEqual(self._make_variable("PORTAL_UNIT_COVERAGE_FLOOR"), "79")

    def test_portal_unit_target_passes_the_overridable_floor_to_pytest_cov(self) -> None:
        for floor in ("79", "81"):
            with self.subTest(floor=floor):
                completed = subprocess.run(  # noqa: S603 -- fixed make target, no shell
                    [  # noqa: S607 -- use make from PATH, as the repository test runner does
                        "make",
                        "-s",
                        "-n",
                        "coverage-portal-unit",
                        f"PORTAL_UNIT_COVERAGE_FLOOR={floor}",
                    ],
                    cwd=_REPOSITORY_ROOT,
                    capture_output=True,
                    text=True,
                    check=False,
                )
                self.assertEqual(completed.returncode, 0, completed.stderr)
                self.assertIn(f"--cov-fail-under={floor}", completed.stdout)
                self.assertIn("--cov-report=xml:coverage-portal.xml", completed.stdout)
                self.assertNotIn("COVERAGE_RCFILE=", completed.stdout)


def _nightly() -> dict[str, Any]:
    return yaml.safe_load(_NIGHTLY_WORKFLOW.read_text(encoding="utf-8"))


class CheckActivityDispatchTests(SimpleTestCase):
    """A manual dispatch tests the branch it was dispatched on, so a change can be proven before merge.

    The dispatch path used to hardcode master and staging, whatever ref was dispatched. These tests run
    check-activity's real script, taken from the workflow file, on the dispatch path, which exits
    before it needs git or the API.
    """

    def _dispatch(self, ref_name: str, ref_type: str = "branch") -> tuple[int, str]:
        steps = _nightly()["jobs"]["check-activity"]["steps"]
        script = next(step["run"] for step in steps if step.get("id") == "check")
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "github_output"
            output.write_text("")
            completed = subprocess.run(  # noqa: S603 -- the workflow's own script, run by a fixed bash
                ["bash", "-c", script],  # noqa: S607 -- bash from PATH, as the runner provides it
                env={
                    "PATH": os.environ.get("PATH", ""),
                    "EVENT_NAME": "workflow_dispatch",
                    "REF_NAME": ref_name,
                    "REF_TYPE": ref_type,
                    "GITHUB_OUTPUT": str(output),
                },
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
            )
            return completed.returncode, output.read_text()

    def test_a_dispatch_tests_the_branch_it_was_dispatched_on(self) -> None:
        for ref in ("master", "staging", "fix/nightly-e2e-shutdown-and-dispatch"):
            with self.subTest(ref=ref):
                code, output = self._dispatch(ref)
                self.assertEqual(code, 0)
                self.assertEqual(output.strip(), f'branches=["{ref}"]')

    def test_a_ref_that_is_not_a_plain_branch_name_is_refused(self) -> None:
        for ref in ("", "a;rm -rf /", "$(id)", "two words", 'quote"d', "back\\slash"):
            with self.subTest(ref=ref):
                code, output = self._dispatch(ref)
                self.assertNotEqual(code, 0)
                self.assertNotIn("branches=", output)

    def test_a_dispatched_tag_is_refused_even_with_a_plain_name(self) -> None:
        code, output = self._dispatch("v1.2.3", ref_type="tag")
        self.assertNotEqual(code, 0)
        self.assertNotIn("branches=", output)

    def test_the_ref_reaches_the_script_through_env_only(self) -> None:
        step = next(s for s in _nightly()["jobs"]["check-activity"]["steps"] if s.get("id") == "check")
        self.assertEqual(step["env"]["REF_NAME"], "${{ github.ref_name }}")
        self.assertEqual(step["env"]["REF_TYPE"], "${{ github.ref_type }}")
        self.assertNotIn("${{", step["run"])


class NightlyArtifactNamesTests(SimpleTestCase):
    """Artifact names may not contain `/`, so a dispatched `fix/...` branch would fail the upload."""

    def _naming_and_upload(self, job_name: str) -> tuple[dict[str, Any], dict[str, Any]]:
        steps = _nightly()["jobs"][job_name]["steps"]
        naming = next(step for step in steps if step.get("id") == "artifact")
        upload = next(step for step in steps if str(step.get("uses", "")).startswith("actions/upload-artifact"))
        return naming, upload

    def test_the_naming_step_replaces_slashes(self) -> None:
        for job_name in ("nightly-e2e",):
            naming, _upload = self._naming_and_upload(job_name)
            self.assertEqual(naming["env"]["BRANCH"], "${{ matrix.branch }}")
            with tempfile.TemporaryDirectory() as directory, self.subTest(job=job_name):
                output = Path(directory) / "github_output"
                output.write_text("")
                subprocess.run(  # noqa: S603 -- the workflow's own script, run by a fixed bash
                    ["bash", "-c", naming["run"]],  # noqa: S607 -- bash from PATH, as the runner provides it
                    env={"PATH": os.environ.get("PATH", ""), "BRANCH": "fix/nightly/x", "GITHUB_OUTPUT": str(output)},
                    check=True,
                    timeout=30,
                )
                self.assertEqual(output.read_text().strip(), "suffix=fix-nightly-x")

    def test_uploads_are_named_from_that_step_with_distinct_prefixes(self) -> None:
        expected = {"nightly-e2e": "nightly-e2e-"}
        for job_name, prefix in expected.items():
            _naming, upload = self._naming_and_upload(job_name)
            self.assertEqual(upload["with"]["name"], prefix + "${{ steps.artifact.outputs.suffix }}")


class ScheduledFailureNotifierTests(SimpleTestCase):
    """A red scheduled run must reach a person: the browser job failed seven nights running unseen."""

    def test_a_failed_scheduled_run_opens_or_updates_the_tracking_issue(self) -> None:
        jobs = _nightly()["jobs"]
        notifier = jobs["notify-scheduled-failure"]
        self.assertEqual(set(notifier["needs"]), {"check-activity", "nightly", "nightly-e2e", "nightly-native-deploy"})
        for clause in ("always()", "github.event_name == 'schedule'", "contains(needs.*.result, 'failure')"):
            self.assertIn(clause, notifier["if"])
        script = "\n".join(str(step.get("run", "")) for step in notifier["steps"])
        self.assertIn("nightly-failure", script)
        self.assertIn("gh issue", script)

    def test_only_the_notifier_can_write_and_it_checks_nothing_out(self) -> None:
        workflow = _nightly()
        self.assertEqual(workflow["permissions"], {"contents": "read"})
        notifier = workflow["jobs"]["notify-scheduled-failure"]
        self.assertEqual(notifier["permissions"], {"issues": "write"})
        self.assertFalse(any("checkout" in str(step.get("uses", "")) for step in notifier["steps"]))
        writers = [name for name, job in workflow["jobs"].items() if "write" in str(job.get("permissions", {}))]
        self.assertEqual(writers, ["notify-scheduled-failure"])
        self.assertEqual(
            workflow["jobs"]["check-activity"]["permissions"], {"contents": "read", "pull-requests": "read"}
        )
