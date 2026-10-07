"""Contract tests for PostgreSQL-only concurrency coverage in nightly CI."""

from __future__ import annotations

import re
import subprocess
from fnmatch import fnmatchcase
from pathlib import Path
from typing import Any, ClassVar, cast

import yaml
from django.test import SimpleTestCase

_REPOSITORY_ROOT = Path(__file__).resolve().parents[4]
_NIGHTLY_WORKFLOW = _REPOSITORY_ROOT / ".github" / "workflows" / "nightly.yml"
_INTEGRATION_WORKFLOW = _REPOSITORY_ROOT / ".github" / "workflows" / "integration.yml"
_CONCURRENCY_STEP_NAME = "Concurrency tests (PostgreSQL)"
_API_TOKEN_STEP_NAME = "API token and registrar intent tests (PostgreSQL)"
_PLATFORM_STEP_NAME = "Platform tests with coverage (no failfast — complete picture)"
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

    @classmethod
    def setUpClass(cls) -> None:
        super().setUpClass()
        cls.workflow = yaml.safe_load(_NIGHTLY_WORKFLOW.read_text(encoding="utf-8"))
        cls.nightly_job = cls.workflow["jobs"]["nightly"]
        integration_workflow = yaml.safe_load(_INTEGRATION_WORKFLOW.read_text(encoding="utf-8"))
        cls.integration_job = integration_workflow["jobs"]["integration-test"]

    def test_concurrency_step_runs_on_postgresql_before_broad_suite(self) -> None:
        postgres_service = self.nightly_job["services"]["postgres"]
        self.assertEqual(postgres_service["image"], "postgres:16-alpine")

        steps = self.nightly_job["steps"]
        steps_by_name = {step.get("name"): step for step in steps}
        self.assertIn(_CONCURRENCY_STEP_NAME, steps_by_name)
        concurrency_step = steps_by_name[_CONCURRENCY_STEP_NAME]

        step_names = [step.get("name") for step in steps]
        self.assertLess(
            step_names.index(_CONCURRENCY_STEP_NAME),
            step_names.index(_PLATFORM_STEP_NAME),
        )
        self.assertEqual(concurrency_step["timeout-minutes"], 5)
        self.assertNotIn("continue-on-error", concurrency_step)
        expected_environment = {
            "DJANGO_SETTINGS_MODULE": "config.settings.ci",
            "DB_NAME": "postgres",
            "DB_USER": "test",
            "DB_PASSWORD": "test",
            "DB_HOST": "localhost",
        }
        for key, value in expected_environment.items():
            self.assertEqual(concurrency_step["env"].get(key), value)

        command = concurrency_step["run"]
        self.assertIn(_BILLING_CONCURRENCY_TEST_CLASS, command)
        self.assertIn(_PROMOTION_CONCURRENCY_TEST_CLASS, command)
        self.assertIn(_RECURRING_COLLECTION_CONCURRENCY_TEST_CLASS, command)
        self.assertIn(_API_TOKEN_CONCURRENCY_TEST_CLASS, command)
        self.assertIn("--settings=config.settings.ci", command)
        self.assertNotIn("config.settings.test", command)
        self.assertNotIn("--parallel", command)

    def test_api_token_concurrency_runs_on_postgresql_for_pull_requests(self) -> None:
        self.assertEqual(self.integration_job["services"]["postgres"]["image"], "postgres:16")
        steps_by_name = {step.get("name"): step for step in self.integration_job["steps"]}
        api_token_step = steps_by_name[_API_TOKEN_STEP_NAME]
        self.assertEqual(api_token_step["timeout-minutes"], 8)
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

    def test_platform_coverage_gate_runs_full_suite_and_package_floors_on_every_pr(self) -> None:
        workflow = self._workflow("platform.yml")
        jobs = _mapping(workflow["jobs"])
        self.assertIn("coverage-gate", jobs)
        job = _mapping(jobs["coverage-gate"])
        self._assert_unfiltered_pr(workflow, job)
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

    def test_shared_changes_trigger_integration_and_quality_jobs(self) -> None:
        workflow = self._workflow("integration.yml")
        jobs = _mapping(workflow["jobs"])
        self.assertIn("integration-test", jobs)
        self.assertIn("lint-and-quality", jobs)
        triggers = _mapping(workflow["on"])
        for event in ("push", "pull_request"):
            with self.subTest(event=event):
                trigger = _mapping(triggers[event])
                paths = trigger["paths"]
                self.assertIsInstance(paths, list)
                patterns = cast(list[str], paths)
                self.assertIn("shared/**", patterns)
                for path in (
                    "shared/ui/templates/components/button.html",
                    "services/platform/apps/common/services.py",
                    "services/portal/apps/common/views.py",
                ):
                    self.assertTrue(any(fnmatchcase(path, pattern) for pattern in patterns), path)
                self.assertNotIn("paths-ignore", trigger)

    def test_nightly_global_floor_reads_the_makefile(self) -> None:
        workflow = self._workflow("nightly.yml")
        jobs = _mapping(workflow["jobs"])
        job = _mapping(jobs["nightly"])
        coverage_steps = [
            step
            for step in _steps(job)
            if step.get("name") == "Platform tests with coverage (no failfast — complete picture)"
        ]
        self.assertEqual(len(coverage_steps), 1)
        command = str(coverage_steps[0]["run"])
        self.assertIn("floor=$(make -s print-PLATFORM_COVERAGE_FLOOR)", command)
        self.assertIn('--fail-under="$floor"', command)
        self.assertNotRegex(command, r"--fail-under[= ]\d+")
        self.assertIn("make coverage-portal-union", _commands(_mapping(jobs["nightly-e2e"])))

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
