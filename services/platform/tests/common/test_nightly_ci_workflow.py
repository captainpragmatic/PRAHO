"""Contract tests for PostgreSQL-only concurrency coverage in nightly CI."""

from __future__ import annotations

import os
import subprocess
import tempfile
from pathlib import Path
from typing import Any, ClassVar

import yaml
from django.test import SimpleTestCase

_REPOSITORY_ROOT = Path(__file__).resolve().parents[4]
_NIGHTLY_WORKFLOW = _REPOSITORY_ROOT / ".github" / "workflows" / "nightly.yml"
_INTEGRATION_WORKFLOW = _REPOSITORY_ROOT / ".github" / "workflows" / "integration.yml"
_CONCURRENCY_STEP_NAME = "Concurrency tests (PostgreSQL)"
_API_TOKEN_STEP_NAME = "API token and registrar intent tests (PostgreSQL)"
_PLATFORM_STEP_NAME = "Platform tests with coverage (no failfast — complete picture)"
_BILLING_CONCURRENCY_TEST_CLASS = (
    "tests.billing.test_payment_intent_security."
    "DirectPaymentIntentPostgresConcurrencyTests"
)
_PROMOTION_CONCURRENCY_TEST_CLASS = (
    "tests.promotions.test_order_discount_concurrency."
    "PromotionOrderPostgresConcurrencyTests"
)
_RECURRING_COLLECTION_CONCURRENCY_TEST_CLASS = (
    "tests.billing.test_recurring_collection_concurrency."
    "RecurringCollectionPostgresConcurrencyTests"
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
        cls.workflow = yaml.safe_load(
            _NIGHTLY_WORKFLOW.read_text(encoding="utf-8")
        )
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
        for job_name in ("nightly", "nightly-e2e"):
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
        expected = {"nightly": "nightly-reports-", "nightly-e2e": "nightly-e2e-"}
        for job_name, prefix in expected.items():
            _naming, upload = self._naming_and_upload(job_name)
            self.assertEqual(upload["with"]["name"], prefix + "${{ steps.artifact.outputs.suffix }}")


class ScheduledFailureNotifierTests(SimpleTestCase):
    """A red scheduled run must reach a person: the browser job failed seven nights running unseen."""

    def test_a_failed_scheduled_run_opens_or_updates_the_tracking_issue(self) -> None:
        jobs = _nightly()["jobs"]
        notifier = jobs["notify-scheduled-failure"]
        self.assertEqual(set(notifier["needs"]), {"check-activity", "nightly", "nightly-e2e"})
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
