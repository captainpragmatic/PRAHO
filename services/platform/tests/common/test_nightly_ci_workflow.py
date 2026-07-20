"""Contract tests for PostgreSQL-only financial concurrency coverage in nightly CI."""

from __future__ import annotations

from pathlib import Path
from typing import Any, ClassVar

import yaml
from django.test import SimpleTestCase

_REPOSITORY_ROOT = Path(__file__).resolve().parents[4]
_NIGHTLY_WORKFLOW = _REPOSITORY_ROOT / ".github" / "workflows" / "nightly.yml"
_CONCURRENCY_STEP_NAME = "Financial concurrency tests (PostgreSQL)"
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


class NightlyPostgresConcurrencyWorkflowTests(SimpleTestCase):
    """Keep the money-safety concurrency regressions wired to real PostgreSQL."""

    workflow: ClassVar[dict[str, Any]]
    nightly_job: ClassVar[dict[str, Any]]

    @classmethod
    def setUpClass(cls) -> None:
        super().setUpClass()
        cls.workflow = yaml.safe_load(
            _NIGHTLY_WORKFLOW.read_text(encoding="utf-8")
        )
        cls.nightly_job = cls.workflow["jobs"]["nightly"]

    def test_financial_concurrency_step_runs_on_postgresql_before_broad_suite(self) -> None:
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
        self.assertIn("--settings=config.settings.ci", command)
        self.assertNotIn("config.settings.test", command)
        self.assertNotIn("--parallel", command)
