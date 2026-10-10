"""Browser prerequisites cannot be mistaken for or repair an ORM test database."""

import json
from io import StringIO

from django.core.management import call_command
from django.core.management.base import CommandError
from django.db import connection
from django.test import TestCase, override_settings
from django_q.models import OrmQ
from django_q.signing import SignedPackage
from django_q.tasks import async_task

from apps.billing.models import Invoice
from apps.common.e2e_fixtures import seed_baseline, seed_scenario, validate_baseline
from apps.common.security_decorators import secure_user_registration
from apps.common.types import Ok, Result
from apps.customers.models import Customer
from apps.orders.models import Order
from apps.products.models import Product
from apps.settings.models import SystemSetting
from apps.users.models import CustomerMembership

RESET_TASK = "apps.users.tasks.send_password_reset_email"


@override_settings(ENCRYPTION_KEYS=["MDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDA="])
class E2EFixtureTests(TestCase):
    def test_commands_reject_regular_settings_and_wrong_database(self):
        for command, options in (
            ("seed_e2e", {}),
            ("validate_e2e", {}),
            ("run_e2e_tasks", {"func": RESET_TASK}),
        ):
            with self.subTest(command=command), self.assertRaisesRegex(CommandError, "dedicated live database"):
                call_command(command, stdout=StringIO(), **options)
            with (
                override_settings(DEBUG=True, E2E_FIXTURES_ENABLED=True, E2E_DATABASE_PATH="not-the-live-db.sqlite3"),
                self.assertRaisesRegex(CommandError, "dedicated live database"),
            ):
                call_command(command, stdout=StringIO(), **options)
        self.assertFalse(Customer.objects.exists())

    def test_queued_task_runner_runs_only_the_named_task(self):
        async_task(RESET_TASK, "nobody@example.test")
        async_task("apps.users.tasks.reconcile_session_index")
        output = StringIO()
        with override_settings(
            DEBUG=True, E2E_FIXTURES_ENABLED=True, E2E_DATABASE_PATH=connection.settings_dict["NAME"]
        ):
            call_command("run_e2e_tasks", func=RESET_TASK, stdout=output)
        self.assertEqual(json.loads(output.getvalue()), [{"reason": "configuration", "sent": False}])
        remaining = [SignedPackage.loads(row.payload)["func"] for row in OrmQ.objects.all()]
        self.assertNotIn(RESET_TASK, remaining)
        self.assertIn("apps.users.tasks.reconcile_session_index", remaining)

    def test_baseline_is_idempotent_and_second_customer_is_independent(self):
        first = seed_baseline()
        self.assertEqual(seed_baseline(), first)
        one, two = first["customers"]
        self.assertNotEqual(one["id"], two["id"])
        self.assertEqual(Invoice.objects.count(), 27)
        for customer in (one, two):
            memberships = CustomerMembership.objects.filter(user__email=customer["email"])
            self.assertEqual(list(memberships.values_list("customer_id", flat=True)), [customer["id"]])

    def test_validation_reports_missing_prerequisite_without_repair(self):
        baseline = seed_baseline()
        CustomerMembership.objects.filter(user__email=baseline["customers"][1]["email"]).delete()
        with self.assertRaisesRegex(CommandError, "exactly its own membership"):
            validate_baseline()
        self.assertFalse(CustomerMembership.objects.filter(user__email=baseline["customers"][1]["email"]).exists())

    def test_named_scenarios_own_inputs_and_use_real_order_submission(self):
        seed_baseline()
        fixture = seed_scenario("billing", "bankpayment01")
        order = Order.objects.get(pk=fixture["order_id"])
        self.assertEqual(order.status, "awaiting_payment")
        self.assertEqual(order.proforma_id, fixture["proforma_id"])
        self.assertEqual(order.proforma.total_cents, fixture["total_cents"])
        self.assertIsNone(order.invoice_id)
        pricing = seed_scenario("pricing", "pricing001")
        product = Product.objects.get(pk=pricing["product_id"])
        self.assertEqual(product.meta["fixture_name"], "pricing001")
        self.assertFalse(product.prices.exists())

    def test_baseline_seeds_a_registration_allowance_for_a_full_browser_run(self) -> None:
        seed_baseline()

        @secure_user_registration()
        def register(*, request_ip: str) -> Result[str, str]:
            return Ok("accepted")

        results = [register(request_ip="127.0.0.1") for _attempt in range(12)]
        self.assertEqual([result.unwrap_or("refused") for result in results], ["accepted"] * 12)
        self.assertEqual(SystemSetting.objects.get(key="security.registration_rate_limit_per_ip").value, 10000)
