"""Browser prerequisites cannot be mistaken for or repair an ORM test database."""

from io import StringIO

from django.core.management import call_command
from django.core.management.base import CommandError
from django.test import TestCase, override_settings

from apps.billing.models import Invoice
from apps.common.e2e_fixtures import seed_baseline, seed_scenario, validate_baseline
from apps.customers.models import Customer
from apps.orders.models import Order
from apps.products.models import Product
from apps.users.models import CustomerMembership


@override_settings(ENCRYPTION_KEYS=["MDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDA="])
class E2EFixtureTests(TestCase):
    def test_commands_reject_regular_settings_and_wrong_database(self):
        for command in ("seed_e2e", "validate_e2e"):
            with self.subTest(command=command), self.assertRaisesRegex(CommandError, "dedicated live database"):
                call_command(command, stdout=StringIO())
            with (
                override_settings(DEBUG=True, E2E_FIXTURES_ENABLED=True, E2E_DATABASE_PATH="not-the-live-db.sqlite3"),
                self.assertRaisesRegex(CommandError, "dedicated live database"),
            ):
                call_command(command, stdout=StringIO())
        self.assertFalse(Customer.objects.exists())

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
