"""Production order, invoice, signal, migration, and backfill paths require evidence."""

from importlib import import_module
from io import StringIO
from unittest.mock import call, patch

from django.apps import apps
from django.core.cache import cache
from django.core.management import call_command
from django.db import connection
from django.test import TestCase, override_settings
from django.utils import timezone

from apps.billing.models import Currency
from apps.billing.services import _build_customer_vat_info
from apps.common.tax_service import TaxService, VATScenario
from apps.customers.models import Customer, CustomerTaxProfile
from apps.orders.models import Order, OrderItem
from apps.orders.preflight import OrderPreflightValidationService
from apps.orders.services import OrderCalculationService
from apps.products.models import Product


@override_settings(COMPANY_COUNTRY_CODE="RO")
class VIESGatePathTests(TestCase):
    def setUp(self) -> None:
        cache.clear()
        self.customer = Customer.objects.create(
            name="Evidence GmbH", company_name="Evidence GmbH", customer_type="company",
            primary_email="evidence-gate@example.test",
        )
        self.profile = CustomerTaxProfile.objects.create(
            customer=self.customer, vat_number="DE123456789", is_vat_payer=True,
            vies_verification_status="valid", reverse_charge_eligible=True,
            vies_verified_at=timezone.now(), vies_verified_name="Evidence GmbH",
        )

    def _order(self) -> Order:
        currency, _created = Currency.objects.get_or_create(code="EUR", defaults={"symbol": "€"})
        order = Order.objects.create(
            order_number="VIES-GATE-1", customer=self.customer, currency=currency,
            subtotal_cents=10000, tax_cents=0, total_cents=10000,
            billing_address={
                "country": "DE", "vat_number": "DE123456789", "company_name": "Evidence GmbH",
                "contact_name": "Billing", "email": "evidence-gate@example.test",
                "address_line1": "Teststrasse 1", "city": "Berlin", "county": "Berlin", "postal_code": "10115",
            },
        )
        product = Product.objects.create(name="Hosting", slug="vies-gate-hosting", product_type="shared_hosting")
        OrderItem.objects.create(
            order=order, product=product, product_name="Hosting", product_type="shared_hosting",
            quantity=1, unit_price_cents=10000, tax_rate=0, tax_cents=0, line_total_cents=10000,
        )
        return Order.objects.get(pk=order.pk)

    def test_order_snapshot_number_requires_its_own_evidence(self) -> None:
        totals = OrderCalculationService.calculate_order_totals(
            [{"quantity": 1, "unit_price_cents": 10000}],
            self.customer,
            {"country": "DE", "company_name": "Evidence GmbH", "vat_number": "DE999999999"},
        )
        self.assertEqual(totals, {"subtotal_cents": 10000, "tax_cents": 1900, "total_cents": 11900})

    def test_invoice_builder_passes_current_evidence(self) -> None:
        info = _build_customer_vat_info(self.customer, country="DE")
        self.assertIs(info["vies_verified"], True)
        self.assertEqual(TaxService.calculate_vat_for_document(10000, info).scenario, VATScenario.EU_B2B_REVERSE_CHARGE)
        self.profile.vies_verification_status = "pending"
        self.profile.save(update_fields=["vies_verification_status"])
        customer = Customer.objects.get(pk=self.customer.pk)
        info = _build_customer_vat_info(customer, country="DE")
        self.assertIs(info["vies_verified"], False)
        self.assertEqual(TaxService.calculate_vat_for_document(10000, info).vat_cents, 1900)

    def test_preflight_blocks_zero_tax_order_without_vies_evidence(self) -> None:
        CustomerTaxProfile.objects.filter(pk=self.profile.pk).update(vies_verification_status="pending")
        order = self._order()
        with self.assertRaisesRegex(ValueError, "VAT evidence missing for reverse charge"):
            OrderPreflightValidationService.assert_valid(order)

    def test_changing_to_dutch_vat_resets_evidence_and_queues_validation(self) -> None:
        queued: list[tuple[str, str, bool, object, str]] = []

        def record(profile: CustomerTaxProfile) -> None:
            current = CustomerTaxProfile.objects.get(pk=profile.pk)
            queued.append((
                current.vat_number, current.vies_verification_status, current.reverse_charge_eligible,
                current.vies_verified_at, current.vies_verified_name,
            ))

        with patch("apps.customers.signals._trigger_vat_validation", side_effect=record):
            self.profile.vat_number = "NL123456782"
            self.profile.save(update_fields=["vat_number"])
        expected = ("NL123456782", "pending", False, None, "")
        self.assertEqual(queued, [expected])
        self.assertEqual(
            (self.profile.vat_number, self.profile.vies_verification_status, self.profile.reverse_charge_eligible,
             self.profile.vies_verified_at, self.profile.vies_verified_name),
            expected,
        )

    def test_migration_clears_stale_human_flag(self) -> None:
        CustomerTaxProfile.objects.filter(pk=self.profile.pk).update(vies_verification_status="pending")
        migration = import_module("apps.customers.migrations.0022_clear_unverified_reverse_charge")
        self.assertEqual(CustomerTaxProfile._meta.db_table, "customer_tax_profiles")
        migration.clear_unverified_reverse_charge(apps, connection.schema_editor())
        self.profile.refresh_from_db()
        self.assertFalse(self.profile.reverse_charge_eligible)

    def test_command_reports_blocked_order_and_enqueues_only_unverified_eu_profiles(self) -> None:
        CustomerTaxProfile.objects.filter(pk=self.profile.pk).update(vies_verification_status="pending")
        order = self._order()
        pending_ids = [str(self.profile.pk)]
        for index, (number, status) in enumerate((
            ("NL123456782", "format_only"), ("FR40303265045", "valid"), ("GB123456789", "pending"), ("", "pending"),
        )):
            customer = Customer.objects.create(name=f"Backfill {index}", primary_email=f"backfill{index}@example.test")
            profile = CustomerTaxProfile.objects.create(
                customer=customer, vat_number=number, vies_verification_status=status,
            )
            if index == 0:
                pending_ids.append(str(profile.pk))
        output = StringIO()
        with patch("django_q.tasks.async_task") as enqueue:
            call_command("validate_vat_numbers", "--blocked-orders", stdout=output)
        self.assertIn("Blocked orders: 1", output.getvalue())
        self.assertIn(str(order.pk), output.getvalue())
        self.assertIn("Enqueued: 2", output.getvalue())
        self.assertCountEqual(
            enqueue.call_args_list,
            [call("apps.billing.tasks.validate_vat_number", profile_id) for profile_id in pending_ids],
        )
