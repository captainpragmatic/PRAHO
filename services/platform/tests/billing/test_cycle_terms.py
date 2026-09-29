"""Billing periods keep the money and metering terms that customers agreed to."""

from decimal import Decimal
from io import StringIO

from django.core.exceptions import ValidationError
from django.core.management import call_command
from django.test import TestCase
from django.utils import timezone

from apps.billing.currency_policy import get_selling_currency_policy
from apps.billing.cycle_provenance import inspect_cycle_provenance
from apps.billing.cycle_terms import get_cycle_currency, get_usage_cycle_currency
from apps.billing.metering_service import RatingEngine
from apps.billing.models import (
    BillingCycle,
    Currency,
    Invoice,
    InvoiceLine,
    PricingTier,
    Subscription,
    UsageAggregation,
    UsageMeter,
)
from apps.customers.models import Customer
from apps.products.models import Product
from apps.settings.models import SystemSetting
from tests.billing import test_metering_services as metering_fixtures


class FrozenUsageInvoiceTests(TestCase):
    def setUp(self) -> None:
        metering_fixtures.UsageInvoiceServiceTestCase.setUp(self)
        self.eur, _ = Currency.objects.get_or_create(code="EUR", defaults={"symbol": "€"})

    def test_delayed_usage_invoice_keeps_its_original_cycle_currency(self) -> None:
        self.subscription.currency = self.eur
        self.subscription.unit_price_cents = 900
        self.subscription.quantity = 4
        self.subscription.save(update_fields=["currency", "unit_price_cents", "quantity"])
        result = self.service.generate_invoice_from_cycle(str(self.billing_cycle.pk))
        self.assertTrue(result.is_ok(), result)
        invoice = Invoice.objects.get(pk=result.unwrap()["invoice_id"])
        self.assertEqual(invoice.currency_id, "RON")
        self.assertEqual(invoice.total_cents, 3025)
        self.billing_cycle.refresh_from_db()
        self.assertEqual(self.billing_cycle.currency_id, "RON")
        self.assertEqual((self.billing_cycle.unit_price_cents, self.billing_cycle.quantity), (2999, 1))

    def test_frozen_cycle_identity_cannot_be_relabelled(self) -> None:
        self.billing_cycle.currency = self.eur
        with self.assertRaises(ValidationError):
            self.billing_cycle.save()
        self.billing_cycle.refresh_from_db()
        self.assertEqual(self.billing_cycle.currency_id, "RON")

    def test_usage_worker_cannot_issue_unknown_historical_money_after_policy_change(self) -> None:
        # Reproduce an old row without any immutable currency evidence.
        BillingCycle.objects.filter(pk=self.billing_cycle.pk).update(
            currency=None, terms_frozen_at=None, pricing_snapshot={}, quantity=None, unit_price_cents=None,
            invoice=None,
        )
        get_selling_currency_policy(lock=True)
        SystemSetting.objects.filter(key="billing.default_currency").update(value="EUR", revision=2)
        before = Invoice.objects.count()
        result = self.service.generate_invoice_from_cycle(str(self.billing_cycle.pk))
        self.assertTrue(result.is_err(), result)
        self.assertIn("Unreviewed historical usage", result.unwrap_err())
        self.assertEqual(Invoice.objects.count(), before)


class FrozenTariffTests(TestCase):
    def setUp(self) -> None:
        # Configure the published tariff before the new measured period begins.
        self.currency, _ = Currency.objects.get_or_create(code="RON", defaults={"symbol": "lei"})
        self.customer = Customer.objects.create(name="Frozen usage buyer", customer_type="individual")
        self.product = Product.objects.create(name="Frozen hosting", slug="frozen-usage", product_type="hosting")
        self.meter = UsageMeter.objects.create(
            name="frozen-bandwidth", display_name="Bandwidth", aggregation_type="sum", unit="gb",
            rounding_mode="up", rounding_increment=Decimal(1),
        )
        self.tier = PricingTier.objects.create(
            meter=self.meter, currency=self.currency, name="Original tariff", pricing_model="per_unit",
            unit_price_cents=50, is_active=True, is_default=True,
        )
        now = timezone.now()
        self.subscription = Subscription.objects.create(
            customer=self.customer, product=self.product, currency=self.currency,
            subscription_number="SUB-FROZEN-TARIFF", status="active", unit_price_cents=2999,
            current_period_start=now, current_period_end=now + timezone.timedelta(days=30), next_billing_date=now,
        )
        self.cycle = BillingCycle.objects.create(
            subscription=self.subscription, period_start=now,
            period_end=now + timezone.timedelta(days=30), status="active",
        )

    def test_rating_uses_frozen_price_and_rounding_after_live_config_changes(self) -> None:
        self.tier.unit_price_cents = 900
        self.tier.save(update_fields=["unit_price_cents"])
        self.meter.rounding_increment = Decimal(10)
        self.meter.save(update_fields=["rounding_increment"])
        aggregation = UsageAggregation.objects.create(
            meter=self.meter, customer=self.customer, subscription=self.subscription, billing_cycle=self.cycle,
            period_start=self.cycle.period_start, period_end=self.cycle.period_end,
            total_value=Decimal("1.1"), status="pending_rating",
        )
        result = RatingEngine().rate_aggregation(str(aggregation.pk))
        self.assertTrue(result.is_ok(), result)
        aggregation.refresh_from_db()
        self.assertEqual(aggregation.billable_value, Decimal(2))
        self.assertEqual(aggregation.charge_cents, 100)
        self.assertEqual(aggregation.meta["rating"]["currency"], "RON")


class HistoricalCycleProvenanceTests(TestCase):
    def setUp(self) -> None:
        fixture = FrozenTariffTests()
        fixture.setUp()
        self.subscription = fixture.subscription
        self.meter = fixture.meter
        self.ron = fixture.currency
        self.eur, _ = Currency.objects.get_or_create(code="EUR", defaults={"symbol": "€"})
        start = fixture.cycle.period_end
        # This intentionally models a legacy upcoming row with no new snapshot fields.
        self.cycle = BillingCycle.objects.create(
            subscription=self.subscription, period_start=start, period_end=start + timezone.timedelta(days=30),
            base_charge_cents=2468, total_cents=2468,
        )

    def link_invoice(self, *, issued: bool = True) -> Invoice:
        invoice = Invoice.objects.create(
            customer=self.subscription.customer, currency=self.ron, number="ORIGINAL-CYCLE", due_at=timezone.now(),
            subtotal_cents=2468, total_cents=2468, locked_at=timezone.now() if issued else None,
        )
        self.cycle.invoice = invoice
        self.cycle.save(update_fields=["invoice"])
        return invoice

    def test_known_original_currency_remains_readable_without_writing_historical_rows(self) -> None:
        invoice = self.link_invoice()
        self.subscription.currency = self.eur
        self.subscription.save(update_fields=["currency"])
        before = BillingCycle.objects.filter(pk=self.cycle.pk).values().get()
        self.assertEqual(get_cycle_currency(self.cycle).code, "RON")
        self.assertEqual(BillingCycle.objects.filter(pk=self.cycle.pk).values().get(), before)
        invoice.refresh_from_db()
        self.assertEqual((invoice.currency_id, invoice.total_cents), ("RON", 2468))

    def test_unreviewed_legacy_usage_retains_behavior_before_first_policy_change(self) -> None:
        self.assertEqual(get_selling_currency_policy().revision, 1)
        before = BillingCycle.objects.filter(pk=self.cycle.pk).values().get()
        self.assertEqual(get_usage_cycle_currency(self.cycle).code, "RON")
        self.assertEqual(BillingCycle.objects.filter(pk=self.cycle.pk).values().get(), before)

    def test_unreviewed_legacy_usage_is_held_if_policy_guard_was_bypassed(self) -> None:
        get_selling_currency_policy(lock=True)
        # Model an out-of-band administrative DB edit, bypassing the normal preflight.
        SystemSetting.objects.filter(key="billing.default_currency").update(value="EUR", revision=2)
        with self.assertRaisesMessage(ValidationError, "Unreviewed historical usage"):
            get_usage_cycle_currency(self.cycle)

    def test_original_invoice_proves_usage_currency_after_policy_change(self) -> None:
        self.link_invoice()
        get_selling_currency_policy(lock=True)
        SystemSetting.objects.filter(key="billing.default_currency").update(value="EUR", revision=2)
        self.subscription.currency = self.eur
        self.subscription.save(update_fields=["currency"])
        self.assertEqual(get_usage_cycle_currency(self.cycle).code, "RON")

    def test_draft_document_and_new_default_cannot_invent_original_currency(self) -> None:
        self.link_invoice(issued=False)
        self.subscription.currency = self.eur
        self.subscription.save(update_fields=["currency"])
        with self.assertRaises(ValidationError):
            get_cycle_currency(self.cycle)

    def test_audit_reports_missing_identity_and_does_not_change_any_cycle(self) -> None:
        before = list(BillingCycle.objects.order_by("pk").values())
        output = StringIO()
        call_command("audit_billing_cycle_terms", stdout=output)
        self.assertIn(str(self.cycle.pk), output.getvalue())
        self.assertIn("held", output.getvalue())
        self.assertEqual(list(BillingCycle.objects.order_by("pk").values()), before)

    def test_exact_original_line_supplies_terms(self) -> None:
        invoice = self.link_invoice(issued=False)
        line = InvoiceLine(invoice=invoice, billing_cycle=self.cycle, description="Original renewal",
                           quantity=2, unit_price_cents=1234, line_total_cents=2468)
        InvoiceLine.objects.bulk_create([line])
        Invoice.objects.filter(pk=invoice.pk).update(locked_at=timezone.now())
        invoice.refresh_from_db()
        provenance = inspect_cycle_provenance(self.cycle)
        self.assertEqual((provenance.currency_code, provenance.quantity, provenance.unit_price_cents), ("RON", 2, 1234))

    def test_duplicate_original_lines_do_not_invent_one_fixed_price(self) -> None:
        invoice = self.link_invoice(issued=False)
        InvoiceLine.objects.bulk_create([
            InvoiceLine(invoice=invoice, billing_cycle=self.cycle, description="Original renewal",
                        quantity=2, unit_price_cents=1234, line_total_cents=2468),
            InvoiceLine(invoice=invoice, billing_cycle=self.cycle, description="Original renewal",
                        quantity=2, unit_price_cents=1234, line_total_cents=2468),
        ])
        Invoice.objects.filter(pk=invoice.pk).update(locked_at=timezone.now())
        invoice.refresh_from_db()
        self.assertTrue(inspect_cycle_provenance(self.cycle).hold_reason)
        self.assertIsNone(inspect_cycle_provenance(self.cycle).quantity)

    def test_invalid_original_order_metadata_is_reported_without_guessing(self) -> None:
        self.cycle.meta = {"source": "initial_subscription_entitlement"}
        self.subscription.meta = {"initial_order_item_id": "not-an-id", "initial_order_id": "invalid"}
        self.subscription.save(update_fields=["meta"])
        self.assertIsNone(inspect_cycle_provenance(self.cycle).currency_code)
        self.assertTrue(inspect_cycle_provenance(self.cycle).hold_reason)

    def test_conflicting_original_rating_and_invoice_currencies_are_held(self) -> None:
        self.link_invoice()
        UsageAggregation.objects.create(
            billing_cycle=self.cycle, subscription=self.subscription, customer=self.subscription.customer,
            meter=self.meter, period_start=self.cycle.period_start, period_end=self.cycle.period_end,
            status="rated", total_value=1, charge_cents=50, meta={"rating": {"currency": "EUR"}},
        )
        with self.assertRaises(ValidationError):
            get_cycle_currency(self.cycle)
