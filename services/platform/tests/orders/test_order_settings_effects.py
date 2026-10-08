"""The `orders.*` settings whose effect nothing asserted.

`max_payment_failures_before_fail` is read only by a getter that has no caller, recorded in
`scripts/settings_inert_baseline.txt`. There is no effect to test until it is wired, and writing a test
against the getter would misrepresent that.

The wired ones are covered here, each through the decision it changes rather than through the getter
that reads it:

* `card_timeout_hours` and `bank_transfer_timeout_hours` decide when an unpaid order is cancelled.
  `test_order_timeout.py` proves the payment-method split (#222) against the shipped defaults; these
  prove the stored value is what the sweep uses, which is a different claim and the one an operator
  depends on when a wire takes longer than usual.
* `review_threshold_cents` decides whether a paid order goes straight to provisioning or waits for a
  human. `test_review_gate.py` covers the gate at `DEFAULT_THRESHOLD`; nothing showed that moving the
  setting moves the gate.
* `max_paid_order_confirmation_failures` bounds an automatic retry loop. The existing test patches
  `get_integer_setting` to 999_999 to prove the clamp, which cannot happen through the settings UI -
  the catalog validation caps the key at 10. Both layers are asserted here, because a clamp with no
  reachable input is only defence in depth if the validation genuinely holds.
* `max_price_override_cents` and `max_price_override_multiplier` bound a staff manual price on an
  order item (#542). They are asserted through the add-item endpoint refusing the price.
"""

from __future__ import annotations

import uuid
from datetime import timedelta
from decimal import Decimal

from django.core.cache import cache
from django.test import TestCase, override_settings
from django.utils import timezone

from apps.billing.models import Currency
from apps.billing.proforma_models import ProformaInvoice
from apps.customers.models import Customer
from apps.orders.models import Order, OrderItem
from apps.orders.services import OrderPaymentConfirmationService
from apps.orders.tasks import (
    _order_timeout_deadline,
    get_max_paid_order_confirmation_failures,
    process_pending_orders,
)
from apps.orders.views import get_max_price_override_cents, get_max_price_override_multiplier
from apps.products.models import Product
from apps.provisioning.models import ServicePlan
from apps.settings.services import SettingsService
from tests.helpers.fsm_helpers import force_status
from tests.orders.test_price_override_enforcement import PriceOverrideTestBase

CARD_TIMEOUT_KEY = "orders.card_timeout_hours"
BANK_TIMEOUT_KEY = "orders.bank_transfer_timeout_hours"
REVIEW_THRESHOLD_KEY = "orders.review_threshold_cents"
CONFIRMATION_FAILURES_KEY = "orders.max_paid_order_confirmation_failures"
MAX_OVERRIDE_CENTS_KEY = "orders.max_price_override_cents"
MAX_OVERRIDE_MULTIPLIER_KEY = "orders.max_price_override_multiplier"


class OrderSettingEffectBase(TestCase):
    def setUp(self) -> None:
        cache.clear()
        self.addCleanup(cache.clear)
        self.currency, _ = Currency.objects.get_or_create(code="RON", defaults={"symbol": "lei", "decimals": 2})
        self.customer = Customer.objects.create(
            name="Order Setting Effects SRL",
            customer_type="company",
            status="active",
            primary_email="order-effects@example.test",
        )

    def set_value(self, key: str, value: int) -> None:
        with self.captureOnCommitCallbacks(execute=True):
            result = SettingsService.update_setting(key, value)
        self.assertTrue(result.is_ok(), result)

    def status_of(self, order: Order) -> str:
        order.refresh_from_db()
        return order.status


@override_settings(CACHES={"default": {"BACKEND": "django.core.cache.backends.locmem.LocMemCache"}})
class OrderTimeoutSettingEffectTests(OrderSettingEffectBase):
    """The configured window, not the shipped one, is what cancels an unpaid order."""

    def order(self, *, payment_method: str, hours_old: float, proforma_valid_days: int | None = None) -> Order:
        order = Order.objects.create(
            customer=self.customer,
            currency=self.currency,
            customer_email=self.customer.primary_email,
            customer_name=self.customer.name,
            payment_method=payment_method,
            subtotal_cents=10000,
            tax_cents=2100,
            total_cents=12100,
            billing_address={},
        )
        force_status(order, "awaiting_payment")
        if proforma_valid_days is not None:
            order.proforma = ProformaInvoice.objects.create(
                customer=self.customer,
                currency=self.currency,
                number=f"PRO-{uuid.uuid4().hex[:8]}",
                total_cents=12100,
                valid_until=timezone.now() + timedelta(days=proforma_valid_days),
            )
            order.save(update_fields=["proforma"])
        # created_at is auto_now_add, so it has to be pushed into the past by update().
        Order.objects.filter(pk=order.pk).update(created_at=timezone.now() - timedelta(hours=hours_old))
        order.refresh_from_db()
        return order

    def sweep(self) -> None:
        with self.captureOnCommitCallbacks(execute=True):
            process_pending_orders()

    def test_a_tightened_card_window_cancels_an_order_the_default_would_spare(self) -> None:
        """6 hours configured, order 8 hours old: the shipped 24h default would leave it alone."""
        self.set_value(CARD_TIMEOUT_KEY, 6)
        order = self.order(payment_method="card", hours_old=8)

        self.sweep()

        self.assertEqual(self.status_of(order), "cancelled")

    def test_a_relaxed_card_window_spares_an_order_the_default_would_cancel(self) -> None:
        """The other direction, so a hardcoded 24 cannot satisfy both tests."""
        self.set_value(CARD_TIMEOUT_KEY, 96)
        order = self.order(payment_method="card", hours_old=30)

        self.sweep()

        self.assertEqual(self.status_of(order), "awaiting_payment")

    def test_the_bank_transfer_fallback_window_governs_when_there_is_no_proforma_to_anchor_on(self) -> None:
        """Without a proforma, the configured bank window supplies the fallback deadline.

        Proforma creation also caps bank-transfer validity at this deadline. The sweep test below
        covers that path; this test covers an order whose proforma has not been created.
        """
        order = self.order(payment_method="bank_transfer", hours_old=10)

        self.set_value(BANK_TIMEOUT_KEY, 200)
        far_deadline, far_basis = _order_timeout_deadline(order)
        self.set_value(BANK_TIMEOUT_KEY, 5)
        near_deadline, near_basis = _order_timeout_deadline(order)

        self.assertEqual(far_basis, "bank_transfer_fallback")
        self.assertEqual(near_basis, "bank_transfer_fallback")
        self.assertEqual(far_deadline, order.created_at + timedelta(hours=200))
        self.assertEqual(near_deadline, order.created_at + timedelta(hours=5))
        # And the near window has already passed for a 10-hour-old order, which is the decision.
        self.assertLess(near_deadline, timezone.now())
        self.assertGreater(far_deadline, timezone.now())

    def test_the_sweep_caps_a_repaired_proforma_at_the_configured_bank_deadline(self) -> None:
        """A repaired proforma keeps the effective deadline anchored to order creation."""
        order = self.order(payment_method="bank_transfer", hours_old=10)
        self.assertIsNone(order.proforma)
        self.set_value(BANK_TIMEOUT_KEY, 5)

        with self.captureOnCommitCallbacks(execute=False) as callbacks:
            process_pending_orders()
            order.refresh_from_db()
            self.assertEqual(order.status, "cancelled")
            self.assertIsNotNone(order.proforma, "the sweep repairs the missing proforma before timing out")
            assert order.proforma is not None
            self.assertEqual(order.proforma.valid_until, order.created_at + timedelta(hours=5))
            self.assertEqual(_order_timeout_deadline(order), (order.proforma.valid_until, "proforma_valid_until"))

        for callback in callbacks:
            callback()
        order.refresh_from_db()
        self.assertIsNone(order.proforma, "cancellation removes the unsent draft")

    def test_the_two_windows_are_not_crossed(self) -> None:
        """Both are read in the same function; swapping them would pass a one-setting test."""
        self.set_value(CARD_TIMEOUT_KEY, 4)
        self.set_value(BANK_TIMEOUT_KEY, 300)
        card = self.order(payment_method="card", hours_old=10)
        bank = self.order(payment_method="bank_transfer", hours_old=10)

        self.sweep()

        self.assertEqual(self.status_of(card), "cancelled")
        self.assertEqual(self.status_of(bank), "awaiting_payment")

    def test_the_catalog_defaults_produce_the_documented_windows(self) -> None:
        """The paired default test: 24h for card, and bank transfer still spared at 25h."""
        self.assertEqual(SettingsService.DEFAULT_SETTINGS[CARD_TIMEOUT_KEY], 24)
        self.assertEqual(SettingsService.DEFAULT_SETTINGS[BANK_TIMEOUT_KEY], 72)
        card = self.order(payment_method="card", hours_old=25)
        bank = self.order(payment_method="bank_transfer", hours_old=25)

        self.sweep()

        self.assertEqual(self.status_of(card), "cancelled")
        self.assertEqual(self.status_of(bank), "awaiting_payment")


@override_settings(CACHES={"default": {"BACKEND": "django.core.cache.backends.locmem.LocMemCache"}})
class ReviewThresholdSettingEffectTests(OrderSettingEffectBase):
    """The configured threshold decides whether a paid order waits for a human."""

    def setUp(self) -> None:
        super().setUp()
        self.product = Product.objects.create(name="Effect VPS", slug="effect-vps", product_type="vps", is_active=True)
        self.product.default_service_plan = ServicePlan.objects.create(
            name="Effect VPS Plan", plan_type="vps", price_monthly=Decimal("100.00")
        )
        self.product.save(update_fields=["default_service_plan"])

    def paid_pending_order(self, total_cents: int) -> Order:
        order = Order.objects.create(
            customer=self.customer,
            currency=self.currency,
            customer_email=self.customer.primary_email,
            customer_name=self.customer.name,
            subtotal_cents=total_cents,
            tax_cents=0,
            total_cents=total_cents,
            billing_address={},
        )
        OrderItem.objects.create(
            order=order,
            product=self.product,
            product_name=self.product.name,
            product_type=self.product.product_type,
            quantity=1,
            unit_price_cents=total_cents,
            tax_rate=Decimal("0"),
            tax_cents=0,
            line_total_cents=total_cents,
        )
        order.refresh_from_db()
        force_status(order, "awaiting_payment")
        return order

    def confirm(self, order: Order) -> None:
        with self.captureOnCommitCallbacks(execute=True):
            result = OrderPaymentConfirmationService.confirm_order(order)
        self.assertTrue(result.is_ok(), result.unwrap_err() if result.is_err() else "")

    def test_an_order_at_the_configured_threshold_is_held_for_review(self) -> None:
        self.set_value(REVIEW_THRESHOLD_KEY, 100_000)
        order = self.paid_pending_order(100_000)

        self.confirm(order)

        self.assertEqual(self.status_of(order), "in_review")

    def test_the_same_order_passes_straight_through_at_a_higher_threshold(self) -> None:
        """Identical order, only the setting differs: the discriminating pair."""
        self.set_value(REVIEW_THRESHOLD_KEY, 10_000_000)
        order = self.paid_pending_order(100_000)

        self.confirm(order)

        self.assertNotEqual(self.status_of(order), "in_review")

    def test_lowering_the_threshold_catches_an_order_the_default_would_release(self) -> None:
        """5,000 RON is the shipped gate; an operator with a tighter risk appetite needs 500 to work."""
        self.set_value(REVIEW_THRESHOLD_KEY, 50_000)
        order = self.paid_pending_order(60_000)

        self.confirm(order)

        self.assertEqual(self.status_of(order), "in_review")

    def test_the_catalog_default_gates_at_five_thousand_lei(self) -> None:
        self.assertEqual(SettingsService.DEFAULT_SETTINGS[REVIEW_THRESHOLD_KEY], 500_000)
        below = self.paid_pending_order(499_999)
        above = self.paid_pending_order(500_000)

        self.confirm(below)
        self.confirm(above)

        self.assertNotEqual(self.status_of(below), "in_review")
        self.assertEqual(self.status_of(above), "in_review")


@override_settings(CACHES={"default": {"BACKEND": "django.core.cache.backends.locmem.LocMemCache"}})
class ConfirmationFailureLimitSettingEffectTests(OrderSettingEffectBase):
    """The retry limit, and the validation that makes its clamp defence in depth rather than the gate."""

    def test_the_stored_limit_is_what_the_task_reads(self) -> None:
        self.set_value(CONFIRMATION_FAILURES_KEY, 7)
        self.assertEqual(get_max_paid_order_confirmation_failures(), 7)

    def test_the_catalog_validation_rejects_a_value_above_its_maximum(self) -> None:
        """The clamp in the getter can only fire on a value the UI cannot store. Prove it cannot."""
        result = SettingsService.update_setting(CONFIRMATION_FAILURES_KEY, 999_999)
        self.assertTrue(result.is_err(), "validation must reject a limit above the catalog maximum")
        self.assertEqual(
            get_max_paid_order_confirmation_failures(), SettingsService.DEFAULT_SETTINGS[CONFIRMATION_FAILURES_KEY]
        )

    def test_the_catalog_validation_rejects_zero(self) -> None:
        """A limit of 0 would mean "escalate on the first failure", which the floor of 1 also prevents."""
        result = SettingsService.update_setting(CONFIRMATION_FAILURES_KEY, 0)
        self.assertTrue(result.is_err(), "validation must reject a limit below the catalog minimum")
        self.assertGreaterEqual(get_max_paid_order_confirmation_failures(), 1)


class PriceOverrideLimitSettingEffectTests(PriceOverrideTestBase):
    """The configured cap and multiplier, not module constants, decide whether a manual price is refused (#542)."""

    def set_value(self, key: str, value: int) -> None:
        with self.captureOnCommitCallbacks(execute=True):
            result = SettingsService.update_setting(key, value)
        self.assertTrue(result.is_ok(), result)

    def test_the_catalog_default_cap_is_what_the_validator_reads(self) -> None:
        self.assertEqual(SettingsService.DEFAULT_SETTINGS[MAX_OVERRIDE_CENTS_KEY], 50_000_000)
        self.assertEqual(get_max_price_override_cents(), 50_000_000)
        self.assertEqual(get_max_price_override_multiplier(), 10)

    def test_lowering_the_multiplier_refuses_an_override_the_default_would_allow(self) -> None:
        self.set_value(MAX_OVERRIDE_MULTIPLIER_KEY, 2)
        before = self.totals()
        response = self.create_item(self.billing, unit=3_000)
        self.assert_rejected(response, "Price override cannot exceed 2x original price")
        self.assertFalse(self.order.items.exists())
        self.assertEqual(self.totals(), before)
        self.assertEqual(self.create_item(self.billing, unit=2_000).status_code, 302)

    def test_lowering_the_cap_refuses_an_override_the_default_would_allow(self) -> None:
        self.set_value(MAX_OVERRIDE_CENTS_KEY, 2_500)
        before = self.totals()
        response = self.create_item(self.billing, unit=3_000)
        self.assert_rejected(response, "Price cannot exceed 2500 cents")
        self.assertFalse(self.order.items.exists())
        self.assertEqual(self.totals(), before)
        self.assertEqual(self.create_item(self.billing, unit=2_500).status_code, 302)
