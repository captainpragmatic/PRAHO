"""Campaign edits and reports must retain the currencies in the original ledgers."""

from concurrent.futures import ThreadPoolExecutor
from threading import Event
from time import monotonic
from unittest import skipUnless
from uuid import uuid4

from django.contrib.admin.sites import AdminSite
from django.contrib.auth import get_user_model
from django.core.exceptions import ValidationError
from django.db import close_old_connections, connection, connections, transaction
from django.test import TestCase, TransactionTestCase
from django.urls import reverse
from django.utils import timezone

from apps.billing.metering_models import BillingCycle
from apps.billing.models import Currency
from apps.billing.subscription_models import Subscription
from apps.customers.models import Customer
from apps.orders.models import Order, OrderItem
from apps.products.models import Product
from apps.promotions.admin import PromotionCampaignAdmin
from apps.promotions.engine import freeze_order, quote_order, release_order, settle_order
from apps.promotions.forms import CampaignForm
from apps.promotions.models import Coupon, PromotionCampaign
from apps.promotions.renewals import reserve_cycle, settle_cycle
from apps.promotions.services import CouponService
from apps.settings.services import SettingsService


class CampaignCurrencyHistoryTests(TestCase):
    @classmethod
    def setUpTestData(cls) -> None:
        cls.currencies = {
            code: Currency.objects.get_or_create(code=code, defaults={"name": code, "symbol": code})[0]
            for code in ("RON", "EUR", "USD")
        }
        cls.customer = Customer.objects.create(name="Campaign buyer", customer_type="individual")
        cls.product = Product.objects.create(name="Campaign plan", slug="campaign-plan", product_type="shared_hosting")
        cls.staff = get_user_model().objects.create_user(
            email="campaign-staff@example.test", password="StrongPass123!", is_staff=True, staff_role="admin",
        )

    def setUp(self) -> None:
        SettingsService.update_setting("promotions.new_offers_enabled", True, reason="Campaign currency tests")
        self.addCleanup(SettingsService._clear_setting_cache, "promotions.new_offers_enabled")
        self.client.force_login(self.staff)
        self.campaign = PromotionCampaign.objects.create(
            name="Campaign history", slug="campaign-history", start_date=timezone.now(), status="active",
        )
        self.coupon = Coupon.objects.create(
            code="CAMPAIGN20", name="Campaign percentage", discount_type="percent", discount_percent=20,
            campaign=self.campaign,
        )

    def order(self, code: str, amount: int = 10000) -> Order:
        order = Order.objects.create(customer=self.customer, currency=self.currencies[code])
        OrderItem.objects.create(
            order=order, product=self.product, product_name=self.product.name, product_type=self.product.product_type,
            quantity=1, unit_price_cents=amount, billing_period="monthly",
        )
        order.calculate_totals()
        return order

    def apply_legacy(self, code: str) -> Order:
        order = self.order(code)
        result = CouponService.apply_coupon(self.coupon.code, order, customer=self.customer)
        self.assertTrue(result.success, result.error_message)
        return order

    def freeze(self, code: str, amount: int = 10000) -> Order:
        order = self.order(code, amount)
        quote = quote_order(order, list(order.items.all()), [self.coupon.code])
        freeze_order(order, [self.coupon.code], quote["quote_token"])
        return order

    def campaign_data(self, **changes: object) -> dict[str, object]:
        self.campaign.refresh_from_db()
        original = CampaignForm(instance=self.campaign)
        return {**{field.name: field.value() if field.value() is not None else "" for field in original}, **changes}

    def test_mixed_used_campaign_cannot_be_assigned_a_euro_budget_by_staff_or_model(self) -> None:
        self.apply_legacy("RON")
        self.apply_legacy("EUR")
        response = self.client.post(
            reverse("promotions:campaign_update", kwargs={"pk": self.campaign.pk}),
            self.campaign_data(budget_currency="EUR", budget_cents=10000),
        )
        self.assertEqual(response.status_code, 200)
        self.assertIn("budget_currency", response.context["form"].errors)
        self.campaign.refresh_from_db()
        self.assertEqual((self.campaign.budget_currency_id, self.campaign.spent_cents), (None, 4000))
        self.campaign.budget_currency_id = "EUR"
        self.campaign.budget_cents = 10000
        with self.assertRaises(ValidationError):
            self.campaign.full_clean(exclude=["status"])
        with self.assertRaises(ValidationError):
            self.campaign.save(update_fields=["budget_currency", "budget_cents"])
        self.assertEqual(set(self.coupon.redemptions.values_list("currency_code", flat=True)), {"RON", "EUR"})

    def test_unused_campaign_can_set_currency_and_known_currency_can_add_budget(self) -> None:
        response = self.client.post(
            reverse("promotions:campaign_update", kwargs={"pk": self.campaign.pk}),
            self.campaign_data(budget_currency="EUR"),
        )
        self.assertEqual(response.status_code, 302)
        self.apply_legacy("EUR")
        response = self.client.post(
            reverse("promotions:campaign_update", kwargs={"pk": self.campaign.pk}),
            self.campaign_data(budget_currency="EUR", budget_cents=10000),
        )
        self.assertEqual(response.status_code, 302)
        self.campaign.refresh_from_db()
        self.assertEqual((self.campaign.budget_currency_id, self.campaign.spent_cents, self.campaign.budget_cents), ("EUR", 2000, 10000))

    def test_consumed_then_reversed_campaign_still_retains_currency(self) -> None:
        self.campaign.budget_currency_id = "RON"
        self.campaign.save(update_fields=["budget_currency"])
        order = self.apply_legacy("RON")
        CouponService.remove_coupon(order, coupon=self.coupon)
        self.campaign.refresh_from_db()
        self.assertEqual(self.campaign.spent_cents, 0)
        self.campaign.budget_currency_id = "EUR"
        with self.assertRaises(ValidationError):
            self.campaign.save(update_fields=["budget_currency"])

    def test_grouped_staff_reports_include_each_live_ledger_once(self) -> None:
        self.apply_legacy("RON")
        settled = self.freeze("EUR", 7500)
        settle_order(settled)
        self.freeze("USD")
        released = self.freeze("EUR", 9000)
        release_order(released)
        reversed_order = self.apply_legacy("USD")
        CouponService.remove_coupon(reversed_order, coupon=self.coupon)
        expected = [
            {"currency_code": "EUR", "spent_cents": 1500, "reserved_cents": 0},
            {"currency_code": "RON", "spent_cents": 2000, "reserved_cents": 0},
            {"currency_code": "USD", "spent_cents": 0, "reserved_cents": 2000},
        ]
        for route, pk in (("campaign_detail", self.campaign.pk), ("coupon_detail", self.coupon.pk)):
            with self.subTest(route=route):
                response = self.client.get(reverse(f"promotions:{route}", kwargs={"pk": pk}))
                self.assertEqual(response.context["money_totals"], expected)
                for code in self.currencies:
                    self.assertContains(response, code)
                self.assertNotIn("total_discount_cents", response.context["stats"])

    def test_campaign_report_uses_charged_campaign_after_coupon_is_moved(self) -> None:
        self.apply_legacy("RON")
        other = PromotionCampaign.objects.create(name="Other", slug="other", start_date=timezone.now())
        self.coupon.campaign = other
        self.coupon.save(update_fields=["campaign"])
        response = self.client.get(reverse("promotions:campaign_detail", kwargs={"pk": self.campaign.pk}))
        self.assertEqual(response.context["money_totals"], [{"currency_code": "RON", "spent_cents": 2000, "reserved_cents": 0}])
        self.assertEqual(response.context["stats"]["total_redemptions"], 1)

    def test_admin_displays_currency_groups_instead_of_mixed_spending(self) -> None:
        self.apply_legacy("RON")
        self.apply_legacy("EUR")
        self.campaign.refresh_from_db()
        display = PromotionCampaignAdmin(PromotionCampaign, AdminSite()).spent_display(self.campaign)
        self.assertIn("20.00 RON", display)
        self.assertIn("20.00 EUR", display)
        self.assertNotIn("40.00", display)

    def test_renewal_reservation_is_counted_once_and_consumption_moves_it_to_spent(self) -> None:
        self.coupon.discount_type = "free_months"
        self.coupon.free_months = 3
        self.coupon.save()
        order = self.freeze("EUR", 1000)
        settle_order(order)
        benefit = order.promotion_applications.get().benefits.get()
        now = timezone.now()
        subscription = Subscription.objects.create(
            customer=self.customer, product=self.product, currency=self.currencies["EUR"],
            subscription_number=f"SUB-{uuid4().hex[:12]}", status="active", unit_price_cents=1000,
            locked_price_cents=1000, current_period_start=now, current_period_end=now + timezone.timedelta(days=30),
            next_billing_date=now,
        )
        benefit.subscription = subscription
        benefit.save(update_fields=["subscription"])
        cycle = BillingCycle.objects.create(
            subscription=subscription, period_start=now, period_end=now + timezone.timedelta(days=30),
        )
        self.assertEqual(reserve_cycle(subscription, cycle, 1000), 1000)
        response = self.client.get(reverse("promotions:campaign_detail", kwargs={"pk": self.campaign.pk}))
        self.assertEqual(response.context["money_totals"], [{"currency_code": "EUR", "spent_cents": 1000, "reserved_cents": 2000}])
        settle_cycle(cycle)
        response = self.client.get(reverse("promotions:campaign_detail", kwargs={"pk": self.campaign.pk}))
        self.assertEqual(response.context["money_totals"], [{"currency_code": "EUR", "spent_cents": 2000, "reserved_cents": 1000}])


@skipUnless(connection.vendor == "postgresql", "PostgreSQL row-lock visibility is required")
class CampaignCurrencyConcurrencyTests(TransactionTestCase):
    def test_first_redemption_rechecks_currency_after_a_concurrent_campaign_edit(self) -> None:
        for code in ("RON", "EUR"):
            Currency.objects.get_or_create(code=code, defaults={"symbol": code})
        customer = Customer.objects.create(name="Concurrent buyer", customer_type="individual")
        product = Product.objects.create(name="Concurrent hosting", slug="concurrent-hosting", product_type="shared_hosting")
        campaign = PromotionCampaign.objects.create(
            name="Concurrent campaign", slug="concurrent-campaign", start_date=timezone.now(), status="active",
            budget_currency_id="RON",
        )
        coupon = Coupon.objects.create(
            code="CONCURRENT20", name="Concurrent offer", discount_type="percent", discount_percent=20, campaign=campaign,
        )
        order = Order.objects.create(customer=customer, currency_id="RON")
        OrderItem.objects.create(order=order, product=product, product_type=product.product_type, quantity=1, unit_price_cents=10000)
        order.calculate_totals()
        ready = Event()
        worker_pid: list[int] = []

        def redeem():
            close_old_connections()
            try:
                with connection.cursor() as cursor:
                    cursor.execute("SELECT pg_backend_pid()")
                    worker_pid.append(cursor.fetchone()[0])
                ready.set()
                return CouponService.apply_coupon(coupon.code, Order.objects.get(pk=order.pk), customer=customer)
            finally:
                connections.close_all()

        with ThreadPoolExecutor(max_workers=1) as pool:
            with transaction.atomic():
                locked = PromotionCampaign.objects.select_for_update().get(pk=campaign.pk)
                with connection.cursor() as cursor:
                    cursor.execute("SELECT pg_backend_pid()")
                    owner_pid = cursor.fetchone()[0]
                pending = pool.submit(redeem)
                self.assertTrue(ready.wait(5), "Redemption did not start")
                deadline = monotonic() + 8
                waiting = False
                poll = Event()
                while monotonic() < deadline:
                    with connection.cursor() as cursor:
                        cursor.execute("SELECT pg_stat_clear_snapshot()")
                        cursor.execute("SELECT pg_blocking_pids(%s)", [worker_pid[0]])
                        waiting = owner_pid in cursor.fetchone()[0]
                    if waiting or pending.done():
                        break
                    poll.wait(0.01)
                self.assertTrue(waiting, "Redemption never waited for the campaign row")
                locked.budget_currency_id = "EUR"
                locked.save(update_fields=["budget_currency"])
            result = pending.result(timeout=10)
        self.assertFalse(result.success)
        order.refresh_from_db()
        campaign.refresh_from_db()
        self.assertEqual((campaign.budget_currency_id, campaign.spent_cents, order.discount_cents), ("EUR", 0, 0))
        self.assertFalse(order.coupon_redemptions.exists())
