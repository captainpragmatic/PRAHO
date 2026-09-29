"""Staff gift and manual proforma sales confirm one current selling currency."""

from concurrent.futures import ThreadPoolExecutor
from decimal import Decimal
from html.parser import HTMLParser
from unittest.mock import patch

from django.core.cache import cache
from django.core.exceptions import ValidationError
from django.db import OperationalError, close_old_connections, connection, connections, transaction
from django.test import Client, TestCase, TransactionTestCase
from django.urls import reverse
from django.utils import timezone

from apps.billing.currency_policy import get_selling_currency_policy
from apps.billing.models import Currency, FXRate, Payment, ProformaInvoice, ProformaSequence
from apps.common.types import Ok
from apps.customers.models import Customer
from apps.promotions.models import GiftCard, GiftCardPurchase
from apps.settings.models import SystemSetting
from apps.settings.services import SettingsService
from apps.users.models import User


class SaleControls(HTMLParser):
    def __init__(self):
        super().__init__()
        self.controls = {}

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag in {"input", "select"} and attrs.get("name"):
            self.controls[attrs["name"]] = {"tag": tag, **attrs}


class StaffSaleFixture:
    def setUp(self):
        super().setUp()
        cache.clear()
        self.addCleanup(cache.clear)
        self.actor = User.objects.create_user(email="staff-sale@example.test", is_staff=True, staff_role="billing")
        self.client.force_login(self.actor)
        self.customer = Customer.objects.create(name="Staff buyer", primary_email="buyer@example.test")
        for code in ("RON", "EUR", "USD"):
            Currency.objects.get_or_create(code=code, defaults={"symbol": code})
            if code != "RON":
                FXRate.objects.create(
                    base_code_id=code, quote_code_id="RON", rate=Decimal("5"), as_of=timezone.localdate(),
                    source=FXRate.Source.BNR, source_reference="staff-sale-test", fetched_at=timezone.now(),
                )
        with transaction.atomic():
            get_selling_currency_policy(lock=True)

    def switch(self, code):
        self.assertIsInstance(SettingsService.update_setting("billing.default_currency", code), Ok)
        return get_selling_currency_policy()

    def gift_data(self, **overrides):
        policy = get_selling_currency_policy()
        return {
            "purchased_by": self.customer.pk, "initial_value_cents": 3456, "card_type": "digital",
            "payment_method": "bank", "currency": policy.currency_code, "currency_revision": policy.revision,
            **overrides,
        }

    def proforma_data(self, **overrides):
        policy = get_selling_currency_policy()
        return {
            "customer": self.customer.pk, "valid_until": (timezone.localdate() + timezone.timedelta(days=30)).isoformat(),
            "currency": policy.currency_code, "currency_revision": policy.revision,
            "line_0_description": "Explicit staff sale", "line_0_quantity": "2", "line_0_unit_price": "34.56",
            "line_0_vat_rate": "0", **overrides,
        }

    def assert_no_sale(self):
        self.assertFalse(GiftCardPurchase.objects.exists())
        self.assertFalse(GiftCard.objects.exists())
        self.assertFalse(Payment.objects.exists())
        self.assertFalse(ProformaInvoice.objects.exists())
        self.assertFalse(ProformaSequence.objects.exists())


class StaffSaleCurrencyTests(StaffSaleFixture, TestCase):
    def test_forms_show_fixed_active_currency_and_revision(self):
        policy = self.switch("EUR")
        for route in ("promotions:gift_card_create", "billing:proforma_create"):
            with self.subTest(route=route):
                response = self.client.get(reverse(route))
                self.assertEqual(response.status_code, 200)
                parser = SaleControls()
                parser.feed(response.content.decode())
                currency = parser.controls["currency"]
                self.assertEqual(currency["tag"], "input")
                self.assertEqual(currency.get("value"), "EUR")
                self.assertTrue(currency.get("type") == "hidden" or "readonly" in currency)
                self.assertEqual(parser.controls["currency_revision"].get("value"), str(policy.revision))

    def test_staff_gift_keeps_flexible_amount_and_original_currency_after_switch(self):
        SystemSetting.objects.update_or_create(
            key="promotions.gift_card_denominations",
            defaults={
                "value": {"RON": [5000], "EUR": [5000], "USD": [5000]},
                "default_value": {}, "data_type": "json", "category": "billing",
            },
        )
        self.switch("EUR")
        response = self.client.post(reverse("promotions:gift_card_create"), self.gift_data())
        self.assertEqual(response.status_code, 302, response.content)
        purchase = GiftCardPurchase.objects.select_related("gift_card", "funding_payment").get()
        self.assertEqual((purchase.gift_card.currency_id, purchase.gift_card.initial_value_cents), ("EUR", 3456))
        self.assertEqual((purchase.funding_payment.currency_id, purchase.funding_payment.amount_cents), ("EUR", 3456))
        self.assertEqual(purchase.gift_card.current_balance_cents, 0)
        self.switch("USD")
        purchase.gift_card.refresh_from_db()
        self.assertEqual((purchase.gift_card.currency_id, purchase.gift_card.initial_value_cents), ("EUR", 3456))

    def test_manual_proforma_records_explicit_price_in_current_currency(self):
        self.switch("USD")
        response = self.client.post(reverse("billing:proforma_create"), self.proforma_data())
        self.assertEqual(response.status_code, 302, response.content)
        proforma = ProformaInvoice.objects.get()
        self.assertEqual((proforma.currency_id, proforma.total_cents), ("USD", 6912))
        self.assertEqual(proforma.lines.get().unit_price_cents, 3456)

    def test_stale_forms_reject_before_any_financial_write_and_keep_entered_amounts(self):
        gift_data, proforma_data = self.gift_data(), self.proforma_data()
        self.switch("EUR")
        for route, data, amount in (
            ("promotions:gift_card_create", gift_data, "3456"),
            ("billing:proforma_create", proforma_data, "34.56"),
        ):
            with self.subTest(route=route):
                response = self.client.post(reverse(route), data)
                self.assertEqual(response.status_code, 200)
                self.assertContains(response, amount)
                self.assertContains(response, "Review")
                self.assert_no_sale()

    def test_round_trip_policy_revision_and_forged_currency_are_rejected(self):
        old_revision = get_selling_currency_policy().revision
        self.switch("EUR")
        self.switch("RON")
        for overrides in ({"currency_revision": old_revision}, {"currency": "EUR"}, {"currency_revision": ""}):
            for route, data in (
                ("promotions:gift_card_create", self.gift_data(**overrides)),
                ("billing:proforma_create", self.proforma_data(**overrides)),
            ):
                with self.subTest(route=route, overrides=overrides):
                    self.assertEqual(self.client.post(reverse(route), data).status_code, 200)
                    self.assert_no_sale()

    def test_stale_form_can_be_reviewed_and_resubmitted_with_current_terms(self):
        for route, factory, model in (
            ("promotions:gift_card_create", self.gift_data, GiftCard),
            ("billing:proforma_create", self.proforma_data, ProformaInvoice),
        ):
            with self.subTest(route=route):
                self.switch("RON")
                data = factory()
                current = self.switch("EUR")
                response = self.client.post(reverse(route), data)
                self.assertEqual(response.status_code, 200)
                parser = SaleControls()
                parser.feed(response.content.decode())
                data.update({name: parser.controls[name]["value"] for name in ("currency", "currency_revision")})
                self.assertEqual(data["currency"], "EUR")
                self.assertEqual(data["currency_revision"], str(current.revision))
                response = self.client.post(reverse(route), data)
                self.assertEqual(response.status_code, 302, response.content)
                self.assertEqual(model.objects.get().currency_id, "EUR")

    def test_gift_rate_failure_is_recoverable_and_creates_no_financial_records(self):
        self.switch("EUR")
        FXRate.objects.filter(base_code_id="EUR").delete()
        response = self.client.post(reverse("promotions:gift_card_create"), self.gift_data())
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "No exchange rate")
        self.assert_no_sale()

    def test_final_card_failure_rolls_back_the_purchase_and_payment(self):
        original = GiftCard.save

        def save(card, *args, **kwargs):
            if "card_type" in (kwargs.get("update_fields") or []):
                raise ValidationError("Final card write rejected")
            original(card, *args, **kwargs)

        with patch.object(GiftCard, "save", save):
            response = self.client.post(reverse("promotions:gift_card_create"), self.gift_data())
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Final card write rejected")
        self.assert_no_sale()

    def test_existing_proforma_edit_keeps_original_currency_after_switch(self):
        response = self.client.post(reverse("billing:proforma_create"), self.proforma_data())
        self.assertEqual(response.status_code, 302)
        proforma = ProformaInvoice.objects.get()
        self.switch("EUR")
        edit_url = reverse("billing:proforma_edit", args=[proforma.pk])
        self.assertContains(self.client.get(edit_url), "0.00 RON")
        response = self.client.post(edit_url, self.proforma_data(currency="EUR"))
        self.assertEqual(response.status_code, 302)
        proforma.refresh_from_db()
        self.assertEqual((proforma.currency_id, proforma.total_cents), ("RON", 6912))

    def test_financial_staff_authorization_and_csrf_remain_required(self):
        for route, data in (
            ("promotions:gift_card_create", self.gift_data()),
            ("billing:proforma_create", self.proforma_data()),
        ):
            client = Client(enforce_csrf_checks=True)
            client.force_login(self.actor)
            self.assertEqual(client.post(reverse(route), data).status_code, 403)
        self.actor.staff_role = "support"
        self.actor.save(update_fields=["staff_role"])
        for route, data in (
            ("promotions:gift_card_create", self.gift_data()),
            ("billing:proforma_create", self.proforma_data()),
        ):
            self.assertIn(self.client.post(reverse(route), data).status_code, {302, 403})
        self.assert_no_sale()


class StaffSalePolicyLockTests(StaffSaleFixture, TransactionTestCase):
    def setUp(self):
        super().setUp()
        if connection.vendor != "postgresql":
            self.skipTest("Requires PostgreSQL row locks")

    @staticmethod
    def policy_is_locked():
        close_old_connections()
        try:
            with transaction.atomic():
                SystemSetting.objects.select_for_update(nowait=True).get(key="billing.default_currency")
            return False
        except OperationalError as exc:
            if getattr(exc.__cause__, "sqlstate", None) != "55P03":
                raise
            return True
        finally:
            connections.close_all()

    def test_gift_policy_lock_covers_final_card_write(self):
        observed = []
        original = GiftCard.save

        def save(card, *args, **kwargs):
            original(card, *args, **kwargs)
            if "card_type" in (kwargs.get("update_fields") or []):
                with ThreadPoolExecutor(max_workers=1) as pool:
                    observed.append(pool.submit(self.policy_is_locked).result(timeout=10))

        with patch.object(GiftCard, "save", save):
            response = self.client.post(reverse("promotions:gift_card_create"), self.gift_data())
        self.assertEqual(response.status_code, 302)
        self.assertEqual(observed, [True])
        self.assertFalse(self.policy_is_locked())

    def test_proforma_policy_lock_covers_lines_and_total_write(self):
        observed = []
        original = ProformaInvoice.save

        def save(proforma, *args, **kwargs):
            original(proforma, *args, **kwargs)
            if proforma.total_cents == 6912:
                with ThreadPoolExecutor(max_workers=1) as pool:
                    observed.append(pool.submit(self.policy_is_locked).result(timeout=10))

        with patch.object(ProformaInvoice, "save", save):
            response = self.client.post(reverse("billing:proforma_create"), self.proforma_data())
        self.assertEqual(response.status_code, 302)
        self.assertEqual(observed, [True])
        self.assertFalse(self.policy_is_locked())
