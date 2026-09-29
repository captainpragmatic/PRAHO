"""Money-bounded offers keep their stated units through both promotion engines."""

from decimal import Decimal
from uuid import uuid4

from django.contrib.auth import get_user_model
from django.core.exceptions import ValidationError
from django.test import TestCase
from django.urls import reverse
from django.utils import timezone

from apps.billing.models import Currency
from apps.billing.proforma_service import ProformaService
from apps.customers.models import Customer
from apps.orders.models import Order, OrderItem
from apps.products.models import Product
from apps.promotions.engine import freeze_order, quote_order, settle_order
from apps.promotions.forms import CouponForm, PromotionRuleForm
from apps.promotions.models import Coupon, CouponRedemption, PromotionCampaign, PromotionRule
from apps.promotions.services import CouponService, PromotionRuleService
from apps.settings.services import SettingsService
from apps.users.models import CustomerMembership


class OfferCurrencyTests(TestCase):
    @classmethod
    def setUpTestData(cls) -> None:
        cls.currencies = {
            code: Currency.objects.get_or_create(code=code, defaults={"name": code, "symbol": code})[0]
            for code in ("RON", "EUR", "USD")
        }
        cls.customer = Customer.objects.create(
            name="Offer currency buyer", customer_type="individual", primary_email="offer-currency@example.test"
        )
        cls.product = Product.objects.create(
            name="Offer currency hosting", slug="offer-currency-hosting", product_type="shared_hosting"
        )
        cls.user = get_user_model().objects.create_user(email="offer-currency@example.test", password="StrongPass123!")
        CustomerMembership.objects.create(user=cls.user, customer=cls.customer, role="owner", is_primary=True)

    def setUp(self) -> None:
        result = SettingsService.update_setting("promotions.new_offers_enabled", True, reason="Offer currency tests")
        self.assertTrue(result.is_ok(), result)
        self.addCleanup(SettingsService._clear_setting_cache, "promotions.new_offers_enabled")

    def order(self, code: str = "EUR", amount: int = 10000) -> Order:
        order = Order.objects.create(customer=self.customer, currency=self.currencies[code])
        OrderItem.objects.create(
            order=order, product=self.product, product_name=self.product.name, product_type=self.product.product_type,
            quantity=1, unit_price_cents=amount, billing_period="monthly", tax_rate=Decimal("0.21"),
        )
        order.calculate_totals()
        return order

    def coupon(self, **values: object) -> Coupon:
        return Coupon.objects.create(**{
            "code": f"CURRENCY{uuid4().hex[:10]}", "name": "Currency coupon", "discount_type": "percent",
            "discount_percent": Decimal(20), **values,
        })

    def rule(self, **values: object) -> PromotionRule:
        return PromotionRule.objects.create(**{
            "name": "Currency rule", "discount_type": "percent", "discount_percent": Decimal(20),
            "published_at": timezone.now(), **values,
        })

    def campaign(self, currency: str | None) -> PromotionCampaign:
        return PromotionCampaign.objects.create(
            name="Currency budget", slug=f"currency-budget-{uuid4().hex[:10]}", start_date=timezone.now(),
            status="active", budget_cents=5000, budget_currency_id=currency,
        )

    def test_coupon_model_requires_currency_for_each_money_bound(self) -> None:
        for values in (
            {"min_order_cents": 5000}, {"max_discount_cents": 500}, {"max_discount_cents": 0},
            {"discount_type": "tiered", "tiers": [{"threshold": 5000, "threshold_type": "amount", "percent": "20"}]},
            {"discount_type": "tiered", "tiers": [{"threshold": 1, "threshold_type": "quantity", "amount_cents": 500}]},
            {"discount_type": "fixed", "discount_amount_cents": 500},
        ):
            with self.subTest(values=values):
                coupon = self.coupon(**values)
                with self.assertRaises(ValidationError) as caught:
                    coupon.full_clean()
                self.assertIn("currency", caught.exception.message_dict)

    def test_rule_model_requires_currency_for_each_money_bound(self) -> None:
        for values in (
            {"conditions": {"min_order_cents": 5000}}, {"conditions": {"max_order_cents": 15000}},
            {"max_discount_cents": 500},
            {"discount_type": "tiered_percent", "tiers": [{"threshold": 5000, "threshold_type": "amount", "percent": "20"}]},
            {"discount_type": "tiered_fixed", "tiers": [{"threshold": 1, "threshold_type": "quantity", "amount_cents": 500}]},
        ):
            with self.subTest(values=values):
                rule = self.rule(**values)
                with self.assertRaises(ValidationError) as caught:
                    rule.full_clean()
                self.assertIn("currency", caught.exception.message_dict)

    def test_staff_forms_explain_missing_original_currency_and_accept_explicit_currency(self) -> None:
        for model, form_class in (
            (self.coupon(min_order_cents=5000), CouponForm),
            (self.rule(conditions={"max_order_cents": 15000}), PromotionRuleForm),
        ):
            with self.subTest(model=type(model).__name__):
                original = form_class(instance=model)
                data = {field.name: field.value() if field.value() is not None else "" for field in original}
                form = form_class(data, instance=model)
                self.assertFalse(form.is_valid())
                self.assertIn("currency", form.errors)
                self.assertIn("original currency", str(form.errors["currency"]).lower())
                data["currency"] = "RON"
                reviewed = form_class(data, instance=model)
                self.assertTrue(reviewed.is_valid(), reviewed.errors)
                reviewed.save()
                model.refresh_from_db()
                self.assertEqual(model.currency_id, "RON")

    def test_unknown_legacy_coupon_money_is_rejected_in_all_order_currencies(self) -> None:
        for code in self.currencies:
            for values in (
                {"min_order_cents": 5000}, {"max_discount_cents": 500},
                {"discount_type": "tiered", "tiers": [{"threshold": 5000, "threshold_type": "amount", "percent": "20"}]},
            ):
                with self.subTest(currency=code, values=values):
                    coupon = self.coupon(**values)
                    order = self.order(code)
                    with self.assertRaises(ValidationError):
                        quote_order(order, list(order.items.all()), [coupon.code])
                    coupon.refresh_from_db()
                    self.assertIsNone(coupon.currency_id)
                    self.assertEqual((coupon.total_uses, coupon.total_discount_cents), (0, 0))

    def test_bounded_coupon_quotes_only_in_recorded_currency(self) -> None:
        for code in self.currencies:
            with self.subTest(currency=code):
                coupon = self.coupon(currency=self.currencies[code], min_order_cents=5000, max_discount_cents=500)
                same = self.order(code)
                self.assertEqual(quote_order(same, list(same.items.all()), [coupon.code])["discount_cents"], 500)
                for other_code in self.currencies.keys() - {code}:
                    other = self.order(other_code)
                    with self.assertRaises(ValidationError):
                        quote_order(other, list(other.items.all()), [coupon.code])

    def test_unknown_rules_do_not_discount_and_reviewed_rules_use_their_currency(self) -> None:
        unknown = self.rule(conditions={"min_order_cents": 5000}, max_discount_cents=500)
        for code in self.currencies:
            with self.subTest(currency=code):
                order = self.order(code)
                self.assertEqual(quote_order(order, list(order.items.all()), [])["discount_cents"], 0)
                self.assertEqual(PromotionRuleService.get_applicable_rules(order), [])
                self.assertEqual(PromotionRuleService.calculate_rule_discount(unknown, order).discount_cents, 0)
        unknown.currency_id = "EUR"
        unknown.save(update_fields=["currency"])
        for code in self.currencies:
            with self.subTest(reviewed_currency=code):
                order = self.order(code)
                expected = 500 if code == "EUR" else 0
                self.assertEqual(quote_order(order, list(order.items.all()), [])["discount_cents"], expected)
                self.assertEqual(PromotionRuleService.calculate_rule_discount(unknown, order).discount_cents, expected)

    def test_unbounded_percent_and_quantity_tiers_remain_currency_neutral(self) -> None:
        coupon = self.coupon(min_order_cents=0)
        quantity_coupon = self.coupon(
            discount_type="tiered", tiers=[{"threshold": 1, "threshold_type": "quantity", "percent": "20"}]
        )
        for code in self.currencies:
            with self.subTest(currency=code):
                for offer in (coupon, quantity_coupon):
                    offer.full_clean()
                    order = self.order(code)
                    self.assertEqual(quote_order(order, list(order.items.all()), [offer.code])["discount_cents"], 2000)
                applied = CouponService.apply_coupon(coupon.code, self.order(code), customer=self.customer)
                self.assertTrue(applied.success, applied.error_message)
                redemption = CouponRedemption.objects.get(pk=applied.redemption_id)
                self.assertEqual((redemption.currency_code, redemption.discount_cents), (code, 2000))

    def test_legacy_apply_rejects_unknown_and_mismatched_percentage_bounds(self) -> None:
        self.client.force_login(self.user)
        for currency in (None, "RON"):
            with self.subTest(currency=currency):
                coupon = self.coupon(currency_id=currency, max_discount_cents=500)
                order = self.order("EUR")
                response = self.client.post(reverse("promotions:api_apply_coupon"), {"order_id": order.pk, "code": coupon.code})
                self.assertEqual(response.status_code, 200)
                self.assertFalse(response.json()["success"])
                self.assertIn("currency", response.json()["error"].lower())
                order.refresh_from_db()
                coupon.refresh_from_db()
                self.assertEqual(order.discount_cents, 0)
                self.assertEqual(coupon.total_uses, 0)
                self.assertFalse(order.coupon_redemptions.exists())

    def test_legacy_apply_checks_campaign_budget_currency_for_percentage_coupon(self) -> None:
        self.client.force_login(self.user)
        for budget_currency in (None, "RON", "USD", "EUR"):
            with self.subTest(budget_currency=budget_currency):
                campaign = self.campaign(budget_currency)
                coupon = self.coupon(campaign=campaign)
                order = self.order("EUR")
                response = self.client.post(reverse("promotions:api_apply_coupon"), {"order_id": order.pk, "code": coupon.code})
                allowed = budget_currency == "EUR"
                self.assertEqual(response.status_code, 200)
                self.assertEqual(response.json()["success"], allowed)
                campaign.refresh_from_db()
                order.refresh_from_db()
                self.assertEqual(campaign.spent_cents, 2000 if allowed else 0)
                self.assertEqual(order.discount_cents, 2000 if allowed else 0)

    def test_legacy_matching_currency_preserves_minimum_boundary_and_cap(self) -> None:
        for code in self.currencies:
            coupon = self.coupon(currency_id=code, min_order_cents=5000, max_discount_cents=500)
            for amount in (4999, 5000, 5001):
                with self.subTest(currency=code, amount=amount):
                    order = self.order(code, amount)
                    applied = CouponService.apply_coupon(coupon.code, order, customer=self.customer)
                    self.assertEqual(applied.success, amount >= 5000, applied.error_message)
                    order.refresh_from_db()
                    self.assertEqual((order.currency_id, order.discount_cents), (code, 500 if amount >= 5000 else 0))

    def test_legacy_rules_and_calculators_enforce_campaign_and_explicit_currency(self) -> None:
        order = self.order("EUR")
        campaign = self.campaign("RON")
        coupon = self.coupon(campaign=campaign)
        rule = self.rule(campaign=campaign)
        self.assertEqual(CouponService.calculate_discount(coupon, order).discount_cents, 0)
        self.assertEqual(PromotionRuleService.get_applicable_rules(order), [])
        self.assertEqual(PromotionRuleService.calculate_rule_discount(rule, order).discount_cents, 0)
        coupon.campaign = None
        coupon.currency_id = "USD"
        coupon.save()
        self.assertFalse(CouponService.apply_coupon(coupon.code, order, customer=self.customer).success)

    def test_legacy_tier_without_threshold_type_still_has_amount_units(self) -> None:
        rule = self.rule(discount_type="tiered_percent", tiers=[{"threshold": 5000, "percent": "20"}])
        order = self.order("EUR")
        self.assertEqual(PromotionRuleService.get_applicable_rules(order), [])
        self.assertEqual(PromotionRuleService.calculate_rule_discount(rule, order).discount_cents, 0)
        rule.currency_id = "EUR"
        rule.save(update_fields=["currency"])
        self.assertEqual(PromotionRuleService.calculate_rule_discount(rule, order).discount_cents, 2000)

    def test_frozen_original_quote_settles_without_reinterpreting_changed_offer(self) -> None:
        campaign = self.campaign("RON")
        coupon = self.coupon(currency_id="RON", campaign=campaign, max_discount_cents=500)
        order = self.order("RON")
        quote = quote_order(order, list(order.items.all()), [coupon.code])
        freeze_order(order, [coupon.code], quote["quote_token"])
        document = ProformaService.create_from_order(order)
        self.assertTrue(document.is_ok(), document)
        proforma = document.unwrap()
        Coupon.objects.filter(pk=coupon.pk).update(currency_id="EUR", max_discount_cents=900)
        settle_order(order)
        order.refresh_from_db()
        campaign.refresh_from_db()
        self.assertEqual((order.currency_id, order.discount_cents, campaign.spent_cents), ("RON", 500, 500))
        proforma.refresh_from_db()
        self.assertEqual((proforma.currency_id, proforma.subtotal_cents), ("RON", 9500))
        self.assertEqual(order.promotion_applications.get().discount_cents, 500)
