"""Switch preflight covers service plans, domains and bespoke renewal periods."""

from decimal import Decimal

from django.core.cache import cache
from django.test import TestCase
from django.utils import timezone

from apps.billing.currency_models import Currency, FXRate
from apps.common.types import Err, Ok
from apps.customers.models import Customer
from apps.domains.models import TLD, Domain, Registrar, TLDRetailPrice
from apps.domains.services import DomainOrderService, TLDService
from apps.orders.models import Order
from apps.provisioning.service_models import ServicePlan, ServicePlanPrice
from apps.settings.models import SystemSetting
from apps.settings.services import SettingsService


class SellingCurrencyPriceTests(TestCase):
    def setUp(self) -> None:
        cache.clear()
        self.addCleanup(cache.clear)
        for code in ("RON", "EUR", "USD"):
            Currency.objects.get_or_create(code=code, defaults={"symbol": code})
            if code != "RON":
                FXRate.objects.create(
                    base_code_id=code,
                    quote_code_id="RON",
                    rate=Decimal("4.97000000"),
                    as_of=timezone.localdate(),
                    source=FXRate.Source.BNR,
                    source_reference="currency-price-test",
                    fetched_at=timezone.now(),
                )

    def plan(self) -> ServicePlan:
        return ServicePlan.objects.create(
            name="Business hosting", plan_type="shared_hosting", price_monthly=Decimal("50.00"),
            price_quarterly=Decimal("145.00"), price_annual=Decimal("550.00"),
        )

    def test_published_service_plan_needs_target_currency_price(self) -> None:
        self.plan()
        result = SettingsService.update_setting("billing.default_currency", "EUR")
        self.assertIsInstance(result, Err)
        self.assertIn("Business hosting", result.error.message)

    def test_every_offered_plan_period_needs_explicit_target_price(self) -> None:
        plan = self.plan()
        price = ServicePlanPrice.objects.create(
            service_plan=plan, currency_id="EUR", monthly_price_cents=1000, annual_price_cents=10000,
        )
        result = SettingsService.update_setting("billing.default_currency", "EUR")
        self.assertIsInstance(result, Err)
        self.assertIn("quarterly", result.error.message)
        price.quarterly_price_cents = 2800
        price.save()
        self.assertIsInstance(SettingsService.update_setting("billing.default_currency", "EUR"), Ok)
        plan.refresh_from_db()
        self.assertEqual(plan.price_monthly, Decimal("50.00"))
        self.assertEqual(plan.price_quarterly, Decimal("145.00"))
        self.assertEqual(plan.get_price_for_currency("EUR").quarterly_price_cents, 2800)

    def test_active_domain_suffix_needs_target_retail_price(self) -> None:
        TLD.objects.create(
            extension="ro", description="Romania", registration_price_cents=6000,
            renewal_price_cents=5500, transfer_price_cents=2000,
        )
        result = SettingsService.update_setting("billing.default_currency", "USD")
        self.assertIsInstance(result, Err)
        self.assertIn(".ro", result.error.message)

    def test_retired_suffix_still_needs_prices_for_existing_domains(self) -> None:
        tld = TLD.objects.create(extension="old", is_active=False, registration_price_cents=1000,
                                 renewal_price_cents=1200, transfer_price_cents=900)
        customer = Customer.objects.create(name="Existing domain owner", primary_email="old@example.test")
        registrar = Registrar.objects.create(name="old-tld", display_name="Old TLD")
        Domain.objects.create(name="existing.old", tld=tld, customer=customer, registrar=registrar, status="active")
        result = SettingsService.update_setting("billing.default_currency", "EUR")
        self.assertIsInstance(result, Err)
        self.assertIn(".old", result.error.message)

    def test_enabled_gift_sales_require_target_denominations_and_usable_payment_method(self) -> None:
        for key, value, data_type in (
            ("promotions.gift_card_sales_enabled", True, "boolean"),
            ("promotions.gift_card_denominations", {"RON": [5000]}, "json"),
            ("promotions.gift_card_payment_methods", ["bank"], "list"),
            ("billing.bank_accounts", {}, "json"),
        ):
            SystemSetting.objects.update_or_create(key=key, defaults={
                "value": value, "default_value": value, "category": "billing", "data_type": data_type,
                "name": key, "description": "Currency test configuration",
            })
        result = SettingsService.update_setting("billing.default_currency", "EUR")
        self.assertIsInstance(result, Err)
        self.assertIn("denominations", result.error.message)
        self.assertIn("payment method", result.error.message)
        self.assertIsInstance(SettingsService.update_setting("promotions.gift_card_denominations", {"EUR": [1000]}), Ok)
        self.assertIsInstance(SettingsService.update_setting("billing.bank_accounts", {
            "EUR": {"iban": "DE89370400440532013000", "bank_name": "EUR bank", "beneficiary": "QA Seller"},
        }), Ok)
        self.assertIsInstance(SettingsService.update_setting("billing.default_currency", "EUR"), Ok)

    def test_non_price_plan_save_does_not_restore_an_outdated_ron_price(self) -> None:
        plan = self.plan()
        price = plan.get_price_for_currency("RON")
        price.monthly_price_cents = 6500
        price.save(update_fields=["monthly_price_cents"])
        plan.is_public = False
        plan.save(update_fields=["is_public"])
        price.refresh_from_db()
        self.assertEqual(price.monthly_price_cents, 6500)
        plan.refresh_from_db()
        self.assertEqual(plan.price_monthly, Decimal("65.00"))

    def test_partial_plan_price_save_mirrors_only_saved_amounts(self) -> None:
        plan = self.plan()
        price = plan.get_price_for_currency("RON")
        price.monthly_price_cents = 6500
        price.annual_price_cents = 1  # Uncommitted change must not leak through the compatibility fields.
        price.save(update_fields=["monthly_price_cents"])
        plan.refresh_from_db()
        self.assertEqual(plan.price_monthly, Decimal("65.00"))
        self.assertEqual(plan.price_annual, Decimal("550.00"))

    def test_domain_cost_uses_requested_currency_and_keeps_vendor_cost(self) -> None:
        tld = TLD.objects.create(
            extension="com", description="Commercial", registration_price_cents=5000,
            renewal_price_cents=6000, transfer_price_cents=4500, registrar_cost_cents=999,
        )
        TLDRetailPrice.objects.create(
            tld=tld, currency_id="USD", registration_price_cents=1200,
            renewal_price_cents=1500, transfer_price_cents=1100, whois_privacy_price_cents=200,
        )
        self.assertIsInstance(SettingsService.update_setting("billing.default_currency", "USD"), Ok)
        cost = TLDService.calculate_domain_cost(tld, 2, currency_code="USD")
        self.assertEqual(cost["total_cost_cents"], 2400)
        self.assertEqual(cost["currency"], "USD")
        old_cost = TLDService.calculate_domain_cost(tld, 2, currency_code="RON")
        self.assertEqual(old_cost["total_cost_cents"], 10000)
        tld.refresh_from_db()
        self.assertEqual(tld.registrar_cost_cents, 999)

    def test_domain_order_item_uses_original_order_currency(self) -> None:
        tld = TLD.objects.create(
            extension="com", description="Commercial", registration_price_cents=5000,
            renewal_price_cents=6000, transfer_price_cents=4500, whois_privacy_available=True,
        )
        TLDRetailPrice.objects.create(
            tld=tld, currency_id="EUR", registration_price_cents=1000,
            renewal_price_cents=1200, transfer_price_cents=900, whois_privacy_price_cents=150,
        )
        customer = Customer.objects.create(name="Domain pricing", primary_email="domain@example.test")
        for action, unit_price in (("register", 1150), ("renew", 1350), ("transfer", 1050)):
            with self.subTest(action=action):
                order = Order.objects.create(customer=customer, currency_id="EUR")
                success, item = DomainOrderService.create_domain_order_item(
                    order, "priced-domain.com", action, years=2, whois_privacy=True,
                )
                self.assertTrue(success, item)
                self.assertEqual(item.unit_price_cents, unit_price)
                self.assertEqual(item.total_price_cents, unit_price * 2)

    def test_missing_domain_price_never_copies_ron_amount_into_eur_order(self) -> None:
        TLD.objects.create(
            extension="com", registration_price_cents=5000, renewal_price_cents=6000, transfer_price_cents=4500,
        )
        customer = Customer.objects.create(name="Missing price", primary_email="missing@example.test")
        order = Order.objects.create(customer=customer, currency_id="EUR")
        success, _error = DomainOrderService.create_domain_order_item(order, "no-price.com", "register")
        self.assertFalse(success)
        self.assertFalse(order.domain_items.exists())

    def test_whois_setting_changes_only_ron_retail_privacy_price(self) -> None:
        tld = TLD.objects.create(
            extension="com", registration_price_cents=5000, renewal_price_cents=6000,
            transfer_price_cents=4500, whois_privacy_available=True,
        )
        TLDRetailPrice.objects.create(
            tld=tld, currency_id="EUR", registration_price_cents=1000,
            renewal_price_cents=1200, transfer_price_cents=900, whois_privacy_price_cents=150,
        )
        self.assertIsInstance(SettingsService.update_setting("domains.whois_privacy_price_cents", 700), Ok)
        ron = TLDService.calculate_domain_cost(tld, 1, include_whois_privacy=True, currency_code="RON")
        eur = TLDService.calculate_domain_cost(tld, 1, include_whois_privacy=True, currency_code="EUR")
        self.assertEqual(ron["total_cost_cents"], 5700)
        self.assertEqual(eur["total_cost_cents"], 1150)
