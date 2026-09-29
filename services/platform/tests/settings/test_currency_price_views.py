"""Staff configure explicit retail prices without rewriting existing money."""

from decimal import Decimal

from django.test import TestCase
from django.urls import reverse

from apps.billing.models import Currency
from apps.domains.models import TLD, TLDRetailPrice
from apps.products.models import Product, ProductPrice
from apps.provisioning.service_models import ServicePlan, ServicePlanPrice
from apps.users.models import User


class CurrencyPriceViewsTests(TestCase):
    def setUp(self) -> None:
        self.actor = User.objects.create_user(email="price-editor@example.test", is_staff=True, staff_role="billing")
        self.client.force_login(self.actor)
        for code in ("RON", "EUR", "USD"):
            Currency.objects.get_or_create(code=code, defaults={"symbol": code})
        self.plan = ServicePlan.objects.create(name="Price editor plan", price_monthly=Decimal("50.00"))
        self.product = Product.objects.create(name="Price editor product", slug="price-editor-product")
        self.tld = TLD.objects.create(
            extension="qa", registration_price_cents=5000, renewal_price_cents=5500, transfer_price_cents=5000,
        )

    def url(self, kind, entity, currency="EUR"):
        return reverse("settings:currency_price_edit", args=[kind, entity.pk, currency])

    def test_catalog_links_are_restricted_to_billing_configuration_staff(self) -> None:
        self.assertContains(self.client.get(reverse("settings:currency_prices")), self.plan.name)
        self.actor.staff_role = "support"
        self.actor.save(update_fields=["staff_role"])
        self.assertEqual(self.client.get(reverse("settings:currency_prices")).status_code, 403)
        self.assertEqual(self.client.post(self.url("plan", self.plan), {"monthly_price": "5"}).status_code, 403)
        self.assertFalse(ServicePlanPrice.objects.filter(service_plan=self.plan, currency_id="EUR").exists())

    def test_service_plan_price_is_entered_in_units_and_leaves_ron_price_unchanged(self) -> None:
        response = self.client.post(self.url("plan", self.plan), {
            "monthly_price": "10.75", "quarterly_price": "30.25", "semiannual_price": "60.00",
            "annual_price": "100.00", "setup": "2.00", "is_active": "on", "version": "",
        })
        self.assertEqual(response.status_code, 302, response.content)
        price = ServicePlanPrice.objects.get(service_plan=self.plan, currency_id="EUR")
        self.assertEqual((price.monthly_price_cents, price.quarterly_price_cents, price.setup_cents), (1075, 3025, 200))
        self.plan.refresh_from_db()
        self.assertEqual(self.plan.price_monthly, Decimal("50.00"))
        self.assertEqual(ServicePlanPrice.objects.get(service_plan=self.plan, currency_id="RON").monthly_price_cents, 5000)

    def test_product_custom_periods_are_explicit_and_bad_amounts_are_rejected(self) -> None:
        payload = {"monthly_price": "10", "quarterly_price": "28", "setup": "0",
                   "semiannual_discount_percent": "5", "annual_discount_percent": "10",
                   "custom_periods": "45=14.50\n90=28.00", "is_active": "on", "version": ""}
        response = self.client.post(self.url("product", self.product), payload)
        self.assertEqual(response.status_code, 302, response.content)
        price = ProductPrice.objects.get(product=self.product, currency_id="EUR")
        self.assertEqual(price.custom_period_prices, {"45": 1450, "90": 2800})
        self.assertEqual(price.quarterly_price_cents, 2800)
        response = self.client.post(self.url("product", self.product, "USD"), {**payload, "monthly_price": "-1"})
        self.assertEqual(response.status_code, 400)
        self.assertFalse(ProductPrice.objects.filter(product=self.product, currency_id="USD").exists())

    def test_domain_prices_include_independent_renewal_and_privacy_amounts(self) -> None:
        response = self.client.post(self.url("tld", self.tld, "USD"), {
            "registration_price": "12", "renewal_price": "13", "transfer_price": "11",
            "whois_privacy_price": "2.50", "is_active": "on", "version": "",
        })
        self.assertEqual(response.status_code, 302, response.content)
        price = TLDRetailPrice.objects.get(tld=self.tld, currency_id="USD")
        self.assertEqual((price.renewal_price_cents, price.whois_privacy_price_cents), (1300, 250))
        self.tld.refresh_from_db()
        self.assertEqual(self.tld.renewal_price_cents, 5500)

    def test_stale_price_form_cannot_overwrite_a_concurrent_edit(self) -> None:
        price = ServicePlanPrice.objects.get(service_plan=self.plan, currency_id="RON")
        version = price.updated_at.isoformat()
        price.monthly_price_cents = 6500
        price.save()
        response = self.client.post(self.url("plan", self.plan, "RON"), {
            "monthly_price": "55", "setup": "0", "version": version, "is_active": "on",
        })
        self.assertEqual(response.status_code, 409)
        price.refresh_from_db()
        self.assertEqual(price.monthly_price_cents, 6500)

    def test_invalid_currency_and_overprecise_amounts_fail_without_writes(self) -> None:
        self.assertEqual(self.client.get(self.url("plan", self.plan, "GBP")).status_code, 404)
        response = self.client.post(self.url("plan", self.plan), {
            "monthly_price": "12.345", "setup": "0", "version": "", "is_active": "on",
        })
        self.assertEqual(response.status_code, 400)
        self.assertFalse(ServicePlanPrice.objects.filter(service_plan=self.plan, currency_id="EUR").exists())
