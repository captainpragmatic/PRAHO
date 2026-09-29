"""Service catalogs use explicit prices; persisted service money keeps its currency."""

from decimal import Decimal
from unittest.mock import patch

from django.test import TestCase
from django.utils import timezone
from rest_framework.test import APIRequestFactory

from apps.api.services.serializers import ServiceDetailSerializer, ServiceListSerializer
from apps.api.services.views import available_service_plans_api, customer_services_summary_api
from apps.billing.currency_models import Currency, FXRate
from apps.common.types import Ok
from apps.customers.models import Customer
from apps.provisioning.service_models import Service, ServicePlan, ServicePlanPrice
from apps.settings.services import SettingsService


class ServiceCurrencyAPITests(TestCase):
    def setUp(self) -> None:
        self.customer = Customer.objects.create(name="Service currency customer")
        self.plan = ServicePlan.objects.create(name="Explicit plan", price_monthly=Decimal("50.00"))
        for code, cents in (("RON", 5000), ("EUR", 1000), ("USD", 1200)):
            Currency.objects.get_or_create(code=code, defaults={"symbol": code})
            ServicePlanPrice.objects.update_or_create(
                service_plan=self.plan, currency_id=code,
                defaults={"monthly_price_cents": cents, "annual_price_cents": cents * 10, "setup_cents": 200},
            )
            if code != "RON":
                FXRate.objects.create(
                    base_code_id=code, quote_code_id="RON", rate=Decimal("4.97"), as_of=timezone.localdate(),
                    source=FXRate.Source.BNR, source_reference="service-currency-test", fetched_at=timezone.now(),
                )
        self.factory = APIRequestFactory()

    def service(self, currency: str, *, price: str = "9.00", period: str = "monthly") -> Service:
        return Service.objects.create(
            customer=self.customer, service_plan=self.plan, currency_id=currency,
            service_name=f"Original {currency}", username=f"original_{currency}",
            price=Decimal(price), billing_cycle=period, status="active",
        )

    def test_public_plan_catalog_uses_each_selling_currency(self) -> None:
        for code, amount in (("RON", "50.00"), ("EUR", "10.00"), ("USD", "12.00")):
            with self.subTest(code=code):
                self.assertIsInstance(SettingsService.update_setting("billing.default_currency", code), Ok)
                response = available_service_plans_api(self.factory.get("/api/services/plans/"))
                self.assertEqual(response.status_code, 200)
                plans = response.data["data"]["plans"]
                self.assertEqual(len(plans), 1)
                self.assertEqual(plans[0]["currency_code"], code)
                self.assertEqual(Decimal(plans[0]["price_monthly"]), Decimal(amount))
                self.assertEqual(Decimal(plans[0]["setup_fee"]), Decimal("2.00"))
                self.assertIsNone(plans[0]["price_quarterly"])
                self.assertEqual(Decimal(plans[0]["annual_savings"]), Decimal(amount) * 2)

    def test_unpriced_or_inactive_currency_rows_are_not_advertised(self) -> None:
        self.assertIsInstance(SettingsService.update_setting("billing.default_currency", "EUR"), Ok)
        ServicePlanPrice.objects.filter(service_plan=self.plan, currency_id="EUR").update(is_active=False)
        response = available_service_plans_api(self.factory.get("/api/services/plans/"))
        self.assertEqual(response.data["data"]["plans"], [])

    def test_existing_service_uses_recorded_price_and_currency_after_switch(self) -> None:
        service = self.service("EUR", price="84.00", period="annual")
        self.assertIsInstance(SettingsService.update_setting("billing.default_currency", "USD"), Ok)
        for serializer in (ServiceListSerializer, ServiceDetailSerializer):
            with self.subTest(serializer=serializer.__name__):
                result = serializer(service).data
                self.assertEqual(result["currency_code"], "EUR")
                self.assertEqual(Decimal(result["monthly_price"]), Decimal("7.00"))
        detail = ServiceDetailSerializer(service).data
        self.assertEqual(detail["service_plan"]["currency_code"], "EUR")
        self.assertEqual(Decimal(detail["service_plan"]["price_monthly"]), Decimal("10.00"))
        self.assertTrue(detail["available_plans"])
        self.assertEqual({plan["currency_code"] for plan in detail["available_plans"]}, {"EUR"})

    def test_summary_keeps_original_amounts_separate_by_currency(self) -> None:
        self.service("EUR", price="84.00", period="annual")
        self.service("RON", price="19.00")
        request = self.factory.post("/api/services/summary/", {}, format="json")
        with patch("apps.api.secure_auth.get_authenticated_customer", return_value=(self.customer, None)):
            response = customer_services_summary_api(request)
        self.assertEqual(response.status_code, 200)
        summary = response.data["data"]["summary"]
        self.assertIsNone(summary["total_monthly_cost"])
        self.assertIsNone(summary["total_monthly_cost_with_vat"])
        amounts = {row["currency_code"]: Decimal(row["total_monthly_cost"]) for row in summary["monthly_costs_by_currency"]}
        self.assertEqual(amounts, {"EUR": Decimal("7.00"), "RON": Decimal("19.00")})
