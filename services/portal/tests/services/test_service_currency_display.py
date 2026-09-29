"""Service prices are labelled with their own currency, including upgrade choices."""

import time
from unittest.mock import patch

from django.template.loader import render_to_string
from django.test import SimpleTestCase, override_settings
from django.urls import reverse


@override_settings(
    SESSION_ENGINE="django.contrib.sessions.backends.cache",
    CACHES={"default": {"BACKEND": "django.core.cache.backends.locmem.LocMemCache"}},
    MIDDLEWARE=["django.contrib.sessions.middleware.SessionMiddleware", "django.contrib.messages.middleware.MessageMiddleware"],
)
class ServiceCurrencyDisplayTests(SimpleTestCase):
    def setUp(self) -> None:
        session = self.client.session
        session.update({
            "customer_id": 42, "user_id": 7,
            "user_memberships": [{"customer_id": 42, "role": "owner"}],
            "user_memberships_fetched_at": time.time(),
        })
        session.save()

    def test_plan_prices_fees_and_savings_use_their_explicit_currency(self) -> None:
        for code in ("RON", "EUR", "USD"):
            with self.subTest(currency=code):
                rendered = render_to_string("services/plans_list.html", {"plans": [{
                    "id": 1, "name": "Currency plan", "description": "Currency hosting plan", "plan_type": "hosting",
                    "currency_code": code, "price_monthly": "10.00", "price_quarterly": "27.00",
                    "price_annual": "100.00", "setup_fee": "2.00", "quarterly_savings": "3.00", "annual_savings": "20.00",
                }]})
                for amount in ("10,00", "27,00", "100,00", "2,00", "3,00", "20,00"):
                    self.assertIn(f"{amount} {code}", rendered)

    def test_upgrade_choices_come_from_existing_service_currency(self) -> None:
        service = {
            "id": 5, "status": "active", "service_name": "Original EUR", "currency_code": "EUR", "monthly_price": "7.00",
            "service_plan": {"name": "Original plan"},
            "available_plans": [{"id": 2, "name": "EUR upgrade", "description": "An EUR plan", "price_monthly": "12.00", "currency_code": "EUR"}],
        }
        with patch("apps.services.views.services_api") as api:
            api.get_service_detail.return_value = service
            api.get_available_plans.return_value = [{
                "id": 3, "name": "New USD sale", "description": "USD only", "price_monthly": "9.00", "currency_code": "USD",
            }]
            response = self.client.get(reverse("services:request_action", kwargs={"service_id": 5}))
        self.assertContains(response, "EUR upgrade")
        self.assertContains(response, "12,00 EUR")
        self.assertContains(response, "7,00 EUR")
        self.assertNotContains(response, "New USD sale")
        api.get_available_plans.assert_not_called()

    def test_missing_currency_renders_unavailable_without_guessing_a_currency(self) -> None:
        plan = {
            "id": 1, "name": "Unpriced plan", "description": "Legacy plan without currency",
            "price_monthly": "10.00", "price_quarterly": "27.00", "price_annual": "100.00",
            "setup_fee": "2.00", "quarterly_savings": "3.00", "annual_savings": "20.00",
        }
        for currency_data in ({}, {"currency_code": None}, {"currency_code": ""}):
            for template in ("services/plans_list.html", "services/service_request_action.html"):
                with self.subTest(currency=currency_data, template=template):
                    rendered = render_to_string(template, {
                        "plans": [plan | currency_data], "available_plans": [plan | currency_data],
                        "service_id": 5,
                        "service": {"id": 5, "status": "active", "monthly_price": "7.00"} | currency_data,
                    })
                    self.assertIn("Unpriced plan", rendered)
                    self.assertIn("—", rendered)
                    for amount in ("7,00", "10,00", "27,00", "100,00", "2,00", "3,00", "20,00"):
                        self.assertNotIn(amount, rendered)

    def test_upgrade_choices_exclude_foreign_and_unknown_currency_prices(self) -> None:
        for code in ("RON", "EUR", "USD"):
            with self.subTest(currency=code), patch("apps.services.views.services_api") as api:
                api.get_service_detail.return_value = {
                    "id": 5, "status": "active", "currency_code": code, "monthly_price": "7.00",
                    "available_plans": [
                        {"id": 1, "name": "Matching plan", "price_monthly": "12.00", "currency_code": code},
                        {"id": 2, "name": "Foreign plan", "price_monthly": "9.00", "currency_code": "EUR" if code != "EUR" else "USD"},
                        {"id": 3, "name": "Unpriced plan", "price_monthly": "15.00"},
                        None,
                    ],
                }
                api.get_available_plans.return_value = [{"name": "New sale", "price_monthly": "25.00", "currency_code": code}]
                response = self.client.get(reverse("services:request_action", kwargs={"service_id": 5}))
                self.assertContains(response, "Matching plan")
                self.assertContains(response, f"12,00 {code}")
                self.assertNotContains(response, "Foreign plan")
                self.assertNotContains(response, "Unpriced plan")
                self.assertNotContains(response, "New sale")
                api.get_available_plans.assert_not_called()

    def test_unknown_service_currency_or_missing_plan_metadata_never_uses_new_sale_prices(self) -> None:
        plan = {"id": 2, "name": "New sale", "price_monthly": "12.00", "currency_code": "USD"}
        for metadata in (
            {"available_plans": [plan]},
            {"currency_code": "EUR"},
            {"currency_code": "EUR", "available_plans": None},
            {"currency_code": "EUR", "available_plans": []},
        ):
            with self.subTest(metadata=metadata), patch("apps.services.views.services_api") as api:
                api.get_service_detail.return_value = {"id": 5, "status": "active", "monthly_price": "7.00"} | metadata
                api.get_available_plans.return_value = [plan]
                response = self.client.get(reverse("services:request_action", kwargs={"service_id": 5}))
                self.assertContains(response, 'id="service-request-form"')
                self.assertNotContains(response, "New sale")
                self.assertNotContains(response, "12,00 USD")
                api.get_available_plans.assert_not_called()
