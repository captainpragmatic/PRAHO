"""Deployment, financial display, and country-consumer localisation boundaries."""

import importlib
import os
from datetime import UTC, datetime
from unittest.mock import patch

from django.template.loader import render_to_string
from django.test import RequestFactory, SimpleTestCase, TestCase
from django.utils.translation import override

from apps.audit.services import CustomersAuditService
from apps.customers.contact_service import ContactService
from apps.customers.models import CustomerAddress
from tests.factories.core_factories import create_full_customer, create_full_invoice, create_staff_user
from tests.settings.test_logging_configuration import _PROD_ENV


class DeploymentLocalisationTests(SimpleTestCase):
    def test_deployed_middleware_resolves_authenticated_preferences(self):
        for environment in ("prod", "staging"):
            with (
                self.subTest(environment=environment),
                patch.dict(os.environ, _PROD_ENV),
                patch("config.settings.base.validate_production_secret_key"),
            ):
                middleware = importlib.import_module(f"config.settings.{environment}").MIDDLEWARE
                auth = middleware.index("django.contrib.auth.middleware.AuthenticationMiddleware")
                locale = middleware.index("apps.common.localisation_middleware.LocalisationMiddleware")
                self.assertGreater(locale, auth)


class FinancialDisplayLocalisationTests(TestCase):
    @override("en")
    def test_dashboard_embedded_documents_keep_fixed_dates_for_both_audiences(self):
        staff = create_staff_user(username="dashboard_locale", staff_role="admin")
        staff.profile.timezone = "UTC"
        staff.profile.date_format = "%Y-%m-%d"
        staff.profile.save()
        request = RequestFactory().get("/")
        request.user = staff
        for is_staff in (True, False):
            for kind in ("invoice", "proforma"):
                with self.subTest(is_staff=is_staff, kind=kind):
                    document = {"id": 1, "document_type": kind, "created_at": datetime(2025, 12, 31, 22, 30, tzinfo=UTC)}
                    rendered = render_to_string(
                        "dashboard.html",
                        {"user": {"is_staff_user": is_staff, "username": "example"}, "recent_documents": [document]},
                        request=request,
                    )
                    self.assertIn("01.01.2026", rendered)
                    self.assertNotIn("2025-12-31", rendered)

    @override("en")
    def test_invoice_page_keeps_the_document_day_and_fixed_format(self):
        staff = create_staff_user(username="financial_locale", staff_role="admin")
        staff.profile.timezone = "UTC"
        staff.profile.date_format = "%Y-%m-%d"
        staff.profile.save()
        invoice = create_full_invoice()
        invoice.issued_at = datetime(2025, 12, 31, 22, 30, tzinfo=UTC)
        invoice.save(update_fields=["issued_at"])
        self.client.force_login(staff)
        response = self.client.get(f"/billing/invoices/{invoice.pk}/")
        self.assertContains(response, "01.01.2026")
        self.assertNotContains(response, "2025-12-31")


class CountryConsumerLocalisationTests(TestCase):
    def test_romanian_names_and_iso_code_share_validation_and_audit_context(self):
        customer = create_full_customer()
        for country in ("RO", "Romania", "România"):
            with self.subTest(country=country):
                address = CustomerAddress(
                    customer=customer,
                    address_line1="Test 1",
                    city="Bucharest",
                    county="Bucharest",
                    postal_code="12345",
                    country=country,
                )
                with patch("apps.customers.signals._trigger_romanian_address_validation") as validate:
                    address.save()
                validate.assert_called_once_with(address)
                self.assertTrue(ContactService.validate_address_completeness(address)["warnings"])
                with patch("apps.audit.services.AuditService.log_event") as log:
                    CustomersAuditService.log_address_event("address_updated", address)
                self.assertTrue(log.call_args.args[1].metadata["is_romanian_address"])
