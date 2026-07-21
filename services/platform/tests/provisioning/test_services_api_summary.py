"""Regression tests for the customer services summary API."""

from decimal import Decimal
from unittest.mock import patch

from django.test import RequestFactory, TestCase

from apps.api.services.views import customer_services_summary_api
from apps.billing.models import Currency
from apps.customers.models import Customer
from apps.provisioning.models import Service, ServicePlan


class ServiceSummaryStatusCountTests(TestCase):
    """The summary exposes one customer-scoped count for every Service status."""

    def setUp(self) -> None:
        self.customer = Customer.objects.create(name="Summary SRL", customer_type="company")
        self.other_customer = Customer.objects.create(name="Other SRL", customer_type="company")
        self.currency, _created = Currency.objects.get_or_create(
            code="RON",
            defaults={"name": "Romanian Leu", "symbol": "lei", "decimals": 2},
        )
        self.plan = ServicePlan.objects.create(
            name="Summary Plan",
            plan_type="shared_hosting",
            price_monthly=Decimal("10.00"),
            setup_fee=Decimal("0.00"),
        )

    def _create_service(self, customer: Customer, status: str, suffix: str) -> Service:
        return Service.objects.create(
            customer=customer,
            service_plan=self.plan,
            currency=self.currency,
            service_name=f"Service {suffix}",
            username=f"summary_{suffix}",
            price=Decimal("10.00"),
            status=status,
        )

    def _post_to_summary(self):
        request = RequestFactory().post("/api/services/summary/")
        with patch(
            "apps.api.secure_auth.get_authenticated_customer",
            return_value=(self.customer, None),
        ):
            return customer_services_summary_api(request)

    def test_summary_includes_every_status_for_authenticated_customer(self) -> None:
        expected_counts = {status: 0 for status, _label in Service.STATUS_CHOICES}
        for suffix, status in enumerate(expected_counts, start=1):
            self._create_service(self.customer, status, str(suffix))
            expected_counts[status] = 1

        self._create_service(self.other_customer, "active", "other-customer")

        response = self._post_to_summary()

        self.assertEqual(response.status_code, 200)
        summary = response.data["data"]["summary"]
        self.assertEqual(summary["status_counts"], expected_counts)
        self.assertEqual(summary["total_services"], len(expected_counts))
        self.assertEqual(summary["active_services"], expected_counts["active"])
        self.assertEqual(summary["pending_services"], expected_counts["pending"])
        self.assertEqual(summary["suspended_services"], expected_counts["suspended"])
