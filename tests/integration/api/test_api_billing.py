from __future__ import annotations

import time
from datetime import timedelta

from django.test import TestCase
from django.utils import timezone
from rest_framework.test import APIRequestFactory

from apps.api.billing.views import customer_invoice_detail_api, customer_invoice_summary_api, customer_invoices_api
from apps.billing.models import Currency, Invoice
from apps.customers.models import Customer
from apps.users.models import CustomerMembership, User


def _make_user(email: str) -> User:
    return User.objects.create_user(email=email, password="testpass123")


def _make_customer(name: str, *, status: str = "active") -> Customer:
    return Customer.objects.create(
        name=name,
        company_name=name,
        customer_type="company",
        status=status,
        primary_email=f"{name.lower().replace(' ', '')}@example.ro",
    )


class BillingAPIIntegrationTests(TestCase):
    def setUp(self) -> None:
        self.factory = APIRequestFactory()
        self.currency, _ = Currency.objects.get_or_create(
            code="RON",
            defaults={"name": "Romanian Leu", "symbol": "lei", "decimals": 2},
        )

        self.user = _make_user("billing-api-user@example.ro")
        self.customer = _make_customer("Billing API Customer SRL", status="active")
        CustomerMembership.objects.create(user=self.user, customer=self.customer, role="owner", is_active=True)

        self.other_customer = _make_customer("Other Customer SRL", status="active")

    def _payload(self, **extra: object) -> dict[str, object]:
        payload: dict[str, object] = {
            "customer_id": self.customer.id,
            "user_id": self.user.id,
            "timestamp": int(time.time()),
            "action": "billing_test",
        }
        payload.update(extra)
        return payload

    def _make_invoice(self, customer: Customer, *, number: str, status: str, total_cents: int) -> Invoice:
        return Invoice.objects.create(
            customer=customer,
            number=number,
            status=status,
            currency=self.currency,
            total_cents=total_cents,
            tax_cents=0,
            due_at=timezone.now() + timedelta(days=10),
        )

    def test_customer_invoices_requires_hmac_portal_authentication(self) -> None:
        request = self.factory.post("/api/billing/invoices/", data=self._payload(), format="json")

        response = customer_invoices_api(request)

        self.assertEqual(response.status_code, 401)
        self.assertEqual(response.data["error"], "Authentication required")

    def test_customer_invoices_returns_only_authenticated_customer_rows(self) -> None:
        own_issued = self._make_invoice(self.customer, number="INV-API-001", status="issued", total_cents=10000)
        self._make_invoice(self.customer, number="INV-API-002", status="paid", total_cents=12000)
        self._make_invoice(self.other_customer, number="INV-OTHER-001", status="issued", total_cents=9000)

        request = self.factory.post(
            "/api/billing/invoices/",
            data=self._payload(status="issued", limit=20, page=1),
            format="json",
        )
        request._portal_authenticated = True

        response = customer_invoices_api(request)

        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.data["success"])
        self.assertEqual(len(response.data["invoices"]), 1)
        self.assertEqual(response.data["invoices"][0]["number"], own_issued.number)

    def test_customer_invoice_detail_cannot_cross_customer_boundary(self) -> None:
        other_invoice = self._make_invoice(self.other_customer, number="INV-OTHER-404", status="issued", total_cents=5000)

        request = self.factory.post("/api/billing/invoices/INV-OTHER-404/", data=self._payload(), format="json")
        request._portal_authenticated = True

        response = customer_invoice_detail_api(request, other_invoice.number)

        self.assertEqual(response.status_code, 404)
        self.assertEqual(response.data["error"], "Invoice not found")

    def test_customer_invoice_summary_reports_status_counts_and_due_total(self) -> None:
        self._make_invoice(self.customer, number="INV-SUM-ISSUED", status="issued", total_cents=5000)
        self._make_invoice(self.customer, number="INV-SUM-OVERDUE", status="overdue", total_cents=2000)
        self._make_invoice(self.customer, number="INV-SUM-PAID", status="paid", total_cents=7000)

        request = self.factory.post("/api/billing/summary/", data=self._payload(), format="json")
        request._portal_authenticated = True

        response = customer_invoice_summary_api(request)

        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.data["success"])
        summary = response.data["summary"]
        self.assertEqual(summary["total_invoices"], 3)
        self.assertEqual(summary["issued_invoices"], 1)
        self.assertEqual(summary["overdue_invoices"], 1)
        self.assertEqual(summary["paid_invoices"], 1)
        self.assertEqual(summary["total_amount_due_cents"], 7000)
