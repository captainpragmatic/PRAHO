"""End-to-end contract tests for the customer billing-document ledger API."""

from __future__ import annotations

from datetime import timedelta

from django.test import TestCase, override_settings
from django.utils import timezone
from tests.factories import CurrencyFactory, CustomerFactory
from tests.helpers.hmac import HMAC_TEST_MIDDLEWARE, HMAC_TEST_SECRET, HMACTestMixin

from apps.billing.models import Invoice
from apps.billing.proforma_models import ProformaInvoice
from apps.users.models import CustomerMembership, User


@override_settings(PLATFORM_API_SECRET=HMAC_TEST_SECRET, MIDDLEWARE=HMAC_TEST_MIDDLEWARE)
class BillingDocumentsAPITestCase(HMACTestMixin, TestCase):
    def setUp(self) -> None:
        self.customer = CustomerFactory(company_name="Complete Ledger SRL")
        self.currency = CurrencyFactory(code="RON", symbol="lei")
        self.owner = User.objects.create_user(email="ledger-owner@example.test")
        CustomerMembership.objects.create(customer=self.customer, user=self.owner, role="owner", is_primary=True)

        invoices = [
            Invoice(
                customer=self.customer,
                currency=self.currency,
                number=f"INV-OLD-{index:03d}",
                status="overdue",
                subtotal_cents=10_000,
                total_cents=10_000,
                due_at=timezone.now() - timedelta(days=30),
            )
            for index in range(1, 6)
        ]
        invoices.extend(
            Invoice(
                customer=self.customer,
                currency=self.currency,
                number=f"INV-PAID-{index:03d}",
                status="paid",
                subtotal_cents=10_000,
                total_cents=10_000,
                due_at=timezone.now() - timedelta(days=1),
                paid_at=timezone.now(),
            )
            for index in range(1, 41)
        )
        Invoice.objects.bulk_create(invoices)

        ProformaInvoice.objects.bulk_create(
            [
                ProformaInvoice(
                    customer=self.customer,
                    currency=self.currency,
                    number=f"PRO-NEW-{index:03d}",
                    status="sent",
                    subtotal_cents=20_000,
                    total_cents=20_000,
                    valid_until=timezone.now() + timedelta(days=14),
                )
                for index in range(1, 3)
            ]
        )
        other_customer = CustomerFactory(company_name="Other Ledger SRL")
        Invoice.objects.create(
            customer=other_customer, currency=self.currency, number="INV-OTHER-001", subtotal_cents=1, total_cents=1
        )

    def _payload(self, **filters: object) -> dict[str, object]:
        return {
            "customer_id": self.customer.id,
            "user_id": self.owner.id,
            "action": "get_billing_documents",
            **filters,
        }

    def test_third_page_contains_old_documents_and_summary_counts_all_overdue_invoices(self) -> None:
        response = self.portal_post(
            "/api/billing/documents/",
            self._payload(page=3, limit=20, document_type="all"),
        )

        self.assertEqual(response.status_code, 200)
        body = response.json()
        self.assertEqual(body["pagination"]["total_items"], 47)
        self.assertEqual(body["pagination"]["current_page"], 3)
        self.assertEqual(len(body["documents"]), 7)
        self.assertEqual(
            {document["number"] for document in body["documents"] if document["status"] == "overdue"},
            {f"INV-OLD-{index:03d}" for index in range(1, 6)},
        )
        self.assertEqual(
            body["summary"],
            {
                "invoice_count": 45,
                "proforma_count": 2,
                "unpaid_invoice_count": 5,
                "total_count": 47,
            },
        )

    def test_search_finds_an_invoice_older_than_the_first_page(self) -> None:
        response = self.portal_post(
            "/api/billing/documents/",
            self._payload(page=1, limit=20, search="INV-OLD-003"),
        )

        self.assertEqual(response.status_code, 200)
        body = response.json()
        self.assertEqual(body["pagination"]["total_items"], 1)
        self.assertEqual([document["number"] for document in body["documents"]], ["INV-OLD-003"])
        self.assertEqual(body["documents"][0]["document_type"], "invoice")
