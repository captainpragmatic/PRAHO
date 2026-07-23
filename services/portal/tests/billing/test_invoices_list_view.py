"""Invoices list view: doc-type clamping and tab-label laziness.

The shared filter component gives only the active tab tabindex="0" (roving
tabindex). An unvalidated ?type= that matches no tab would leave every tab
tabindex="-1" — the whole tablist becomes unreachable by keyboard — so the view
must clamp unknown values to the All Documents tab.
"""
from __future__ import annotations

import time
from types import SimpleNamespace
from unittest.mock import patch

from django.test import TestCase
from django.urls import reverse
from django.utils import timezone
from django.utils.functional import Promise

from apps.billing.schemas import BillingDocumentPage
from apps.billing.views import INVOICE_DOC_TYPE_TABS, INVOICE_STATUS_CHOICES


class InvoiceTabConfigTests(TestCase):
    def test_tab_and_status_labels_are_lazy_for_per_request_language(self) -> None:
        """Module-level labels must be lazy or they freeze to the import-time locale."""
        for tab in INVOICE_DOC_TYPE_TABS:
            self.assertIsInstance(tab["label"], Promise, f"tab {tab['value']!r} label is not lazy")
        for value, label in INVOICE_STATUS_CHOICES:
            self.assertIsInstance(label, Promise, f"status {value!r} label is not lazy")


class InvoicesListDocTypeClampTests(TestCase):
    def setUp(self) -> None:
        session = self.client.session
        session["customer_id"] = 42
        session["user_id"] = 7
        session["email"] = "owner@example.com"
        session["user_memberships"] = [{"customer_id": 42, "role": "owner"}]
        session["user_memberships_fetched_at"] = time.time()
        session.save()

    @patch("apps.billing.views.InvoiceViewService.get_customer_documents")
    def test_unknown_doc_type_falls_back_to_all(self, mock_fetch: object) -> None:
        mock_fetch.return_value = BillingDocumentPage()

        response = self.client.get(reverse("billing:invoices_list"), {"type": "bogus"})

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.context["doc_type"], "all")
        # The All Documents tab is selected on both the desktop and mobile
        # tablists, so the roving tabindex keeps the widget keyboard-reachable.
        self.assertEqual(response.content.decode().count('aria-selected="true"'), 2)

    @patch("apps.billing.views.InvoiceViewService.get_customer_documents")
    def test_known_doc_type_is_preserved(self, mock_fetch: object) -> None:
        mock_fetch.return_value = BillingDocumentPage()

        response = self.client.get(reverse("billing:invoices_list"), {"type": "proforma"})

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.context["doc_type"], "proforma")

    @patch("apps.billing.views.InvoiceViewService.get_customer_documents")
    def test_backend_document_statuses_are_not_silently_clamped(self, mock_fetch: object) -> None:
        mock_fetch.return_value = BillingDocumentPage()

        for document_status in ("partially_refunded", "converted"):
            with self.subTest(document_status=document_status):
                response = self.client.get(reverse("billing:invoices_list"), {"status": document_status})

                self.assertEqual(response.status_code, 200)
                self.assertEqual(response.context["status_filter"], document_status)
                self.assertEqual(mock_fetch.call_args.kwargs["status"], document_status)

    @patch("apps.billing.views.InvoiceViewService.get_customer_documents")
    def test_platform_page_and_totals_are_rendered_without_local_repagination(self, mock_fetch: object) -> None:
        document = SimpleNamespace(
            document_type="invoice",
            number="INV-OLD-041",
            status="overdue",
            status_display="Overdue",
            total_cents=1000,
            currency=SimpleNamespace(code="RON"),
            created_at=timezone.now(),
        )
        mock_fetch.return_value = BillingDocumentPage(
            documents=[document],
            current_page=3,
            page_size=20,
            total_items=45,
            invoice_count=45,
            unpaid_invoice_count=5,
        )

        response = self.client.get(reverse("billing:invoices_list"), {"page": 3, "q": "INV-OLD"})

        self.assertEqual(response.context["invoices"], [document])
        self.assertEqual(response.context["paginator_data"].number, 3)
        self.assertEqual(response.context["paginator_data"].paginator.count, 45)
        self.assertEqual(response.context["header_stats"][2]["value"], "5")
