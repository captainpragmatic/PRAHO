"""Customers cannot request or trigger a refund from the portal; staff refund on Platform.

The invoice page's "Request Refund" button promised a review by the billing team, but it was
wired to a Platform endpoint that refunded immediately. Refunds are now staff-only, and customers
ask through an ordinary support ticket.
"""

from __future__ import annotations

import time
from datetime import timedelta
from unittest.mock import patch

from django.test import TestCase
from django.urls import NoReverseMatch, reverse
from django.utils import timezone

from apps.api_client.services import PlatformAPIClient
from apps.billing.schemas import Currency, Invoice
from apps.billing.services import InvoiceViewService


def _invoice(status: str) -> Invoice:
    currency = Currency(id=1, code="RON", name="Romanian Leu", symbol="lei", decimal_places=2)
    now = timezone.now()
    invoice = Invoice(
        id=1,
        number="INV-2026-0100",
        status=status,
        currency=currency,
        exchange_to_ron=None,
        subtotal_cents=10000,
        tax_cents=2100,
        total_cents=12100,
        issued_at=now,
        due_at=now,
        created_at=now,
        updated_at=now,
        locked_at=None,
        sent_at=None,
        paid_at=now if status == "paid" else None,
    )
    invoice.lines = []
    return invoice


class InvoiceRefundRemovedTests(TestCase):
    def setUp(self) -> None:
        now = timezone.now()
        session = self.client.session
        session["customer_id"] = 42
        session["user_id"] = 7
        session["user_memberships"] = [{"customer_id": 42, "role": "owner"}]
        session["user_memberships_fetched_at"] = time.time()
        session["session_auth_hash"] = "test-session"
        session["validated_at"] = now.isoformat()
        session["next_validate_at"] = (now + timedelta(minutes=10)).isoformat()
        session.save()

    def test_no_invoice_offers_a_refund_control(self) -> None:
        for status in ("paid", "issued"):
            with (
                self.subTest(status=status),
                patch("apps.billing.views.InvoiceViewService.get_invoice_detail", return_value=_invoice(status)),
            ):
                response = self.client.get(reverse("billing:invoice_detail", kwargs={"invoice_number": "INV-2026-0100"}))
                self.assertContains(response, "INV-2026-0100")  # the invoice itself still renders
                for leftover in ("Request Refund", "invoiceRefundRequestModal", 'name="refund_reason"', "/refund/"):
                    self.assertNotContains(response, leftover)

    def test_the_refund_route_is_gone(self) -> None:
        with self.assertRaises(NoReverseMatch):
            reverse("billing:request_refund", kwargs={"invoice_number": "INV-2026-0100"})
        with patch("apps.api_client.services.portal_request") as transport:
            response = self.client.post("/billing/invoices/INV-2026-0100/refund/", {"refund_reason": "other"})
        self.assertEqual(response.status_code, 404)
        transport.assert_not_called()

    def test_no_client_method_can_ask_platform_for_a_refund(self) -> None:
        self.assertFalse(hasattr(PlatformAPIClient, "process_refund"))
        self.assertFalse(hasattr(InvoiceViewService, "request_refund"))
