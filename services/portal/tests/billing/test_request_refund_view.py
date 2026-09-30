"""`request_refund_view`, found untouched by any test - a money-affecting action.

A refund is the one request on this endpoint where the customer's assumption ("it worked" vs
"it did not") has a financial consequence if wrong. A status-only check could not distinguish
a successful refund from a rejected one, since the view answers 200 for a rejection with
`success: False` in the body as much as for an acceptance.
"""

from __future__ import annotations

import json
import time
from unittest.mock import patch

from django.test import TestCase
from django.urls import reverse


class RequestRefundViewTests(TestCase):
    def setUp(self) -> None:
        session = self.client.session
        session["customer_id"] = 42
        session["user_id"] = 7
        session["user_memberships"] = [{"customer_id": 42, "role": "owner"}]
        session["user_memberships_fetched_at"] = time.time()
        session.save()

    @patch("apps.billing.views.InvoiceViewService.request_refund")
    def test_a_successful_refund_returns_its_refund_id(self, request_refund) -> None:
        request_refund.return_value = {"success": True, "refund_id": "ref-789"}

        response = self.client.post(
            reverse("billing:request_refund", kwargs={"invoice_number": "INV-2026-0100"}),
            data=json.dumps({"refund_reason": "duplicate_charge"}),
            content_type="application/json",
        )

        self.assertEqual(response.status_code, 200)
        body = json.loads(response.content)
        self.assertTrue(body["success"])
        self.assertEqual(body["refund_id"], "ref-789")
        request_refund.assert_called_once_with(
            invoice_number="INV-2026-0100",
            customer_id=42,
            user_id=7,
            amount_cents=None,
            reason="duplicate_charge",
        )

    @patch("apps.billing.views.InvoiceViewService.request_refund")
    def test_a_rejected_refund_is_a_400_naming_why_not_a_500(self, request_refund) -> None:
        """200-with-success:False and a genuine failure are different states the customer needs
        told apart - this view maps a platform rejection to 400 with the platform's own reason."""
        request_refund.return_value = {"success": False, "error": "Invoice already refunded"}

        response = self.client.post(
            reverse("billing:request_refund", kwargs={"invoice_number": "INV-2026-0100"}),
            data=json.dumps({"refund_reason": "customer_request"}),
            content_type="application/json",
        )

        self.assertEqual(response.status_code, 400)
        self.assertEqual(json.loads(response.content)["error"], "Invoice already refunded")

    @patch("apps.billing.views.InvoiceViewService.request_refund")
    def test_a_partial_amount_is_forwarded_as_an_integer(self, request_refund) -> None:
        request_refund.return_value = {"success": True, "refund_id": "ref-790"}

        self.client.post(
            reverse("billing:request_refund", kwargs={"invoice_number": "INV-2026-0100"}),
            data=json.dumps({"refund_reason": "goodwill", "amount_cents": "1500"}),
            content_type="application/json",
        )

        request_refund.assert_called_once_with(
            invoice_number="INV-2026-0100",
            customer_id=42,
            user_id=7,
            amount_cents=1500,
            reason="goodwill",
        )

    def test_get_is_rejected(self) -> None:
        response = self.client.get(reverse("billing:request_refund", kwargs={"invoice_number": "INV-2026-0100"}))
        self.assertEqual(response.status_code, 405)
