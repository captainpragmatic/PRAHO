"""Portal retains safe retry keys and shows the Platform's tender amounts."""

import time
from unittest.mock import patch

from django.template.loader import render_to_string
from django.test import SimpleTestCase, TestCase
from django.urls import reverse

from apps.api_client.services import PlatformAPIError
from apps.billing.serializers import create_proforma_from_api


def proforma_data():
    return {
        "id": 1,
        "number": "PRO-GIFT",
        "status": "draft",
        "subtotal_cents": 10000,
        "tax_cents": 2100,
        "total_cents": 12100,
        "gift_reserved_cents": 5000,
        "cash_due_cents": 7100,
        "currency": {"id": 1, "code": "RON", "symbol": "lei", "decimal_places": 2, "name": "Leu"},
        "valid_until": "2099-01-01T00:00:00Z",
        "created_at": "2026-09-28T00:00:00Z",
    }


class GiftPaymentDisplayTests(SimpleTestCase):
    def test_remaining_payment_comes_from_api_without_changing_document_total(self):
        proforma = create_proforma_from_api(proforma_data())
        html = render_to_string("billing/partials/gift_card_payment.html", {"proforma": proforma})
        self.assertEqual(proforma.total_cents, 12100)
        self.assertIn("50.00", html)
        self.assertIn("71.00", html)
        self.assertIn("Remaining to pay", html)


class GiftPaymentFlowTests(TestCase):
    def setUp(self):
        session = self.client.session
        session.update(
            {
                "customer_id": 42,
                "user_id": 7,
                "email": "gift@example.test",
                "user_memberships": [{"customer_id": 42, "role": "owner"}],
                "user_memberships_fetched_at": time.time(),
            }
        )
        session.save()

    @patch("apps.billing.views.InvoiceViewService.get_proforma_detail")
    @patch("apps.billing.views.PlatformAPIClient.post")
    def test_response_loss_preserves_the_operation_key_after_reload(self, post, fetch):
        fetch.return_value = create_proforma_from_api(proforma_data())
        url = reverse("billing:proforma_detail", kwargs={"proforma_number": "PRO-GIFT"})
        first = self.client.get(url)
        self.assertEqual(first.status_code, 200)
        key = str(first.context["gift_card_form"].initial["operation_key"])
        post.side_effect = PlatformAPIError("Connection lost", status_code=503)
        response = self.client.post(
            reverse("billing:gift_card_payment"),
            {
                "document_type": "proforma",
                "document_number": "PRO-GIFT",
                "code": "EXISTING-GIFT",
                "operation_key": key,
            },
        )
        self.assertEqual(response.status_code, 302)
        self.assertEqual(post.call_args.kwargs["data"]["customer_id"], 42)
        self.assertEqual(post.call_args.kwargs["user_id"], 7)
        second = self.client.get(url)
        self.assertEqual(str(second.context["gift_card_form"].initial["operation_key"]), key)
