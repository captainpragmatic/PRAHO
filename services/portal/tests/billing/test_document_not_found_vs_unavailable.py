"""An invoice or proforma is "not found" only when Platform says so; anything else is "couldn't load it".

Platform answers a document that does not exist, or is not this customer's, with 404. The portal used
to turn every failure (a server error, an answer without the document) into None, which the views
showed as "not found or access denied": a claim about the customer's own account that was false
during an outage, and that sent the invoice view on to look the number up as a proforma.
"""

from __future__ import annotations

import time
from typing import Any
from unittest.mock import MagicMock, patch

from django.test import SimpleTestCase, TestCase, override_settings
from django.urls import reverse

from apps.api_client.services import PlatformAPIError
from apps.billing.services import InvoiceViewService
from tests.billing.test_gift_card_payment import proforma_data

NOT_FOUND = PlatformAPIError("Invoice not found", status_code=404, response_data={"success": False})
SERVER_ERROR = PlatformAPIError("Server error", status_code=500)
DOCUMENTS: tuple[tuple[str, str, str], ...] = (
    ("get_invoice_detail", "invoice", "INV-1"),
    ("get_proforma_detail", "proforma", "PRO-1"),
)


@override_settings(PLATFORM_API_BASE_URL="http://localhost:8700/api", PLATFORM_API_SECRET="test-secret")
class DocumentDetailServiceTests(SimpleTestCase):
    def setUp(self) -> None:
        self.service = InvoiceViewService()
        self.service.api_client = MagicMock()

    def fetch(self, method: str, number: str) -> Any:
        return getattr(self.service, method)(number, 1, 1)

    def test_platform_saying_not_found_is_not_found(self) -> None:
        self.service.api_client.post.side_effect = NOT_FOUND
        for method, _kind, number in DOCUMENTS:
            with self.subTest(method=method):
                self.assertIsNone(self.fetch(method, number))

    def test_a_server_error_is_an_error_not_a_missing_document(self) -> None:
        self.service.api_client.post.side_effect = SERVER_ERROR
        for method, _kind, number in DOCUMENTS:
            with self.subTest(method=method), self.assertRaises(PlatformAPIError):
                self.fetch(method, number)

    def test_success_without_the_document_breaks_the_contract(self) -> None:
        self.service.api_client.post.side_effect = None
        self.service.api_client.post.return_value = {"success": True}
        for method, _kind, number in DOCUMENTS:
            with self.subTest(method=method), self.assertRaises(PlatformAPIError):
                self.fetch(method, number)

    def test_a_refusal_without_a_status_is_an_error(self) -> None:
        self.service.api_client.post.side_effect = None
        self.service.api_client.post.return_value = {"success": False, "error": "something"}
        for method, _kind, number in DOCUMENTS:
            with self.subTest(method=method), self.assertRaises(PlatformAPIError):
                self.fetch(method, number)

    def test_a_number_that_cannot_be_a_path_segment_is_nobodys_document(self) -> None:
        for method, _kind, _number in DOCUMENTS:
            with self.subTest(method=method):
                self.assertIsNone(self.fetch(method, ".."))
        self.service.api_client.post.assert_not_called()

    def test_a_document_that_cannot_be_read_is_an_error(self) -> None:
        # Only the path check's ValueError means "no such document": a serializer failing on what
        # Platform sent is a broken answer, not a missing invoice.
        self.service.api_client.post.side_effect = None
        self.service.api_client.post.return_value = {"success": True, "invoice": {"bad": 1}, "proforma": {"bad": 1}}
        for method, kind, number in DOCUMENTS:
            serializer = f"apps.billing.services.create_{kind}_from_api"
            with (
                self.subTest(method=method),
                patch(serializer, side_effect=ValueError("bad data")),
                self.assertRaises((PlatformAPIError, ValueError)),
            ):
                self.fetch(method, number)


class DocumentDetailViewTests(TestCase):
    def setUp(self) -> None:
        session = self.client.session
        session.update(
            {
                "customer_id": 42,
                "user_id": 7,
                "email": "docs@example.test",
                "user_memberships": [{"customer_id": 42, "role": "owner"}],
                "user_memberships_fetched_at": time.time(),
            }
        )
        session.save()

    @patch("apps.billing.views.InvoiceViewService.get_proforma_detail")
    @patch("apps.billing.views.InvoiceViewService.get_invoice_detail")
    def test_an_invoice_that_could_not_be_loaded_is_not_called_missing(self, invoice: Any, proforma: Any) -> None:
        invoice.side_effect = SERVER_ERROR
        response = self.client.get(reverse("billing:invoice_detail", args=["INV-1"]))
        self.assertEqual(response.status_code, 502)
        self.assertContains(response, "could not be loaded", status_code=502)
        self.assertNotContains(response, "could not be found", status_code=502)
        self.assertNotContains(response, "Not Found", status_code=502)
        proforma.assert_not_called()  # an outage is no reason to look the number up as a proforma

    @patch("apps.billing.views.InvoiceViewService.get_proforma_detail")
    @patch("apps.billing.views.InvoiceViewService.get_invoice_detail")
    def test_a_missing_invoice_is_tried_as_a_proforma_then_called_missing(self, invoice: Any, proforma: Any) -> None:
        invoice.return_value = None
        proforma.return_value = None
        response = self.client.get(reverse("billing:invoice_detail", args=["INV-1"]))
        self.assertEqual(response.status_code, 404)
        self.assertContains(response, "could not be found", status_code=404)
        proforma.assert_called_once()

    @patch("apps.billing.views.InvoiceViewService.get_proforma_detail")
    @patch("apps.billing.views.InvoiceViewService.get_invoice_detail")
    def test_a_proforma_lookup_that_fails_is_an_error_too(self, invoice: Any, proforma: Any) -> None:
        invoice.return_value = None
        proforma.side_effect = SERVER_ERROR
        response = self.client.get(reverse("billing:invoice_detail", args=["INV-1"]))
        self.assertEqual(response.status_code, 502)
        self.assertNotContains(response, "could not be found", status_code=502)

    @patch("apps.billing.views.InvoiceViewService.get_proforma_detail")
    def test_a_proforma_that_could_not_be_loaded_is_not_called_missing(self, proforma: Any) -> None:
        proforma.side_effect = SERVER_ERROR
        response = self.client.get(reverse("billing:proforma_detail", args=["PRO-1"]))
        self.assertEqual(response.status_code, 502)
        self.assertContains(response, "could not be loaded", status_code=502)
        self.assertNotContains(response, "could not be found", status_code=502)

    @patch("apps.billing.views.InvoiceViewService.get_proforma_detail")
    def test_a_missing_proforma_is_called_missing(self, proforma: Any) -> None:
        proforma.return_value = None
        response = self.client.get(reverse("billing:proforma_detail", args=["PRO-1"]))
        self.assertEqual(response.status_code, 404)
        self.assertContains(response, "could not be found", status_code=404)

    @patch("apps.billing.views.InvoiceViewService.get_invoice_detail")
    def test_the_romanian_page_also_says_could_not_load_not_not_found(self, invoice: Any) -> None:
        session = self.client.session
        session["_language"] = "ro"  # a signed-in customer's language comes from the session
        session.save()
        invoice.side_effect = SERVER_ERROR
        response = self.client.get(reverse("billing:invoice_detail", args=["INV-1"]))
        self.assertEqual(response.status_code, 502)
        self.assertContains(response, "nu a putut fi încărcată momentan", status_code=502)
        self.assertNotContains(response, "nu a putut fi găsită", status_code=502)

    @patch("apps.billing.views.InvoiceViewService.get_invoice_detail")
    def test_a_found_invoice_still_renders(self, invoice: Any) -> None:
        from apps.billing.serializers import create_invoice_from_api  # noqa: PLC0415

        invoice.return_value = create_invoice_from_api({**proforma_data(), "number": "INV-1", "status": "paid"})
        response = self.client.get(reverse("billing:invoice_detail", args=["INV-1"]))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "INV-1")
