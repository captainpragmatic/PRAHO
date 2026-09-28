"""Customer role guards on Portal billing and ticket views."""

import time
from unittest.mock import patch

from django.test import SimpleTestCase, override_settings
from django.urls import reverse

from apps.billing.schemas import BillingDocumentPage


@override_settings(
    SESSION_ENGINE="django.contrib.sessions.backends.cache",
    CACHES={
        "default": {
            "BACKEND": "django.core.cache.backends.locmem.LocMemCache",
            "LOCATION": "portal-billing-role-guards",
        }
    },
    MIDDLEWARE=[
        "django.contrib.sessions.middleware.SessionMiddleware",
        "django.contrib.messages.middleware.MessageMiddleware",
    ],
    LANGUAGE_CODE="en",
)
class PortalRoleGuardTests(SimpleTestCase):
    def setUp(self) -> None:
        self._set_role("viewer")

    def _set_role(self, role: str) -> None:
        session = self.client.session
        session["user_id"] = 7
        session["customer_id"] = "42"
        session["user_memberships"] = [{"customer_id": "42", "role": role}]
        session["user_memberships_fetched_at"] = time.time()
        session.save()

    def test_viewer_gets_403_on_invoice_search_htmx_and_page(self) -> None:
        with patch("apps.billing.views.InvoiceViewService.get_customer_documents", return_value=BillingDocumentPage()):
            response = self.client.get(reverse("billing:invoices_search_api"), HTTP_HX_REQUEST="true")
        self.assertEqual(response.status_code, 403)
        self.assertEqual(response["Content-Type"], "text/html; charset=utf-8")
        self.assertContains(response, "You do not have permission to perform this action.", status_code=403)
        self.assertContains(response, "Insufficient permissions", status_code=403)
        self.assertTemplateUsed(response, "components/permission_denied_partial.html")
        response = self.client.get(reverse("billing:invoice_detail", kwargs={"invoice_number": "INV-ROLE-001"}))
        self.assertEqual(response.status_code, 403)

    def test_owner_passes_the_guard(self) -> None:
        with patch("apps.billing.views.InvoiceViewService.get_customer_documents", return_value=BillingDocumentPage()):
            denied = self.client.get(reverse("billing:invoices_search_api"))
            self.assertEqual(denied.status_code, 403)
            self._set_role("owner")
            response = self.client.get(reverse("billing:invoices_search_api"))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "billing/partials/invoices_table.html")
        self.assertEqual(response.context["invoices"], [])

    def test_tax_profile_requires_billing_access_after_method_validation(self) -> None:
        path = reverse("customers:tax_profile")
        for role in ("viewer", "tech"):
            with self.subTest(role=role):
                self._set_role(role)
                self.assertEqual(self.client.get(path).status_code, 403)
                self.assertEqual(self.client.post(path, {"vat_number": "DE136695976"}).status_code, 403)
                self.assertEqual(self.client.delete(path).status_code, 405)

    def test_viewer_cannot_open_ticket_or_reply(self) -> None:
        response = self.client.post(reverse("tickets:create"))
        self.assertEqual(response.status_code, 403)
        response = self.client.post(reverse("tickets:reply", kwargs={"ticket_id": 1}))
        self.assertEqual(response.status_code, 403)
