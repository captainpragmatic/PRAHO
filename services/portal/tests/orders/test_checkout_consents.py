"""The checkout page carries the consents Platform records with the order (ADR-0062).

Platform's preflight names the Terms of Service release in force and whether this customer must ask
for an early start; the page links and sends back exactly that release, and asks the question only
when Platform does. A refused consent is never replayed: the next checkout sends what its page shows.
"""

import time
from copy import deepcopy
from typing import Any
from unittest.mock import Mock, patch

from django.core.cache import cache
from django.test import SimpleTestCase, override_settings
from django.urls import reverse

from apps.api_client.services import PlatformAPIError, api_client
from apps.common.localisation import LocalisationDefaults
from apps.orders.services import GDPRCompliantCartSession, OrderCreationService
from tests.orders.test_selling_currency import product, totals

TERMS_ID = "6f0c1b1e-3d2a-4c5b-8e9f-0a1b2c3d4e5f"
IDENTITY = {
    "legal_name": "Checkout Test SRL",
    "email_support": "help@checkout.example.test",
    "email_privacy": "privacy@checkout.example.test",
    "email_finance": "",
    "phone": "",
}


@override_settings(
    SESSION_ENGINE="django.contrib.sessions.backends.cache",
    CACHES={"default": {"BACKEND": "django.core.cache.backends.locmem.LocMemCache"}},
    MIDDLEWARE=[
        "django.contrib.sessions.middleware.SessionMiddleware",
        "django.contrib.messages.middleware.MessageMiddleware",
    ],
)
class CheckoutConsentTests(SimpleTestCase):
    def setUp(self) -> None:
        cache.clear()
        self.addCleanup(cache.clear)
        self.api = Mock()
        self.api.get.return_value = product("RON", 1)
        self.api.post.side_effect = self.platform
        self.enterContext(patch("apps.orders.services.PlatformAPIClient", return_value=self.api))
        self.enterContext(patch("apps.orders.views.PlatformAPIClient", return_value=self.api))
        payload = {"success": True, "localisation": LocalisationDefaults().customer_payload(), "company": IDENTITY}
        self.enterContext(patch.object(api_client, "get_localisation_defaults", return_value=payload))
        counters = self.enterContext(patch("apps.orders.views.counters"))
        counters.lookup.return_value = None
        counters.claim.return_value = True
        counters.complete.return_value = True
        session = self.client.session
        session.update(
            {
                "customer_id": 42,
                "user_id": 7,
                "user_memberships": [{"customer_id": 42, "role": "owner"}],
                "user_memberships_fetched_at": time.time(),
            }
        )
        cart = GDPRCompliantCartSession(session)
        cart.add_item("basic-hosting", 1, "monthly")
        session.save()
        self.form = {"cart_version": cart.get_cart_version(), "agree_terms": "on", "payment_method": "bank_transfer"}
        self.early_start_required = True
        self.create_requests: list[dict[str, Any]] = []
        self.create_error: PlatformAPIError | None = None

    def platform(self, path: str, data: dict[str, Any], *, user_id: int) -> dict[str, Any]:
        if path == "orders/preflight/":
            terms = {"document_id": TERMS_ID, "kind": "terms", "language": "en", "release": "2026-10-14.1", "sha256": "0" * 64}
            return {
                "success": True,
                "errors": [],
                "warnings": [],
                "checkout": {"terms_document": terms, "early_start_required": self.early_start_required},
            }
        if path == "orders/calculate/":
            return totals("RON", 1)
        if path == "orders/create/":
            self.create_requests.append(deepcopy(data))
            if self.create_error is not None:
                raise self.create_error
            order = {"id": "550e8400-e29b-41d4-a716-446655440099", "order_number": "ORD-1", "status": "awaiting_payment"}
            return {"success": True, "order": order}
        raise AssertionError(f"Unexpected endpoint {path}")

    def test_the_page_links_and_carries_the_release_and_asks_for_an_early_start_when_platform_does(self) -> None:
        page = self.client.get(reverse("orders:checkout"))
        self.assertContains(page, f'name="terms_document_id" value="{TERMS_ID}"')
        self.assertContains(page, f'href="/legal/{TERMS_ID}/"')
        self.assertContains(page, 'name="early_start_requested"')

        self.early_start_required = False
        self.assertNotContains(self.client.get(reverse("orders:checkout")), 'name="early_start_requested"')

    def test_the_order_sends_the_release_and_the_early_start_request(self) -> None:
        self.form.update(terms_document_id=TERMS_ID, early_start_requested="on")
        self.client.post(reverse("orders:create_order"), self.form)
        [sent] = self.create_requests
        self.assertEqual((sent["terms_document_id"], sent["early_start_requested"]), (TERMS_ID, True))

    def test_a_refused_consent_is_explained_and_never_replayed(self) -> None:
        self.create_error = PlatformAPIError("changed", status_code=409, response_data={"code": "terms_changed"})
        self.form.update(terms_document_id=TERMS_ID)
        response = self.client.post(reverse("orders:create_order"), self.form, follow=True)
        self.assertContains(response, "The Terms of Service have changed")
        cart = GDPRCompliantCartSession(self.client.session)
        self.assertIsNone(OrderCreationService.pending_attempt(cart, "42", "7"))
