"""The domain storefront keeps names distinct and sends secrets only to the signed APIs."""
from __future__ import annotations

import json
import time
import uuid
from unittest.mock import Mock, patch

from django.contrib.messages import get_messages
from django.core.cache import cache
from django.core.exceptions import ValidationError
from django.http import HttpResponse
from django.test import SimpleTestCase, override_settings
from django.urls import reverse
from django.views.debug import SafeExceptionReporterFilter

from apps.api_client.services import PlatformAPIError, api_client
from apps.common.localisation import LocalisationDefaults
from apps.orders.services import GDPRCompliantCartSession

PRODUCT = {"id": str(uuid.uuid4()), "slug": "domain", "name": "Domain", "description": "", "short_description": "", "product_type": "domain", "requires_domain": True, "is_active": True, "prices": [], "selling_currency": "RON", "currency_revision": 1}
TERMS = {"document_id": str(uuid.uuid4()), "kind": "terms", "release": "2026-10-15.1", "language": "en"}
ORDER_ID = uuid.UUID("550e8400-e29b-41d4-a716-446655440099")
LINE_ID = uuid.UUID("550e8400-e29b-41d4-a716-446655440098")
CNP = "1850101123451"
CODE = "Transfer-Secret!123"


@override_settings(SESSION_ENGINE="django.contrib.sessions.backends.cache", CACHES={"default": {"BACKEND": "django.core.cache.backends.locmem.LocMemCache"}}, MIDDLEWARE=["django.contrib.sessions.middleware.SessionMiddleware", "django.contrib.messages.middleware.MessageMiddleware"])
class DomainStorefrontTests(SimpleTestCase):
    def setUp(self) -> None:
        cache.clear()
        self.addCleanup(cache.clear)
        self.api = Mock()
        self.api.get.return_value = PRODUCT
        self.api.post.return_value = {"success": True}
        self.enterContext(patch("apps.orders.services.PlatformAPIClient", return_value=self.api))
        self.enterContext(patch("apps.orders.views.PlatformAPIClient", return_value=self.api))
        self.enterContext(patch.object(api_client, "get_localisation_defaults", return_value={"success": True, "localisation": LocalisationDefaults().customer_payload(), "company": {"brand_name": "PRAHO"}}))
        self.enterContext(patch("apps.orders.security.OrderSecurityHardening.uniform_response_delay"))
        self.session = self.client.session
        self.session.update({"customer_id": 42, "user_id": 7, "user_memberships": [{"customer_id": 42, "role": "owner"}], "user_memberships_fetched_at": time.time()})
        self.session.save()

    def response_evidence(self, response: HttpResponse) -> str:
        # Notices are cookie-backed and would be displayed on the redirect target.
        notices = " ".join(str(message) for message in get_messages(response.wsgi_request))
        return response.content.decode() + json.dumps(dict(self.client.session)) + notices + str(response.headers)

    def cart(self) -> GDPRCompliantCartSession:
        return GDPRCompliantCartSession(self.client.session)

    def seed_cart(self) -> None:
        session = self.client.session
        cart = GDPRCompliantCartSession(session)
        cart.add_item("domain", 1, "annual", "first.ro", {"domain_mode": "register"})
        cart.add_item("domain", 1, "annual", "second.ro", {"domain_mode": "transfer"})
        session.save()

    def test_domain_names_have_distinct_cart_identity_and_only_the_named_line_is_removed(self) -> None:
        self.seed_cart()
        items = self.cart().get_items()
        self.assertEqual(len(items), 2)
        self.assertNotEqual(items[0]["item_id"], items[1]["item_id"])
        self.assertEqual(items[1]["config"], {"domain_mode": "transfer"})
        response = self.client.post(reverse("orders:remove_from_cart"), {"product_slug": "domain", "billing_period": "annual", "domain_name": "first.ro"})
        self.assertEqual(response.status_code, 200, response.content)
        self.assertEqual([item["domain_name"] for item in self.cart().get_items()], ["second.ro"])

    def test_domain_mode_is_validated_and_quantity_is_one(self) -> None:
        cart = self.cart()
        for config, quantity in (({"domain_mode": "renew"}, 1), ({"domain_mode": "transfer"}, 2)):
            with self.assertRaises(ValidationError):
                cart.add_item("domain", quantity, "annual", "invalid.ro", config)
        self.assertFalse(cart.has_items())

    def test_domain_product_needs_no_catalog_price_and_has_the_lookup_and_mode_controls(self) -> None:
        response = self.client.get(reverse("orders:product_detail", args=["domain"]))
        self.assertEqual(response.status_code, 200, response.content)
        self.assertContains(response, 'name="domain_mode"')
        self.assertContains(response, 'value="register"')
        self.assertContains(response, 'value="transfer"')
        self.assertContains(response, reverse("orders:domain_availability"))
        self.assertContains(response, 'name="domain_name"')
        self.assertNotContains(response, 'name="billing_period" class=')

    def test_lookup_forwards_the_signed_ip_customer_and_mode_and_escapes_the_answer(self) -> None:
        self.api.post.return_value = {"success": True, "orderable": True, "available": True, "domain_name": "checkout.ro", "register_price_cents": 1000, "transfer_price_cents": 800, "currency": "RON", "requires": ["cnp"]}
        response = self.client.post(reverse("orders:domain_availability"), {"domain_name": "checkout.ro", "domain_mode": "register"}, REMOTE_ADDR="192.0.2.44")
        self.assertEqual(response.status_code, 200, response.content)
        self.assertContains(response, "checkout.ro")
        self.api.post.assert_called_once_with("orders/domains/availability/", {"domain_name": "checkout.ro", "domain_mode": "register", "client_ip": "192.0.2.44", "customer_id": "42"}, user_id=7)

    def test_checkout_maps_totals_by_domain_and_shows_cnp_only_when_platform_requires_it(self) -> None:
        self.seed_cart()
        calculation = {"items": [{"product_slug": "domain", "billing_period": "once", "domain_name": "first.ro", "line_total_cents": 1210}, {"product_slug": "domain", "billing_period": "once", "domain_name": "second.ro", "line_total_cents": 2420}], "currency": "RON", "selling_currency": "RON", "currency_revision": 1, "subtotal_cents": 3000, "tax_cents": 630, "total_cents": 3630, "warnings": []}
        preflight = {"success": False, "errors": ["Complete the registrant identity fields required by this domain registrar."], "warnings": [], "checkout": {"terms_document": TERMS, "early_start_required": True, "registrant_requires": ["cnp"]}}
        self.api.post.side_effect = lambda path, *args, **kwargs: calculation if path == "orders/calculate/" else preflight
        response = self.client.get(reverse("orders:checkout"))
        self.assertEqual(response.status_code, 200, response.content)
        self.assertContains(response, 'name="cnp"')
        self.assertContains(response, "proformas, invoices and e-Factura")
        self.assertEqual([item["line_total_cents"] for item in response.context["cart_items"]], [1210, 2420])
        preflight["checkout"]["registrant_requires"] = []
        response = self.client.get(reverse("orders:checkout"))
        self.assertNotContains(response, 'name="cnp"')

    def test_cnp_and_transfer_forms_forward_once_without_secrets_in_response_session_or_logs(self) -> None:
        for path, field, value, endpoint in ((reverse("orders:registrant_identity"), "cnp", CNP, "customers/tax-profile/"), (reverse("orders:transfer_code", args=[ORDER_ID, LINE_ID]), "transfer_code", CODE, f"orders/{ORDER_ID}/items/{LINE_ID}/transfer-code/")):
            self.api.post.reset_mock()
            with self.assertLogs("apps", level="DEBUG") as logs:
                response = self.client.post(path, {field: value})
            self.assertEqual(response.status_code, 302)
            self.api.post.assert_called_once_with(endpoint, {"customer_id": "42", field: value}, user_id=7)
            evidence = self.response_evidence(response) + "\n".join(logs.output)
            self.assertNotIn(value, evidence)
            self.api.post.side_effect = PlatformAPIError(f"Rejected secret {value}", status_code=400)
            with self.assertLogs("apps", level="DEBUG") as error_logs:
                response = self.client.post(path, {field: value})
            self.assertNotIn(value, self.response_evidence(response) + "\n".join(error_logs.output))
            self.api.post.side_effect = None
        session = self.client.session
        session["user_memberships"] = [{"customer_id": 42, "role": "tech"}]
        session.save()
        self.api.post.reset_mock()
        response = self.client.post(reverse("orders:registrant_identity"), {"cnp": CNP})
        self.assertEqual(response.status_code, 403)
        self.api.post.assert_not_called()

    def test_order_page_offers_the_transfer_code_only_for_a_line_that_accepts_it(self) -> None:
        self.api.post.return_value = {"id": str(ORDER_ID), "order_number": "ORD-1", "status": "provisioning", "items": [{"id": str(LINE_ID), "domain_name": "transfer.ro", "product_name": "Domain", "can_submit_transfer_code": True}]}
        response = self.client.get(reverse("orders:confirmation", args=[ORDER_ID]))
        self.assertEqual(response.status_code, 200, response.content)
        self.assertContains(response, 'name="transfer_code"')
        self.assertContains(response, reverse("orders:transfer_code", args=[ORDER_ID, LINE_ID]))
        self.assertNotContains(response, 'value="Transfer-Secret')
        self.api.post.return_value["items"][0]["can_submit_transfer_code"] = False
        response = self.client.get(reverse("orders:confirmation", args=[ORDER_ID]))
        self.assertNotContains(response, 'name="transfer_code"')

    def test_catalog_keeps_the_domain_product_without_a_product_price(self) -> None:
        self.api.get.return_value = {"results": [PRODUCT], "selling_currency": "RON", "currency_revision": 1}
        response = self.client.get(reverse("orders:catalog"))
        self.assertEqual(response.status_code, 200, response.content)
        self.assertContains(response, reverse("orders:product_detail", args=["domain"]))
        self.assertContains(response, "Check domain prices")

    @override_settings(DEBUG=False)
    def test_secret_post_data_is_masked_in_django_error_reports(self) -> None:
        for path, field, value in ((reverse("orders:registrant_identity"), "cnp", CNP), (reverse("orders:transfer_code", args=[ORDER_ID, LINE_ID]), "transfer_code", CODE)):
            response = self.client.post(path, {field: value})
            self.assertEqual(response.status_code, 302)
            filtered = SafeExceptionReporterFilter().get_post_parameters(response.wsgi_request)
            self.assertNotIn(value, str(filtered))
            self.assertNotEqual(filtered[field], value)
