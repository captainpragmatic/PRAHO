"""What a visitor came to buy survives registration, and orders say where the visit came from.

A link from the operator's site names the product, period and domain; the registration carries
them to Platform with the visit's first UTM tags and referring site. Confirming the emailed link,
on whichever device, leads through sign-in to that product with the period and domain chosen.
Every order carries the attribution. A link may also name the page's language (?lang=).
"""

from __future__ import annotations

import time
from copy import deepcopy
from typing import Any
from unittest.mock import Mock, patch
from urllib.parse import parse_qs, urlsplit

from django.contrib.sessions.backends.cache import SessionStore
from django.core.cache import cache
from django.test import SimpleTestCase, TestCase, override_settings

from apps.orders.services import GDPRCompliantCartSession, OrderCreationService
from apps.users.constants import ATTRIBUTION_SESSION_KEY, REGISTRATION_INTENT_SESSION_KEY
from tests.orders.test_selling_currency import product
from tests.users.test_registration_confirm import DETAILS, LINK, PAGE, form

LOCAL_SESSIONS = {
    "SESSION_ENGINE": "django.contrib.sessions.backends.cache",
    "CACHES": {"default": {"BACKEND": "django.core.cache.backends.locmem.LocMemCache"}},
    "RATE_LIMITING_ENABLED": False,
}
INTENT = {"product": "web-hosting", "period": "annual", "domain": "example.ro", "utm_source": "newsletter"}


@override_settings(**LOCAL_SESSIONS)
class RegistrationIntentHandoffTests(TestCase):
    def setUp(self) -> None:
        cache.clear()

    def test_confirm_redirects_to_login_with_resume_next(self) -> None:
        details = deepcopy(DETAILS)
        details["registration"]["intent"] = INTENT
        with patch("apps.users.views.api_client") as api:
            api.get_pending_registration.return_value = details
            api.confirm_registration.return_value = {"success": True}
            self.client.get(LINK)
            self.client.get(PAGE)
            response = self.client.post(PAGE, form())

        self.assertEqual(response.status_code, 302)
        location = urlsplit(response["Location"])
        self.assertEqual(location.path, "/login/")
        resume = urlsplit(parse_qs(location.query)["next"][0])
        self.assertEqual(resume.path, "/order/products/web-hosting/")
        self.assertEqual(parse_qs(resume.query), {"period": ["annual"], "domain": ["example.ro"]})
        # The confirming device may never have seen the visit: it takes the registration's attribution.
        self.assertEqual(self.client.session[ATTRIBUTION_SESSION_KEY], {"utm_source": "newsletter"})

    def test_a_registration_without_an_intent_signs_in_to_the_dashboard(self) -> None:
        with patch("apps.users.views.api_client") as api:
            api.get_pending_registration.return_value = DETAILS
            api.confirm_registration.return_value = {"success": True}
            self.client.get(LINK)
            self.client.get(PAGE)
            response = self.client.post(PAGE, form())
        self.assertEqual(response["Location"], "/login/")

    def test_the_link_from_the_site_and_the_first_touch_go_with_the_registration(self) -> None:
        self.client.get(
            "/register/?product=web-hosting&period=annual&domain=Example.ro&utm_source=newsletter&is_staff=1",
            HTTP_REFERER="https://blog.example.com/post?id=7",
        )
        # A later page with other tags is not the first touch.
        self.client.get("/login/?utm_source=retargeting")
        self.assertEqual(
            self.client.session[REGISTRATION_INTENT_SESSION_KEY],
            {"product": "web-hosting", "period": "annual", "domain": "example.ro"},
        )
        self.assertEqual(
            self.client.session[ATTRIBUTION_SESSION_KEY],
            {"utm_source": "newsletter", "referrer": "https://blog.example.com"},
        )

        with patch("apps.users.forms.api_client._make_request", return_value={"success": True}) as request:
            self.client.post("/register/", registration_form())
        sent = request.call_args.kwargs["data"]["intent"]
        self.assertEqual(
            sent,
            {
                "product": "web-hosting",
                "period": "annual",
                "domain": "example.ro",
                "utm_source": "newsletter",
                "referrer": "https://blog.example.com",
            },
        )

    def test_a_plain_visit_writes_no_session(self) -> None:
        self.client.get("/login/")
        self.assertNotIn(ATTRIBUTION_SESSION_KEY, self.client.session)
        self.assertNotIn(REGISTRATION_INTENT_SESSION_KEY, self.client.session)

    def test_a_link_names_the_language_of_public_pages(self) -> None:
        page = self.client.get("/login/?lang=ro").content.decode()
        self.assertIn('lang="ro"', page)
        self.assertEqual(self.client.session["_language"], "ro")
        self.assertIn('lang="ro"', self.client.get("/register/").content.decode(), "it lasts the visit")


@override_settings(**LOCAL_SESSIONS)
class ProductPreselectionTests(TestCase):
    def test_the_product_page_preselects_the_period_and_domain(self) -> None:
        session = self.client.session
        session.update(
            {
                "customer_id": 42,
                "user_id": 7,
                "user_memberships": [{"customer_id": 42, "role": "owner"}],
                "user_memberships_fetched_at": time.time(),
            }
        )
        session.save()
        hosting = product("RON", 1)
        hosting["requires_domain"] = True
        hosting["prices"][0]["annual_price"] = "100.00"
        api = Mock()
        api.get.return_value = hosting
        with patch("apps.orders.views.PlatformAPIClient", return_value=api), patch(
            "apps.orders.services.PlatformAPIClient", return_value=api
        ):
            page = self.client.get("/order/products/basic-hosting/?period=annual&domain=Example.ro")
        html = page.content.decode()
        self.assertEqual(page.status_code, 200, html[:300])
        self.assertRegex(html, r'<option value="annual"\s+selected')
        self.assertIn('value="example.ro"', html)


@override_settings(**LOCAL_SESSIONS)
class DraftOrderAttributionTests(SimpleTestCase):
    def test_the_order_carries_the_attribution(self) -> None:
        api = Mock()
        api.get.return_value = product("RON", 1)
        session = SessionStore()
        session.create()
        with patch("apps.orders.services.PlatformAPIClient", return_value=api):
            cart = GDPRCompliantCartSession(session)
            cart.add_item("basic-hosting", 1, "monthly")
            api.post.return_value = {"order": {"id": "existing", "currency_code": "RON"}}
            OrderCreationService.create_draft_order(cart, "42", "7", attribution={"utm_source": "newsletter"})
        sent: dict[str, Any] = api.post.call_args.args[1]
        self.assertEqual(sent["attribution"], {"utm_source": "newsletter"})


def registration_form() -> dict[str, str]:
    return {
        "email": "visitor@example.com",
        "first_name": "Ana",
        "last_name": "Pop",
        "customer_type": "srl",
        "company_name": "Ana SRL",
        "cui": "14399840",
        "address_line1": "Str. Test 1",
        "city": "Bucuresti",
        "county": "Bucuresti",
        "postal_code": "010001",
        "country": "România",
        "terms_accepted": "on",
    }
