"""The portal publishes the Terms of Service a customer accepts.

Checkout and (soon) registration ask customers to accept the terms, but the portal had no
terms page: checkout linked to /terms/, which answered 404 and, being outside the public
paths, sent anonymous visitors to the login page. The text is shared with Platform's page
(shared/ui/templates/legal/terms_of_service_content.html), and the version shown is the one
Platform records.
"""

from unittest.mock import patch

from django.core.cache import cache
from django.test import Client, SimpleTestCase, override_settings
from django.urls import reverse
from django.utils import translation

from apps.api_client.services import api_client
from apps.common.legal import TERMS_OF_SERVICE_VERSION
from apps.common.localisation import LocalisationDefaults

IDENTITY = {
    "legal_name": "Terms Test SRL",
    "email_support": "help@terms.example.test",
    "email_privacy": "privacy@terms.example.test",
    "email_finance": "",
    "phone": "+40721000000",
}


@override_settings(
    SESSION_ENGINE="django.contrib.sessions.backends.cache",
    CACHES={"default": {"BACKEND": "django.core.cache.backends.locmem.LocMemCache"}},
)
class TermsPageTests(SimpleTestCase):
    def setUp(self) -> None:
        cache.clear()
        self.addCleanup(cache.clear)
        payload = {"success": True, "localisation": LocalisationDefaults().customer_payload(), "company": IDENTITY}
        identity = patch.object(api_client, "get_localisation_defaults", return_value=payload)
        identity.start()
        self.addCleanup(identity.stop)

    def test_anonymous_visitors_can_read_the_terms(self) -> None:
        response = Client().get("/terms/")
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'id="acceptance"')
        self.assertContains(response, 'id="governing-law"')

    def test_the_page_states_the_version_platform_records(self) -> None:
        response = Client().get(reverse("terms_of_service"))
        self.assertContains(response, TERMS_OF_SERVICE_VERSION)

    def test_the_company_is_named_and_unknown_details_are_left_out(self) -> None:
        html = Client().get("/terms/").content.decode()
        self.assertIn("between you and Terms Test SRL.", " ".join(html.split()))
        self.assertIn("help@terms.example.test", html)
        self.assertIn("+40721000000", html)
        # The portal has no address or registration number for the company: no empty rows.
        self.assertNotIn("Registration Number", html)
        self.assertNotIn("Address", html)

    def test_the_footer_links_to_the_terms(self) -> None:
        html = Client().get("/cookie-policy/").content.decode()
        self.assertIn(f'href="{reverse("terms_of_service")}"', html)

    def test_the_effective_date_is_the_version_date_in_any_timezone(self) -> None:
        payload = {
            "success": True,
            "localisation": {**LocalisationDefaults().customer_payload(), "timezone": "America/New_York"},
            "company": IDENTITY,
        }
        with patch.object(api_client, "get_localisation_defaults", return_value=payload):
            cache.clear()
            html = Client().get("/terms/").content.decode()
        self.assertIn("27.12.2024", html)
        self.assertNotIn("26.12.2024", html)

    def test_only_the_page_itself_is_public(self) -> None:
        # A later /terms/<something>/ route must not become public by sharing the prefix.
        response = Client().get("/terms/accept/")
        self.assertEqual(response.status_code, 302)
        self.assertTrue(response["Location"].startswith("/login/"))

    def test_the_terms_read_in_romanian(self) -> None:
        # The text moved into the shared catalog; the portal must find its translations there.
        # The request activates Romanian for the thread; override() puts the previous language back.
        with translation.override(None):
            response = Client(headers={"Accept-Language": "ro"}).get("/terms/")
        text = " ".join(response.content.decode().split())
        self.assertIn("un acord legal obligatoriu între dvs. și Terms Test SRL.", text)
        self.assertIn("Încetare", text)
