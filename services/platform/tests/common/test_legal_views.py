"""The legal pages are the portal's: Platform's legal addresses redirect there (ADR-0062)."""

from django.core.cache import cache
from django.test import TestCase, override_settings
from django.urls import reverse

from tests.helpers.portal import set_portal_origin

PORTAL = "https://portal.example.test"  # From the test settings' PORTAL_DOMAIN


class LegalRedirectTests(TestCase):
    def setUp(self) -> None:
        cache.clear()
        self.addCleanup(cache.clear)

    def test_each_legal_address_redirects_to_the_portal_page(self) -> None:
        for name, path in (
            ("terms_of_service", "/terms/"),
            ("privacy_policy", "/privacy-policy/"),
            ("cookie_policy", "/cookie-policy/"),
        ):
            with self.subTest(name):
                response = self.client.get(reverse(name))
                self.assertRedirects(response, PORTAL + path, fetch_redirect_response=False)

    @override_settings(PORTAL_DOMAIN="")
    def test_without_a_portal_origin_the_address_is_not_found(self) -> None:
        set_portal_origin("")
        self.assertEqual(self.client.get(reverse("terms_of_service")).status_code, 404)
