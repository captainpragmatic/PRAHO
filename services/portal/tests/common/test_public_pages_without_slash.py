"""The public legal pages are reachable from their slash-less addresses too.

PortalAuthenticationMiddleware answers before URL routing, and CommonMiddleware adds the trailing
slash only for a 404 response. A slash-less legal page therefore got the login redirect, and only a
signed-in visitor reached the page. The exact slash-less paths are public, so the request reaches
routing and CommonMiddleware redirects it to the page.
"""

from django.conf import settings
from django.core.cache import cache
from django.test import Client, SimpleTestCase, override_settings

# The debug toolbar is development-only; the production order of the remaining middleware is kept.
PRODUCTION_MIDDLEWARE = [m for m in settings.MIDDLEWARE if not m.startswith("debug_toolbar.")]


@override_settings(
    MIDDLEWARE=PRODUCTION_MIDDLEWARE,
    SESSION_ENGINE="django.contrib.sessions.backends.cache",
    CACHES={"default": {"BACKEND": "django.core.cache.backends.locmem.LocMemCache"}},
)
class PublicPagesWithoutSlashTests(SimpleTestCase):
    def setUp(self) -> None:
        cache.clear()
        self.addCleanup(cache.clear)

    def test_each_legal_page_redirects_to_its_slash_form(self) -> None:
        for path in ("/terms", "/privacy-policy", "/cookie-policy"):
            with self.subTest(path=path):
                response = Client().get(path)
                self.assertEqual(response.status_code, 301)
                self.assertEqual(response["Location"], f"{path}/")

    def test_the_query_string_survives_the_redirect(self) -> None:
        response = Client().get("/privacy-policy?lang=ro")
        self.assertEqual(response.status_code, 301)
        self.assertEqual(response["Location"], "/privacy-policy/?lang=ro")

    def test_a_longer_path_stays_private(self) -> None:
        for path in ("/privacy-policyX", "/termsX", "/terms/x"):
            with self.subTest(path=path):
                response = Client().get(path)
                self.assertEqual(response.status_code, 302)
                self.assertTrue(response["Location"].startswith("/login/?next="))
