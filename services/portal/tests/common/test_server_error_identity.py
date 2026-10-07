"""The registered 500 handler retains support contact details during failures."""

from __future__ import annotations

from unittest.mock import patch

from django.conf import settings
from django.core.cache import cache
from django.http import HttpRequest, HttpResponse
from django.test import Client, RequestFactory, SimpleTestCase, override_settings
from django.urls import clear_url_caches, get_resolver, path

from apps.api_client.services import PlatformAPIError, api_client
from apps.common.localisation import LocalisationDefaults
from config import urls as portal_urls

COMPANY = {
    "legal_name": "Error Page SRL",
    "email_support": "error-support@example.test",
    "email_privacy": "privacy@example.test",
    "email_finance": "",
    "phone": "",
}


def crashing_view(request: HttpRequest) -> HttpResponse:
    raise RuntimeError("private exception details")


@override_settings(
    DEBUG=False,
    ROOT_URLCONF="config.urls",
    CACHES={"default": {"BACKEND": "django.core.cache.backends.locmem.LocMemCache"}},
)
class PortalServerErrorIdentityTests(SimpleTestCase):
    def setUp(self) -> None:
        cache.clear()
        clear_url_caches()
        self.addCleanup(cache.clear)
        self.addCleanup(clear_url_caches)

    def response_from_handler(self) -> HttpResponse:
        handler = get_resolver().resolve_error_handler(500)
        try:
            # No session or request context processors are available on this path.
            return handler(RequestFactory().get("/"))
        except Exception as exc:
            self.fail(f"handler500 raised {type(exc).__name__}: {exc}")

    def assert_support(self, response: HttpResponse, address: str) -> None:
        self.assertEqual(response.status_code, 500)
        self.assertContains(response, f'href="mailto:{address}"', status_code=500)
        self.assertContains(response, address, status_code=500)
        self.assertNotContains(response, 'href="mailto:"', status_code=500)
        self.assertNotContains(response, "private exception details", status_code=500)

    def test_registered_handler_reads_company_identity_without_context_processors(self) -> None:
        payload = {
            "success": True,
            "localisation": LocalisationDefaults().customer_payload(),
            "company": COMPANY,
        }
        with patch.object(api_client, "get_localisation_defaults", return_value=payload):
            self.assert_support(self.response_from_handler(), COMPANY["email_support"])

    @override_settings(MIDDLEWARE=[])
    def test_view_exception_uses_registered_handler_with_identity_and_outage_defaults(self) -> None:
        payload = {
            "success": True,
            "localisation": LocalisationDefaults().customer_payload(),
            "company": COMPANY,
        }
        cases = (
            (payload, None, COMPANY["email_support"]),
            (None, PlatformAPIError("offline"), settings.COMPANY_IDENTITY_DEFAULTS["email_support"]),
        )
        for payload_value, error, address in cases:
            with self.subTest(address=address):
                cache.clear()
                clear_url_caches()
                with (
                    patch.object(
                        portal_urls, "urlpatterns", [path("_server-error/", crashing_view), *portal_urls.urlpatterns]
                    ),
                    patch.object(
                        api_client, "get_localisation_defaults", return_value=payload_value, side_effect=error
                    ),
                ):
                    clear_url_caches()
                    # The portal conftest forces DEBUG=True per test; a real 500 page needs DEBUG off,
                    # applied inside the test (memory: portal DEBUG overrides go per method).
                    with override_settings(DEBUG=False):
                        response = Client(raise_request_exception=False).get("/_server-error/")
                self.assert_support(response, address)

    def test_reader_failure_keeps_catalog_support_address(self) -> None:
        with patch(
            "apps.common.localisation_services.get_company_identity", side_effect=RuntimeError("cache unavailable")
        ):
            response = self.response_from_handler()
        self.assert_support(response, settings.COMPANY_IDENTITY_DEFAULTS["email_support"])

    def test_template_failure_returns_a_safe_response_with_support_address(self) -> None:
        with (
            patch.object(api_client, "get_localisation_defaults", side_effect=PlatformAPIError("offline")),
            patch("django.template.loader.get_template", side_effect=RuntimeError("template unavailable")),
        ):
            response = self.response_from_handler()
        self.assert_support(response, settings.COMPANY_IDENTITY_DEFAULTS["email_support"])
        self.assertNotContains(response, "template unavailable", status_code=500)
