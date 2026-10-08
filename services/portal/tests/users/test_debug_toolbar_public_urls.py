"""Debug Toolbar authentication follows the current runtime settings."""

from django.conf import settings
from django.contrib.sessions.backends.signed_cookies import SessionStore
from django.http import HttpResponse, JsonResponse
from django.test import RequestFactory, SimpleTestCase, override_settings

from apps.users.middleware import PortalAuthenticationMiddleware


class DebugToolbarPublicURLTests(SimpleTestCase):
    def setUp(self) -> None:
        self.factory = RequestFactory()
        self.middleware = PortalAuthenticationMiddleware(lambda request: JsonResponse({"panel": "available"}))
        self.apps_without_toolbar = [app for app in settings.INSTALLED_APPS if app != "debug_toolbar"]
        self.apps_with_toolbar = [*self.apps_without_toolbar, "debug_toolbar"]

    def _response(self, path: str) -> HttpResponse:
        request = self.factory.get(path)
        request.session = SessionStore()
        return self.middleware(request)

    def _assert_public(self) -> None:
        for path in ("/__debug__/", "/__debug__/render_panel/"):
            with self.subTest(path=path):
                response = self._response(path)
                self.assertEqual(response.status_code, 200)
                self.assertEqual(response.content, b'{"panel": "available"}')
                self.assertNotIn("Location", response)
        self.assertFalse(self.middleware.is_public_url("/__debug__private/"))
        self.assertFalse(self.middleware.is_public_url("/dashboard/"))

    def _assert_private(self) -> None:
        for path in ("/__debug__/", "/__debug__/render_panel/"):
            with self.subTest(path=path):
                self.assertFalse(self.middleware.is_public_url(path))
                response = self._response(path)
                self.assertEqual(response.status_code, 302)
                self.assertTrue(response["Location"].startswith("/login/?next="))
                self.assertNotIn(b'"panel": "available"', response.content)
        self.assertTrue(self.middleware.is_public_url("/login/"))

    def test_debug_toolbar_access_changes_with_debug_on_the_same_middleware(self) -> None:
        with override_settings(INSTALLED_APPS=self.apps_with_toolbar, PORTAL_EXTRA_PUBLIC_URLS=()):
            for debug in (False, True, False):
                with self.subTest(debug=debug), override_settings(DEBUG=debug):
                    if debug:
                        self._assert_public()
                    else:
                        self._assert_private()

    def test_debug_toolbar_access_changes_with_installation_on_the_same_middleware(self) -> None:
        with override_settings(DEBUG=True, PORTAL_EXTRA_PUBLIC_URLS=()):
            for installed in (False, True, False):
                apps = self.apps_with_toolbar if installed else self.apps_without_toolbar
                with self.subTest(installed=installed), override_settings(INSTALLED_APPS=apps):
                    if installed:
                        self._assert_public()
                    else:
                        self._assert_private()
