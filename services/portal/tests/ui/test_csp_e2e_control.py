"""Production-safety tests for the CSP E2E positive-control endpoint.

These assert the positive control is unreachable in production. The portal's
unauthenticated-redirect middleware would turn a client GET into a 302 before URL
resolution, masking the property under test — so these exercise the resolver and
the view directly instead:

  * the route is absent from the normal URLconf (config.urls);
  * it exists only in the E2E URLconf (config.e2e_urls); and
  * the view itself fails closed with Http404 when E2E_TEST_ROUTES_ENABLED is off.
"""

from __future__ import annotations

from django.http import Http404
from django.template.loader import render_to_string
from django.test import RequestFactory, SimpleTestCase, override_settings
from django.urls import Resolver404, resolve

from apps.common.e2e_views import csp_violation_positive_control
from apps.users.middleware import PortalAuthenticationMiddleware

CONTROL_PATH = "/__e2e__/csp-violation/"
CONTROL_TEMPLATE = "e2e/csp_violation_positive_control.html"


class CSPE2EPositiveControlSafetyTests(SimpleTestCase):
    def setUp(self) -> None:
        self.factory = RequestFactory()

    def test_control_route_is_absent_from_standard_urlconf(self) -> None:
        with self.assertRaises(Resolver404):
            resolve(CONTROL_PATH, urlconf="config.urls")

    def test_control_route_is_present_only_in_e2e_urlconf(self) -> None:
        match = resolve(CONTROL_PATH, urlconf="config.e2e_urls")
        self.assertEqual(match.view_name, "e2e_csp_violation_positive_control")

    @override_settings(E2E_TEST_ROUTES_ENABLED=False)
    def test_control_view_fails_closed_when_flag_is_disabled(self) -> None:
        request = self.factory.get(CONTROL_PATH)
        with self.assertRaises(Http404):
            csp_violation_positive_control(request)

    @override_settings(PORTAL_EXTRA_PUBLIC_URLS=[])
    def test_e2e_path_requires_auth_without_the_whitelist(self) -> None:
        # Production default: the path is NOT public, so the auth middleware
        # would redirect — its unreachability is defence-in-depth beyond the flag.
        middleware = PortalAuthenticationMiddleware(lambda _request: None)
        self.assertFalse(middleware.is_public_url(CONTROL_PATH))

    @override_settings(PORTAL_EXTRA_PUBLIC_URLS=["/__e2e__/"])
    def test_e2e_path_is_public_only_when_whitelisted(self) -> None:
        # E2E runtime: the browser oracle must reach the page without a login.
        middleware = PortalAuthenticationMiddleware(lambda _request: None)
        self.assertTrue(middleware.is_public_url(CONTROL_PATH))

    def test_positive_control_template_contains_deliberate_inline_handler(
        self,
    ) -> None:
        # render_to_string with no request avoids the portal context processors
        # (which need request.session) and DB access — the full view→render path
        # is exercised against the running portal by the browser gate.
        html = render_to_string(CONTROL_TEMPLATE)
        self.assertIn(
            'onclick="window.__cspPositiveControlExecuted = true"',
            html,
        )
