"""The HMAC exemption must follow the @public_api_endpoint marker, not a parallel list.

The middleware used to consult a hand-kept frozenset of literal paths that had drifted
from the marker decorator. Six of the eight marked views were absent from it and
answered 401 to every caller, including /api/users/token/, the endpoint whose entire
purpose is to be reachable before you hold a token.

The marker must sit OUTERMOST in each decorator stack: DRF's ``api_view`` returns the
callable from ``as_view()`` and does not copy ``__dict__``, so a marker applied beneath
it never reaches ``resolve().func``. ``test_marker_is_outermost_on_every_public_view``
is what stops someone reinstating the old order and silently re-breaking all eight.
"""

from __future__ import annotations

import json

from django.conf import settings
from django.test import RequestFactory, TestCase, override_settings
from django.urls import URLPattern, URLResolver, get_resolver

from apps.common.middleware import _is_auth_exempt

PUBLIC_PATHS = [
    "/api/users/health/",
    "/api/users/token/",
    "/api/orders/products/",
    "/api/orders/products/some-product-slug/",
    "/api/billing/currencies/",
    "/api/customers/register/",
    "/api/services/plans/",
    "/api/tickets/categories/",
    "/api/users/token/me/",
    "/api/users/token/revoke/",
]

HMAC_REJECTION = {"error": "HMAC authentication failed"}


# Every view intended to answer without HMAC. Adding a name here removes authentication
# from an endpoint, so it is a deliberate, reviewable act rather than a count that drifts.
# Routes, not function names: DRF's api_view returns the callable from as_view(), which
# is named "view" for every one of them, so __name__ cannot tell them apart.
EXPECTED_PUBLIC_ROUTES = {
    "api/billing/currencies/",
    "api/customers/register/",
    "api/orders/products/",
    "api/orders/products/<slug:slug>/",
    "api/services/plans/",
    "api/tickets/categories/",
    "api/users/health/",
    "api/users/token/",
    # A bare token's own lifecycle, nothing else (#569, ADR-0031).
    "api/users/token/me/",
    "api/users/token/revoke/",
}


class PublicEndpointExemptionTests(TestCase):
    def setUp(self) -> None:
        self.factory = RequestFactory()

    def test_every_public_path_is_exempt(self) -> None:
        for path in PUBLIC_PATHS:
            with self.subTest(path=path):
                self.assertTrue(
                    _is_auth_exempt(self.factory.get(path)),
                    f"{path} carries @public_api_endpoint but the middleware would still reject it",
                )

    def test_parameterised_route_is_exempt_for_any_slug(self) -> None:
        """Exact string matching structurally could not express this one."""
        for slug in ("a", "hosting-pro", "a-much-longer-product-slug-99"):
            with self.subTest(slug=slug):
                self.assertTrue(_is_auth_exempt(self.factory.get(f"/api/orders/products/{slug}/")))

    def test_protected_api_paths_are_not_exempt(self) -> None:
        for path in ("/api/users/login/", "/api/users/profile/", "/api/customers/tax-profile/"):
            with self.subTest(path=path):
                self.assertFalse(
                    _is_auth_exempt(self.factory.get(path)),
                    f"{path} must still require a signature",
                )

    def test_unresolvable_path_fails_closed(self) -> None:
        """A 404 probe must not become an authentication bypass."""
        self.assertFalse(_is_auth_exempt(self.factory.get("/api/this/does/not/exist/at/all/")))

    def test_marker_is_outermost_on_every_public_view(self) -> None:
        """Guards the decorator ordering the middleware depends on.

        If someone moves @public_api_endpoint back under @api_view, the attribute stops
        reaching resolve().func and all eight endpoints silently 401 again.
        """

        def walk(patterns: list, prefix: str = "") -> list[tuple[str, object]]:
            found: list[tuple[str, object]] = []
            for pattern in patterns:
                if isinstance(pattern, URLResolver):
                    found.extend(walk(pattern.url_patterns, prefix + str(pattern.pattern)))
                elif isinstance(pattern, URLPattern):
                    found.append((prefix + str(pattern.pattern), pattern.callback))
            return found

        marked = {
            url for url, cb in walk(get_resolver().url_patterns) if getattr(cb, "_is_public_api_endpoint", False)
        }
        # Compared as a SET, not a count. Counting passes when the marker moves off one
        # view and onto another, which is the exact leak this test exists to catch: the
        # total stays at eight while a staff view has quietly become world-reachable.
        self.assertEqual(
            marked,
            EXPECTED_PUBLIC_ROUTES,
            "the set of views exposing the public marker changed; each addition removes HMAC from an endpoint",
        )


@override_settings(MIDDLEWARE=[*settings.MIDDLEWARE, "apps.common.middleware.PortalServiceHMACMiddleware"])
class PublicEndpointExemptionIntegrationTests(TestCase):
    """End to end through the real middleware.

    config/settings/test.py strips PortalServiceHMACMiddleware from MIDDLEWARE, so the
    default suite never exercises it. It is added back here deliberately: an exemption
    rule that is only unit-tested is an exemption rule nobody has watched run.
    """

    def test_unsigned_request_to_a_public_endpoint_is_not_rejected_by_hmac(self) -> None:
        """Asserted against the middleware's own rejection body, not 'not 401'.

        obtain_token legitimately answers 401 for bad credentials, so a status-only
        assertion would pass while the endpoint stayed completely unreachable.
        """
        response = self.client.get("/api/tickets/categories/")

        # A positive assertion. "not the HMAC rejection" alone is satisfied by a
        # redirect, an HTML error page or a 404, so it would pass even if the route
        # stopped existing.
        self.assertEqual(response.status_code, 200, response.content[:200])
        self.assertEqual(response["Content-Type"].split(";")[0], "application/json")
        body = response.content.decode()
        self.assertNotEqual(json.loads(body), HMAC_REJECTION, "a view marked public was rejected by HMAC")

    def test_unsigned_request_to_a_protected_endpoint_is_still_rejected(self) -> None:
        """GET, so CSRF cannot reject it before the HMAC middleware is reached."""
        response = self.client.get("/api/users/profile/")

        self.assertEqual(response.status_code, 401)
        self.assertEqual(json.loads(response.content.decode()), HMAC_REJECTION)
