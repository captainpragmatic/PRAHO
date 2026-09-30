"""A view that accepts an API token must also require the service-to-service signature.

The public token endpoint issues a key valid for `API_TOKEN_DEFAULT_TTL_DAYS` (90) after
checking only an email and password. Its sibling `portal_login_api` verifies a second
factor when the account has one enabled; this path does not. So a password obtained by
phishing or reuse yields a 90-day key even for an account with two-factor turned on.

That gap is currently harmless, and this test is what keeps it that way — but not for the
reason it first appears. Token authentication is a project DEFAULT, so most DRF views
accept a key; what makes a key unspendable from outside is that those views all sit
behind the HMAC gate. The moment a view accepts token authentication WITHOUT that gate,
the missing second factor turns into account takeover.

Six public endpoints were in exactly that position and are fixed alongside this test.
They inherited the default classes, so a caller could authenticate to them with any valid
key. Beyond the second-factor question that also silently removed their only rate limit,
because DRF's anonymous throttle returns no cache key for an authenticated request and
therefore does not limit it at all.

Nothing in the code says so, and the endpoint's own docstring cannot enforce it. This
test is the enforcement: it fails the build the day that precondition stops holding,
rather than leaving it to be remembered during review.

Deliberately a precondition guard, not a fix. Adding a second factor to a documented
public endpoint changes its contract and belongs in its own change.
"""

from __future__ import annotations

from django.test import TestCase
from django.urls import get_resolver
from django.urls.resolvers import URLPattern, URLResolver

from apps.api.users.authentication import HashedTokenAuthentication

# Token authentication is a PROJECT DEFAULT, not opt-in: settings list
# HashedTokenAuthentication in DEFAULT_AUTHENTICATION_CLASSES, so every DRF view that does
# not clear them accepts a key. Safety therefore rests entirely on the HMAC gate, and on
# public views clearing their authentication classes.
#
# Listed explicitly so adding a token-authenticated view that answers without the service
# signature is a conscious act with a reviewer attached, rather than something that slips
# in behind a passing suite.
EXPECTED_TOKEN_AUTHENTICATED_PUBLIC_ROUTES: set[str] = set()


def _walk(patterns: list, prefix: str = "") -> list[tuple[str, object]]:
    found: list[tuple[str, object]] = []
    for pattern in patterns:
        if isinstance(pattern, URLResolver):
            found.extend(_walk(pattern.url_patterns, prefix + str(pattern.pattern)))
        elif isinstance(pattern, URLPattern):
            found.append((prefix + str(pattern.pattern), pattern.callback))
    return found


def _accepts_api_token(callback: object) -> bool:
    """True when the resolved view would authenticate a caller by API token.

    `@api_view` builds an APIView subclass and hangs it on the returned callable as
    ``cls``, which is where the authentication classes actually live. Reading the
    function's own attributes would find nothing and this guard would pass vacuously.
    """
    view_class = getattr(callback, "cls", None)
    classes = getattr(view_class, "authentication_classes", None) or ()
    return any(issubclass(c, HashedTokenAuthentication) for c in classes if isinstance(c, type))


class TokenAuthenticatedViewsStayBehindHmacTests(TestCase):
    def test_the_detector_actually_finds_token_authenticated_views(self) -> None:
        """Guards the guard.

        Token auth is the default, so a healthy codebase has MANY such views. If this
        finds none, the walk or the attribute lookup has broken and every assertion below
        would pass while checking nothing at all.
        """
        routes = [url for url, cb in _walk(get_resolver().url_patterns) if _accepts_api_token(cb)]

        self.assertGreater(len(routes), 10, "the detector found almost nothing; it is broken")
        self.assertIn("api/users/token/revoke/", routes, "a known token-authenticated route went missing")

    def test_no_token_authenticated_view_is_publicly_reachable(self) -> None:
        """The precondition that makes the missing second factor harmless.

        A view marked `@public_api_endpoint` answers without the service signature. If one
        of those also accepted an API token, a key obtained with a password alone — no
        second factor — would be spendable from the open internet.
        """
        offenders = {
            url
            for url, cb in _walk(get_resolver().url_patterns)
            if _accepts_api_token(cb) and getattr(cb, "_is_public_api_endpoint", False)
        }

        self.assertEqual(
            offenders,
            EXPECTED_TOKEN_AUTHENTICATED_PUBLIC_ROUTES,
            "these public views accept an API token without requiring the service signature. "
            "A key issued with a password alone becomes usable from the open internet, and "
            "an authenticated request also drops the anonymous throttle that is their only "
            "remaining limit: " + ", ".join(sorted(offenders)),
        )
