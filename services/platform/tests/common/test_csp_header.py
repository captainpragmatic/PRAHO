"""H11: CSP header must not contain unsafe-eval."""
from django.http import HttpRequest, HttpResponse
from django.test import SimpleTestCase

from apps.common.middleware import SecurityHeadersMiddleware


class CSPNoUnsafeEvalTests(SimpleTestCase):
    """H11: Content-Security-Policy must not include 'unsafe-eval'."""

    def test_csp_does_not_contain_unsafe_eval(self) -> None:
        mw = SecurityHeadersMiddleware(lambda r: HttpResponse("ok"))
        request = HttpRequest()
        request.method = "GET"
        request.path = "/"
        response = mw(request)
        csp = response.get("Content-Security-Policy", "")
        self.assertNotIn("unsafe-eval", csp)

    def test_csp_still_contains_self(self) -> None:
        """Sanity check: CSP should still have 'self' directive."""
        mw = SecurityHeadersMiddleware(lambda r: HttpResponse("ok"))
        request = HttpRequest()
        request.method = "GET"
        request.path = "/"
        response = mw(request)
        csp = response.get("Content-Security-Policy", "")
        self.assertIn("'self'", csp)
