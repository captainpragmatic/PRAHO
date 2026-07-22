"""Platform CSP script-src contract.

History: the comprehensive security audit (H11) removed 'unsafe-eval', which
silently broke ALL Alpine.js interactivity (standard Alpine compiles directive
expressions via new Function()) and htmx hx-on:: handlers — the only symptom
was a console CSP error. 'unsafe-eval' is restored deliberately until the
CSP-hardening migration (#206 / #284) replaces both framework usages; only
then may this contract flip back.
"""
from django.http import HttpRequest, HttpResponse
from django.test import SimpleTestCase

from apps.common.middleware import SecurityHeadersMiddleware


def _served_csp() -> str:
    mw = SecurityHeadersMiddleware(lambda r: HttpResponse("ok"))
    request = HttpRequest()
    request.method = "GET"
    request.path = "/"
    response = mw(request)
    return response.get("Content-Security-Policy", "")


class CSPScriptSrcContractTests(SimpleTestCase):
    """script-src must keep Alpine/htmx working until #206/#284 land."""

    def test_csp_contains_unsafe_eval_for_alpine_and_htmx(self) -> None:
        """Regression: dropping 'unsafe-eval' kills every Alpine directive and
        hx-on:: handler in the admin UI (deploy form, modals, dropdowns)."""
        self.assertIn("'unsafe-eval'", _served_csp())

    def test_csp_contains_unsafe_inline_until_nonce_migration(self) -> None:
        """Inline event handlers (onclick=...) cannot carry nonces; removal is
        gated on the #206 migration."""
        self.assertIn("'unsafe-inline'", _served_csp())

    def test_csp_still_contains_self(self) -> None:
        """Sanity check: CSP should still have 'self' directive."""
        self.assertIn("'self'", _served_csp())

    def test_csp_keeps_hardened_directives(self) -> None:
        """Restoring eval must not regress the directives that stay strict."""
        csp = _served_csp()
        self.assertIn("object-src 'none'", csp)
        self.assertNotIn("unpkg.com", csp)
        self.assertNotIn("cdn.tailwindcss.com", csp)
