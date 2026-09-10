"""Platform CSP script-src contract.

History: the comprehensive security audit (H11) removed 'unsafe-eval', which
silently broke ALL Alpine.js interactivity (standard Alpine compiles directive
expressions via new Function()) and htmx hx-on:: handlers. 'unsafe-eval' is
retained deliberately.

#284 landed the script 'unsafe-inline' removal: every inline on*= handler is a
delegated data-action (freeze guardrail at 0) and every fragment script is
relocated, so script-src now carries a per-request nonce + script-src-attr 'none'
and drops 'unsafe-inline'. The middleware falls back to 'unsafe-inline' only when
the request has no nonce (nonce middleware disabled) — a fail-safe, not the norm.
"""
from django.http import HttpRequest, HttpResponse
from django.test import SimpleTestCase

from apps.common.middleware import CSPNonceMiddleware, SecurityHeadersMiddleware


def _served_csp(nonce: str = "testnonce1234567890") -> str:
    mw = SecurityHeadersMiddleware(lambda r: HttpResponse("ok"))
    request = HttpRequest()
    request.method = "GET"
    request.path = "/"
    if nonce:
        # Mirror CSPNonceMiddleware, which runs before SecurityHeadersMiddleware in prod.
        request.csp_nonce = nonce
    response = mw(request)
    return response.get("Content-Security-Policy", "")


def _script_src(csp: str) -> str:
    for directive in csp.split(";"):
        if directive.strip().startswith("script-src "):
            return directive.strip()
    return ""


class CSPScriptSrcContractTests(SimpleTestCase):
    """script-src keeps Alpine/htmx working (unsafe-eval) but is nonce-based (#284)."""

    def test_csp_contains_unsafe_eval_for_alpine_and_htmx(self) -> None:
        """Regression: dropping 'unsafe-eval' kills every Alpine directive and
        hx-on:: handler in the admin UI (deploy form, modals, dropdowns)."""
        self.assertIn("'unsafe-eval'", _served_csp())

    def test_script_src_is_nonce_based_without_unsafe_inline(self) -> None:
        """#284: with a request nonce, script-src carries 'nonce-...' + script-src-attr
        'none' and drops 'unsafe-inline' (the nonce makes it inert anyway)."""
        csp = _served_csp()
        script_src = _script_src(csp)
        self.assertIn("'nonce-testnonce1234567890'", script_src)
        self.assertNotIn("'unsafe-inline'", script_src)
        self.assertIn("'unsafe-eval'", script_src)
        self.assertIn("script-src-attr 'none'", csp)

    def test_missing_nonce_falls_back_to_unsafe_inline(self) -> None:
        """Fail-safe: no request nonce (nonce middleware disabled) keeps 'unsafe-inline'
        rather than emitting an empty nonce that blocks every inline script."""
        script_src = _script_src(_served_csp(nonce=""))
        self.assertIn("'unsafe-inline'", script_src)
        self.assertNotIn("'nonce-", script_src)

    def test_csp_still_contains_self(self) -> None:
        """Sanity check: CSP should still have 'self' directive."""
        self.assertIn("'self'", _served_csp())

    def test_csp_keeps_hardened_directives(self) -> None:
        """Restoring eval must not regress the directives that stay strict."""
        csp = _served_csp()
        self.assertIn("object-src 'none'", csp)
        self.assertNotIn("unpkg.com", csp)
        self.assertNotIn("cdn.tailwindcss.com", csp)

    def test_csp_drops_unused_google_fonts(self) -> None:
        """base.html loads only self-hosted assets — the Google Fonts allowlist was dead (#284)."""
        csp = _served_csp()
        self.assertNotIn("fonts.googleapis.com", csp)
        self.assertNotIn("fonts.gstatic.com", csp)


class CSPMiddlewareActiveInTestsTests(SimpleTestCase):
    """The CSP/nonce middleware must be exercised in the test settings so CI can
    catch a missing header or nonce — the guarantee is only real if it runs (#284)."""

    def test_response_carries_csp_header(self) -> None:
        response = self.client.get("/")
        self.assertIn("Content-Security-Policy", response)

    def test_request_receives_a_nonce(self) -> None:
        # CSPNonceMiddleware stamps request.csp_nonce; without it in MIDDLEWARE, templates
        # render nonce="" and the nonce contract is untested.
        request = HttpRequest()
        CSPNonceMiddleware(lambda r: HttpResponse("ok"))(request)
        self.assertTrue(getattr(request, "csp_nonce", ""))
