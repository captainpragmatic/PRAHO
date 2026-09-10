"""Platform CSP script-src contract.

#284 fully hardened the platform script CSP. script-src is nonce-based +
script-src-attr 'none' with NEITHER 'unsafe-inline' NOR 'unsafe-eval':
  - 'unsafe-inline' removed: every inline on*= handler is a delegated data-action
    (freeze guardrail at 0) and every fragment script is relocated/nonce'd.
  - 'unsafe-eval' removed: the platform runs the @alpinejs/csp build (directive
    expressions are parsed, not new Function()) and htmx allowEval=false, with every
    hx-on migrated. (Historically 'unsafe-eval' was load-bearing for standard Alpine —
    the CSP-build migration is what let it go.)
The middleware falls back to 'unsafe-inline' (never 'unsafe-eval') only when the
request has no nonce (nonce middleware disabled) — a fail-safe, not the norm.
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
    """script-src is nonce-only — no 'unsafe-inline', no 'unsafe-eval' (#284)."""

    def test_csp_has_no_unsafe_eval(self) -> None:
        """#284: the platform runs the @alpinejs/csp build and htmx allowEval=false, so
        'unsafe-eval' is gone (a regression that re-adds it would relax the whole policy)."""
        self.assertNotIn("'unsafe-eval'", _served_csp())

    def test_script_src_is_nonce_based_without_unsafe_inline_or_eval(self) -> None:
        """#284 fully landed: script-src is nonce-only + script-src-attr 'none', with
        neither 'unsafe-inline' nor 'unsafe-eval'."""
        csp = _served_csp()
        script_src = _script_src(csp)
        self.assertIn("'nonce-testnonce1234567890'", script_src)
        self.assertNotIn("'unsafe-inline'", script_src)
        self.assertNotIn("'unsafe-eval'", script_src)
        self.assertIn("script-src-attr 'none'", csp)

    def test_missing_nonce_falls_back_to_unsafe_inline(self) -> None:
        """Fail-safe: no request nonce (nonce middleware disabled) keeps 'unsafe-inline'
        rather than emitting an empty nonce that blocks every inline script — but still
        never re-adds 'unsafe-eval' (the CSP Alpine build never needs it)."""
        script_src = _script_src(_served_csp(nonce=""))
        self.assertIn("'unsafe-inline'", script_src)
        self.assertNotIn("'unsafe-eval'", script_src)
        self.assertNotIn("'nonce-", script_src)

    def test_csp_still_contains_self(self) -> None:
        """Sanity check: CSP should still have 'self' directive."""
        self.assertIn("'self'", _served_csp())

    def test_csp_keeps_hardened_directives(self) -> None:
        """The already-strict directives stay strict."""
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
