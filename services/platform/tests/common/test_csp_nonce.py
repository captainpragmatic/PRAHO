"""#104 [M7] step 1: CSP nonce plumbing — attributes render, header stays inert.

Step 1 adds nonce="{{ csp_nonce }}" to every inline <script>/<style> tag while
the CSP header still allows 'unsafe-inline' and carries no 'nonce-...' source,
so the attributes are deliberately inert (zero behavioral change). These tests
lock in both halves: rendered nonces must be real and non-empty (so a later
step can safely flip the header), and the header must not gain a nonce source
as a side effect of this step.

NOTE: config/settings/test.py replaces MIDDLEWARE with a trimmed list that
omits CSPNonceMiddleware and SecurityHeadersMiddleware, so ordinary test
renders produce nonce="" and no CSP header. These tests prepend the two
middleware (production order: nonce before headers) to exercise the real
stack. Before a later [M7] step removes 'unsafe-inline', the test settings
must gain both middleware globally or CI will not catch missing nonces.
"""

from __future__ import annotations

from django.test import TestCase, modify_settings

LOGIN_URL = "/auth/login/"

PRODUCTION_CSP_MIDDLEWARE = modify_settings(
    MIDDLEWARE={
        "prepend": [
            "apps.common.middleware.CSPNonceMiddleware",
            "apps.common.middleware.SecurityHeadersMiddleware",
        ],
    }
)


@PRODUCTION_CSP_MIDDLEWARE
class CSPNonceRenderingTests(TestCase):
    """Rendered pages must carry a non-empty per-request nonce on inline tags."""

    def test_login_page_inline_script_carries_request_nonce(self) -> None:
        response = self.client.get(LOGIN_URL)
        self.assertEqual(response.status_code, 200)
        nonce = getattr(response.wsgi_request, "csp_nonce", "")
        self.assertTrue(nonce, "CSPNonceMiddleware must set a non-empty request.csp_nonce")
        self.assertIn(f'<script nonce="{nonce}">', response.content.decode())

    def test_login_page_inline_style_carries_request_nonce(self) -> None:
        response = self.client.get(LOGIN_URL)
        self.assertEqual(response.status_code, 200)
        nonce = response.wsgi_request.csp_nonce
        self.assertIn(f'<style nonce="{nonce}">', response.content.decode())

    def test_no_empty_nonce_attributes_render(self) -> None:
        response = self.client.get(LOGIN_URL)
        self.assertNotIn('nonce=""', response.content.decode())

    def test_nonce_is_unique_per_request(self) -> None:
        first = self.client.get(LOGIN_URL).wsgi_request.csp_nonce
        second = self.client.get(LOGIN_URL).wsgi_request.csp_nonce
        self.assertNotEqual(first, second)


@PRODUCTION_CSP_MIDDLEWARE
class CSPHeaderEnforcementTests(TestCase):
    """#284 fully landed: with a per-request nonce, script-src is nonce-ONLY (no
    'unsafe-inline', no 'unsafe-eval') + script-src-attr 'none'. style-src keeps
    'unsafe-inline' (out of #284 scope); the platform runs the @alpinejs/csp build.
    """

    def test_script_src_is_nonce_only_no_unsafe(self) -> None:
        response = self.client.get(LOGIN_URL)
        csp = response.get("Content-Security-Policy", "")
        nonce = response.wsgi_request.csp_nonce
        self.assertIn(f"script-src 'self' 'nonce-{nonce}';", csp)
        self.assertNotIn("'unsafe-eval'", csp)
        self.assertIn("script-src-attr 'none'", csp)
        # style-src is deliberately unchanged.
        self.assertIn("style-src 'self' 'unsafe-inline'", csp)

    def test_header_carries_a_nonce_source(self) -> None:
        response = self.client.get(LOGIN_URL)
        csp = response.get("Content-Security-Policy", "")
        self.assertIn(f"'nonce-{response.wsgi_request.csp_nonce}'", csp)
