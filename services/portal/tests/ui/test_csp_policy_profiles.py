"""Unit tests for server-selected portal CSP policy profiles (#104 [M7], UNIT 0.1).

The CSP-hardening rollout selects a policy PROFILE (content) and a DISPOSITION
(enforced vs Report-Only) purely from server settings — never from request data.
The enforced default is now ``phase2-target`` (nonce-based, no 'unsafe-inline',
``script-src-attr 'none'``); ``current`` remains the byte-exact legacy policy the
middleware also falls back to when no request nonce is available.
"""

from __future__ import annotations

from django.conf import settings
from django.http import HttpRequest, HttpResponse
from django.test import RequestFactory, SimpleTestCase, override_settings

from apps.common.middleware import (
    CSPNonceMiddleware,
    SecurityHeadersMiddleware,
)

CURRENT_CSP = (
    "default-src 'self'; "
    "script-src 'self' 'unsafe-inline' 'unsafe-eval' "
    "https://js.stripe.com; "
    "style-src 'self' 'unsafe-inline'; "
    "img-src 'self' data: https:; "
    "font-src 'self'; "
    "connect-src 'self' https://api.stripe.com; "
    "frame-src 'self' https://js.stripe.com https://*.stripe.com; "
    "frame-ancestors 'none'; "
    "form-action 'self'; "
    "base-uri 'self'; "
    "object-src 'none'; "
    "media-src 'self'"
)


def _noop_view(_request: HttpRequest) -> HttpResponse:
    return HttpResponse("ok")


class CSPPolicyProfileTests(SimpleTestCase):
    """CSP content and disposition are controlled only by Django settings."""

    def setUp(self) -> None:
        self.factory = RequestFactory()

    def _request_with_nonce(
        self,
        path: str = "/",
        **request_meta: str,
    ) -> tuple[HttpRequest, HttpResponse]:
        request = self.factory.get(path, **request_meta)
        middleware = CSPNonceMiddleware(
            SecurityHeadersMiddleware(_noop_view)
        )
        response = middleware(request)
        return request, response

    def _directive(self, csp: str, name: str) -> str:
        matching = [
            part
            for part in csp.split("; ")
            if part == name or part.startswith(f"{name} ")
        ]
        self.assertEqual(
            len(matching),
            1,
            f"Expected exactly one {name!r} directive, got {matching!r}",
        )
        return matching[0]

    @override_settings(
        CSP_PROFILE="current",
        CSP_REPORT_ONLY=False,
    )
    def test_current_profile_emits_byte_exact_policy(self) -> None:
        _request, response = self._request_with_nonce()

        self.assertEqual(
            response["Content-Security-Policy"],
            CURRENT_CSP,
        )
        self.assertNotIn(
            "Content-Security-Policy-Report-Only",
            response,
        )

    def test_settings_default_profile_is_phase2_target_enforced(self) -> None:
        """GUARD: the shipped default (``base.py`` ``CSP_PROFILE``) must be the
        enforced phase2-target policy. This test deliberately uses NO
        ``override_settings`` so it reads the REAL default — it goes RED if the
        enforce-flip is ever reverted to ``current``. Every other test here
        pins its own profile via ``override_settings`` and so cannot catch a
        default regression."""
        request, response = self._request_with_nonce()

        self.assertIn(
            "Content-Security-Policy",
            response,
            "Default disposition must be enforced, not Report-Only.",
        )
        self.assertNotIn("Content-Security-Policy-Report-Only", response)

        csp = response["Content-Security-Policy"]
        script_src = self._directive(csp, "script-src")
        self.assertNotIn("'unsafe-inline'", script_src)
        self.assertIn(f"'nonce-{request.csp_nonce}'", script_src)
        self.assertIn("script-src-attr 'none'", csp.split("; "))

    @override_settings(
        CSP_PROFILE="phase2-target",
        CSP_REPORT_ONLY=False,
    )
    def test_phase2_target_uses_nonce_and_keeps_unsafe_eval(self) -> None:
        request, response = self._request_with_nonce()
        csp = response["Content-Security-Policy"]
        script_src = self._directive(csp, "script-src")

        self.assertNotIn("'unsafe-inline'", script_src)
        self.assertIn(f"'nonce-{request.csp_nonce}'", script_src)
        self.assertIn("'unsafe-eval'", script_src)
        self.assertIn(
            "script-src-attr 'none'",
            csp.split("; "),
        )

    @override_settings(
        CSP_PROFILE="phase3-target",
        CSP_REPORT_ONLY=False,
    )
    def test_phase3_target_uses_nonce_without_unsafe_sources(self) -> None:
        request, response = self._request_with_nonce()
        csp = response["Content-Security-Policy"]
        script_src = self._directive(csp, "script-src")

        self.assertNotIn("'unsafe-inline'", script_src)
        self.assertNotIn("'unsafe-eval'", script_src)
        self.assertIn(f"'nonce-{request.csp_nonce}'", script_src)
        self.assertIn(
            "script-src-attr 'none'",
            csp.split("; "),
        )

    @override_settings(
        CSP_PROFILE="current",
        CSP_REPORT_ONLY=True,
    )
    def test_report_only_emits_no_enforced_csp_header(self) -> None:
        _request, response = self._request_with_nonce()

        self.assertNotIn("Content-Security-Policy", response)
        self.assertEqual(
            response["Content-Security-Policy-Report-Only"],
            CURRENT_CSP,
        )

    @override_settings(
        CSP_PROFILE="phase2-target",
        CSP_REPORT_ONLY=False,
    )
    def test_request_data_cannot_override_server_selected_profile(
        self,
    ) -> None:
        request, response = self._request_with_nonce(
            "/?csp_profile=phase3-target",
            HTTP_X_CSP_PROFILE="phase3-target",
        )
        csp = response["Content-Security-Policy"]
        script_src = self._directive(csp, "script-src")

        # phase2-target retains unsafe-eval; phase3-target would remove it.
        self.assertIn("'unsafe-eval'", script_src)
        self.assertNotIn("'unsafe-inline'", script_src)
        self.assertIn(f"'nonce-{request.csp_nonce}'", script_src)
        self.assertIn(
            "script-src-attr 'none'",
            csp.split("; "),
        )

    @override_settings(
        CSP_PROFILE="phase3-target",
        CSP_REPORT_ONLY=False,
    )
    def test_target_profile_without_nonce_falls_back_to_current(
        self,
    ) -> None:
        request = self.factory.get("/")
        response = SecurityHeadersMiddleware(_noop_view)(request)

        self.assertEqual(
            response["Content-Security-Policy"],
            CURRENT_CSP,
        )
        self.assertNotIn(
            "Content-Security-Policy-Report-Only",
            response,
        )

    @override_settings(
        CSP_PROFILE="unknown-profile",
        CSP_REPORT_ONLY=False,
    )
    def test_unknown_profile_falls_back_to_current(self) -> None:
        _request, response = self._request_with_nonce()

        self.assertEqual(
            response["Content-Security-Policy"],
            CURRENT_CSP,
        )

    def test_nonce_middleware_precedes_security_headers_middleware(self) -> None:
        """The fail-safe (no nonce -> emit 'current') means the qualification
        gate would SILENTLY degrade to the current policy if CSPNonceMiddleware
        stopped running before SecurityHeadersMiddleware. Pin the ordering so a
        future MIDDLEWARE reorder fails loudly here instead of yielding a
        false-green gate."""
        middleware = settings.MIDDLEWARE
        nonce = "apps.common.middleware.CSPNonceMiddleware"
        headers = "apps.common.middleware.SecurityHeadersMiddleware"

        self.assertIn(nonce, middleware)
        self.assertIn(headers, middleware)
        self.assertLess(
            middleware.index(nonce),
            middleware.index(headers),
            "CSPNonceMiddleware must run before SecurityHeadersMiddleware so "
            "request.csp_nonce is set when a target CSP profile is selected.",
        )
