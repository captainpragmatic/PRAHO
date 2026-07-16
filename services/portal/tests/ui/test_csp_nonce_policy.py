"""
CSP nonce policy tests — #104 [M7] step 1.

Three layers of protection for the CSP hardening rollout:

1. Plumbing: CSPNonceMiddleware populates a fresh per-request nonce and the
   csp_nonce context processor exposes it to templates, so every
   nonce="{{ csp_nonce }}" attribute renders a non-empty value.
2. Header state: the portal CSP header still carries 'unsafe-inline' and no
   nonce-source, so the nonce attributes are inert by spec (browsers ignore
   nonces until a nonce-source appears in the policy). When [M7] step 3
   injects the nonce into the header, update these assertions deliberately.
3. Completeness: every inline <script>/<style> tag in every template the
   portal can render (service templates + shared UI components) carries a
   nonce attribute. Once 'unsafe-inline' is dropped ([M7] step 4), any
   inline tag without a nonce silently stops executing — this scan is the
   guardrail that keeps that from ever being true.

No database access (portal test isolation).
"""

from __future__ import annotations

import re
from pathlib import Path

from django.conf import settings
from django.http import HttpRequest, HttpResponse
from django.template import RequestContext, Template
from django.test import RequestFactory, SimpleTestCase

from apps.common.context_processors import csp_nonce
from apps.common.middleware import CSPNonceMiddleware, SecurityHeadersMiddleware

REPO_ROOT = Path(__file__).resolve().parents[4]

# Every directory the portal template engine can load templates from.
TEMPLATE_ROOTS = (
    REPO_ROOT / "services" / "portal" / "templates",
    REPO_ROOT / "shared" / "ui" / "templates",
)

# Opening tags, including multi-line attribute lists.
SCRIPT_TAG_RE = re.compile(r"<script\b[^>]*>", re.IGNORECASE | re.DOTALL)
STYLE_TAG_RE = re.compile(r"<style\b[^>]*>", re.IGNORECASE | re.DOTALL)
SRC_ATTR_RE = re.compile(r"\bsrc\s*=", re.IGNORECASE)
NONCE_ATTR_RE = re.compile(r'\bnonce="\{\{ csp_nonce \}\}"')


def _noop_view(_request: HttpRequest) -> HttpResponse:
    return HttpResponse("ok")


class CSPNoncePlumbingTests(SimpleTestCase):
    """The nonce must be populated per-request and reach template context."""

    def setUp(self) -> None:
        self.factory = RequestFactory()

    def _request_through_middleware(self) -> HttpRequest:
        request = self.factory.get("/")
        CSPNonceMiddleware(_noop_view)(request)
        return request

    def test_middleware_sets_nonempty_nonce(self) -> None:
        request = self._request_through_middleware()
        nonce = getattr(request, "csp_nonce", "")
        self.assertTrue(nonce, "CSPNonceMiddleware must set request.csp_nonce")
        self.assertGreaterEqual(len(nonce), 32)

    def test_nonce_is_unique_per_request(self) -> None:
        first = self._request_through_middleware()
        second = self._request_through_middleware()
        self.assertNotEqual(first.csp_nonce, second.csp_nonce)

    def test_context_processor_exposes_nonce(self) -> None:
        request = self._request_through_middleware()
        self.assertEqual(csp_nonce(request), {"csp_nonce": request.csp_nonce})

    def test_context_processor_registered_in_settings(self) -> None:
        processors = settings.TEMPLATES[0]["OPTIONS"]["context_processors"]
        self.assertIn("apps.common.context_processors.csp_nonce", processors)

    def test_nonce_attribute_renders_nonempty_value(self) -> None:
        """End-to-end: the exact template pattern renders a non-empty nonce."""
        request = self._request_through_middleware()
        request.session = {}  # portal_context reads request.session (no DB)
        rendered = Template('<script nonce="{{ csp_nonce }}">x()</script>').render(
            RequestContext(request)
        )
        self.assertIn(f'nonce="{request.csp_nonce}"', rendered)
        self.assertNotIn('nonce=""', rendered)


class CSPHeaderStateTests(SimpleTestCase):
    """Documents [M7] step 1 inertness: unsafe-inline present, no nonce-source.

    When step 3 injects 'nonce-{request.csp_nonce}' into the header, these
    assertions must be updated in the same change — that is the point at
    which the nonce attributes stop being inert.
    """

    def _csp_header(self) -> str:
        request = RequestFactory().get("/")
        response = SecurityHeadersMiddleware(_noop_view)(request)
        return response["Content-Security-Policy"]

    def test_header_still_allows_unsafe_inline(self) -> None:
        csp = self._csp_header()
        self.assertIn("'unsafe-inline'", csp)

    def test_header_has_no_nonce_source_yet(self) -> None:
        csp = self._csp_header()
        self.assertNotIn("'nonce-", csp)


class InlineNonceCompletenessTests(SimpleTestCase):
    """Every inline <script>/<style> tag the portal can render carries a nonce.

    This is the precondition for dropping 'unsafe-inline' ([M7] step 4):
    at that point any inline tag without a nonce silently stops executing.
    """

    def _tags_missing_nonce(self, tag_re: re.Pattern[str], *, skip_src: bool) -> list[str]:
        missing: list[str] = []
        for root in TEMPLATE_ROOTS:
            for template in sorted(root.rglob("*.html")):
                text = template.read_text(encoding="utf-8")
                for match in tag_re.finditer(text):
                    tag = match.group(0)
                    if skip_src and SRC_ATTR_RE.search(tag):
                        continue  # external script: covered by 'self'/host sources
                    if NONCE_ATTR_RE.search(tag):
                        continue
                    line = text.count("\n", 0, match.start()) + 1
                    rel = template.relative_to(REPO_ROOT).as_posix()
                    missing.append(f"{rel}:{line}")
        return missing

    def test_every_inline_script_has_nonce(self) -> None:
        missing = self._tags_missing_nonce(SCRIPT_TAG_RE, skip_src=True)
        self.assertEqual(
            missing,
            [],
            "Inline <script> tags without nonce=\"{{ csp_nonce }}\" — these will "
            f"silently stop executing when 'unsafe-inline' is dropped: {missing}",
        )

    def test_every_style_tag_has_nonce(self) -> None:
        missing = self._tags_missing_nonce(STYLE_TAG_RE, skip_src=False)
        self.assertEqual(
            missing,
            [],
            "<style> tags without nonce=\"{{ csp_nonce }}\" — these will silently "
            f"stop applying when 'unsafe-inline' is dropped: {missing}",
        )
