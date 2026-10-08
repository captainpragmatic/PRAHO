"""The portal's HSTS header follows its `SECURE_HSTS_*` settings.

`SecurityHeadersMiddleware` used to set a hardcoded `max-age=31536000; includeSubDomains` on every
secure response. Django's `SecurityMiddleware` only adds HSTS when the header is absent, so the
portal's settings never took effect: staging's one-hour policy and the production preload flag were
both dead. Where Caddy fronts the portal it replaces the header anyway, but deployments with no edge
(the container-service and portal-only topologies) get exactly what Django sends.

The middleware pair is built inside each override, because `SecurityMiddleware` reads its settings
once, when it is constructed. The request arrives the way it does behind a proxy: over plain HTTP with
`X-Forwarded-Proto: https`.
"""

from __future__ import annotations

from django.http import HttpRequest, HttpResponse
from django.middleware.security import SecurityMiddleware
from django.test import RequestFactory, SimpleTestCase, override_settings

from apps.common.middleware import SecurityHeadersMiddleware

_BEHIND_PROXY = {"SECURE_PROXY_SSL_HEADER": ("HTTP_X_FORWARDED_PROTO", "https")}


def _ok(_request: HttpRequest) -> HttpResponse:
    return HttpResponse("ok")


class PortalHstsHeaderTests(SimpleTestCase):
    def _hsts(self, *, forwarded_proto: str | None = "https") -> str | None:
        stack = SecurityMiddleware(SecurityHeadersMiddleware(_ok))
        extra = {"HTTP_X_FORWARDED_PROTO": forwarded_proto} if forwarded_proto else {}
        return stack(RequestFactory().get("/status/", **extra)).headers.get("Strict-Transport-Security")

    @override_settings(
        **_BEHIND_PROXY, SECURE_HSTS_SECONDS=3600, SECURE_HSTS_INCLUDE_SUBDOMAINS=False, SECURE_HSTS_PRELOAD=False
    )
    def test_the_staging_policy_is_the_one_sent(self) -> None:
        self.assertEqual(self._hsts(), "max-age=3600")

    @override_settings(
        **_BEHIND_PROXY, SECURE_HSTS_SECONDS=31536000, SECURE_HSTS_INCLUDE_SUBDOMAINS=True, SECURE_HSTS_PRELOAD=True
    )
    def test_the_preload_setting_is_honoured(self) -> None:
        self.assertEqual(self._hsts(), "max-age=31536000; includeSubDomains; preload")

    @override_settings(**_BEHIND_PROXY, SECURE_HSTS_SECONDS=3600)
    def test_a_plain_http_request_gets_no_hsts(self) -> None:
        self.assertIsNone(self._hsts(forwarded_proto=None))
