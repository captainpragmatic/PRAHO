"""Authenticated requests write no per-request session-activity audit rows (#622).

`SessionSecurityMiddleware` wrote a `session_activity_*` AuditEvent on every authenticated
request under /users/, /billing/, /customers/, /admin/, /api/, /settings/ or /tickets/. The
rows carried no user, only the user's id, a session-key prefix, the path and the IP in their
metadata, so GDPR export and erasure, which select by user, never found them. Nothing read
them either. The request log (`AuditMiddleware`) already records the method, path, user and
IP of every request, each change writes its own audit event, and suspicious activity is
audited separately.

The middleware is absent from `config/settings/test.py`, so these tests add it back.
"""

from __future__ import annotations

from datetime import timedelta

from django.conf import settings
from django.core.cache import cache
from django.test import RequestFactory, TestCase, override_settings
from freezegun import freeze_time

from apps.audit.models import AuditEvent
from apps.users.models import User
from apps.users.services import SessionSecurityService

SESSION_ACTIVITY = "session_activity_"


@override_settings(MIDDLEWARE=[*settings.MIDDLEWARE, "apps.common.middleware.SessionSecurityMiddleware"])
class SessionActivityAuditThroughMiddlewareTests(TestCase):
    """End to end through the middleware production runs on every authenticated request."""

    def setUp(self) -> None:
        self.user = User.objects.create_user(
            email="session-activity@example.com", password="Activity-password123!", staff_role="admin"
        )
        self.client.force_login(self.user)

    def rows(self, action: str = SESSION_ACTIVITY) -> int:
        return AuditEvent.objects.filter(action__startswith=action).count()

    def test_authenticated_requests_write_no_session_activity_rows(self) -> None:
        """FAILS on master: each of these requests inserted a `session_activity_*` row."""
        response = self.client.get("/customers/")
        self.client.get("/billing/")
        self.client.get("/tickets/")
        self.client.post("/customers/", {})

        self.assertEqual(self.rows(), 0)
        # Positive control: only SessionSecurityMiddleware gives an admin the 30-minute window and
        # says so in this header, so the zero above comes from requests the middleware processed.
        self.assertEqual(response["X-Session-Timeout"], "1800")
        self.assertEqual(AuditEvent.objects.filter(action="session_timeout_updated").count(), 1)


@override_settings(CACHES={"default": {"BACKEND": "django.core.cache.backends.locmem.LocMemCache"}})
class SuspiciousActivityDetectionTests(TestCase):
    """The multiple-address check runs on every authenticated request, so it must stay cheap.

    It appended one entry per request to the user's address history, so a page polling every
    two seconds added about 1,800 an hour, and once three addresses were seen it wrote a
    `suspicious_activity_detected` audit row on every request for up to an hour. It now keeps
    one last-seen time per address and records an address when it joins the pattern.
    """

    def setUp(self) -> None:
        cache.clear()
        self.addCleanup(cache.clear)
        self.user = User.objects.create_user(email="roaming@example.com", password="Roaming-password123!")
        self.factory = RequestFactory()

    def detect(self, ip: str) -> bool:
        request = self.factory.get("/customers/", REMOTE_ADDR=ip)
        request.user = self.user
        return SessionSecurityService.detect_suspicious_activity(request)

    def detections(self) -> int:
        return AuditEvent.objects.filter(action="suspicious_activity_detected").count()

    def test_repeated_requests_from_one_address_keep_one_entry(self) -> None:
        for _ in range(50):
            self.assertFalse(self.detect("203.0.113.1"))

        self.assertEqual(len(cache.get(f"recent_ips:{self.user.id}")), 1)

    def test_a_suspicious_pattern_is_audited_once_per_address_that_joins_it(self) -> None:
        self.assertFalse(self.detect("203.0.113.1"))
        self.assertFalse(self.detect("203.0.113.2"))
        self.assertEqual(self.detections(), 0)

        self.assertTrue(self.detect("203.0.113.3"))  # the third address in an hour
        self.assertEqual(self.detections(), 1)

        for ip in ("203.0.113.1", "203.0.113.2", "203.0.113.3") * 3:
            self.assertTrue(self.detect(ip))  # still suspicious, but nothing new to record
        self.assertEqual(self.detections(), 1)

        self.assertTrue(self.detect("203.0.113.4"))
        self.assertEqual(self.detections(), 2)

    def test_an_address_older_than_an_hour_leaves_the_pattern_and_can_rejoin(self) -> None:
        """Guard: each address ages out on its own, while the stored history stays alive."""
        with freeze_time("2026-10-11 09:00:00") as clock:
            self.detect("203.0.113.1")  # A at 09:00
            clock.tick(timedelta(minutes=50))
            self.detect("203.0.113.2")  # B at 09:50 keeps the cached history alive past 10:00
            clock.tick(timedelta(minutes=11))  # 10:01: A was last seen 61 minutes ago
            self.assertFalse(self.detect("203.0.113.3"))  # only B and C count
            self.assertEqual(self.detections(), 0)

            self.assertTrue(self.detect("203.0.113.1"))  # A comes back: three addresses again
            self.assertEqual(self.detections(), 1)
