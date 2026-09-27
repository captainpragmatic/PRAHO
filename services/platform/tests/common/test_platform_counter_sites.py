"""Production services use the shared store throughout their counter lifecycles."""

from __future__ import annotations

from unittest.mock import patch

from django.core import mail
from django.db import OperationalError
from django.test import TestCase, override_settings

from apps.billing.efactura.quota import ANAFQuotaTracker, QuotaEndpoint
from apps.common import counters
from apps.common.models import Counter
from apps.customers.models import Customer
from apps.notifications.services import EmailService
from apps.users.models import User
from apps.users.services import SecureCustomerUserService


@override_settings(
    EMAIL_BACKEND="django.core.mail.backends.locmem.EmailBackend",
    CACHES={"default": {"BACKEND": "django.core.cache.backends.dummy.DummyCache"}},
)
class PlatformCounterSiteTests(TestCase):
    def setUp(self) -> None:
        self.clock = self.enterContext(patch("apps.common.counters.time.time", return_value=10_000))
        self.enterContext(patch("apps.common.counters.randbelow", return_value=1))
        self.customer = Customer.objects.create(
            name="Counter customer",
            company_name="Counter customer",
            primary_email="customer@example.test",
            customer_type="company",
        )
        self.user = User.objects.create_user(email="invite@example.test")

    def test_invite_store_failure_denies_delivery(self) -> None:
        with patch("apps.common.counters.increment", side_effect=OperationalError("Store unavailable")):
            self.assertFalse(SecureCustomerUserService.send_welcome_invite(self.user, self.customer))
        self.assertEqual(len(mail.outbox), 0)
        self.assertEqual(Counter.objects.count(), 0)

    def test_invite_release_preserves_quota_and_first_expiry(self) -> None:
        key = f"welcome_invite:{self.user.pk}"
        for _ in range(3):
            self.assertTrue(SecureCustomerUserService.send_welcome_invite(self.user, self.customer))
        self.clock.return_value = 13_599
        self.assertFalse(SecureCustomerUserService.send_welcome_invite(self.user, self.customer))
        self.assertEqual(counters.peek(key), 3)
        self.assertEqual(Counter.objects.get(key=key).expires_at, 13_600)
        self.assertEqual(len(mail.outbox), 3)

        self.clock.return_value = 13_600
        self.assertTrue(SecureCustomerUserService.send_welcome_invite(self.user, self.customer))
        self.assertEqual(counters.peek(key), 1)
        self.assertEqual(len(mail.outbox), 4)

    def test_failed_invite_releases_reservation_for_retry(self) -> None:
        key = f"welcome_invite:{self.user.pk}"
        with patch("django.core.mail.EmailMessage.send", side_effect=OSError("SMTP unavailable")):
            self.assertFalse(SecureCustomerUserService.send_welcome_invite(self.user, self.customer))
        self.assertEqual(counters.peek(key), 0)
        self.assertTrue(SecureCustomerUserService.send_welcome_invite(self.user, self.customer))
        self.assertEqual(counters.peek(key), 1)
        self.assertEqual(len(mail.outbox), 1)

    def test_email_increment_failure_prevents_delivery(self) -> None:
        with patch("apps.common.counters.increment", side_effect=OperationalError("Store unavailable")):
            result = EmailService.send_email(
                to="recipient@example.test", subject="Counter test", body_text="Test", async_send=False
            )
        self.assertFalse(result.success)
        self.assertEqual(len(mail.outbox), 0)

    def test_email_read_failure_prevents_delivery(self) -> None:
        with patch("apps.common.counters.peek", side_effect=OperationalError("Store unavailable")):
            result = EmailService.send_email(
                to="recipient@example.test", subject="Counter test", body_text="Test", async_send=False
            )
        self.assertFalse(result.success)
        self.assertEqual(len(mail.outbox), 0)

    def test_quota_delta_reset_and_global_counter_use_the_store(self) -> None:
        tracker = ANAFQuotaTracker()
        self.assertEqual(tracker.increment(QuotaEndpoint.STATUS, "12345678", "message", count=5), 5)
        key = tracker._get_cache_key(QuotaEndpoint.STATUS, "12345678", "message")
        self.assertEqual(counters.peek(key), 5)
        self.assertEqual(counters.peek(tracker._get_global_minute_key()), 5)
        self.assertEqual(tracker.increment(QuotaEndpoint.STATUS, "12345678", "message"), 6)
        tracker.reset_quota(QuotaEndpoint.STATUS, "12345678", "message")
        self.assertEqual(counters.peek(key), 0)
        self.assertEqual(counters.peek(tracker._get_global_minute_key()), 6)

    def test_quota_increment_error_stops_the_decorated_operation(self) -> None:
        tracker = ANAFQuotaTracker()
        results: list[str] = []

        @tracker.rate_limited(QuotaEndpoint.STATUS)
        def operation(cui: str, message_id: str) -> None:
            results.append(message_id)

        with (
            patch("apps.common.counters.increment", side_effect=OperationalError("Store unavailable")),
            self.assertRaises(OperationalError),
        ):
            operation(cui="12345678", message_id="message")
        self.assertEqual(results, [])
