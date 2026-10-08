"""Permanent failures cannot consume the limited retry batch."""

from datetime import timedelta
from typing import cast

from django.core.cache import cache
from django.test import TestCase
from django.utils import timezone
from django_q.models import OrmQ
from django_q.signing import SignedPackage

from apps.notifications.models import EmailLog
from apps.notifications.tasks import retry_failed_emails
from apps.settings.services import SettingsService


class RetryEligibilityTests(TestCase):
    def setUp(self) -> None:
        super().setUp()
        cache.clear()
        self.addCleanup(cache.clear)
        OrmQ.objects.all().delete()

    def failed_email(self, response: dict[str, object], *, age_minutes: int) -> EmailLog:
        log = EmailLog.objects.create(
            to_addr="retry@example.test",
            from_addr="original@example.test",
            subject="Retry me",
            body_text="Original body",
            body_encrypted=False,
            status="failed",
            provider_response=response,
        )
        EmailLog.objects.filter(pk=log.pk).update(sent_at=timezone.now() - timedelta(minutes=age_minutes))
        return log

    def queued_email_ids(self) -> set[str]:
        packages = [cast("dict[str, object]", SignedPackage.loads(row.payload)) for row in OrmQ.objects.all()]
        ids: set[str] = set()
        for package in packages:
            self.assertEqual(package["func"], "apps.notifications.tasks.send_email_task")
            payload = cast("dict[str, object]", package["kwargs"])
            self.assertEqual(payload["body_text"], "Original body")
            self.assertEqual(payload["from_email"], "original@example.test")
            self.assertEqual(payload["retry_count"], 1)
            ids.add(cast("str", payload["email_log_id"]))
        return ids

    def test_missing_false_and_null_flags_remain_eligible_before_slicing(self) -> None:
        result = SettingsService.update_setting("notifications.email_batch_size", 3)
        self.assertTrue(result.is_ok(), result)
        permanent = self.failed_email({"permanent_failure": True}, age_minutes=4)
        eligible = [
            self.failed_email({}, age_minutes=3),
            self.failed_email({"permanent_failure": False}, age_minutes=2),
            self.failed_email({"permanent_failure": None}, age_minutes=1),
        ]
        self.assertEqual(retry_failed_emails(), {"retried": 3, "skipped": 0})
        self.assertEqual(self.queued_email_ids(), {str(log.pk) for log in eligible})
        permanent.refresh_from_db()
        self.assertEqual(permanent.status, "failed")
        self.assertEqual(permanent.provider_response, {"permanent_failure": True})
        for log in eligible:
            log.refresh_from_db()
            self.assertEqual(log.status, "queued")

    def test_a_full_permanent_batch_cannot_starve_later_retries_across_sweeps(
        self,
    ) -> None:
        result = SettingsService.update_setting("notifications.email_batch_size", 2)
        self.assertTrue(result.is_ok(), result)
        permanent = [self.failed_email({"permanent_failure": True}, age_minutes=10 + i) for i in range(2)]
        eligible = [self.failed_email({}, age_minutes=3 - i) for i in range(3)]
        self.assertEqual(retry_failed_emails(), {"retried": 2, "skipped": 0})
        self.assertEqual(self.queued_email_ids(), {str(log.pk) for log in eligible[:2]})
        self.assertEqual(retry_failed_emails(), {"retried": 1, "skipped": 0})
        self.assertEqual(self.queued_email_ids(), {str(log.pk) for log in eligible})
        self.assertEqual(retry_failed_emails(), {"retried": 0, "skipped": 0})
        for log in permanent:
            log.refresh_from_db()
            self.assertEqual(log.status, "failed")
            self.assertEqual(log.provider_response, {"permanent_failure": True})
        for log in eligible:
            log.refresh_from_db()
            self.assertEqual(log.status, "queued")
