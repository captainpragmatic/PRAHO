"""Subject limits reject invalid templates and delivery before producing side effects."""

from __future__ import annotations

from typing import cast

from django.core import mail
from django.core.cache import cache
from django.core.exceptions import ValidationError
from django.test import TestCase, override_settings
from django_q.models import OrmQ
from django_q.signing import SignedPackage

from apps.notifications.models import EmailLog, EmailTemplate
from apps.notifications.services import EmailService
from apps.settings.services import SettingsService
from apps.users.models import User


@override_settings(EMAIL_BACKEND="django.core.mail.backends.locmem.EmailBackend", LANGUAGE_CODE="en")
class SubjectLimitDeliveryTests(TestCase):
    def setUp(self) -> None:
        cache.clear()
        self.addCleanup(cache.clear)
        result = SettingsService.update_setting("notifications.max_subject_length", 10)
        self.assertTrue(result.is_ok(), result)

    def test_template_full_clean_rejects_the_live_limit(self) -> None:
        author = User.objects.create_user(email="subject-author@example.test", password="test")
        template = EmailTemplate(
            key="subject-limit", locale="en", subject="x" * 11, body_html="<p>Body</p>", created_by=author
        )
        with self.assertRaisesMessage(ValidationError, "Subject too long") as error:
            template.full_clean()
        self.assertEqual(error.exception.message_dict["subject"], ["Subject too long"])
        self.assertFalse(EmailTemplate.objects.filter(key=template.key).exists())

        for length in (9, 10):
            template.subject = "x" * length
            template.full_clean()
        result = SettingsService.update_setting("notifications.max_subject_length", 11)
        self.assertTrue(result.is_ok(), result)
        template.subject = "x" * 11
        template.full_clean()

    def test_synchronous_delivery_rejects_before_logging_or_sending(self) -> None:
        before_logs = EmailLog.objects.count()
        before_queue = OrmQ.objects.count()
        result = EmailService.send_email(
            to="subject-limit@example.test", subject="x" * 11, body_text="Body", async_send=False
        )
        self.assertFalse(result.success)
        self.assertEqual(result.error, "Subject too long")
        self.assertEqual(mail.outbox, [])
        self.assertEqual(EmailLog.objects.count(), before_logs)
        self.assertEqual(OrmQ.objects.count(), before_queue)

        for length in (9, 10):
            sent = EmailService.send_email(
                to="subject-limit@example.test", subject="x" * length, body_text="Body", async_send=False
            )
            self.assertTrue(sent.success, sent.error)
            self.assertEqual(mail.outbox[-1].subject, "x" * length)
            self.assertEqual(EmailLog.objects.get(pk=sent.email_log_id).status, "sent")

    def test_asynchronous_delivery_rejects_before_logging_or_enqueueing(self) -> None:
        before_logs = EmailLog.objects.count()
        before_queue = OrmQ.objects.count()
        for allowance in (50, 0):
            with self.subTest(allowance=allowance), self.settings(EMAIL_RATE_LIMIT={"MAX_PER_MINUTE": allowance}):
                result = EmailService.send_email(
                    to="subject-limit@example.test", subject="x" * 11, body_text="Body", async_send=True
                )
                self.assertFalse(result.success)
                self.assertEqual(result.error, "Subject too long")
                self.assertEqual(mail.outbox, [])
                self.assertEqual(EmailLog.objects.count(), before_logs)
                self.assertEqual(OrmQ.objects.count(), before_queue)

        result = SettingsService.update_setting("notifications.max_subject_length", 11)
        self.assertTrue(result.is_ok(), result)
        queued = EmailService.send_email(
            to="subject-limit@example.test", subject="x" * 11, body_text="Body", async_send=True
        )
        self.assertTrue(queued.success, queued.error)
        log = EmailLog.objects.get(pk=queued.email_log_id)
        self.assertEqual((log.subject, log.status), ("x" * 11, "queued"))
        packages = [cast("dict[str, object]", SignedPackage.loads(row.payload)) for row in OrmQ.objects.all()]
        matching = [
            package
            for package in packages
            if cast("dict[str, object]", package["kwargs"]).get("email_log_id") == queued.email_log_id
        ]
        self.assertEqual(len(matching), 1)
        self.assertEqual(matching[0]["func"], "apps.notifications.tasks.send_email_task")
        self.assertEqual(cast("dict[str, object]", matching[0]["kwargs"])["subject"], "x" * 11)
        self.assertEqual(mail.outbox, [])

    def test_internal_synchronous_delivery_also_rejects_the_live_limit(self) -> None:
        self.assertFalse(EmailService._send_email("subject-limit@example.test", "x" * 11, "Body"))
        self.assertEqual(mail.outbox, [])
        self.assertTrue(EmailService._send_email("subject-limit@example.test", "x" * 10, "Body"))
        self.assertEqual([message.subject for message in mail.outbox], ["x" * 10])
