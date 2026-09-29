"""Accepted domain notices are durable, exact, and safe under worker overlap."""

from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta
from threading import Event
from unittest import skipUnless
from unittest.mock import patch

from django.core import mail
from django.core.cache import cache
from django.db import close_old_connections, connection
from django.test import TestCase, TransactionTestCase, override_settings
from django.utils import timezone

from apps.common.types import Ok
from apps.customers.models import Customer
from apps.domains.currency_terms import domain_renewal_quote, reconcile_domain_currency_notices
from apps.domains.models import DomainCurrencyTransition
from apps.notifications.models import EmailLog
from apps.notifications.services import EmailResult
from apps.settings.services import SettingsService
from tests.domains.test_currency_terms_lifecycle import DomainCurrencyFixture


def accepted_email(**kwargs):
    log = EmailLog.objects.create(
        customer=kwargs["customer"], to_addr=kwargs["to"], from_addr="billing@example.test",
        subject=kwargs["subject"], body_text=kwargs["body_text"], template_key=kwargs["template_key"],
        status="sent", provider="local-test",
    )
    return EmailResult(success=True, email_log_id=str(log.pk))


class DomainCurrencyNoticeRecoveryTests(DomainCurrencyFixture, TestCase):
    def switch(self):
        self.assertIsInstance(SettingsService.update_setting("billing.default_currency", "EUR"), Ok)

    @override_settings(EMAIL_BACKEND="django.core.mail.backends.locmem.EmailBackend", EMAIL_PROVIDER="smtp")
    def test_real_email_service_records_the_exact_notice_using_only_memory(self):
        self.switch()
        cache.clear()
        self.assertEqual(reconcile_domain_currency_notices()["sent"], 1)
        offer = DomainCurrencyTransition.objects.get()
        self.assertEqual(offer.status, "notified")
        self.assertEqual(len(mail.outbox), 1)
        self.assertEqual(mail.outbox[0].to, ["owner@example.test"])
        self.assertEqual(mail.outbox[0].body, offer.notice_body)
        self.assertEqual(offer.notice_email.get_decrypted_body_text(), offer.notice_body)
        self.assertEqual(offer.notice_email.template_key, f"domain_currency_notice:{offer.pk}")
        self.assertEqual(offer.preparation_not_before, offer.notice_sent_at + timedelta(days=30))

    def test_accepted_log_survives_crash_before_offer_link_and_is_not_resent(self):
        self.switch()

        def accepted_then_crashed(**kwargs):
            accepted_email(**kwargs)
            raise RuntimeError("Worker lost after provider acceptance")

        with patch("apps.notifications.services.EmailService.send_email", side_effect=accepted_then_crashed):
            self.assertEqual(reconcile_domain_currency_notices()["held"], 1)
        offer = DomainCurrencyTransition.objects.get()
        self.assertEqual(offer.status, "pending")
        recovered_at = timezone.now() + timedelta(days=1)
        with (
            patch("django.utils.timezone.now", return_value=recovered_at),
            patch("apps.notifications.services.EmailService.send_email") as sender,
        ):
            self.assertEqual(reconcile_domain_currency_notices()["recovered"], 1)
        sender.assert_not_called()
        offer.refresh_from_db()
        self.assertEqual(offer.notice_sent_at, recovered_at)
        self.assertEqual(offer.preparation_not_before, recovered_at + timedelta(days=30))
        self.assertEqual(offer.notice_email.get_decrypted_body_text(), offer.notice_body)
        self.assertEqual(EmailLog.objects.filter(template_key=f"domain_currency_notice:{offer.pk}").count(), 1)

    def test_each_notice_identity_must_match_the_accepted_log(self):
        self.switch()
        other_customer = Customer.objects.create(name="Other owner", primary_email="other@example.test")
        changed_fields = (
            {"to": "other@example.test"}, {"subject": "Different subject"},
            {"body_text": "Different renewal price"}, {"customer": other_customer},
            {"template_key": "domain_currency_notice:another-offer"},
        )
        now = timezone.now()
        for attempt, changes in enumerate(changed_fields):
            with self.subTest(changes=changes):
                def mismatched_email(*, changes=changes, **kwargs):
                    return accepted_email(**{**kwargs, **changes})

                with (
                    patch("django.utils.timezone.now", return_value=now + timedelta(minutes=attempt * 6)),
                    patch("apps.notifications.services.EmailService.send_email", side_effect=mismatched_email),
                ):
                    self.assertEqual(reconcile_domain_currency_notices()["sent"], 0)
                offer = DomainCurrencyTransition.objects.get()
                self.assertEqual(offer.status, "pending")
                self.assertIsNone(offer.preparation_not_before)
        self.assertEqual(domain_renewal_quote(self.domain, prepared_at=now + timedelta(days=60)).currency_code, "RON")

    def test_queued_notice_starts_wait_when_acceptance_is_observed(self):
        self.switch()

        def queued_email(**kwargs):
            result = accepted_email(**kwargs)
            EmailLog.objects.filter(pk=result.email_log_id).update(status="queued")
            return result

        with patch("apps.notifications.services.EmailService.send_email", side_effect=queued_email):
            self.assertEqual(reconcile_domain_currency_notices()["sent"], 0)
        offer = DomainCurrencyTransition.objects.get()
        accepted_at = timezone.now() + timedelta(days=5)
        EmailLog.objects.filter(template_key=f"domain_currency_notice:{offer.pk}").update(status="sent")
        with (
            patch("django.utils.timezone.now", return_value=accepted_at),
            patch("apps.notifications.services.EmailService.send_email") as sender,
        ):
            self.assertEqual(reconcile_domain_currency_notices()["recovered"], 1)
        sender.assert_not_called()
        offer.refresh_from_db()
        self.assertEqual(offer.preparation_not_before, accepted_at + timedelta(days=30))

    def test_failed_attempt_retries_after_lease_and_requires_full_wait(self):
        self.switch()
        with patch("apps.notifications.services.EmailService.send_email", return_value=EmailResult(success=False)):
            self.assertEqual(reconcile_domain_currency_notices()["sent"], 0)
        accepted_at = timezone.now() + timedelta(minutes=6)
        with (
            patch("django.utils.timezone.now", return_value=accepted_at),
            patch("apps.notifications.services.EmailService.send_email", side_effect=accepted_email),
        ):
            self.assertEqual(reconcile_domain_currency_notices()["sent"], 1)
        self.assertEqual(domain_renewal_quote(self.domain, prepared_at=accepted_at + timedelta(days=29)).currency_code, "RON")
        self.assertEqual(domain_renewal_quote(self.domain, prepared_at=accepted_at + timedelta(days=30)).currency_code, "EUR")


class DomainCurrencyNoticeConcurrencyTests(DomainCurrencyFixture, TransactionTestCase):
    @skipUnless(connection.vendor == "postgresql", "Requires PostgreSQL row locks")
    def test_two_workers_send_one_notice_while_first_sender_is_waiting(self):
        self.assertIsInstance(SettingsService.update_setting("billing.default_currency", "EUR"), Ok)
        started = Event()
        release = Event()

        def sender(**kwargs):
            started.set()
            if not release.wait(timeout=15):
                raise TimeoutError("Test worker was not released")
            return accepted_email(**kwargs)

        def reconcile():
            close_old_connections()
            try:
                return reconcile_domain_currency_notices()
            finally:
                close_old_connections()

        with (
            patch("apps.notifications.services.EmailService.send_email", side_effect=sender) as send,
            ThreadPoolExecutor(max_workers=2) as pool,
        ):
            first = pool.submit(reconcile)
            try:
                self.assertTrue(started.wait(timeout=10))
                second_result = pool.submit(reconcile).result(timeout=10)
                self.assertEqual(second_result["sent"], 0)
            finally:
                release.set()
            self.assertEqual(first.result(timeout=10)["sent"], 1)
        self.assertEqual(send.call_count, 1)
        self.assertEqual(DomainCurrencyTransition.objects.filter(status="notified").count(), 1)
