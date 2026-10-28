"""Old email logs are cleaned up without touching the ones a record still points at (#751 follow-up).

A currency notice keeps its email log (PROTECT): the notice is the proof the customer was told. The
cleanup used to delete every old log in one batch, so a single referenced row raised and stopped it.
"""

from __future__ import annotations

from datetime import timedelta

from django.db.models import ProtectedError
from django.test import TestCase
from django.utils import timezone

from apps.customers.models import Customer
from apps.domains.models import TLD, Domain, DomainCurrencyTransition, Registrar
from apps.notifications.models import EmailLog
from apps.notifications.tasks import cleanup_old_email_logs


def _old_log(subject: str) -> EmailLog:
    row = EmailLog.objects.create(to_addr="owner@example.test", subject=subject, body_text="Body", status="sent")
    EmailLog.objects.filter(pk=row.pk).update(sent_at=timezone.now() - timedelta(days=120))
    return row


class EmailLogCleanupTests(TestCase):
    def test_a_log_a_notice_points_at_is_kept_and_the_rest_are_deleted(self) -> None:
        customer = Customer.objects.create(name="Domain owner", primary_email="owner@example.test")
        tld = TLD.objects.create(
            extension="com", registration_price_cents=6000, renewal_price_cents=5000, transfer_price_cents=4500
        )
        registrar = Registrar.objects.create(name="gandi", api_endpoint="https://api.sandbox.gandi.net/v5")
        domain = Domain.objects.create(
            name="cleanup.com",
            customer=customer,
            tld=tld,
            registrar=registrar,
            status="active",
            registrar_domain_id="cleanup",
            expires_at=timezone.now() + timedelta(days=90),
        )
        referenced = _old_log("Currency notice")
        DomainCurrencyTransition.objects.create(
            domain=domain,
            policy_revision=1,
            old_terms={},
            target_terms={},
            target_fingerprint="0" * 64,
            notice_recipient="owner@example.test",
            notice_subject="Currency notice",
            notice_body="Body",
            notice_email=referenced,
        )
        unreferenced = _old_log("Old newsletter")

        try:
            result = cleanup_old_email_logs(retention_days=90)
        except ProtectedError:
            self.fail("a log a notice points at must not stop the cleanup")

        self.assertEqual(result["deleted"], 1)
        self.assertTrue(EmailLog.objects.filter(pk=referenced.pk).exists())
        self.assertFalse(EmailLog.objects.filter(pk=unreferenced.pk).exists())


class UndeliveredRetentionTests(TestCase):
    def test_a_message_not_yet_delivered_is_never_cleaned_up(self) -> None:
        outstanding = [_old_log(f"Outstanding {status}") for status in ("queued", "sending")]
        for row, status in zip(outstanding, ("queued", "sending"), strict=True):
            EmailLog.objects.filter(pk=row.pk).update(status=status)
        finished = _old_log("Delivered long ago")

        cleanup_old_email_logs(retention_days=90)

        remaining = set(EmailLog.objects.values_list("pk", flat=True))
        self.assertEqual(remaining, {row.pk for row in outstanding}, "only finished messages age out")
        self.assertNotIn(finished.pk, remaining)
