"""The day 0 and day 14 notices of a database overage episode: email, ticket, and the last check before sending."""

from __future__ import annotations

from datetime import timedelta
from unittest.mock import patch
from uuid import uuid4

from django.db import IntegrityError, transaction
from django.db.models import QuerySet
from django.test import TestCase, override_settings
from django.utils import timezone

from apps.customers.models import Customer
from apps.notifications.models import EmailLog, EmailSuppression
from apps.notifications.tasks import send_email_task
from apps.provisioning import database_overage_delivery as delivery
from apps.provisioning.database_overage_delivery import (
    notice_due,
    notice_status,
    overage_dispatch_allowed,
    record_notice_acceptance,
    send_notice,
    setup_overage_notices,
)
from apps.provisioning.database_overage_models import DatabaseOverageEpisode, DatabaseOverageNotice
from apps.tickets.models import Ticket
from apps.tickets.services import TicketStatusService
from tests.helpers.fsm_helpers import force_status
from tests.provisioning.database_overage_fixtures import make_overage_account


class _Notices:
    def setUp(self):
        self.fixture = make_overage_account("notice")
        setup_overage_notices()
        now = timezone.now()
        self.episode = DatabaseOverageEpisode.objects.create(
            account=self.fixture.account,
            service=self.fixture.service,
            service_id_snapshot=self.fixture.service.pk,
            customer_id_snapshot=self.fixture.customer.pk,
            owner_scope=self.fixture.usage.owner_scope,
            server_id=self.fixture.server.pk,
            domain_id=self.fixture.usage.domain_id,
            domain=self.fixture.account.domain,
            installation=self.fixture.installation,
            opened_at=now,
            deadline_at=now + timedelta(days=14),
        )

    def hold(self, digest="sha256:held"):
        self.episode.refresh_from_db()  # a day-0 notice moves the deadline, so the copy here is older
        self.episode.start_hold(token=uuid4(), generation=self.episode.hold_generation + 1)
        self.episode.confirm_held(digest=digest)
        self.episode.save()

    def claim(self, log: EmailLog) -> uuid4:
        """The worker's claim on a queued email, as the queue takes it just before the provider."""
        token = uuid4()
        EmailLog.objects.filter(pk=log.pk).update(
            status="sending", claim_token=token, lease_until=timezone.now() + timedelta(minutes=5)
        )
        return token


class DatabaseOverageNoticeTests(_Notices, TestCase):
    def test_day_zero_stores_one_email_and_opens_one_system_ticket(self):
        self.assertEqual(send_notice(self.episode.pk, "day0"), "sent")
        notice = DatabaseOverageNotice.objects.get(episode=self.episode, kind="day0")
        log = notice.email_log
        self.assertEqual((log.template_key, log.to_addr), ("database_overage_day0", self.fixture.customer.primary_email))
        ticket = notice.ticket
        self.assertEqual(
            (ticket.customer_id, ticket.created_by_id, ticket.source, ticket.related_service_id, ticket.contact_email),
            (self.fixture.customer.pk, None, "internal", self.fixture.service.pk, self.fixture.customer.primary_email),
        )
        self.assertIn(self.fixture.service.service_name, ticket.title)
        self.assertEqual(send_notice(self.episode.pk, "day0"), "exists")
        self.assertEqual((EmailLog.objects.count(), Ticket.objects.count()), (1, 1))

    def test_a_notice_has_an_html_body_as_well_as_its_text(self):
        send_notice(self.episode.pk, "day0")
        log = DatabaseOverageNotice.objects.get(kind="day0").email_log
        text, html = log.get_decrypted_body_text(), log.get_decrypted_body_html()
        self.assertIn(self.fixture.service.service_name, text)
        self.assertTrue(html.startswith("<p>"), html)
        self.assertEqual(html.count("<p>"), len(text.strip().split("\n")))  # paragraph for paragraph
        self.assertIn(self.fixture.service.service_name, html)

    def test_one_notice_of_each_kind_per_episode(self):
        send_notice(self.episode.pk, "day0")
        with self.assertRaises(IntegrityError), transaction.atomic():
            DatabaseOverageNotice.objects.create(episode=self.episode, kind="day0", recipient_hash="x")

    def test_day_fourteen_needs_a_confirmed_hold_and_writes_on_the_day_zero_ticket(self):
        send_notice(self.episode.pk, "day0")
        self.assertEqual(send_notice(self.episode.pk, "day14"), "overage_not_held")
        ticket = DatabaseOverageNotice.objects.get(kind="day0").ticket
        TicketStatusService.close_ticket(ticket, "fixed")
        self.hold()
        self.assertEqual(send_notice(self.episode.pk, "day14"), "sent")
        notice = DatabaseOverageNotice.objects.get(kind="day14")
        self.assertEqual((notice.ticket_id, notice.held_digest), (ticket.pk, "sha256:held"))
        ticket.refresh_from_db()
        self.assertEqual(ticket.status, "open")  # news the customer needs reopens a ticket they closed
        self.assertEqual(ticket.comments.filter(is_public=True, author__isnull=True).count(), 1)
        self.assertEqual(Ticket.objects.count(), 1)

    def test_no_notice_for_a_closed_episode_or_an_inactive_service(self):
        self.episode.close("waived")
        self.episode.save()
        self.assertEqual(send_notice(self.episode.pk, "day0"), "overage_episode_closed")
        self.assertFalse(EmailLog.objects.exists())

    def test_a_day_zero_sent_late_gives_a_full_grace_period_and_says_so(self):
        now = timezone.now().replace(microsecond=0)
        DatabaseOverageEpisode.objects.filter(pk=self.episode.pk).update(deadline_at=now + timedelta(days=10))
        self.assertEqual(send_notice(self.episode.pk, "day0", at=now), "sent")
        self.episode.refresh_from_db()
        self.assertEqual(self.episode.deadline_at, now + timedelta(days=14))
        body = DatabaseOverageNotice.objects.get(kind="day0").email_log.get_decrypted_body_text()
        self.assertIn(timezone.localtime(now + timedelta(days=14)).strftime("%Y-%m-%d %H:%M"), body)

    def test_a_refused_notice_can_be_replaced_but_an_accepted_one_cannot(self):
        send_notice(self.episode.pk, "day0")
        notice = DatabaseOverageNotice.objects.get(kind="day0")
        first = notice.email_log
        token = self.claim(first)
        force_status(self.fixture.service, "suspended")
        self.assertFalse(overage_dispatch_allowed(str(first.pk), token))
        force_status(self.fixture.service, "active")
        self.assertEqual(send_notice(self.episode.pk, "day0"), "sent")
        notice.refresh_from_db()
        self.assertNotEqual(notice.email_log_id, first.pk)
        self.assertEqual((notice.refusal_reason, Ticket.objects.count()), ("", 1))
        EmailLog.objects.filter(pk=notice.email_log_id).update(status="sent", sent_at=timezone.now())
        record_notice_acceptance()
        self.assertEqual(send_notice(self.episode.pk, "day0"), "exists")
        self.assertEqual(EmailLog.objects.count(), 2)
        # A provider that reports a failure after accepting it, and an address changed since: still told once.
        EmailLog.objects.filter(pk=notice.email_log_id).update(status="failed")
        Customer.objects.filter(pk=self.fixture.customer.pk).update(primary_email="fixed@example.test")
        self.assertEqual(send_notice(self.episode.pk, "day0"), "exists")

    def test_a_notice_that_failed_for_good_goes_again_only_to_a_corrected_address(self):
        send_notice(self.episode.pk, "day0")
        notice = DatabaseOverageNotice.objects.get(kind="day0")
        first = notice.email_log
        EmailLog.objects.filter(pk=first.pk).update(status="failed", provider_response={})  # a retry may follow
        Customer.objects.filter(pk=self.fixture.customer.pk).update(primary_email="fixed@example.test")
        self.assertEqual(send_notice(self.episode.pk, "day0"), "exists")  # the email queue may still send it
        self.assertFalse(notice_due(self.episode, "day0"))
        Customer.objects.filter(pk=self.fixture.customer.pk).update(primary_email=self.fixture.customer.primary_email)
        # The recipient's server refused it for good.
        EmailLog.objects.filter(pk=first.pk).update(provider_response={"permanent_failure": True})
        self.assertEqual(send_notice(self.episode.pk, "day0"), "exists")  # never again to the failing address
        self.assertFalse(notice_due(self.episode, "day0"))
        Customer.objects.filter(pk=self.fixture.customer.pk).update(primary_email="fixed@example.test")
        self.assertTrue(notice_due(self.episode, "day0"))
        self.assertEqual(send_notice(self.episode.pk, "day0"), "sent")
        notice.refresh_from_db()
        self.assertNotEqual(notice.email_log_id, first.pk)
        self.assertEqual((notice.email_log.to_addr, Ticket.objects.count()), ("fixed@example.test", 1))
        EmailLog.objects.filter(pk=notice.email_log_id).update(status="queued")
        Customer.objects.filter(pk=self.fixture.customer.pk).update(primary_email="again@example.test")
        self.assertEqual(send_notice(self.episode.pk, "day0"), "exists")  # still in flight: the queue decides

    def test_accepted_means_the_provider_accepted_it_and_a_late_day_zero_moves_the_deadline(self):
        send_notice(self.episode.pk, "day0")
        notice = DatabaseOverageNotice.objects.get(kind="day0")
        self.assertEqual(record_notice_acceptance(), 0)  # queued is not accepted
        accepted = self.episode.deadline_at - timedelta(days=10)  # 4 days after opening
        EmailLog.objects.filter(pk=notice.email_log_id).update(status="sent", sent_at=accepted)
        self.assertEqual(record_notice_acceptance(), 1)
        notice.refresh_from_db()
        self.episode.refresh_from_db()
        self.assertEqual(notice.accepted_at, accepted)
        self.assertEqual(self.episode.deadline_at, accepted + timedelta(days=14))


class NoticeStatusTests(_Notices, TestCase):
    """What staff see for a notice comes from its email's own state, failures included."""

    def status(self, **email) -> dict:
        notice = DatabaseOverageNotice.objects.get(kind="day0")
        if email:
            EmailLog.objects.filter(pk=notice.email_log_id).update(**email)
        notice = DatabaseOverageNotice.objects.select_related("email_log").get(pk=notice.pk)
        return notice_status(notice)

    def setUp(self):
        super().setUp()
        send_notice(self.episode.pk, "day0")

    def test_each_email_state_is_shown_as_it_is(self):
        cases = [
            ({}, "Queued"),
            ({"status": "sending"}, "Sending"),
            ({"status": "failed", "provider_response": {"final_error": "timeout"}}, "Failed, to be retried"),
            ({"status": "soft_bounced"}, "Soft bounce, to be retried"),
            ({"status": "failed", "provider_response": {"permanent_failure": True, "final_error": "550 no such user"}},
             "Failed for good: 550 no such user"),
            ({"status": "failed", "provider_response": {"retry_exhausted": True}}, "Failed for good: retries exhausted"),
            ({"status": "rejected", "provider_response": {}}, "Failed for good: rejected by the provider"),
        ]
        for email, label in cases:
            with self.subTest(label=label):
                self.assertEqual(self.status(**email)["label"], label)

    def test_accepted_then_bounced_is_not_shown_as_delivered(self):
        sent = timezone.now()
        self.status(status="sent", sent_at=sent)
        record_notice_acceptance()
        self.assertEqual(self.status()["label"], "Accepted by the provider")
        self.assertEqual(self.status(status="bounced")["label"], "Bounced after the provider accepted it")
        self.assertEqual(self.status(status="complained")["label"], "Marked as spam by the recipient")
        self.assertEqual(self.status(status="delivered")["label"], "Delivered")

    def test_an_accepted_notice_whose_email_log_was_purged_stays_accepted(self):
        sent = timezone.now()
        self.status(status="sent", sent_at=sent)
        record_notice_acceptance()
        EmailLog.objects.all().delete()  # email retention removes logs; the notice keeps its acceptance
        status = self.status()
        self.assertEqual(status["label"], "Accepted by the provider (delivery details no longer kept)")
        self.assertEqual(status["at"], DatabaseOverageNotice.objects.get(kind="day0").accepted_at)

    def test_a_refused_notice_says_why(self):
        DatabaseOverageNotice.objects.filter(kind="day0").update(refusal_reason="overage_recipient_changed")
        self.assertEqual(self.status()["label"], "Not sent: overage_recipient_changed")


class DatabaseOverageDispatchTests(_Notices, TestCase):
    def setUp(self):
        super().setUp()
        send_notice(self.episode.pk, "day0")
        self.episode.refresh_from_db()
        self.notice = DatabaseOverageNotice.objects.get(kind="day0")
        self.log = self.notice.email_log

    def test_a_current_notice_is_allowed_and_an_unrelated_email_is_left_alone(self):
        self.assertTrue(overage_dispatch_allowed(str(self.log.pk), self.claim(self.log)))
        other = EmailLog.objects.create(to_addr="other@example.test", subject="Other", template_key="welcome")
        self.assertTrue(overage_dispatch_allowed(str(other.pk), None))

    def test_a_notice_whose_episode_moved_on_is_refused_for_good(self):
        token = self.claim(self.log)
        self.episode.close("under_allowance")
        self.episode.save()
        self.assertFalse(overage_dispatch_allowed(str(self.log.pk), token))
        self.log.refresh_from_db()
        self.notice.refresh_from_db()
        self.assertEqual((self.log.status, self.notice.refusal_reason), ("failed", "overage_episode_closed"))

    def test_a_changed_recipient_or_owner_is_refused(self):
        for change in ("recipient", "owner"):
            with self.subTest(change=change), transaction.atomic():
                token = self.claim(self.log)
                if change == "recipient":
                    self.fixture.customer.primary_email = "someone-else@example.test"
                    self.fixture.customer.save(update_fields=["primary_email"])
                else:
                    self.fixture.usage.owner_scope = uuid4()
                    self.fixture.usage.save(update_fields=["owner_scope"])
                self.assertFalse(overage_dispatch_allowed(str(self.log.pk), token))
                transaction.set_rollback(True)

    def test_a_day_fourteen_notice_for_an_older_hold_is_refused(self):
        self.hold("sha256:first")
        send_notice(self.episode.pk, "day14")
        notice = DatabaseOverageNotice.objects.get(kind="day14")
        token = self.claim(notice.email_log)
        self.episode.start_release("hold_refused")
        self.episode.save()
        self.episode.confirm_released_to_grace()
        self.episode.save()
        self.hold("sha256:second")
        self.assertFalse(overage_dispatch_allowed(str(notice.email_log_id), token))
        notice.refresh_from_db()
        self.assertEqual(notice.refusal_reason, "overage_not_held")

    @override_settings(EMAIL_BACKEND="django.core.mail.backends.smtp.EmailBackend")
    def test_the_queue_asks_before_the_provider_sees_a_notice(self):
        self.episode.close("waived")
        self.episode.save()
        with patch("django.core.mail.EmailMultiAlternatives.send", autospec=True, return_value=1) as provider:
            result = send_email_task(str(self.log.pk))
        self.assertEqual(result["error"], "Database overage notice is no longer permitted", result)
        provider.assert_not_called()
        self.log.refresh_from_db()
        self.assertEqual(self.log.status, "failed")  # refused for good, never retried

    def test_an_address_suppressed_after_queueing_is_refused(self):
        token = self.claim(self.log)
        EmailSuppression.suppress(self.fixture.customer.primary_email, "hard_bounce")
        self.assertFalse(overage_dispatch_allowed(str(self.log.pk), token))
        self.notice.refresh_from_db()
        self.assertEqual(self.notice.refusal_reason, "overage_recipient_suppressed")

    def test_a_new_hold_with_the_same_digest_is_still_a_different_hold(self):
        self.hold("sha256:same")
        send_notice(self.episode.pk, "day14")
        notice = DatabaseOverageNotice.objects.get(kind="day14")
        token = self.claim(notice.email_log)
        self.episode.start_release("hold_refused")
        self.episode.save()
        self.episode.confirm_released_to_grace()
        self.episode.save()
        self.hold("sha256:same")
        self.assertFalse(overage_dispatch_allowed(str(notice.email_log_id), token))

    def test_an_email_its_notice_replaced_meanwhile_is_refused(self):
        notice = DatabaseOverageNotice.objects.get(kind="day0")
        old = notice.email_log
        stale = delivery._notice_hint(str(old.pk))  # read by the queue before the replacement committed
        EmailLog.objects.filter(pk=old.pk).update(status="failed", provider_response={"permanent_failure": True})
        Customer.objects.filter(pk=self.fixture.customer.pk).update(primary_email="fixed@example.test")
        self.assertEqual(send_notice(self.episode.pk, "day0"), "sent")
        EmailLog.objects.filter(pk=old.pk).update(status="queued")  # an operator requeues the old one anyway
        token = self.claim(old)
        with patch.object(delivery, "_notice_hint", return_value=stale):
            self.assertFalse(overage_dispatch_allowed(str(old.pk), token))
        old.refresh_from_db()
        self.assertEqual(old.status, "failed")
        notice.refresh_from_db()
        self.assertEqual(notice.refusal_reason, "")  # the replacement stands

    def test_an_orphan_notice_email_is_refused(self):
        orphan = EmailLog.objects.create(to_addr="x@example.test", subject="x", template_key="database_overage_day0")
        token = self.claim(orphan)
        self.assertFalse(overage_dispatch_allowed(str(orphan.pk), token))
        orphan.refresh_from_db()
        self.assertEqual(orphan.status, "failed")


class DatabaseOverageLockOrderTests(_Notices, TestCase):
    """Every notice path locks the episode before its notice, so two of them can't deadlock on each other."""

    def locked_models(self, action) -> list[str]:
        order: list[str] = []
        original = QuerySet.select_for_update

        def record(queryset, *args, **kwargs):
            order.append(queryset.model.__name__)
            return original(queryset, *args, **kwargs)

        with patch.object(QuerySet, "select_for_update", autospec=True, side_effect=record):
            action()
        return [name for name in order if name in {"DatabaseOverageEpisode", "DatabaseOverageNotice", "EmailLog"}]

    def assert_episode_first(self, locked: list[str]) -> None:
        self.assertIn("DatabaseOverageNotice", locked)
        self.assertEqual(locked[0], "DatabaseOverageEpisode", locked)

    def test_send_dispatch_and_acceptance_lock_the_episode_first(self):
        self.assert_episode_first(self.locked_models(lambda: send_notice(self.episode.pk, "day0")))
        notice = DatabaseOverageNotice.objects.get(kind="day0")
        token = self.claim(notice.email_log)
        self.assert_episode_first(self.locked_models(lambda: overage_dispatch_allowed(str(notice.email_log_id), token)))
        EmailLog.objects.filter(pk=notice.email_log_id).update(status="sent", sent_at=timezone.now())
        self.assert_episode_first(self.locked_models(record_notice_acceptance))

    def test_a_replacement_locks_the_failed_email_last_as_the_queue_does(self):
        send_notice(self.episode.pk, "day0")
        notice = DatabaseOverageNotice.objects.get(kind="day0")
        EmailLog.objects.filter(pk=notice.email_log_id).update(
            status="failed", provider_response={"permanent_failure": True}
        )
        Customer.objects.filter(pk=self.fixture.customer.pk).update(primary_email="fixed@example.test")
        locked = self.locked_models(lambda: send_notice(self.episode.pk, "day0"))
        self.assertEqual(locked[:3], ["DatabaseOverageEpisode", "DatabaseOverageNotice", "EmailLog"])
