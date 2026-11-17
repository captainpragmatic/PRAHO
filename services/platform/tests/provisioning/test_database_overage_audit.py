"""What a database overage episode leaves in the audit trail, and how long the trail is kept."""

from __future__ import annotations

from datetime import timedelta
from unittest.mock import patch
from uuid import uuid4

from django.contrib.contenttypes.models import ContentType
from django.test import TestCase
from django.utils import timezone

from apps.audit.models import AuditEvent
from apps.audit.services import AuditRetentionService
from apps.notifications.models import EmailLog
from apps.provisioning.database_overage_delivery import (
    overage_dispatch_allowed,
    record_notice_acceptance,
    send_notice,
    setup_overage_notices,
)
from apps.provisioning.database_overage_models import DatabaseOverageEpisode, DatabaseOverageNotice
from apps.provisioning.database_overage_service import AUDIT_ACTIONS, MIB, audit_episode, evaluate_account
from apps.provisioning.virtualmin_usage_models import UsageReading
from apps.settings.models import SystemSetting
from tests.helpers.fsm_helpers import force_status
from tests.provisioning.database_overage_fixtures import make_overage_account


class DatabaseOverageAuditTests(TestCase):
    def setUp(self):
        self.fixture = make_overage_account("audit")
        self.start = timezone.now().replace(microsecond=0) - timedelta(days=3)
        self.fixture.usage.gauge_not_before = self.start - timedelta(days=1)
        self.fixture.usage.save(update_fields=["gauge_not_before"])
        SystemSetting.objects.create(
            key="provisioning.database_overage_enabled",
            value=True,
            default_value=False,
            data_type="boolean",
            category="provisioning",
        )
        allowance = patch("apps.provisioning.database_overage_service.allowance_bytes", return_value=1000 * MIB)
        allowance.start()
        self.addCleanup(allowance.stop)

    def read(self, at, total):
        reading = UsageReading.objects.create(
            account=self.fixture.account,
            owner_scope=self.fixture.usage.owner_scope,
            sync_token=uuid4(),
            server_id_snapshot=self.fixture.server.pk,
            chain_epoch=self.fixture.account.chain_epoch,
            taken_at=at,
            scan_started_at=at - timedelta(minutes=1),
            disk_files_bytes=total - 300 * MIB,
            disk_db_bytes=300 * MIB,
            disk_total_bytes=total,
            period_start=at - timedelta(days=1),
            period_end=at + timedelta(days=30),
            period_timezone="UTC",
        )
        self.fixture.usage.disk_reading = reading
        self.fixture.usage.save(update_fields=["disk_reading"])

    def events(self, episode) -> list[AuditEvent]:
        return list(
            AuditEvent.objects.filter(
                content_type=ContentType.objects.get_for_model(DatabaseOverageEpisode),
                object_id=str(episode.pk),
                action__in=AUDIT_ACTIONS,  # the generic status_changed trail is recorded alongside
            ).order_by("timestamp")
        )

    def test_opening_notices_and_closing_are_system_events_on_the_episode(self):
        self.read(self.start, 1200 * MIB)
        evaluate_account(self.fixture.account.pk, at=self.start)
        episode = DatabaseOverageEpisode.objects.get(account=self.fixture.account)
        setup_overage_notices()
        send_notice(episode.pk, "day0", at=self.start)
        notice = DatabaseOverageNotice.objects.get(kind="day0")
        EmailLog.objects.filter(pk=notice.email_log_id).update(status="sent", sent_at=self.start + timedelta(minutes=1))
        record_notice_acceptance()
        for hour in range(1, 26):
            self.read(self.start + timedelta(hours=hour), 800 * MIB)
            evaluate_account(self.fixture.account.pk, at=self.start + timedelta(hours=hour, minutes=5))
        events = self.events(episode)
        self.assertEqual(
            [event.action for event in events],
            ["database_overage_opened", "database_overage_notice_sent", "database_overage_closed"],
        )
        self.assertEqual({event.actor_type for event in events}, {"system"})
        self.assertEqual(events[2].new_values["close_reason"], "under_allowance")

    def test_the_trail_keeps_its_evidence_after_readings_and_emails_are_purged(self):
        """Readings and email logs are cleaned up long before the claims period ends."""
        self.read(self.start, 1200 * MIB)
        evaluate_account(self.fixture.account.pk, at=self.start)
        episode = DatabaseOverageEpisode.objects.get(account=self.fixture.account)
        setup_overage_notices()
        send_notice(episode.pk, "day0", at=self.start)
        notice = DatabaseOverageNotice.objects.get(kind="day0")
        self.assertEqual(self.events(episode)[-1].action, "database_overage_opened")  # queued is not sent
        accepted = self.start + timedelta(minutes=1)
        EmailLog.objects.filter(pk=notice.email_log_id).update(status="sent", sent_at=accepted)
        record_notice_acceptance()
        UsageReading.objects.all().delete()
        EmailLog.objects.all().delete()
        opened, sent = self.events(episode)
        self.assertEqual(
            {key: opened.new_values[key] for key in ("disk_total_bytes", "disk_db_bytes", "allowance_bytes")},
            {"disk_total_bytes": 1200 * MIB, "disk_db_bytes": 300 * MIB, "allowance_bytes": 1000 * MIB},
        )
        self.assertEqual(opened.new_values["taken_at"], self.start.isoformat())
        self.assertEqual(sent.new_values["kind"], "day0")
        self.assertEqual(sent.new_values["accepted_at"], accepted.isoformat())
        self.assertEqual(sent.new_values["template_key"], "database_overage_day0")
        self.assertIn("deadline", sent.new_values["context"])
        self.assertEqual(len(sent.new_values["body_sha256"]), 64)

    def test_a_notice_refused_before_the_provider_is_never_recorded_as_sent(self):
        self.read(self.start, 1200 * MIB)
        evaluate_account(self.fixture.account.pk, at=self.start)
        episode = DatabaseOverageEpisode.objects.get(account=self.fixture.account)
        setup_overage_notices()
        send_notice(episode.pk, "day0", at=self.start)
        notice = DatabaseOverageNotice.objects.get(kind="day0")
        token = uuid4()
        EmailLog.objects.filter(pk=notice.email_log_id).update(
            status="sending", claim_token=token, lease_until=timezone.now() + timedelta(minutes=5)
        )
        force_status(self.fixture.service, "suspended")
        self.assertFalse(overage_dispatch_allowed(str(notice.email_log_id), token))
        record_notice_acceptance()
        self.assertNotIn("database_overage_notice_sent", [event.action for event in self.events(episode)])

    def test_a_change_of_owner_closes_with_its_own_reason_on_record(self):
        self.read(self.start, 1200 * MIB)
        evaluate_account(self.fixture.account.pk, at=self.start)
        episode = DatabaseOverageEpisode.objects.get(account=self.fixture.account)
        self.fixture.usage.owner_scope = uuid4()
        self.fixture.usage.save(update_fields=["owner_scope"])
        evaluate_account(self.fixture.account.pk, at=self.start + timedelta(minutes=10))
        closed = self.events(episode)[-1]
        self.assertEqual((closed.action, closed.new_values["close_reason"]), ("database_overage_closed", "ownership_changed"))

    def test_only_the_episode_actions_are_written(self):
        self.read(self.start, 1200 * MIB)
        evaluate_account(self.fixture.account.pk, at=self.start)
        episode = DatabaseOverageEpisode.objects.get(account=self.fixture.account)
        with self.assertRaises(ValueError):
            audit_episode(episode, "update", "not an overage action")

    def test_every_overage_action_is_kept_as_contract_evidence(self):
        now = timezone.now()
        for action in AUDIT_ACTIONS:
            with self.subTest(action=action):
                event = AuditEvent(action=action, timestamp=now - timedelta(days=400))
                self.assertTrue(AuditRetentionService.is_held_for_claims(event, now))
