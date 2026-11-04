"""Ended decisions and alert summaries expire independently without moving source cursors."""

from datetime import timedelta
from unittest.mock import patch

from django.test import TestCase

from apps.security import tasks
from apps.security.models import SecurityAlert, SecurityDecision, SecuritySyncState
from tests.security.fixtures import SecurityFixture


class SecurityRetentionTests(SecurityFixture, TestCase):
    def test_expiry_and_bounded_retention_preserve_live_history_and_alert_cursor(self) -> None:
        old = self.now - timedelta(days=91)
        common = {
            "source": self.source,
            "source_created_at": old,
            "scenario": "crowdsecurity/ssh-bf",
            "type": "ban",
            "scope": "ip",
            "value": "198.51.100.8",
            "origin": "crowdsec",
            "address_family": 4,
            "network_start": b"\0" * 12 + bytes((198, 51, 100, 8)),
            "network_end": b"\0" * 12 + bytes((198, 51, 100, 8)),
        }
        SecurityDecision.objects.create(**common, remote_id=1, expires_at=old, ended_at=old)
        expired = SecurityDecision.objects.create(**common, remote_id=2, expires_at=self.now - timedelta(seconds=1))
        live = SecurityDecision.objects.create(**common, remote_id=3, expires_at=self.now + timedelta(hours=4))
        SecurityAlert.objects.create(
            source=self.source,
            remote_id=1,
            source_created_at=self.now - timedelta(days=31),
            scenario="crowdsecurity/ssh-bf",
            event_count=1,
        )
        recent = SecurityAlert.objects.create(
            source=self.source,
            remote_id=2,
            source_created_at=self.now - timedelta(days=29),
            scenario="crowdsecurity/ssh-bf",
            event_count=1,
        )
        SecuritySyncState.objects.filter(source=self.source).update(alert_cursor=2)
        with patch("apps.security.tasks.RETENTION_BATCH", 1):
            self.assertEqual(tasks.prune_security_history(), {"expired": 1, "decisions": 1, "alerts": 1, "observations": 0})
        expired.refresh_from_db()
        self.assertEqual(expired.ended_at, expired.expires_at)
        self.assertTrue(SecurityDecision.objects.filter(pk=live.pk, ended_at__isnull=True).exists())
        self.assertTrue(SecurityAlert.objects.filter(pk=recent.pk).exists())
        self.assertEqual(SecuritySyncState.objects.get(source=self.source).alert_cursor, 2)

    def test_retention_drains_multiple_bounded_batches_and_limits_future_clock_history(self) -> None:
        cutoff = self.now - timedelta(days=31)
        for remote_id in range(1, 4):
            SecurityAlert.objects.create(
                source=self.source,
                remote_id=remote_id,
                source_created_at=cutoff,
                scenario="crowdsecurity/ssh-bf",
                event_count=1,
            )
        future = SecurityAlert.objects.create(
            source=self.source,
            remote_id=4,
            source_created_at=self.now + timedelta(days=365),
            scenario="crowdsecurity/ssh-bf",
            event_count=1,
        )
        SecurityAlert.objects.filter(pk=future.pk).update(created_at=cutoff)
        with patch("apps.security.tasks.RETENTION_BATCH", 1):
            self.assertEqual(tasks.prune_security_history()["alerts"], 4)
        self.assertFalse(SecurityAlert.objects.exists())
