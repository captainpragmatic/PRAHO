"""Staff can extend retention or retry cleanup without changing account ownership."""

from datetime import datetime, timedelta
from unittest.mock import patch

from django.utils import timezone

from apps.provisioning.migration_bridge_cleanup import control_bridge, schedule_bridge_cleanup
from apps.provisioning.virtualmin_migration_models import VirtualminMigration
from tests.provisioning.test_virtualmin_migration_bridge import BridgeCase


class BridgeControlTests(BridgeCase):
    def test_delayed_convergence_cannot_schedule_retention_past_the_certificate(self):
        bridge, migration = self.active()
        deadline = timezone.now() + timedelta(hours=2)
        bridge.evidence = {"certificate_not_after": deadline.isoformat()}
        bridge.save(update_fields=["evidence", "updated_at"])
        with patch("apps.provisioning.migration_bridge_cleanup.schedule"):
            schedule_bridge_cleanup(migration.pk)
        bridge.refresh_from_db()
        self.assertLessEqual(datetime.fromisoformat(bridge.evidence["expires_at"]), deadline - timedelta(hours=1))

    def active(self):
        bridge, migration = self._bridge()
        bridge.activate()
        bridge.evidence = {
            "expires_at": (timezone.now() + timedelta(hours=1)).isoformat(),
            "certificate_not_after": (timezone.now() + timedelta(days=30)).isoformat(),
        }
        bridge.save()
        VirtualminMigration.objects.filter(pk=migration.pk).update(status="completed")  # fsm-bypass: completed fixture
        return bridge, migration

    def test_extension_moves_the_deadline_forward_and_keeps_the_target(self):
        bridge, migration = self.active()
        before = datetime.fromisoformat(bridge.evidence["expires_at"])
        with patch("apps.provisioning.migration_bridge_cleanup.schedule_bridge_cleanup"):
            result = control_bridge(migration.pk, action="extend", actor=self.staff)
        self.assertTrue(result.is_ok(), result)
        bridge.refresh_from_db()
        self.assertGreaterEqual(datetime.fromisoformat(bridge.evidence["expires_at"]), before + timedelta(hours=48))
        self.assertEqual(bridge.status, "active")

    def test_failed_cleanup_is_retried_without_discarding_progress(self):
        bridge, migration = self.active()
        bridge.evidence["source_removed"] = True
        bridge.fail()
        bridge.save()
        with patch("apps.provisioning.migration_bridge_cleanup.schedule_bridge_cleanup"):
            result = control_bridge(migration.pk, action="retry", actor=self.staff)
        self.assertTrue(result.is_ok(), result)
        bridge.refresh_from_db()
        self.assertEqual(bridge.status, "active")
        self.assertTrue(bridge.evidence["source_removed"])

    def test_extension_refuses_unknown_or_insufficient_certificate_lifetime(self):
        bridge, migration = self.active()
        for deadline in (None, (timezone.now() + timedelta(hours=2)).isoformat()):
            with self.subTest(deadline=deadline):
                bridge.evidence["certificate_not_after"] = deadline
                bridge.save(update_fields=["evidence", "updated_at"])
                before = bridge.evidence["expires_at"]
                with patch("apps.provisioning.migration_bridge_cleanup.schedule_bridge_cleanup") as dispatch:
                    result = control_bridge(migration.pk, action="extend", actor=self.staff)
                self.assertTrue(result.is_err(), result)
                bridge.refresh_from_db()
                self.assertEqual(bridge.evidence["expires_at"], before)
                dispatch.assert_not_called()
