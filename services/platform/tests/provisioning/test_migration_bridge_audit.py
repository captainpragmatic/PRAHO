"""A retained bridge has its own audited lifecycle after the migration completes."""

from django.test import override_settings

from apps.audit.models import AuditEvent
from tests.provisioning.test_virtualmin_migration_bridge import BridgeCase


@override_settings(DISABLE_AUDIT_SIGNALS=False)
class BridgeAuditTests(BridgeCase):
    def test_each_bridge_transition_is_audited_once_and_evidence_updates_are_not(self) -> None:
        bridge, _migration = self._bridge()
        bridge.activate()
        bridge.save()
        bridge.evidence = {"checked": True}
        bridge.save(update_fields=["evidence", "updated_at"])
        bridge.start_removing_source()
        bridge.save()
        bridge.tear_down()
        bridge.save()

        self.assertCountEqual(
            AuditEvent.objects.filter(object_id=str(bridge.pk), action__startswith="virtualmin_bridge_").values_list(
                "action", flat=True
            ),
            [
                "virtualmin_bridge_pending",
                "virtualmin_bridge_active",
                "virtualmin_bridge_removing_source",
                "virtualmin_bridge_torn_down",
            ],
        )

    def test_a_failed_bridge_is_audited(self) -> None:
        bridge, _migration = self._bridge()
        bridge.fail()
        bridge.save()

        self.assertEqual(
            AuditEvent.objects.filter(object_id=str(bridge.pk), action="virtualmin_bridge_failed").count(), 1
        )
