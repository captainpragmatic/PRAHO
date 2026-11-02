"""A completed migration's active target bridge still owns its native identity."""

from django.core.exceptions import ValidationError
from django.test import TransactionTestCase, override_settings

from apps.provisioning.component_migration_models import SourceServiceRelease
from apps.provisioning.virtualmin_migration_models import MigrationBridge
from apps.provisioning.virtualmin_security import record_inspection
from apps.provisioning.virtualmin_security_execution import claim_hardening
from apps.provisioning.virtualmin_security_models import NodeSecurityDecision, NodeSecurityExecution
from tests.infrastructure.maintenance_retained_fixtures import RetainedMaintenanceFixture


@override_settings(
    CACHES={"default": {"BACKEND": "django.core.cache.backends.locmem.LocMemCache"}},
    Q_CLUSTER={"name": "hardening-retained-bridge", "orm": "default", "retry": 100000},
)
class NodeMaintenanceHardeningBridgeTests(RetainedMaintenanceFixture, TransactionTestCase):
    def review_target_hardening(self):
        evidence = self.inspect(self.target)
        return record_inspection(self.target, evidence), evidence

    def test_completed_active_target_bridge_refuses_hardening_before_new_authority(self) -> None:
        self.publish_retained_website(cleanup=False)
        bridge = MigrationBridge.objects.get(migration=self.migration)
        self.assertEqual((self.migration.status, bridge.status), ("completed", "active"))
        self.assertIsNone(self.migration.lease_token)
        self.assertFalse(self.target.retained_source_services.exists())
        review, evidence = self.review_target_hardening()
        decisions = set(NodeSecurityDecision.objects.values_list("pk", flat=True))
        executions = set(NodeSecurityExecution.objects.values_list("pk", flat=True))

        with self.assertRaisesMessage(ValidationError, "migration"):
            claim_hardening(review, evidence, self.actor, "Accept reviewed access changes after service preparation")

        self.assertEqual(set(NodeSecurityDecision.objects.values_list("pk", flat=True)), decisions)
        self.assertEqual(set(NodeSecurityExecution.objects.values_list("pk", flat=True)), executions)
        self.target.refresh_from_db()
        self.assertIsNone(self.target.security_operation)
        bridge.refresh_from_db()
        self.assertEqual(bridge.status, "active")

    def test_actual_native_retirement_allows_new_target_hardening_authority(self) -> None:
        self.publish_retained_website()
        self.assertEqual(MigrationBridge.objects.get(migration=self.migration).status, "torn_down")
        self.assertIsNone(self.migration.lease_token)
        review, evidence = self.review_target_hardening()

        execution = claim_hardening(
            review, evidence, self.actor, "Native bridge retirement verified; accept reviewed access changes"
        )

        self.target.refresh_from_db()
        self.assertEqual(self.target.security_operation, execution.pk)
        self.assertEqual(execution.decision.review_id, review.pk)
        self.assertFalse(
            SourceServiceRelease.objects.filter(obligation_id=self.obligation.pk).exists(),
            "Target hardening must not release source service duties",
        )
