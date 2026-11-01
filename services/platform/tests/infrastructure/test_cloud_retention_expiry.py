"""Operator-retained cloud snapshots are protected from the older drift expiry worker."""

from datetime import timedelta
from unittest.mock import Mock, patch

from django.test import TestCase
from django.utils import timezone

from apps.common.types import Ok
from apps.infrastructure.cloud_destroy_models import CloudResourceRetention, NodeDestroyPlan
from apps.infrastructure.deployment_lifecycle import provider_token_fingerprint
from apps.infrastructure.models import DriftSnapshot
from apps.infrastructure.tasks import cleanup_old_snapshots_task
from apps.users.models import User
from tests.infrastructure.test_deployment_service_pipeline import _create_deployment


class RetainedExpiryTests(TestCase):
    def setUp(self):
        self.deployment = _create_deployment("completed", external_node_id="vm")
        self.deployment.provider_token_fingerprint = provider_token_fingerprint("token")
        self.deployment.save(update_fields=["provider_token_fingerprint"])
        self.actor = User.objects.create_superuser(email="retention-operator@example.test", password="test-only")
        self.snapshot = DriftSnapshot.objects.create(
            deployment=self.deployment,
            provider_snapshot_id="s",
            snapshot_type="manual",
            status="available",
            expires_at=timezone.now() - timedelta(days=1),
        )
        self.plan = NodeDestroyPlan.objects.create(
            deployment=self.deployment,
            deployment_correlation_id=self.deployment.correlation_id,
            actor=self.actor,
            provider=self.deployment.provider,
            provider_type=self.deployment.provider.provider_type,
            hostname=self.deployment.hostname,
            token_fingerprint=provider_token_fingerprint("token"),
            digest="a" * 64,
            restore_point_policy="keep",
            server_ids=["vm"],
            inventory=[],
            decisions=[],
            reason="Keep",
        )

    def retain(self):
        CloudResourceRetention.objects.create(
            plan=self.plan,
            provider=self.deployment.provider,
            token_fingerprint=self.plan.token_fingerprint,
            kind="snapshot",
            resource_id="s",
        )

    @patch("apps.infrastructure.provider_config.get_provider_token", return_value=Ok("token"))
    @patch("apps.infrastructure.cloud_gateway.get_cloud_gateway")
    def test_expired_snapshot_selected_before_retention_is_rechecked_under_lock(self, gateway, _token):
        # The expiry candidate already exists and is expired before the operator retains it.
        self.retain()
        gateway.return_value.delete_snapshot.return_value = Ok(True)
        result = cleanup_old_snapshots_task()
        gateway.return_value.delete_snapshot.assert_not_called()
        self.snapshot.refresh_from_db()
        self.assertEqual(self.snapshot.status, "available")
        self.assertEqual(result["deleted"], 0)

    @patch("apps.infrastructure.provider_config.get_provider_token", return_value=Ok("replacement"))
    @patch("apps.infrastructure.cloud_gateway.get_cloud_gateway")
    def test_creating_provider_identity_must_match_before_expiry_deletes_anything(self, gateway, _token):
        gateway.return_value.delete_snapshot.return_value = Ok(True)
        result = cleanup_old_snapshots_task()
        gateway.return_value.delete_snapshot.assert_not_called()
        self.snapshot.refresh_from_db()
        self.assertEqual(self.snapshot.status, "cleanup_failed")
        self.assertEqual(result["failed"], 1)

    @patch("apps.infrastructure.provider_config.get_provider_token", return_value=Ok("token"))
    @patch("apps.infrastructure.cloud_gateway.get_cloud_gateway")
    def test_worker_reloads_a_stale_candidate_before_deleting(self, gateway, _token):
        stale = self.snapshot
        DriftSnapshot.objects.filter(pk=stale.pk).update(expires_at=timezone.now() + timedelta(days=10))
        original_filter = DriftSnapshot.objects.filter

        def candidates(*args, **kwargs):
            if kwargs.get("status") == "available" and "expires_at__lte" in kwargs:
                return Mock(select_related=Mock(return_value=[stale]))
            return original_filter(*args, **kwargs)

        gateway.return_value.delete_snapshot.return_value = Ok(True)
        with patch.object(DriftSnapshot.objects, "filter", side_effect=candidates):
            result = cleanup_old_snapshots_task()
        gateway.return_value.delete_snapshot.assert_not_called()
        self.assertEqual(result["deleted"], 0)
