"""Destroy approvals and resource provenance survive retries and cannot be rewritten."""

from django.core.exceptions import ValidationError
from django.test import TestCase

from apps.infrastructure.cloud_destroy_models import CloudResourceOwnership, NodeDestroyPlan
from apps.users.models import User
from tests.infrastructure.test_deployment_service_pipeline import _create_deployment


class DestroyRecordTests(TestCase):
    def setUp(self):
        self.deployment = _create_deployment("completed", external_node_id="vm")
        self.actor = User.objects.create_user(email="destroy-operator@example.test", password="test-only")

    def test_ownership_provenance_cannot_be_reassigned_or_deleted(self):
        proof = CloudResourceOwnership.objects.create(
            deployment=self.deployment,
            deployment_correlation_id=self.deployment.correlation_id,
            provider=self.deployment.provider,
            token_fingerprint="a" * 64,
            kind="server",
            resource_id="vm",
            provenance="create_response",
        )
        proof.resource_id = "another"
        with self.assertRaises(ValidationError):
            proof.save()
        with self.assertRaises(ValidationError):
            CloudResourceOwnership.objects.filter(pk=proof.pk).update(deployment_id=999)
        with self.assertRaises(ValidationError):
            CloudResourceOwnership.objects.filter(pk=proof.pk).delete()

    def test_approval_binds_actor_inventory_choices_and_cannot_be_overwritten(self):
        plan = NodeDestroyPlan.objects.create(
            deployment=self.deployment,
            deployment_correlation_id=self.deployment.correlation_id,
            provider=self.deployment.provider,
            provider_type=self.deployment.provider.provider_type,
            actor=self.actor,
            hostname=self.deployment.hostname,
            token_fingerprint="a" * 64,
            digest="b" * 64,
            restore_point_policy="keep",
            server_ids=["vm"],
            inventory=[],
            decisions=[],
            reason="Keep existing restore points",
        )
        self.assertEqual(plan.actor_id, self.actor.pk)
        plan.restore_point_policy = "delete"
        with self.assertRaises(ValidationError):
            plan.save()
        with self.assertRaises(ValidationError):
            NodeDestroyPlan.objects.filter(pk=plan.pk).delete()
        with self.assertRaises(ValidationError):
            NodeDestroyPlan.objects.bulk_create([plan])

    def test_attested_ownership_must_use_the_deployments_provider(self):
        with self.assertRaises(ValidationError):
            CloudResourceOwnership.objects.create(
                deployment=self.deployment,
                deployment_correlation_id=self.deployment.correlation_id,
                provider_id=999,
                token_fingerprint="a" * 64,
                kind="server",
                resource_id="vm",
                provenance="create_response",
            )

    def test_destructive_retention_choice_requires_an_actor(self):
        with self.assertRaises(ValidationError):
            NodeDestroyPlan.objects.create(
                deployment=self.deployment,
                deployment_correlation_id=self.deployment.correlation_id,
                provider=self.deployment.provider,
                provider_type=self.deployment.provider.provider_type,
                hostname=self.deployment.hostname,
                token_fingerprint="a" * 64,
                digest="b" * 64,
                restore_point_policy="delete",
                server_ids=["vm"],
                inventory=[],
                decisions=[],
            )
