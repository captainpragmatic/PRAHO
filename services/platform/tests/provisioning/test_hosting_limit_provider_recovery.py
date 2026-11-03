"""Original-credential, exact-resource GET proof is distinct from a failed node."""

from types import SimpleNamespace
from unittest.mock import patch

from django.test import TransactionTestCase

from apps.common.types import Ok
from apps.infrastructure.cloud_resource_inventory import CloudResourceClient, ResourceResponse
from apps.infrastructure.deployment_lifecycle import provider_token_fingerprint
from apps.infrastructure.models import NodeDeployment
from apps.provisioning.hosting_limit_execution import apply_hosting_limits
from apps.provisioning.hosting_limit_execution_models import HostingLimitExecution
from apps.provisioning.hosting_limit_provider_recovery import resolve_provider_destroyed_quota
from apps.provisioning.virtualmin_migration_models import account_has_active_operation
from apps.provisioning.virtualmin_models import VirtualminAccount, VirtualminServer
from apps.provisioning.virtualmin_security import connection_identity
from tests.infrastructure.test_deployment_service_pipeline import _create_deployment
from tests.provisioning.test_hosting_limit_execution import HostingLimitWorkerFixture
from tests.provisioning.test_virtualmin_tasks import VirtualminTaskTestBase

_TOKEN = "original-provider-project-fixture"


class QuotaProviderRecoveryTests(HostingLimitWorkerFixture, TransactionTestCase):
    def setUp(self):
        queue = patch("apps.provisioning.hosting_limit_tasks.async_task")
        queue.start()
        self.addCleanup(queue.stop)
        VirtualminTaskTestBase.setUp(self)
        self.setup_native_fixture()
        self.deployment = _create_deployment(status="completed", external_node_id="123")
        self.deployment.virtualmin_server = self.server
        self.deployment.provider_token_fingerprint = provider_token_fingerprint(_TOKEN)
        self.deployment.save(update_fields=["virtualmin_server", "provider_token_fingerprint"])
        self.server = VirtualminServer.objects.get(pk=self.server.pk)
        identity = connection_identity(self.server)
        self.policy.connection_identity = identity
        self.policy.quota_evidence = {**self.policy.quota_evidence, "identity": identity}
        self.policy.save(update_fields=["connection_identity", "quota_evidence"])
        with (
            patch("apps.provisioning.hosting_limit_transport.probe_account_quota", return_value=self.receipt()),
            patch(
                "apps.provisioning.hosting_limit_transport.run_quota_operation",
                side_effect=RuntimeError("response lost"),
            ),
        ):
            self.assertEqual(apply_hosting_limits(self.application.pk), "attention")
        self.execution = HostingLimitExecution.objects.get()
        self.job = self.execution.job
        self.requests = []

    def resolve(self, *, status=404, token=_TOKEN, during_request=None):
        def request(method, path, **kwargs):
            self.requests.append((method, path))
            self.assertEqual(method, "GET", "Source proof can never issue provider destruction")
            self.assertEqual(path, "/servers/123")
            if during_request is not None:
                during_request()
            return ResourceResponse(status, {"server": {"id": 123}} if status == 200 else {})

        client = CloudResourceClient("hetzner", request)
        with (
            patch("apps.infrastructure.provider_config.get_provider_token", return_value=Ok(token)),
            patch(
                "apps.infrastructure.cloud_gateway.get_cloud_gateway",
                return_value=SimpleNamespace(resource_client=lambda: client),
            ),
        ):
            return resolve_provider_destroyed_quota(
                self.job, resolved_by="quota-admin", note="Original source investigated"
            )

    def test_authoritative_original_project_absence_permanently_releases_only_original_execution(self):
        self.assertTrue(self.resolve().is_ok())
        self.execution.refresh_from_db()
        self.assertEqual(self.requests, [("GET", "/servers/123")])
        self.assertEqual(self.execution.phase, "fenced")
        self.assertIsNotNone(self.execution.reservation_released_at)
        self.assertEqual(self.execution.receipt["outcome"], "provider_source_absent")
        self.assertEqual(self.execution.receipt["provider_binding"]["resource_id"], "123")
        self.assertFalse(account_has_active_operation(self.account))
        self.server.refresh_from_db()
        self.assertEqual(self.server.status, "disabled")
        self.account.refresh_from_db()
        self.assertEqual(self.account.status, "error")

    def test_present_original_vm_keeps_native_and_capacity_ownership(self):
        self.assertTrue(self.resolve(status=200).is_err())
        self.execution.refresh_from_db()
        self.assertEqual(self.execution.phase, "attention")
        self.assertIsNone(self.execution.reservation_released_at)

    def test_unknown_provider_result_never_counts_as_absence(self):
        self.assertTrue(self.resolve(status=503).is_err())
        self.execution.refresh_from_db()
        self.assertIsNone(self.execution.reservation_released_at)

    def test_wrong_or_rotated_project_token_cannot_fake_a_not_found(self):
        self.assertTrue(self.resolve(token="rotated-or-wrong-project-fixture").is_err())
        self.assertEqual(self.requests, [])
        self.execution.refresh_from_db()
        self.assertIsNone(self.execution.reservation_released_at)

    def test_canonical_retarget_during_provider_gap_refuses_release(self):
        replacement = VirtualminServer.objects.create(
            name="replacement", hostname="replacement.example.com", api_username="root"
        )
        self.assertTrue(
            self.resolve(
                during_request=lambda: VirtualminAccount.objects.filter(pk=self.account.pk).update(server=replacement)
            ).is_err()
        )
        self.execution.refresh_from_db()
        self.assertEqual(self.execution.phase, "attention")
        self.assertIsNone(self.execution.reservation_released_at)

    def test_provider_resource_retarget_during_gap_refuses_release(self):
        self.assertTrue(
            self.resolve(
                during_request=lambda: NodeDeployment.objects.filter(pk=self.deployment.pk).update(
                    external_node_id="456"
                )
            ).is_err()
        )
        self.execution.refresh_from_db()
        self.assertIsNone(self.execution.reservation_released_at)
