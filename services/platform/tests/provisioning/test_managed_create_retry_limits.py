"""Public create retries publish verified quotas while their parent still owns its claim."""

from unittest.mock import patch

from django.db import DatabaseError, connection
from django.utils import timezone

from apps.common.types import Ok
from apps.provisioning.hosting_limit_execution_models import HostingLimitExecution
from apps.provisioning.hosting_limit_models import ServiceHostingLimits
from apps.provisioning.hosting_node_policy_models import NodeHostingPolicy
from apps.provisioning.virtualmin_models import VirtualminAccount
from apps.provisioning.virtualmin_security import connection_identity
from apps.settings.services import SettingsService
from tests.provisioning import test_hosting_limit_execution as limit_fixtures
from tests.provisioning.test_hosting_node_policy import quota_evidence
from tests.provisioning.test_virtualmin_create_retry_node_capability import CombinedRetryFixture


class ManagedCreateRetryLimitsTests(limit_fixtures.HostingLimitWorkerFixture, CombinedRetryFixture):
    def setUp(self) -> None:
        self.assertTrue(SettingsService.update_setting("virtualmin.domain_quota_default_mb", 1024).is_ok())
        self.assertTrue(SettingsService.update_setting("virtualmin.bandwidth_quota_default_mb", 20 * 1024).is_ok())
        super().setUp()
        evidence = quota_evidence()
        evidence["identity"] = connection_identity(self.server)
        NodeHostingPolicy.objects.create(
            server=self.server,
            connection_identity=evidence["identity"],
            quota_adopted=True,
            quota_verified_at=timezone.now(),
            quota_evidence=evidence,
        )
        self.native_identity = {key: evidence[key] for key in ("installation", "filesystem_uuid", "boot_id")}
        self.native_identity.update(domain_id="12345", domain=self.service.domain, uid=1001, gid=1001)
        health = patch.object(
            self.gateway,
            "test_connection",
            return_value=Ok({"healthy": True, "data": {"available_disk_mb": 100 * 1024}}),
        )
        probe = patch("apps.provisioning.hosting_limit_transport.probe_account_quota", return_value=self.receipt())
        native = patch(
            "apps.provisioning.hosting_limit_transport.run_quota_operation",
            side_effect=lambda server, action, request: {
                **self.receipt(cap=request["disk_limit_kib"] // 1024, request=request),
                "configured_bandwidth_bytes": request["bandwidth_limit_bytes"],
            },
        )
        for boundary in (health, probe, native):
            boundary.start()
            self.addCleanup(boundary.stop)

    def assert_settled_managed_retry(self, outcome, *, creates: int) -> None:
        self.assertTrue(
            outcome["success"],
            (outcome, list(HostingLimitExecution.objects.values("phase", "job__status_message"))),
        )
        self.account.refresh_from_db()
        self.job.refresh_from_db()
        self.server.refresh_from_db()
        self.service.refresh_from_db()
        limits = ServiceHostingLimits.objects.get(service=self.service)
        self.assertEqual((self.account.status, self.job.status), ("active", "completed"))
        self.assertTrue(self.account.quota_managed)
        self.assertEqual(limits.applied_revision, limits.revision)
        self.assertEqual(limits.operational_revision, limits.revision)
        cap = self.account.effective_disk_quota_mb
        if cap is None:
            self.fail("Verified managed retry did not publish its effective native quota")
        self.assertEqual(limits.verified_receipt["uid_hard_kib"], cap * 1024)
        self.assertEqual(limits.verified_receipt["gid_hard_kib"], cap * 1024)
        self.assertEqual(self.server.current_domains, 1)
        self.assertEqual(self.service.price, 10)
        self.assertTrue(limits.verified_receipt)
        execution = HostingLimitExecution.objects.get(job__account=self.account, phase="completed")
        self.assertIsNotNone(execution.reservation_released_at)
        self.assertEqual(limits.verified_receipt["token"], execution.receipt["token"])
        self.assertEqual(len(self.gateway.get_calls("create-domain")), creates)
        self.assertEqual(len(self.gateway.get_calls("delete-domain")), 0)
        self.assertEqual(len(self.gateway.get_calls("enable-domain")), 0)

    def test_absent_remote_retry_publishes_verified_limits_with_canonical_settlement(self) -> None:
        self._failed_public_create()
        self.assert_settled_managed_retry(self._retry_through_public_sweep(), creates=2)

    def test_accepted_original_retry_publishes_verified_limits_without_recreating_domain(self) -> None:
        self._accepted_original()
        self.assert_settled_managed_retry(self._staff_probe(), creates=1)

    def test_publication_failure_rolls_back_canonical_settlement_and_preserves_native_domain(self) -> None:
        self._failed_public_create()
        credential = bytes(self.account.encrypted_password)
        canonical_write = False
        interrupted = False

        def fail_publication_read(execute, sql, params, many, context):
            nonlocal canonical_write, interrupted
            if (
                len(self.gateway.get_calls("create-domain")) == 2
                and sql.startswith(f'UPDATE "{VirtualminAccount._meta.db_table}"')
                and '"provisioned_at" =' in sql
            ):
                canonical_write = True
            if (
                canonical_write
                and not interrupted
                and sql.startswith("SELECT")
                and f'"{HostingLimitExecution._meta.db_table}"' in sql
            ):
                interrupted = True
                raise DatabaseError("Injected quota publication read failure")
            return execute(sql, params, many, context)

        with connection.execute_wrapper(fail_publication_read):
            outcome = self._retry_through_public_sweep()
        self.assertTrue(interrupted, "The real quota publication boundary was never reached")
        self.assertFalse(outcome["success"], outcome)
        self.account.refresh_from_db()
        self.job.refresh_from_db()
        self.server.refresh_from_db()
        self.assertEqual((self.account.status, self.job.status, self.server.current_domains), ("error", "attention", 0))
        self.assertIsNone(self.account.provisioned_at)
        self.assertIsNone(self.job.next_retry_at)
        self.assertEqual(bytes(self.account.encrypted_password), credential)
        self.assertIsNotNone(self.gateway.domain_state_of(self.account.domain))
        self.assertEqual(len(self.gateway.get_calls("create-domain")), 2)
        self.assertEqual(len(self.gateway.get_calls("delete-domain")), 0)
