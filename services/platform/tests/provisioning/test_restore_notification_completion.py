"""Imported archive restoration must not bypass independent customer-mail ownership."""

from __future__ import annotations

import ast
import copy
import hashlib
import io
import tarfile
import tempfile
from collections.abc import Callable
from datetime import timedelta
from pathlib import Path
from typing import Any, cast
from unittest.mock import patch
from uuid import uuid4

import paramiko
from django.db import connection
from django.test import SimpleTestCase, TransactionTestCase, override_settings
from django.utils import timezone

from apps.common.types import Ok, Retriability
from apps.provisioning import virtualmin_pair_restore as pair
from apps.provisioning.component_migration_worker import ComponentMigrationWorker
from apps.provisioning.hosting_limit_execution import ensure_managed_limits
from apps.provisioning.hosting_limit_execution_models import HostingLimitExecution
from apps.provisioning.hosting_node_policy import NOTIFICATION_EMITTERS
from apps.provisioning.hosting_node_policy_models import NodeHostingPolicy
from apps.provisioning.hosting_notification_completion import verify_lifecycle_notification_policy
from apps.provisioning.models import Service
from apps.provisioning.virtualmin_backup_service import RestoreConfig, VirtualminBackupService
from apps.provisioning.virtualmin_disaster_recovery import VirtualminDisasterRecoveryService
from apps.provisioning.virtualmin_gateway import VirtualminGateway, VirtualminResponse
from apps.provisioning.virtualmin_migration_models import VirtualminMigration
from apps.provisioning.virtualmin_migration_service import VirtualminMigrationService
from apps.provisioning.virtualmin_models import VirtualminProvisioningJob, VirtualminServer
from apps.provisioning.virtualmin_recovery_service import VirtualminRecoveryService
from apps.provisioning.virtualmin_security import connection_identity
from apps.provisioning.virtualmin_service import (
    VirtualminAccountCreationData,
    VirtualminBackupManagementService,
    VirtualminProvisioningService,
)
from apps.provisioning.virtualmin_tasks import retry_virtualmin_job, run_virtualmin_restore
from apps.provisioning.virtualmin_validators import WEB_ONLY_VIRTUALMIN_FEATURES
from apps.settings.services import SettingsService
from tests.helpers.task_queue import quiet_task_queue
from tests.mocks.virtualmin_mock import MockVirtualminGateway
from tests.provisioning.test_hosting_node_policy import quota_evidence
from tests.provisioning.test_virtualmin_chain_playbook import SNAP_A, SNAP_B
from tests.provisioning.test_virtualmin_pair_restore import GOOD_CHECKPOINTS
from tests.provisioning.test_virtualmin_tasks import VirtualminTaskTestBase


def archive_metadata(path: Path, domain: str) -> bytes:
    with tarfile.open(path) as archive:
        member = archive.extractfile(f"./{domain}_virtualmin")
        assert member is not None
        return member.read()


class LifecycleNotificationWiringTests(SimpleTestCase):
    root = Path(__file__).resolve().parents[2] / "apps/provisioning"

    def callers(self, target: str) -> list[tuple[str, str]]:
        found = []
        for source in self.root.glob("*.py"):
            tree = ast.parse(source.read_text())
            parents = {child: parent for parent in ast.walk(tree) for child in ast.iter_child_nodes(parent)}
            for node in ast.walk(tree):
                if not isinstance(node, ast.Call):
                    continue
                name = node.func.id if isinstance(node.func, ast.Name) else getattr(node.func, "attr", None)
                if name != target:
                    continue
                scope = parents.get(node)
                while scope is not None and not isinstance(scope, ast.FunctionDef):
                    scope = parents.get(scope)
                assert isinstance(scope, ast.FunctionDef)
                found.append((source.name, scope.name))
        return found

    def test_all_seven_quota_completion_callers_keep_the_shared_gate(self) -> None:
        callers = self.callers("ensure_managed_limits")
        expected = {
            ("virtualmin_migration_service.py", "_activate"),
            ("virtualmin_backup_service.py", "_verify_restored_domain"),
            ("virtualmin_disaster_recovery.py", "_restore_quotas"),
            ("component_migration_worker.py", "_activate"),
            ("virtualmin_service.py", "_execute_domain_creation"),
            ("virtualmin_service.py", "_settle_observed_create"),
            ("virtualmin_recovery_service.py", "_activate"),
        }
        self.assertEqual(len(callers), 7)
        self.assertEqual(set(callers), expected)
        self.assertIn(("virtualmin_service.py", "_settle_observed_create"), callers)

    def test_ordinary_and_pair_restore_share_the_domain_verifier(self) -> None:
        callers = self.callers("_verify_restored_domain")
        self.assertEqual(len(callers), 2)
        self.assertEqual(
            set(callers),
            {("virtualmin_backup_service.py", "_restore_workflow"), ("virtualmin_pair_restore.py", "restore_pair")},
        )
        self.assertIn(("virtualmin_pair_restore.py", "restore_pair"), callers)

    def test_both_public_migration_dispatchers_wrap_only_the_restoring_handler(self) -> None:
        found = []
        for name in ("virtualmin_migration_service.py", "component_migration_worker.py"):
            for node in ast.walk(ast.parse((self.root / name).read_text())):
                if not isinstance(node, ast.Dict):
                    continue
                for key, value in zip(node.keys, node.values, strict=True):
                    if isinstance(key, ast.Constant) and key.value == "restoring" and isinstance(value, ast.Attribute):
                        found.append((name, value.attr))
        self.assertEqual(len(found), 2)
        self.assertEqual(
            set(found),
            {
                ("virtualmin_migration_service.py", "_restore_with_notification_policy"),
                ("component_migration_worker.py", "_restore_with_notification_policy"),
            },
        )
        self.assertIn(("component_migration_worker.py", "_restore_with_notification_policy"), found)


class RestoreNotificationCompletionTests(TransactionTestCase):
    def setUp(self) -> None:
        # Share the plain factory without inheriting TestCase's atomic wrapper.
        VirtualminTaskTestBase.setUp(cast(VirtualminTaskTestBase, self))
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.directory = Path(directory.name)
        key = self.directory / "private-fixture-key"
        key.write_text("No SSH is executed by this external-boundary fixture")
        key.chmod(0o600)
        configured = override_settings(VIRTUALMIN_IMPORTED_SSH_PRIVATE_KEY_PATH=str(key))
        configured.enable()
        self.addCleanup(configured.disable)
        host_key = paramiko.RSAKey.generate(2048)
        self.server.imported_ssh_host_keys = f"{host_key.get_name()} {host_key.get_base64()}"
        self.server.save(update_fields=["imported_ssh_host_keys"])
        self.archive = self.directory / f"virtualmin_backup_{uuid4().hex}.tar.gz"
        metadata = "\n".join(
            [f"dom={self.account.domain}", "id=12345", "uid=1001", "gid=1001", "letsencrypt_email=0"]
            + [f"{feature}=1" for feature in WEB_ONLY_VIRTUALMIN_FEATURES]
        ).encode()
        with tarfile.open(self.archive, "w:gz") as archive:
            member = tarfile.TarInfo(f"./{self.account.domain}_virtualmin")
            member.size = len(metadata)
            archive.addfile(member, io.BytesIO(metadata))
        self.manifest = {
            "manifest_version": 1,
            "status": "completed",
            "backup_id": "imported-single",
            "chain_role": "standalone",
            "domain": self.account.domain,
            "praho_service_id": str(self.service.pk),
            "virtualmin_domain_id": "12345",
            "archive_name": self.archive.name,
            "checksum_sha256": hashlib.sha256(self.archive.read_bytes()).hexdigest(),
            "file_size_bytes": self.archive.stat().st_size,
            "domain_features": list(WEB_ONLY_VIRTUALMIN_FEATURES),
            **dict.fromkeys(("include_email", "include_databases", "include_files", "include_ssl"), True),
        }
        self.notification_proof: dict[str, Any] = {
            "schema": 1,
            "policy_version": "hosting-node-v1",
            "identity": connection_identity(self.server),
            "installation": str(uuid4()),
            "emitters": dict.fromkeys(NOTIFICATION_EMITTERS, True),
            "operator_alerts_preserved": True,
            "tenant_mail_preserved": True,
        }
        quota = quota_evidence()
        quota["identity"] = self.notification_proof["identity"]
        self.policy = NodeHostingPolicy.objects.create(
            server=self.server,
            connection_identity=self.notification_proof["identity"],
            quota_adopted=True,
            quota_verified_at=timezone.now(),
            quota_evidence=quota,
            notification_owner="platform",
            notifications_verified_at=timezone.now(),
            notification_evidence=self.notification_proof,
        )
        self.native_acme_setting = "2"
        self.native_domain_exists = False
        self.native_owner_guard = True
        self.guard_lost_on_restore = False
        self.native_disabled = False
        self.inspect_error = False
        self.inspect_error_at = 1
        self.after_inspection: Callable[[], object] | None = None
        self.after_inspection_at = 2
        self.inspection_installation: str | None = None
        self.replace_before_create_mail = False
        self.replacement_claim: dict[str, Any] | None = None
        self.create_response_data: dict[str, Any] | None = None
        self.restore_calls = 0
        self.inspect_calls = 0
        self.broker = quiet_task_queue(self)

    def archive_preference(self, value: str) -> None:
        content = archive_metadata(self.archive, self.account.domain)
        content = content.replace(b"letsencrypt_email=0", f"letsencrypt_email={value}".encode())
        with tarfile.open(self.archive, "w:gz") as archive:
            member = tarfile.TarInfo(f"./{self.account.domain}_virtualmin")
            member.size = len(content)
            archive.addfile(member, io.BytesIO(content))
        self.manifest.update(
            checksum_sha256=hashlib.sha256(self.archive.read_bytes()).hexdigest(),
            file_size_bytes=self.archive.stat().st_size,
        )

    def gateway(self, gateway, program, params=None, **kwargs):
        if program == "restore-domain":
            self.restore_calls += 1
            # Virtualmin 8.3 recreates a missing domain from full archive metadata.
            # Existing-domain restore_virtualmin merges selected fields and does
            # not replace letsencrypt_email; do not invent that native behavior.
            if not self.native_domain_exists:
                content = archive_metadata(self.archive, self.account.domain).decode()
                self.native_acme_setting = dict(line.split("=", 1) for line in content.splitlines())[
                    "letsencrypt_email"
                ]
            self.native_domain_exists = True
            if self.guard_lost_on_restore:
                self.native_owner_guard = False
        elif program == "disable-domain":
            self.native_disabled = True
        else:
            self.assertEqual(program, "list-domains")
        values = {
            "Username": [self.account.virtualmin_username],
            "ID": ["12345"],
            "Features": [" ".join(WEB_ONLY_VIRTUALMIN_FEATURES)],
            "Disabled": ["Yes" if self.native_disabled else "No"],
            "Type": ["Top-level server"],
        }
        return Ok(
            VirtualminResponse(
                success=True,
                data={
                    "status": "success",
                    "data": [{"name": self.account.domain, "values": values}] if self.native_domain_exists else [],
                },
                raw_response='{"status":"success"}',
                http_status=200,
                execution_time=0.01,
                program=program,
                server_hostname=self.server.hostname,
            )
        )

    def inspect(self, server, action, request):
        self.assertFalse(connection.in_atomic_block)
        self.assertEqual(server.pk, self.server.pk)
        self.assertEqual((action, request), ("inspect", {"identity": self.notification_proof["identity"]}))
        self.inspect_calls += 1
        if self.inspect_error and self.inspect_calls >= self.inspect_error_at:
            raise RuntimeError("Lost read-only inspection response")
        proof = copy.deepcopy(self.notification_proof)
        # The native boundary attests protected source/Platform ownership, not
        # merely an archived flag that may be overwritten by restoration.
        proof["emitters"]["acme_owners"] = self.native_owner_guard
        if self.inspection_installation is not None:
            proof["installation"] = self.inspection_installation
        if self.after_inspection is not None and self.inspect_calls == self.after_inspection_at:
            self.after_inspection()
        return {"identity": proof["identity"], "notifications": proof, "quota": {}}

    def execute_restore(self, *, paired=False, existing=False):
        self.assertFalse(self.account.quota_managed)
        self.assertEqual(self.native_acme_setting, "2")
        self.native_domain_exists = paired or existing
        archives = {"imported-single": (self.archive, dict(self.manifest))}
        if paired:
            self.assertTrue(SettingsService.update_setting("provisioning.incremental_backups_enabled", True).is_ok())
            base = archives["imported-single"][1]
            base.update(chain_role="base", fp_before=SNAP_B, fp_after=SNAP_A, node_id="native-1", chain_epoch=3)
            differential = self.directory / f"virtualmin_backup_{uuid4().hex}.tar.gz"
            differential.write_bytes(self.archive.read_bytes())
            archives["imported-diff"] = (
                differential,
                {
                    **base,
                    "backup_id": "imported-diff",
                    "base_backup_id": "imported-single",
                    "chain_role": "differential",
                    "archive_name": differential.name,
                    "fp_before": SNAP_A,
                },
            )

        def node_restore(server, variables, **kwargs):
            self.assertEqual(self.account.__class__.objects.get(pk=self.account.pk).status, "suspended")
            self.restore_calls += 1
            content = archive_metadata(archives["imported-diff"][0], self.account.domain).decode()
            self.assertEqual(dict(line.split("=", 1) for line in content.splitlines())["letsencrypt_email"], "0")
            # Pair restoration requires an existing domain; preserve native 8.3's
            # selected-field merge instead of fabricating an ACME overwrite.
            if self.guard_lost_on_restore:
                self.native_owner_guard = False
            self.native_disabled = True
            return Ok(pair.PairStepResult("ok", "completed", True, GOOD_CHECKPOINTS))

        with (
            patch.object(VirtualminBackupService, "read_manifest", side_effect=lambda key: Ok(dict(archives[key][1]))),
            patch.object(
                VirtualminBackupService,
                "_download_backup_to_spool",
                side_effect=lambda key: Ok((str(archives[key][0]), dict(archives[key][1]))),
            ),
            patch.object(VirtualminBackupService, "backup_domain", return_value=Ok({"backup_id": "safety"})),
            patch.object(VirtualminBackupService, "_push_archive_to_target", return_value=Ok(None)),
            patch.object(VirtualminBackupService, "_cleanup_remote_archive") as cleanup,
            patch.object(VirtualminGateway, "call", autospec=True, side_effect=self.gateway),
            patch.object(pair, "run_pair_step", side_effect=node_restore),
            patch("apps.provisioning.hosting_node_transport.run_node_operation", side_effect=self.inspect),
        ):
            management = VirtualminBackupManagementService(self.server)
            admitted = (
                management.create_pair_restore_job(
                    self.account, "imported-single", "imported-diff", force_restore=True, initiated_by="staff"
                )
                if paired
                else management.create_restore_job(
                    self.account, RestoreConfig("imported-single", force_restore=True), initiated_by="staff"
                )
            )
            self.assertTrue(admitted.is_ok(), admitted)
            job = admitted.unwrap()
            self.assertIsNone(job.hosting_limit_application_id)
            result = run_virtualmin_restore(str(job.pk))
            replay = run_virtualmin_restore(str(job.pk))
        job.refresh_from_db()
        self.account.refresh_from_db()
        return job, result, replay, cleanup

    def test_missing_native_guard_prevents_archive_dispatch_without_quota_adoption(self) -> None:
        self.native_owner_guard = False
        job, result, replay, cleanup = self.execute_restore()
        self.assertEqual(self.native_acme_setting, "2", "The unsafe guard must stop archive dispatch")
        self.assertEqual(result["status"], "failed", result)
        self.assertEqual(job.status, "failed")
        self.assertEqual(job.result["retriability"], Retriability.NOT_RETRIABLE.value)
        self.assertEqual(replay["status"], "stale")
        self.assertEqual((self.restore_calls, self.inspect_calls), (0, 1))
        self.assertFalse(self.account.quota_managed)
        self.assertFalse(HostingLimitExecution.objects.filter(job__account=self.account).exists())
        cleanup.assert_not_called()
        self.assertTrue(VirtualminProvisioningJob.objects.filter(pk=job.pk, status="failed").exists())

    def test_guarded_old_archive_completes_without_adopting_imported_quotas(self) -> None:
        self.native_owner_guard = True
        job, result, replay, cleanup = self.execute_restore()
        self.assertEqual((result["status"], job.status, replay["status"]), ("completed", "completed", "stale"))
        self.assertEqual((self.restore_calls, self.inspect_calls, self.native_acme_setting), (1, 2, "0"))
        self.assertFalse(self.account.quota_managed)
        self.assertFalse(HostingLimitExecution.objects.exists())
        cleanup.assert_called_once()

    def test_pair_restore_uses_the_same_independent_mail_completion_barrier(self) -> None:
        self.guard_lost_on_restore = True
        job, result, replay, cleanup = self.execute_restore(paired=True)
        self.assertEqual(self.native_acme_setting, "2")
        self.assertEqual((result["status"], job.status, replay["status"]), ("attention", "attention", "stale"))
        self.assertEqual((self.restore_calls, self.inspect_calls), (1, 2))
        self.assertFalse(self.account.quota_managed)
        self.assertFalse(HostingLimitExecution.objects.exists())
        self.assertEqual(self.account.status, "suspended")
        self.assertTrue(self.native_disabled)
        cleanup.assert_not_called()

    def test_existing_domain_restore_preserves_native_acme_metadata(self) -> None:
        job, result, replay, cleanup = self.execute_restore(existing=True)
        self.assertEqual((result["status"], job.status, replay["status"]), ("completed", "completed", "stale"))
        self.assertEqual((self.restore_calls, self.inspect_calls, self.native_acme_setting), (1, 2, "2"))
        self.assertFalse(self.account.quota_managed)
        self.assertFalse(HostingLimitExecution.objects.exists())
        cleanup.assert_called_once()

    def test_missing_native_guard_prevents_pair_archive_dispatch(self) -> None:
        self.native_owner_guard = False
        job, result, replay, cleanup = self.execute_restore(paired=True)
        self.assertEqual((result["status"], job.status, replay["status"]), ("failed", "failed", "stale"))
        self.assertEqual((self.restore_calls, self.inspect_calls, self.native_acme_setting), (0, 1, "2"))
        self.assertFalse(self.account.quota_managed)
        self.assertFalse(HostingLimitExecution.objects.exists())
        self.assertFalse(self.native_disabled)
        cleanup.assert_not_called()

    def test_guard_lost_after_archive_dispatch_parks_without_restore_replay(self) -> None:
        self.guard_lost_on_restore = True
        job, result, replay, cleanup = self.execute_restore()
        self.assertEqual(self.native_acme_setting, "0")
        self.assertEqual((result["status"], job.status, replay["status"]), ("attention", "attention", "stale"))
        self.assertEqual(job.result["retriability"], Retriability.UNKNOWN.value)
        self.assertEqual((self.restore_calls, self.inspect_calls), (1, 2))
        self.assertFalse(self.account.quota_managed)
        self.assertFalse(HostingLimitExecution.objects.exists())
        cleanup.assert_not_called()

    def test_native_owned_import_remains_observational(self) -> None:
        self.policy.notification_owner = "native"
        self.policy.save(update_fields=["notification_owner"])
        job, result, replay, cleanup = self.execute_restore()
        self.assertEqual((result["status"], job.status, replay["status"]), ("completed", "completed", "stale"))
        self.assertEqual((self.restore_calls, self.inspect_calls, self.native_acme_setting), (1, 0, "0"))
        self.assertFalse(self.account.quota_managed)
        self.assertFalse(HostingLimitExecution.objects.exists())
        cleanup.assert_called_once()

    def test_notification_ownership_survives_independent_quota_nonadoption(self) -> None:
        self.native_owner_guard = False
        self.policy.quota_adopted = False
        self.policy.save(update_fields=["quota_adopted"])
        job, result, replay, cleanup = self.execute_restore()
        self.assertEqual((result["status"], job.status, replay["status"]), ("failed", "failed", "stale"))
        self.assertEqual((self.restore_calls, self.inspect_calls), (0, 1))
        self.assertFalse(self.account.quota_managed)
        self.assertFalse(HostingLimitExecution.objects.exists())
        cleanup.assert_not_called()

    def test_unavailable_preflight_inspection_never_dispatches_the_archive(self) -> None:
        self.inspect_error = True
        job, result, replay, cleanup = self.execute_restore()
        self.assertEqual((result["status"], job.status, replay["status"]), ("failed", "failed", "stale"))
        self.assertEqual((self.restore_calls, self.inspect_calls), (0, 1))
        self.assertFalse(self.account.quota_managed)
        self.assertFalse(HostingLimitExecution.objects.exists())
        cleanup.assert_not_called()

    def test_unavailable_postflight_inspection_retains_uncertainty_without_replay(self) -> None:
        self.inspect_error = True
        self.inspect_error_at = 2
        job, result, replay, cleanup = self.execute_restore()
        self.assertEqual((result["status"], job.status, replay["status"]), ("attention", "attention", "stale"))
        self.assertEqual((self.restore_calls, self.inspect_calls), (1, 2))
        self.assertEqual(job.result["retriability"], Retriability.UNKNOWN.value)
        cleanup.assert_not_called()

    def test_foreign_installation_cannot_complete_even_with_safe_emitters(self) -> None:
        self.native_owner_guard = True
        self.archive_preference("2")
        self.inspection_installation = str(uuid4())
        job, result, replay, cleanup = self.execute_restore()
        self.assertEqual((result["status"], job.status, replay["status"]), ("failed", "failed", "stale"))
        self.assertEqual((self.restore_calls, self.inspect_calls), (0, 1))
        cleanup.assert_not_called()

    def test_rotated_parent_token_cannot_publish_completion_from_a_late_inspection(self) -> None:
        self.native_owner_guard = True
        self.archive_preference("2")
        self.after_inspection = lambda: VirtualminProvisioningJob.objects.filter(
            account=self.account, operation="restore_domain", status="running"
        ).update(execution_token=uuid4())
        job, result, replay, cleanup = self.execute_restore()
        self.assertEqual((result["status"], job.status, replay["status"]), ("superseded", "running", "stale"))
        self.assertEqual((self.restore_calls, self.inspect_calls), (1, 2))
        cleanup.assert_not_called()

    def test_retired_legacy_disaster_recovery_still_refuses_a_real_rebuild(self) -> None:
        with patch.object(VirtualminGateway, "call") as gateway:
            result = VirtualminDisasterRecoveryService().rebuild_server_from_praho(self.server, dry_run=False)
        self.assertTrue(result.is_err())
        self.assertIn("dry run only", result.unwrap_err())
        self.assertFalse(HostingLimitExecution.objects.exists())
        gateway.assert_not_called()

    def test_unfenced_platform_owned_completion_refuses_without_native_io(self) -> None:
        self.policy.quota_adopted = False
        self.policy.save(update_fields=["quota_adopted"])
        with patch("apps.provisioning.hosting_node_transport.run_node_operation") as native:
            result = ensure_managed_limits(self.account, native_server=self.server)
        self.assertTrue(result.is_err(), result)
        self.assertIn("notification", result.unwrap_err())
        self.assertFalse(HostingLimitExecution.objects.exists())
        native.assert_not_called()

    def running_restore(self):
        job = VirtualminProvisioningJob.objects.create(
            account=self.account,
            server=self.server,
            operation="restore_domain",
            status="pending",
            correlation_id=f"mail-inspection-{uuid4()}",
        )
        token = uuid4()
        self.assertTrue(VirtualminProvisioningJob.claim_execution(job.pk, token, timezone.now() + timedelta(hours=1)))
        job.execution_token = token
        return job

    def test_stale_server_instance_refuses_before_inspecting_a_different_endpoint(self) -> None:
        job = self.running_restore()
        stale = copy.copy(self.server)
        stale.api_port += 1
        self.assertNotEqual(connection_identity(stale), self.notification_proof["identity"])
        with patch("apps.provisioning.hosting_node_transport.run_node_operation", side_effect=self.inspect) as native:
            result = verify_lifecycle_notification_policy(self.account, native_server=stale, parent_job=job)
        self.assertTrue(result.is_err(), result)
        native.assert_not_called()

    def test_policy_removed_during_inspection_returns_uncertainty_without_escaping(self) -> None:
        job = self.running_restore()
        self.after_inspection_at = 1
        self.after_inspection = lambda: NodeHostingPolicy.objects.filter(pk=self.policy.pk).delete()
        with patch("apps.provisioning.hosting_node_transport.run_node_operation", side_effect=self.inspect):
            result = verify_lifecycle_notification_policy(self.account, native_server=self.server, parent_job=job)
        self.assertTrue(result.is_err(), result)
        self.assertEqual(self.inspect_calls, 1)
        self.assertEqual(VirtualminProvisioningJob.objects.get(pk=job.pk).status, "running")

    def test_read_only_barrier_itself_rechecks_the_parent_claim_after_io(self) -> None:
        job = self.running_restore()
        self.after_inspection_at = 1
        self.after_inspection = lambda: VirtualminProvisioningJob.objects.filter(pk=job.pk).update(
            execution_token=uuid4()
        )
        with patch("apps.provisioning.hosting_node_transport.run_node_operation", side_effect=self.inspect):
            result = verify_lifecycle_notification_policy(self.account, native_server=self.server, parent_job=job)
        self.assertTrue(result.is_err(), result)
        self.assertEqual(self.inspect_calls, 1)
        current = VirtualminProvisioningJob.objects.get(pk=job.pk)
        self.assertEqual(current.status, "running")
        self.assertNotEqual(current.execution_token, job.execution_token)
        self.assertFalse(HostingLimitExecution.objects.exists())

    def test_migration_recovery_and_component_activation_share_the_read_only_barrier(self) -> None:
        # Mail ownership remains independent when managed quota adoption is absent.
        # Qualified targets keep their existing separate quota application path.
        self.policy.quota_adopted = False
        self.policy.save(update_fields=["quota_adopted"])
        source = VirtualminServer.objects.create(
            name="unavailable source", hostname="source.example.test", status="disabled"
        )
        token = uuid4()
        migration = VirtualminMigration.objects.create(
            account=self.account,
            source_server=source,
            target_server=self.server,
            status="activating",
            contract=VirtualminMigration.Contract.CUTOVER,
            cutover_committed_at=timezone.now(),
            restore_issued=True,
            lease_token=token,
            worker_lease_expires_at=timezone.now() + timedelta(hours=1),
            pre_migration_snapshot={"status": "active"},
            barrier_state={"target_domain_id": "12345"},
        )
        self.native_acme_setting = "0"
        self.native_owner_guard = False
        cases = (
            (
                VirtualminMigrationService,
                VirtualminMigration.Contract.CUTOVER,
                "apps.provisioning.migration_target_hold.run_held_target_node",
            ),
            (
                VirtualminRecoveryService,
                VirtualminMigration.Contract.RECOVERY,
                "apps.provisioning.virtualmin_recovery_service.run_held_target_node",
            ),
            (
                ComponentMigrationWorker,
                VirtualminMigration.Contract.IMPORTED_WEB,
                "apps.provisioning.component_migration_worker.run_target_operation",
            ),
        )
        for worker_type, contract, native_path in cases:
            with self.subTest(contract=contract):
                VirtualminMigration.objects.filter(pk=migration.pk).update(contract=contract)
                migration.refresh_from_db()
                with (
                    patch("apps.provisioning.hosting_node_transport.run_node_operation", side_effect=self.inspect),
                    patch(native_path, side_effect=RuntimeError("Unsafe native activation was issued")) as activate,
                ):
                    failure = None
                    try:
                        worker_type()._activate(migration, token)
                    except (RuntimeError, ValueError) as error:
                        failure = error
                activate.assert_not_called()
                self.assertIsInstance(failure, ValueError)
                self.assertIn("notification", str(failure))
                migration.refresh_from_db()
                self.assertEqual(migration.status, "activating")
                self.assertIsNone(migration.barrier_state.get("target_activation"))
        self.assertEqual(self.inspect_calls, len(cases))
        self.assertFalse(self.account.quota_managed)
        self.assertFalse(HostingLimitExecution.objects.exists())

    def test_whole_domain_worker_checks_mail_before_dispatching_an_archive(self) -> None:
        source = VirtualminServer.objects.create(
            name="precommit source", hostname="precommit-source.example.test", status="disabled"
        )
        self.account.server = source
        self.account.save(update_fields=["server", "updated_at"])
        self.policy.quota_adopted = False
        self.policy.save(update_fields=["quota_adopted"])
        self.native_owner_guard = False
        token = uuid4()
        migration = VirtualminMigration.objects.create(
            account=self.account,
            source_server=source,
            target_server=self.server,
            status="restoring",
            contract=VirtualminMigration.Contract.LEGACY,
            lease_token=token,
            worker_lease_expires_at=timezone.now() + timedelta(hours=1),
            pre_migration_snapshot={"status": "active"},
        )
        archive = self.directory / migration.archive_name
        archive.write_bytes(self.archive.read_bytes())
        worker = VirtualminMigrationService()
        worker.spool = self.directory
        with (
            patch.object(VirtualminGateway, "call", autospec=True, side_effect=self.gateway),
            patch("apps.provisioning.hosting_node_transport.run_node_operation", side_effect=self.inspect),
        ):
            result = worker.execute(migration, token)
            replay = worker.execute(migration, token)
        self.assertTrue(result.is_ok(), result)
        self.assertTrue(replay.is_ok(), replay)
        migration.refresh_from_db()
        self.assertEqual(migration.status, "needs_review")
        self.assertEqual((self.restore_calls, self.inspect_calls), (0, 1))
        self.assertFalse(migration.restore_issued)
        self.assertIn("notification", migration.error_detail)
        self.assertFalse(HostingLimitExecution.objects.exists())

    def public_create(self):
        self.policy.quota_adopted = False
        self.policy.save(update_fields=["quota_adopted"])
        service = Service.objects.create(
            customer=self.customer,
            service_plan=self.plan,
            currency=self.currency,
            service_name="mail-owned-create.example.test",
            domain="mail-owned-create.example.test",
            username="mailowned",
            billing_cycle="monthly",
            price=10,
            status="active",
        )
        gateway = MockVirtualminGateway()
        original_call = gateway.call

        def call(program, params=None, **kwargs):
            result = original_call(program, params, **kwargs)
            if program == "create-domain" and result.is_ok():
                self.create_response_data = copy.deepcopy(result.unwrap().data)
            if program == "create-domain" and self.replace_before_create_mail:
                self.replace_creation_claim()
            return result

        with (
            patch("apps.provisioning.virtualmin_service.VirtualminGateway", return_value=gateway),
            patch.object(gateway, "call", side_effect=call),
            patch("apps.provisioning.hosting_node_transport.run_node_operation", side_effect=self.inspect),
        ):
            result = VirtualminProvisioningService(self.server).create_virtualmin_account(
                VirtualminAccountCreationData(
                    service=service, domain=service.domain, template="Default Settings", server=self.server
                )
            )
        account = self.account.__class__.objects.get(service=service)
        job = VirtualminProvisioningJob.objects.get(account=account, operation="create_domain")
        return result, account, job, gateway

    def test_platform_owned_unadopted_fresh_create_keeps_its_real_nullable_token_claim(self) -> None:
        result, account, job, gateway = self.public_create()
        self.assertTrue(result.is_ok(), result)
        self.assertEqual((account.status, job.status), ("active", "completed"))
        self.assertIsNone(job.execution_token)
        self.assertIsNone(job.execution_deadline)
        self.assertIsNotNone(job.started_at)
        self.assertEqual(self.inspect_calls, 1)
        self.assertEqual(len(gateway.get_calls("create-domain")), 1)
        self.assertFalse(account.quota_managed)
        self.assertFalse(HostingLimitExecution.objects.exists())

    def public_observed_retry(self):
        self.policy.quota_adopted = False
        self.policy.save(update_fields=["quota_adopted"])
        gateway = MockVirtualminGateway()
        gateway.seed_domain(self.account.domain, username=self.account.virtualmin_username)
        job = VirtualminProvisioningJob.objects.create(
            operation="create_domain",
            account=self.account,
            server=self.server,
            status="pending",
            claimed_at=timezone.now(),
            retry_count=1,
            correlation_id=f"mail-owned-retry-{uuid4()}",
        )
        with (
            patch("apps.provisioning.virtualmin_service.VirtualminGateway", return_value=gateway),
            patch("apps.provisioning.hosting_node_transport.run_node_operation", side_effect=self.inspect),
        ):
            result = retry_virtualmin_job(str(job.pk))
        job.refresh_from_db()
        self.account.refresh_from_db()
        return result, job, gateway

    def test_platform_owned_unadopted_observed_retry_keeps_the_real_creation_claim(self) -> None:
        result, job, gateway = self.public_observed_retry()
        self.assertTrue(result["success"], result)
        self.assertEqual((self.account.status, job.status), ("active", "completed"))
        self.assertIsNone(job.execution_token)
        self.assertIsNone(job.execution_deadline)
        self.assertEqual(self.inspect_calls, 1)
        self.assertFalse(gateway.get_calls("create-domain"))
        self.assertFalse(self.account.quota_managed)
        self.assertFalse(HostingLimitExecution.objects.exists())

    def replace_creation_claim(self) -> None:
        current = VirtualminProvisioningJob.objects.get(server=self.server, operation="create_domain", status="running")
        claimed_at = timezone.now()
        started_at = timezone.now() + timedelta(seconds=1)
        # Persist the durable tuple held by an independent replacement worker.
        changed = VirtualminProvisioningJob.objects.filter(
            pk=current.pk, status="running", claimed_at=current.claimed_at, started_at=current.started_at
        ).update(
            claimed_at=claimed_at,
            started_at=started_at,
            status_message="replacement create owner",
            result={"replacement_evidence": "retained"},
        )
        self.assertEqual(changed, 1)
        self.replacement_claim = {"id": current.pk, "claimed_at": claimed_at, "started_at": started_at}

    def assert_replacement_preserved(self, job) -> None:
        assert self.replacement_claim is not None
        self.assertEqual(job.pk, self.replacement_claim["id"])
        self.assertEqual(job.status, "running", job.status_message)
        self.assertEqual(job.claimed_at, self.replacement_claim["claimed_at"])
        self.assertEqual(job.started_at, self.replacement_claim["started_at"])
        self.assertEqual(job.status_message, "replacement create owner")
        self.assertEqual(job.result, {"replacement_evidence": "retained"})

    def test_fresh_create_mail_refusal_does_not_park_a_claim_replaced_before_inspection(self) -> None:
        self.replace_before_create_mail = True
        result, account, job, gateway = self.public_create()
        self.assertTrue(result.is_err(), result)
        self.assert_replacement_preserved(job)
        self.assertEqual(self.inspect_calls, 0)
        self.assertNotEqual(account.status, "active")
        self.assertEqual(len(gateway.get_calls("create-domain")), 1)
        self.assertFalse(gateway.get_calls("delete-domain"))

    def test_fresh_create_mail_refusal_does_not_park_a_claim_replaced_during_inspection(self) -> None:
        self.after_inspection = self.replace_creation_claim
        self.after_inspection_at = 1
        result, account, job, gateway = self.public_create()
        self.assertTrue(result.is_err(), result)
        self.assert_replacement_preserved(job)
        self.assertEqual(self.inspect_calls, 1)
        self.assertNotEqual(account.status, "active")
        self.assertEqual(len(gateway.get_calls("create-domain")), 1)
        self.assertFalse(gateway.get_calls("delete-domain"))

    def test_observed_retry_mail_refusal_preserves_a_replacement_creation_claim(self) -> None:
        self.after_inspection = self.replace_creation_claim
        self.after_inspection_at = 1
        result, job, gateway = self.public_observed_retry()
        self.assertFalse(result["success"], result)
        self.assert_replacement_preserved(job)
        self.assertEqual(self.inspect_calls, 1)
        self.assertNotEqual(self.account.status, "active")
        self.assertFalse(gateway.get_calls("create-domain"))
        self.assertFalse(gateway.get_calls("delete-domain"))

    def test_same_fresh_create_claim_still_parks_with_mail_reason_and_native_evidence(self) -> None:
        self.native_owner_guard = False
        result, account, job, gateway = self.public_create()
        self.assertTrue(result.is_err(), result)
        self.assertEqual(job.status, "attention")
        self.assertIn("notification policy", job.status_message)
        self.assertEqual(job.result["creation_review"]["native_outcome"], "created")
        self.assertEqual(job.result["creation_review"]["server_id"], str(self.server.pk))
        assert self.create_response_data is not None
        self.assertEqual(self.create_response_data["command"], "create-domain")
        self.assertEqual(self.create_response_data["status"], "success")
        self.assertIn(account.domain, self.create_response_data["output"])
        for key in ("command", "status", "output"):
            self.assertEqual(job.result[key], self.create_response_data[key])
        self.assertNotEqual(account.status, "active")
        self.assertEqual(len(gateway.get_calls("create-domain")), 1)
        self.assertFalse(gateway.get_calls("delete-domain"))
        self.assertFalse(account.quota_managed)

    def test_same_observed_retry_claim_still_parks_with_the_actual_mail_refusal(self) -> None:
        self.native_owner_guard = False
        result, job, gateway = self.public_observed_retry()
        self.assertFalse(result["success"], result)
        self.assertEqual(job.status, "attention")
        self.assertIn("notification policy", job.status_message)
        self.assertEqual(job.result["creation_review"]["native_outcome"], "adopted")
        self.assertEqual(job.result["creation_review"]["server_id"], str(self.server.pk))
        self.assertNotEqual(self.account.status, "active")
        self.assertFalse(gateway.get_calls("create-domain"))
        self.assertFalse(gateway.get_calls("delete-domain"))
        self.assertFalse(self.account.quota_managed)

    def test_platform_owned_unadopted_reprovision_preserves_its_canonical_source_binding(self) -> None:
        self.policy.quota_adopted = False
        self.policy.save(update_fields=["quota_adopted"])
        source = VirtualminServer.objects.create(
            name="reprovision source", hostname="reprovision-source.example.test", status="disabled"
        )
        self.account.server = source
        self.account.template_name = "Default Settings"
        self.account.save(update_fields=["server", "template_name", "updated_at"])
        original_password = bytes(self.account.encrypted_password)
        gateway = MockVirtualminGateway()
        with (
            patch("apps.provisioning.virtualmin_service.VirtualminGateway", return_value=gateway),
            patch("apps.provisioning.hosting_node_transport.run_node_operation", side_effect=self.inspect),
        ):
            result = VirtualminProvisioningService(self.server).reprovision_virtualmin_account(
                self.account, self.server
            )
        self.account.refresh_from_db()
        job = VirtualminProvisioningJob.objects.get(account=self.account, operation="create_domain")
        self.assertTrue(result.is_ok(), result)
        self.assertEqual(
            (self.account.server_id, self.account.status, job.status), (self.server.pk, "active", "completed")
        )
        self.assertEqual(job.parameters["reprovision_source_server_id"], str(source.pk))
        self.assertNotEqual(bytes(self.account.encrypted_password), original_password)
        self.assertIsNone(job.execution_token)
        self.assertIsNone(job.execution_deadline)
        self.assertEqual(self.inspect_calls, 1)
        self.assertEqual(len(gateway.get_calls("create-domain")), 1)
        self.assertFalse(self.account.quota_managed)
        self.assertFalse(HostingLimitExecution.objects.exists())
