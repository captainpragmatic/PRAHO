"""An old single archive cannot enable a managed account before current quotas are proved.

Only S3, the Virtualmin API and SSH execution are replaced. Admission, archive inspection,
restore parameter preparation, the quota child and both durable job state machines are real.
"""

import hashlib
import io
import tarfile
import tempfile
from pathlib import Path
from unittest.mock import patch
from uuid import uuid4

import paramiko
from django.test import override_settings
from django.utils import timezone

from apps.common.types import Ok
from apps.provisioning import virtualmin_pair_restore as pair
from apps.provisioning.hosting_limit_execution_models import HostingLimitExecution
from apps.provisioning.hosting_limit_override_service import grant_resource_override
from apps.provisioning.hosting_node_policy_models import NodeHostingPolicy
from apps.provisioning.models import ServicePlan
from apps.provisioning.virtualmin_backup_service import RestoreConfig, VirtualminBackupService
from apps.provisioning.virtualmin_gateway import VirtualminGateway, VirtualminResponse
from apps.provisioning.virtualmin_models import VirtualminAccount
from apps.provisioning.virtualmin_security import connection_identity
from apps.provisioning.virtualmin_service import VirtualminBackupManagementService
from apps.provisioning.virtualmin_tasks import run_virtualmin_restore
from apps.provisioning.virtualmin_validators import WEB_ONLY_VIRTUALMIN_FEATURES
from apps.tickets.models import Ticket
from apps.users.models import User
from tests.helpers.task_queue import quiet_task_queue
from tests.provisioning import test_hosting_limit_surfaces as surface_fixtures
from tests.provisioning.test_hosting_node_policy import quota_evidence
from tests.provisioning.test_virtualmin_pair_restore import checkpoint
from tests.provisioning.test_virtualmin_tasks import VirtualminTaskTestBase


class ManagedSingleRestoreLimitsTests(VirtualminTaskTestBase):
    receipt = surface_fixtures.VerifiedHostingLimitSurfaceTests.receipt
    publish_usage = surface_fixtures.VerifiedHostingLimitSurfaceTests.publish_usage
    apply = surface_fixtures.VerifiedHostingLimitSurfaceTests.apply

    def setUp(self) -> None:
        super().setUp()
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.directory = Path(directory.name)
        key = self.directory / "root-key"
        key.write_text("private fixture key, no real SSH transport")
        key.chmod(0o600)
        configuration = override_settings(VIRTUALMIN_IMPORTED_SSH_PRIVATE_KEY_PATH=str(key))
        configuration.enable()
        self.addCleanup(configuration.disable)
        host_key = paramiko.RSAKey.generate(2048)
        self.server.imported_ssh_host_keys = f"{host_key.get_name()} {host_key.get_base64()}"
        self.server.save(update_fields=["imported_ssh_host_keys"])
        evidence = quota_evidence()
        evidence["identity"] = connection_identity(self.server)
        NodeHostingPolicy.objects.create(
            server=self.server,
            connection_identity=evidence["identity"],
            quota_adopted=True,
            quota_verified_at=timezone.now(),
            quota_evidence=evidence,
        )
        self.identity = {key: evidence[key] for key in ("installation", "filesystem_uuid", "boot_id")}
        self.identity.update(domain_id="12345", domain=self.account.domain, uid=1001, gid=1001)
        target = ServicePlan.objects.create(
            name="Managed five", plan_type="shared_hosting", price_monthly=25, disk_space_gb=5, bandwidth_gb=20
        )
        actor = User.objects.create_user(email="restore-adoption@example.com", staff_role="admin")
        ticket = Ticket.objects.create(customer=self.customer, title="Adopt this account", description="Reviewed")
        self.application = grant_resource_override(
            user=actor,
            service=self.service,
            target_plan_id=target.pk,
            expected_revision=1,
            submission_id=uuid4(),
            reason="Explicit staff adoption before an old archive is restored",
            ticket_id=ticket.pk,
            billing_unchanged=True,
            adopt_existing_native_limits=True,
        )
        self.apply()
        self.account.refresh_from_db()
        self.assertTrue(self.account.quota_managed)
        self.broker = quiet_task_queue(self)
        self.node_disabled = False
        self.node_variables = []
        self.quota_requests = []
        self.api_calls = []
        self.archive = self.directory / f"virtualmin_backup_{uuid4().hex}.tar.gz"
        metadata = "\n".join(
            [f"dom={self.account.domain}", "id=12345", "uid=1001", "gid=1001", "quota=1048576", "uquota=1048576"]
            + [f"{feature}=1" for feature in WEB_ONLY_VIRTUALMIN_FEATURES]
        ).encode()
        with tarfile.open(self.archive, "w:gz") as bundle:
            member = tarfile.TarInfo(f"./{self.account.domain}_virtualmin")
            member.size = len(metadata)
            bundle.addfile(member, io.BytesIO(metadata))
        self.manifest = {
            "manifest_version": 1,
            "status": "completed",
            "backup_id": "old-single",
            "chain_role": "standalone",
            "domain": self.account.domain,
            "praho_service_id": str(self.service.pk),
            "virtualmin_domain_id": "12345",
            "archive_name": self.archive.name,
            "checksum_sha256": hashlib.sha256(self.archive.read_bytes()).hexdigest(),
            "file_size_bytes": self.archive.stat().st_size,
            "domain_features": list(WEB_ONLY_VIRTUALMIN_FEATURES),
            "include_email": True,
            "include_databases": True,
            "include_files": True,
            "include_ssl": True,
        }

    def gateway_call(self, gateway, program, params=None, **kwargs):
        self.api_calls.append(program)
        if program == "disable-domain":
            self.node_disabled = True
        elif program == "enable-domain":
            self.node_disabled = False
        elif program != "list-domains":
            self.fail(f"Unexpected Virtualmin mutation: {program}")
        values = {
            "Username": [self.account.virtualmin_username],
            "ID": ["12345"],
            "Features": [" ".join(WEB_ONLY_VIRTUALMIN_FEATURES)],
            "Disabled": ["Yes" if self.node_disabled else "No"],
            "Type": ["Top-level server"],
        }
        return Ok(
            VirtualminResponse(
                success=True,
                data={"data": [{"name": self.account.domain, "values": values}]},
                raw_response="",
                http_status=200,
                execution_time=0.01,
                program=program,
                server_hostname=self.server.hostname,
            )
        )

    def node_restore(self, server, variables, **kwargs):
        self.assertEqual(VirtualminAccount.objects.get(pk=self.account.pk).status, "suspended")
        self.node_variables.append(variables)
        self.node_disabled = True
        checkpoints = (
            checkpoint("barrier_up"),
            checkpoint("after_base"),
            checkpoint("barrier_down", http80="200", http443="200", odd_hosts="200"),
        )
        return Ok(pair.PairStepResult("ok", "completed", True, checkpoints))

    def fresh_receipt(self, cap, request=None):
        return {
            **self.receipt(cap, request),
            "observation": {"files_bytes": 1024**2, "database_bytes": 1024**2, "total_bytes": 2 * 1024**2},
        }

    def execute_restore(self, *, lost_quota_response=False):
        def apply(server, action, request):
            self.assertTrue(self.node_disabled)
            self.assertEqual(VirtualminAccount.objects.get(pk=self.account.pk).status, "suspended")
            self.quota_requests.append(request)
            if lost_quota_response:
                raise RuntimeError("SSH response lost after quota dispatch")
            return self.fresh_receipt(request["disk_limit_kib"] // 1024, request)

        with (
            patch.object(VirtualminBackupService, "read_manifest", return_value=Ok(dict(self.manifest))),
            patch.object(
                VirtualminBackupService,
                "_download_backup_to_spool",
                return_value=Ok((str(self.archive), dict(self.manifest))),
            ),
            patch.object(VirtualminBackupService, "backup_domain", return_value=Ok({"backup_id": "safety"})),
            patch.object(VirtualminBackupService, "_push_archive_to_target", return_value=Ok(None)),
            patch.object(VirtualminBackupService, "_cleanup_remote_archive"),
            patch.object(VirtualminGateway, "call", autospec=True, side_effect=self.gateway_call),
            patch.object(pair, "run_pair_step", side_effect=self.node_restore),
            patch(
                "apps.provisioning.hosting_limit_transport.probe_account_quota", return_value=self.fresh_receipt(1024)
            ),
            patch("apps.provisioning.hosting_limit_transport.run_quota_operation", side_effect=apply),
        ):
            admitted = VirtualminBackupManagementService(self.server).create_restore_job(
                self.account, RestoreConfig("old-single", force_restore=True), initiated_by="staff"
            )
            self.assertTrue(admitted.is_ok(), admitted)
            job = admitted.unwrap()
            self.assertIs(job.parameters.get("managed_single_restore"), True)
            outcome = run_virtualmin_restore(str(job.pk))
        job.refresh_from_db()
        self.account.refresh_from_db()
        self.service.refresh_from_db()
        return job, outcome

    def test_old_single_archive_reapplies_current_cap_before_reconcile(self) -> None:
        job, outcome = self.execute_restore()
        self.assertEqual(
            outcome["status"],
            "completed",
            (outcome, list(HostingLimitExecution.objects.values("phase", "job__status_message", "job__parameters"))),
        )
        self.assertEqual(job.status, "completed")
        self.assertEqual(len(self.node_variables), 1)
        variables = self.node_variables[0]
        self.assertIs(variables["pair_single"], True)
        self.assertIs(variables["pair_web_only"], True)
        self.assertIs(variables["pair_restore_configuration"], True)
        self.assertEqual(variables["pair_diff_archive"], "")
        self.assertEqual(variables["pair_diff_sha"], "")
        self.assertEqual(len(self.quota_requests), 1)
        self.assertEqual(self.quota_requests[0]["disk_limit_kib"], 5632 * 1024)
        self.assertEqual(self.account.status, "suspended")
        self.assertTrue(self.node_disabled)
        self.assertNotIn("enable-domain", self.api_calls)
        self.assertEqual(self.service.price, 10)
        children = HostingLimitExecution.objects.filter(job__hosting_limit_application=self.application)
        self.assertEqual(children.count(), 2)
        self.assertEqual(set(children.values_list("phase", flat=True)), {"completed"})
        reconciles = [
            call
            for call in self.broker.queued()
            if call[0] == "apps.provisioning.virtualmin_tasks.reconcile_virtualmin_service_state"
        ]
        self.assertEqual(
            reconciles,
            [("apps.provisioning.virtualmin_tasks.reconcile_virtualmin_service_state", str(self.service.pk))],
        )

    def test_lost_quota_response_keeps_both_jobs_held_and_never_enables(self) -> None:
        job, outcome = self.execute_restore(lost_quota_response=True)
        self.assertEqual(outcome["status"], "attention", outcome)
        self.assertEqual(job.status, "attention")
        self.assertEqual(len(self.quota_requests), 1)
        self.assertEqual(self.account.status, "suspended")
        self.assertTrue(self.node_disabled)
        self.assertNotIn("enable-domain", self.api_calls)
        self.assertIsNone(self.service.hosting_limits.verified_at)
        child = HostingLimitExecution.objects.get(job__hosting_limit_application=self.application, phase="attention")
        self.assertGreater(child.reserved_bytes, 0)
        self.assertIsNone(child.reservation_released_at)
        reconciles = [
            call
            for call in self.broker.queued()
            if call[0] == "apps.provisioning.virtualmin_tasks.reconcile_virtualmin_service_state"
        ]
        self.assertEqual(reconciles, [])
