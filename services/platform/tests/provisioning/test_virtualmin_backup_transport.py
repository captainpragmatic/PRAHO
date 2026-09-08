"""Backup transport contracts: fetch-to-spool, checksum evidence, honest publication."""

from __future__ import annotations

import hashlib
import io
import json
import os
import tarfile
import tempfile
import time
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from unittest.mock import MagicMock, patch
from uuid import uuid4

from apps.common.types import Ok
from apps.infrastructure.models import CloudProvider, NodeDeployment, NodeRegion, NodeSize, PanelType
from apps.provisioning import virtualmin_tasks
from apps.provisioning.spool import acquire_spool_reservation
from apps.provisioning.virtualmin_backup_service import BackupConfig, VirtualminBackupService
from apps.provisioning.virtualmin_gateway import VirtualminResponse
from apps.provisioning.virtualmin_migration_models import SpoolReservation, VirtualminMigration
from apps.provisioning.virtualmin_migration_service import VirtualminMigrationService
from tests.provisioning import test_virtualmin_tasks as task_tests


def _tiny_archive_bytes() -> bytes:
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:gz") as tar:
        payload = io.BytesIO(b"backup-content")
        info = tarfile.TarInfo(name="home/site/index.html")
        info.size = len(b"backup-content")
        tar.addfile(info, payload)
    return buffer.getvalue()


ARCHIVE_BYTES = _tiny_archive_bytes()


def _response(program: str, *, success: bool = True, raw: str | None = None) -> Ok[VirtualminResponse]:
    body = raw if raw is not None else json.dumps({"status": "success", "command": program})
    data: dict[str, Any] = {"status": "success"} if success else {"error": "parser guesswork"}
    return Ok(
        VirtualminResponse(
            success=success,
            data=data,
            raw_response=body,
            http_status=200,
            execution_time=0.1,
            program=program,
            server_hostname="vm1.example.com",
        )
    )


class BackupTransportTests(task_tests.VirtualminTaskTestBase):
    def setUp(self) -> None:
        super().setUp()
        provider = CloudProvider.objects.create(
            name="Backup provider", provider_type="hetzner", code="het", credential_identifier="backup-test"
        )
        region = NodeRegion.objects.create(
            provider=provider, name="Falkenstein", provider_region_id="fsn1",
            normalized_code="fsn1", country_code="de", city="Falkenstein",
        )
        size = NodeSize.objects.create(
            provider=provider, name="Backup small", display_name="Small", provider_type_id="cpx21",
            vcpus=2, memory_gb=4, disk_gb=40, hourly_cost_eur="0.01", monthly_cost_eur="5.00",
        )
        panel = PanelType.objects.create(
            name="Backup Virtualmin", panel_type="virtualmin", ansible_playbook="virtualmin.yml"
        )
        NodeDeployment.objects.create(
            provider=provider, node_size=size, region=region, panel_type=panel,
            hostname="prd-bak-het-de-fsn1-001", node_number=1, ipv4_address="203.0.113.10",
            virtualmin_server=self.server,
        )
        self.server.refresh_from_db()
        self.spool = tempfile.TemporaryDirectory()
        self.addCleanup(self.spool.cleanup)
        settings_patch = patch(
            "apps.settings.services.SettingsService.get_setting",
            side_effect=lambda key, default=None: {
                "provisioning.migration_spool_dir": self.spool.name,
                "backup.s3_bucket_name": "test-bucket",
            }.get(key, default),
        )
        settings_patch.start()
        self.addCleanup(settings_patch.stop)

        self.svc = VirtualminBackupService(self.server)
        self.gateway = MagicMock()
        self.gateway.ping_server.return_value = True
        self.gateway.get_domain_info.return_value = Ok({"disk_usage_mb": 100, "disk_quota_mb": 1000})
        self.gateway.call.return_value = _response("backup-domain")
        gateway_patch = patch(
            "apps.provisioning.virtualmin_backup_service.VirtualminGateway", return_value=self.gateway
        )
        gateway_patch.start()
        self.addCleanup(gateway_patch.stop)

        self.s3 = MagicMock()
        s3_patch = patch.object(self.svc, "_get_s3_client", return_value=self.s3)
        bucket_patch = patch.object(self.svc, "_get_backup_bucket", return_value="test-bucket")
        s3_patch.start()
        bucket_patch.start()
        self.addCleanup(s3_patch.stop)
        self.addCleanup(bucket_patch.stop)

        self.ansible = MagicMock()
        ansible_patch = patch("apps.infrastructure.ansible_service.AnsibleService", return_value=self.ansible)
        ansible_patch.start()
        self.addCleanup(ansible_patch.stop)
        self.ansible.run_playbook.side_effect = self._fake_fetch

    def _fake_fetch(self, deployment: Any, playbook: str, variables: dict[str, Any], **kwargs: Any) -> Any:
        self.assertEqual(playbook, "virtualmin_backup_fetch.yml")
        self.assertEqual(deployment.virtualmin_server_id, self.server.pk)
        archive = Path(variables["spool_dir"]) / variables["archive_name"]
        archive.write_bytes(ARCHIVE_BYTES)
        sha = hashlib.sha256(ARCHIVE_BYTES).hexdigest()
        return Ok(SimpleNamespace(success=True, stdout=f"MIGRATE noise\nBACKUP_SHA256={sha}\n", return_code=0))

    def test_happy_path_publishes_finalized_manifest_and_cleans_spool(self) -> None:
        result = self.svc.backup_domain(account=self.account, config=BackupConfig())
        self.assertTrue(result.is_ok(), result)
        # Archive object then metadata LAST; manifest finalized before publish.
        put_calls = self.s3.put_object.call_args_list
        keys = [call.kwargs["Key"] for call in put_calls]
        self.assertEqual(len(keys), 2)
        self.assertTrue(keys[0].endswith("backup.tar.gz"))
        self.assertTrue(keys[1].endswith("metadata.json"))
        manifest = json.loads(put_calls[1].kwargs["Body"])
        self.assertEqual(manifest["status"], "completed")
        self.assertEqual(manifest["checksum_sha256"], hashlib.sha256(ARCHIVE_BYTES).hexdigest())
        self.assertEqual(manifest["backup_type"], "full")
        self.assertTrue(manifest["archive_name"].startswith("virtualmin_backup_"))
        # Spool cleaned; reservation released.
        self.assertEqual(list(Path(self.spool.name).iterdir()), [])
        self.assertFalse(SpoolReservation.objects.exists())
        # No tenant strings in the remote dest.
        dest = self.gateway.call.call_args.args[1]["dest"]
        self.assertNotIn(self.account.domain, dest)

    def test_ambiguous_backup_response_is_an_honest_error(self) -> None:
        self.gateway.call.return_value = _response("backup-domain", success=False, raw="")
        result = self.svc.backup_domain(account=self.account, config=BackupConfig())
        self.assertTrue(result.is_err())
        self.assertIn("ambiguous", result.unwrap_err())
        self.s3.put_object.assert_not_called()

    def test_explicit_rejection_surfaces_the_reason(self) -> None:
        raw = json.dumps({"status": "error", "error": "disk full"})
        self.gateway.call.return_value = _response("backup-domain", success=False, raw=raw)
        result = self.svc.backup_domain(account=self.account, config=BackupConfig())
        self.assertTrue(result.is_err())
        self.assertIn("disk full", result.unwrap_err())

    def test_preflight_refuses_manually_registered_server(self) -> None:
        deployment = self.server.node_deployment
        deployment.virtualmin_server = None
        deployment.save(update_fields=["virtualmin_server"])
        self.server.refresh_from_db()
        svc = VirtualminBackupService(self.server)
        result = svc.backup_domain(account=self.account, config=BackupConfig())
        self.assertTrue(result.is_err())
        self.assertIn("node_deployment", result.unwrap_err())
        self.gateway.call.assert_not_called()

    def test_fetch_timeout_shape_fails_without_publication(self) -> None:
        self.ansible.run_playbook.side_effect = None
        self.ansible.run_playbook.return_value = Ok(SimpleNamespace(success=False, stdout="", return_code=-1))
        result = self.svc.backup_domain(account=self.account, config=BackupConfig())
        self.assertTrue(result.is_err())
        self.assertIn("fetch failed", result.unwrap_err())
        self.s3.put_object.assert_not_called()
        self.assertFalse(SpoolReservation.objects.exists())

    def test_checksum_mismatch_refuses_publication(self) -> None:
        def corrupt_fetch(deployment: Any, playbook: str, variables: dict[str, Any], **kwargs: Any) -> Any:
            archive = Path(variables["spool_dir"]) / variables["archive_name"]
            archive.write_bytes(ARCHIVE_BYTES)
            return Ok(SimpleNamespace(success=True, stdout=f"BACKUP_SHA256={'a' * 64}\n", return_code=0))

        self.ansible.run_playbook.side_effect = corrupt_fetch
        result = self.svc.backup_domain(account=self.account, config=BackupConfig())
        self.assertTrue(result.is_err())
        self.assertIn("checksum mismatch", result.unwrap_err())
        self.s3.put_object.assert_not_called()

    def test_incremental_is_refused_honestly(self) -> None:
        result = self.svc.backup_domain(account=self.account, config=BackupConfig(backup_type="incremental"))
        self.assertTrue(result.is_err())
        self.assertIn("Unsupported backup type", result.unwrap_err())

    def test_superseded_runner_stops_before_publication(self) -> None:
        calls = {"n": 0}

        def ownership() -> bool:
            calls["n"] += 1
            # Own the execution through backup+fetch; lose it before upload.
            return calls["n"] < 2

        result = self.svc.backup_domain(account=self.account, config=BackupConfig(), ownership=ownership)
        self.assertTrue(result.is_err())
        self.assertIn("superseded", result.unwrap_err())
        self.s3.put_object.assert_not_called()

    def test_janitor_sweeps_only_old_orphans_of_both_families(self) -> None:
        spool = Path(self.spool.name)
        old_backup = spool / f"virtualmin_backup_{uuid4().hex}.tar.gz"
        old_migration = spool / f"migration_{uuid4()}.tar.gz"
        fresh = spool / f"virtualmin_backup_{uuid4().hex}.tar.gz"
        stranger = spool / "unrelated.tar.gz"
        for path in (old_backup, old_migration, fresh, stranger):
            path.write_bytes(b"x")
        old_stamp = time.time() - 60 * 60 * 60
        os.utime(old_backup, (old_stamp, old_stamp))
        os.utime(old_migration, (old_stamp, old_stamp))
        os.utime(stranger, (old_stamp, old_stamp))
        counts = {"spool_orphans_removed": 0}
        virtualmin_tasks._sweep_spool_orphans(counts)
        self.assertEqual(counts["spool_orphans_removed"], 2)
        self.assertFalse(old_backup.exists())
        self.assertFalse(old_migration.exists())
        self.assertTrue(fresh.exists())
        self.assertTrue(stranger.exists())

    def test_migration_fetch_leg_aborts_when_spool_is_reserved(self) -> None:
        """Drive the REAL migration _transfer fetch leg against a standing reservation."""
        migration = VirtualminMigration.objects.create(
            account=self.account, source_server=self.server, target_server=self.server, reason="manual", status="fetching"
        )
        service = VirtualminMigrationService()
        service.spool = Path(self.spool.name)
        service.transfer_timeout = 60
        with patch("apps.provisioning.spool.shutil.disk_usage") as usage:
            usage.return_value = type("du", (), {"free": 1000})()
            blocker = acquire_spool_reservation(Path(self.spool.name), "migration_block.tar.gz", 900, "t", 60)
            self.assertTrue(blocker.is_ok())
            token = migration.lease_token
            # _transfer aborts the migration (calls _abort) when the fetch leg
            # cannot reserve spool capacity; assert it never ran a playbook.
            with patch.object(service, "_abort") as abort:
                service._transfer(migration, token or migration.pk)
            abort.assert_called_once()
        self.ansible.run_playbook.assert_not_called()
