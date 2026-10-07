"""Regression tests for provisioning configuration and backup data safety."""

from __future__ import annotations

import hashlib
import io
import tarfile
from collections.abc import Mapping
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import cast
from unittest.mock import patch

import requests
from django.core.cache import cache
from django.test import override_settings

from apps.common.types import Ok
from apps.infrastructure.ansible_service import AnsibleResult
from apps.infrastructure.models import CloudProvider, NodeDeployment, NodeRegion, NodeSize, PanelType
from apps.provisioning.models import Server
from apps.provisioning.provisioning_service import ProvisioningService
from apps.provisioning.virtualmin_backup_service import BackupConfig, RestoreConfig, VirtualminBackupService
from apps.provisioning.virtualmin_forms import VirtualminAccountForm, VirtualminServerForm
from apps.provisioning.virtualmin_migration_models import SpoolReservation
from apps.settings.services import SettingsService
from tests.helpers.fsm_helpers import force_status
from tests.provisioning.test_cov_provisioning_backups_storage import MemoryS3
from tests.provisioning.test_cov_virtualmin_gateway_listing import http_response
from tests.provisioning.test_virtualmin_tasks import VirtualminTaskTestBase


class PartialDeleteS3(MemoryS3):
    def delete_objects(self, **kwargs: object) -> dict[str, object]:
        objects = cast("dict[str, list[dict[str, str]]]", kwargs["Delete"])["Objects"]
        deleted: list[dict[str, str]] = []
        errors: list[dict[str, str]] = []
        for item in objects:
            if item["Key"].endswith("backup.tar.gz"):
                errors.append({**item, "Code": "AccessDenied", "Message": "archive retained"})
            else:
                self.objects.pop(item["Key"], None)
                deleted.append(item)
        return {"Deleted": deleted, "Errors": errors}


@override_settings(CACHES={"default": {"BACKEND": "django.core.cache.backends.locmem.LocMemCache"}})
class ProvisioningRegressionTests(VirtualminTaskTestBase):
    def setUp(self) -> None:
        super().setUp()
        cache.clear()
        self.addCleanup(cache.clear)
        self.backups = VirtualminBackupService(self.server)
        self.domain_usage = "1M"

    def test_configured_server_uses_management_api_url(self) -> None:
        server = Server.objects.create(
            name="Configured VPS host",
            hostname="vps.example.test",
            server_type="vps_host",
            primary_ip="203.0.113.8",
            cpu_cores=4,
            ram_gb=8,
            disk_capacity_gb=100,
            control_panel="Virtualizor",
            management_api_url="https://vps.example.test/api",
        )
        self.service.server = server
        force_status(self.service, "pending")
        self.service.save(update_fields=["server"])
        result = ProvisioningService.provision_service(self.service)
        self.assertEqual(result["status"], "pending_implementation")
        self.service.refresh_from_db()
        self.assertEqual(self.service.provisioning_errors, "Virtualizor gateway pending implementation")
        server.management_api_url = ""
        server.save(update_fields=["management_api_url"])
        force_status(self.service, "pending")
        refused = ProvisioningService.provision_service(self.service)
        self.assertEqual(refused["status"], "pending_manual")

    def test_unsaved_uuid_server_requires_password_but_saved_server_preserves_it(self) -> None:
        data = {
            "name": "New API server",
            "hostname": "new-api.example.test",
            "api_port": "10000",
            "api_username": "root",
            "use_ssl": "on",
            "ssl_verify": "on",
            "status": "active",
            "max_domains": "100",
        }
        form = VirtualminServerForm(data)
        self.assertIsNotNone(form.instance.pk)
        self.assertFalse(form.is_valid())
        self.assertEqual(list(form.errors["api_password"]), ["API password is required for new servers"])
        self.assertFalse(type(self.server).objects.filter(hostname=data["hostname"]).exists())
        data["api_password"] = "StrongPassword123!"
        valid = VirtualminServerForm(data)
        self.assertTrue(valid.is_valid(), valid.errors)
        saved = valid.save()
        ciphertext = bytes(saved.encrypted_api_password)
        data["api_password"] = ""
        edit = VirtualminServerForm(data, instance=saved)
        self.assertTrue(edit.is_valid(), edit.errors)
        edit.save()
        saved.refresh_from_db()
        self.assertEqual(bytes(saved.encrypted_api_password), ciphertext)
        self.assertEqual(saved.get_api_password(), "StrongPassword123!")

    def account_form(self, domain: str) -> VirtualminAccountForm:
        return VirtualminAccountForm(
            {
                "domain": domain,
                "server": str(self.server.pk),
                "service": str(self.service.pk),
                "virtualmin_username": "regressionuser",
                "disk_quota_mb": "1000",
                "bandwidth_quota_mb": "10000",
                "status": "active",
            }
        )

    def test_account_form_accepts_and_normalizes_multilabel_domains(self) -> None:
        self.account.delete()
        for domain in ("Tenant.Example.COM", "deep.tenant.example.co.uk", "x.example.test"):
            form = self.account_form(domain)
            self.assertTrue(form.is_valid(), form.errors)
            self.assertEqual(form.cleaned_data["domain"], domain.lower())
        account = self.account_form("tenant.example.com").save()
        self.assertEqual(account.domain, "tenant.example.com")
        duplicate = self.account_form("TENANT.EXAMPLE.COM")
        self.assertFalse(duplicate.is_valid())
        self.assertIn("An account with this domain already exists", str(duplicate.errors["domain"]))

    def test_account_form_rejects_invalid_labels(self) -> None:
        self.account.delete()
        for domain in ("tenant-.com", "-tenant.com", "tenant..com", "tenant", "tenant.c", "a" * 64 + ".com"):
            with self.subTest(domain=domain):
                form = self.account_form(domain)
                self.assertFalse(form.is_valid())
                self.assertIn("domain", form.errors)

    def s3_transport(self, s3: MemoryS3) -> None:
        result = SettingsService.update_setting("backup.s3_bucket_name", "regression-backups")
        self.assertTrue(result.is_ok(), result)
        transport = patch("apps.provisioning.virtualmin_backup_service.boto3.client", return_value=s3)
        transport.start()
        self.addCleanup(transport.stop)

    def test_deletion_preserves_backups_sharing_the_selected_id_prefix(self) -> None:
        s3 = MemoryS3()
        self.s3_transport(s3)
        for backup_id in ("abc", "abc-other", "abcd"):
            s3.manifest(backup_id, {})
        expected = {key: value for key, value in s3.objects.items() if not key.startswith("virtualmin-backups/abc/")}
        result = self.backups.delete_backup("abc")
        self.assertEqual(s3.objects, expected)
        self.assertEqual(result.unwrap()["deleted_objects"], 2)
        missing = self.backups.delete_backup("ab")
        self.assertTrue(missing.is_err())
        self.assertEqual(s3.objects, expected)

    def test_partial_s3_deletion_returns_the_failed_key_and_reason(self) -> None:
        s3 = PartialDeleteS3()
        self.s3_transport(s3)
        s3.manifest("abc", {})
        result = self.backups.delete_backup("abc")
        self.assertTrue(result.is_err())
        self.assertIn("virtualmin-backups/abc/backup.tar.gz", result.unwrap_err())
        self.assertIn("AccessDenied", result.unwrap_err())
        self.assertIn("archive retained", result.unwrap_err())
        self.assertEqual(s3.objects, {"virtualmin-backups/abc/backup.tar.gz": b"archive"})

    def test_precondition_refusal_records_terminal_backup_progress(self) -> None:
        result = self.backups.backup_domain(self.account, progress_key="refused-job")
        self.assertTrue(result.is_err())
        self.assertIn("archive transport is unavailable", result.unwrap_err())
        progress = self.backups.get_backup_status("refused-job")
        self.assertEqual((progress["status"], progress["progress"]), ("failed", 100))
        self.assertIsNone(self.backups._progress_key)

    def test_restore_progress_uses_the_callers_job_key(self) -> None:
        s3 = MemoryS3()
        self.s3_transport(s3)
        result = self.backups.restore_domain(
            self.account, RestoreConfig(backup_id="missing"), progress_key="restore-job"
        )
        self.assertTrue(result.is_err())
        progress = self.backups.get_restore_status("restore-job")
        self.assertEqual((progress["status"], progress["progress"]), ("downloading", 10))
        self.assertTrue(str(progress["restore_id"]).startswith(self.account.domain + "_restore_"))
        self.assertIsNone(self.backups._progress_key)

    def managed_node(self) -> None:
        provider = CloudProvider.objects.create(
            name="Regression provider", provider_type="hetzner", code="reg", credential_identifier="regression-test"
        )
        region = NodeRegion.objects.create(
            provider=provider,
            name="Regression region",
            provider_region_id="fsn1",
            normalized_code="fsn1",
            country_code="de",
            city="Falkenstein",
        )
        size = NodeSize.objects.create(
            provider=provider,
            name="Regression small",
            display_name="Small",
            provider_type_id="cpx21",
            vcpus=2,
            memory_gb=4,
            disk_gb=40,
            hourly_cost_eur="0.01",
            monthly_cost_eur="5.00",
        )
        panel = PanelType.objects.create(
            name="Regression Virtualmin", panel_type="virtualmin", ansible_playbook="virtualmin.yml"
        )
        NodeDeployment.objects.create(
            provider=provider,
            node_size=size,
            region=region,
            panel_type=panel,
            hostname="prd-sha-reg-de-fsn1-001",
            node_number=1,
            ipv4_address="203.0.113.1",
            virtualmin_server=self.server,
        )

    def http_transport(self, method: str, url: str, **kwargs: object) -> requests.Response:
        params = cast("Mapping[str, object]", kwargs["params"])
        program = str(params["program"])
        if program == "list-domains":
            return http_response(
                {
                    "status": "success",
                    "data": [
                        {
                            "name": self.account.domain,
                            "values": {"disk_usage": self.domain_usage, "Username": "testexample"},
                        }
                    ],
                }
            )
        if program in ("info", "list-bandwidth", "backup-domain"):
            return http_response({"status": "success", "data": []})
        raise AssertionError(f"Unexpected Virtualmin command: {program}")

    def test_existing_empty_domain_passes_preconditions_but_absent_domain_does_not(self) -> None:
        self.managed_node()
        self.domain_usage = "0M"
        with patch("apps.provisioning.virtualmin_gateway.safe_request", side_effect=self.http_transport):
            result = self.backups._validate_backup_preconditions(self.account)
        self.assertTrue(result.is_ok(), result)
        with patch(
            "apps.provisioning.virtualmin_gateway.safe_request",
            return_value=http_response({"status": "success", "data": []}),
        ):
            missing = self.backups._validate_backup_preconditions(self.account)
        self.assertIn(f"Domain {self.account.domain} not found on server", missing.unwrap_err())

    def archive(self, features: tuple[str, ...]) -> bytes:
        buffer = io.BytesIO()
        with tarfile.open(fileobj=buffer, mode="w:gz") as archive:
            for feature in features:
                member = tarfile.TarInfo(f"{self.account.domain}_{feature}")
                member.size = 4
                archive.addfile(member, io.BytesIO(b"data"))
        return buffer.getvalue()

    def test_each_requested_feature_requires_matching_archive_members(self) -> None:
        with TemporaryDirectory() as directory:
            path = Path(directory) / "backup.tar.gz"
            for flag, feature in (
                ("include_email", "mail"),
                ("include_databases", "mysql"),
                ("include_files", "dir"),
                ("include_ssl", "ssl"),
            ):
                metadata: dict[str, object] = {
                    "backup_type": "full",
                    "domain": self.account.domain,
                    "backup_location": "spool",
                    "backup_path": str(path),
                    flag: True,
                }
                path.write_bytes(self.archive(("virtualmin",)))
                metadata["checksum_sha256_remote"] = hashlib.sha256(path.read_bytes()).hexdigest()
                with self.subTest(feature=feature):
                    refused = self.backups._verify_backup_integrity("verify", metadata)
                    self.assertTrue(refused.is_err())
                    self.assertIn(feature, refused.unwrap_err())
                    self.assertNotIn("verification_status", metadata)
                    path.write_bytes(self.archive((feature, "virtualmin")))
                    metadata["checksum_sha256_remote"] = hashlib.sha256(path.read_bytes()).hexdigest()
                    accepted = self.backups._verify_backup_integrity("verify", metadata)
                    self.assertTrue(accepted.is_ok(), accepted)
                    self.assertEqual(metadata["verification_status"], "passed")
            path.write_bytes(self.archive(("virtualmin", "dir")))
            config_metadata = self.backups._initialize_backup_metadata(
                self.account, "config_only", "config", BackupConfig(backup_type="config_only")
            )
            config_metadata.update(
                backup_location="spool",
                backup_path=str(path),
                checksum_sha256_remote=hashlib.sha256(path.read_bytes()).hexdigest(),
            )
            self.assertTrue(self.backups._verify_backup_integrity("config", config_metadata).is_ok())

    def test_incomplete_backup_is_never_published_and_spool_capacity_is_released(self) -> None:
        self.managed_node()
        s3 = MemoryS3()
        self.s3_transport(s3)
        with TemporaryDirectory() as directory:
            spool = Path(directory)
            spool.chmod(0o700)
            updated = SettingsService.update_setting("provisioning.migration_spool_dir", directory)
            self.assertTrue(updated.is_ok(), updated)

            def fetch(
                deployment: NodeDeployment, playbook: str, variables: dict[str, object], **kwargs: object
            ) -> Ok[AnsibleResult]:
                data = self.archive(("virtualmin", "dir", "mysql", "ssl"))
                path = Path(str(variables["spool_dir"])) / str(variables["archive_name"])
                path.write_bytes(data)
                return Ok(
                    AnsibleResult(
                        success=True,
                        playbook=playbook,
                        stdout=f"BACKUP_SHA256={hashlib.sha256(data).hexdigest()}",
                        stderr="",
                        return_code=0,
                    )
                )

            with (
                patch("apps.provisioning.virtualmin_gateway.safe_request", side_effect=self.http_transport),
                patch("apps.infrastructure.ansible_service.AnsibleService", autospec=True) as ssh,
            ):
                ssh.return_value.run_playbook.side_effect = fetch
                result = self.backups.backup_domain(self.account, progress_key="incomplete-job")
            self.assertTrue(result.is_err())
            self.assertIn("mail", result.unwrap_err())
            self.assertEqual(s3.objects, {})
            self.assertEqual(s3.writes, [])
            self.assertEqual(list(spool.iterdir()), [])
            self.assertFalse(SpoolReservation.objects.exists())
            self.assertEqual(self.backups.get_backup_status("incomplete-job")["status"], "failed")
