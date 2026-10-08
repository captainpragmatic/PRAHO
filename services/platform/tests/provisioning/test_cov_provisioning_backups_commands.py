"""Coverage additions for backup, usage sync and deletion-protection commands."""

from __future__ import annotations

import io
from contextlib import redirect_stdout
from datetime import timedelta
from unittest.mock import patch
from uuid import uuid4

from django.core.cache import cache
from django.core.management import call_command
from django.core.management.base import CommandError
from django.test import override_settings
from django.utils import timezone

from apps.provisioning.virtualmin_models import VirtualminAccount, VirtualminProvisioningJob, VirtualminServer
from apps.settings.services import SettingsService
from tests.fixtures.virtualmin.responses import list_bandwidth, list_domains
from tests.provisioning.test_cov_provisioning_backups_storage import MemoryS3
from tests.provisioning.test_cov_virtualmin_gateway_listing import http_response
from tests.provisioning.test_virtualmin_tasks import VirtualminTaskTestBase


@override_settings(
    CACHES={"default": {"BACKEND": "django.core.cache.backends.locmem.LocMemCache"}},
    Q_CLUSTER={"retry": 14400, "orm": "default"},
)
class BackupCommandCoverageTests(VirtualminTaskTestBase):
    def setUp(self) -> None:
        super().setUp()
        cache.clear()
        self.addCleanup(cache.clear)
        result = SettingsService.update_setting("backup.s3_bucket_name", "coverage-backups")
        self.assertTrue(result.is_ok(), result)
        self.s3 = MemoryS3()
        transport = patch("apps.provisioning.virtualmin_backup_service.boto3.client", return_value=self.s3)
        transport.start()
        self.addCleanup(transport.stop)

    def command(self, *arguments: str) -> str:
        output = io.StringIO()
        call_command("virtualmin_backup", *arguments, stdout=output, no_color=True)
        return output.getvalue()

    def test_no_action_renders_cli_help(self) -> None:
        console = io.StringIO()
        with redirect_stdout(console):
            self.command()
        self.assertIn("Manage Virtualmin domain backups and restores", console.getvalue())
        self.assertIn("{backup,restore,list,delete,status}", console.getvalue())

    def test_missing_account_and_explicit_server_report_actionable_errors(self) -> None:
        cases = (
            (("backup", "missing.example.test"), "Virtualmin account for domain"),
            (("restore", "missing.example.test", "published"), "Virtualmin account for domain"),
            (("backup", self.account.domain, "--server", "missing.example.test"), "Server 'missing"),
            (
                ("restore", self.account.domain, "published", "--target-server", "missing.example.test"),
                "Target server 'missing",
            ),
            (("list", "--domain", "missing.example.test"), "Domain 'missing"),
        )
        for arguments, diagnostic in cases:
            with self.subTest(arguments=arguments), self.assertRaisesRegex(CommandError, diagnostic):
                self.command(*arguments)
        self.assertFalse(VirtualminProvisioningJob.objects.exists())

    def test_inline_commands_refuse_transactional_execution_without_admitting_jobs(self) -> None:
        for arguments in (
            (
                "backup",
                self.account.domain,
                "--type",
                "config_only",
                "--server",
                self.server.hostname,
                "--no-email",
                "--no-databases",
                "--no-files",
                "--no-ssl",
            ),
            (
                "restore",
                self.account.domain,
                "published",
                "--target-server",
                self.server.hostname,
                "--force-restore",
                "--no-email",
                "--no-databases",
                "--no-files",
                "--no-ssl",
            ),
        ):
            with self.subTest(arguments=arguments), self.assertRaisesRegex(CommandError, "requires autocommit"):
                self.command(*arguments)
        self.assertFalse(VirtualminProvisioningJob.objects.exists())

    def test_listing_renders_filtered_metadata_and_enabled_features(self) -> None:
        metadata: dict[str, object] = {
            "backup_id": "published",
            "domain": self.account.domain,
            "backup_type": "full",
            "created_at": timezone.now().isoformat(),
            "status": "completed",
            "praho_service_id": str(self.account.service_id),
            "include_email": True,
            "include_databases": True,
            "include_files": True,
            "include_ssl": True,
        }
        self.s3.manifest("published", metadata)
        self.s3.manifest("foreign", {**metadata, "backup_id": "foreign", "praho_service_id": "foreign"})
        self.s3.manifest(
            "expired",
            {
                **metadata,
                "backup_id": "expired",
                "created_at": (timezone.now() - timedelta(days=3)).isoformat(),
            },
        )
        output = self.command("list", "--domain", self.account.domain, "--type", "full", "--max-age", "1")
        self.assertIn("Found 1 backup(s)", output)
        self.assertIn("Backup ID: published", output)
        self.assertIn(f"Domain: {self.account.domain}", output)
        self.assertIn("Status: completed", output)
        self.assertIn("Features: email, databases, files, ssl", output)
        self.assertNotIn("Backup ID: foreign", output)
        self.assertNotIn("Backup ID: expired", output)

    def test_empty_listing_and_featureless_metadata_render_without_a_features_line(self) -> None:
        self.assertIn("No backups found matching criteria", self.command("list"))
        self.s3.manifest(
            "minimal",
            {
                "backup_id": "minimal",
                "domain": self.account.domain,
                "backup_type": "config_only",
                "created_at": timezone.now().isoformat(),
                "status": "completed",
            },
        )
        output = self.command("list")
        self.assertIn("Type: config_only", output)
        self.assertNotIn("Features:", output)

    def test_list_transport_failure_becomes_command_error(self) -> None:
        self.s3.failure = "list"
        with self.assertRaisesRegex(CommandError, "Failed to list backups:.*S3 listing unavailable"):
            self.command("list")

    def test_delete_requires_confirmation_and_then_removes_stored_objects(self) -> None:
        self.s3.manifest("published", {})
        self.assertIn("Add --confirm to proceed", self.command("delete", "published"))
        self.assertEqual(len(self.s3.objects), 2)
        output = self.command("delete", "published", "--confirm")
        self.assertIn("deleted successfully", output)
        self.assertIn("Deleted 2 objects", output)
        self.assertEqual(self.s3.objects, {})

    def test_missing_delete_and_transport_failure_become_command_errors(self) -> None:
        with self.assertRaisesRegex(CommandError, "Backup missing not found"):
            self.command("delete", "missing", "--confirm")
        self.s3.manifest("published", {})
        self.s3.failure = "delete"
        with self.assertRaisesRegex(CommandError, "S3 deletion unavailable"):
            self.command("delete", "published", "--confirm")
        self.assertEqual(len(self.s3.objects), 2)

    def test_commands_requiring_a_server_refuse_when_none_is_active(self) -> None:
        VirtualminServer.objects.filter(pk=self.server.pk).update(status="maintenance")
        for arguments in (("list",), ("delete", "published", "--confirm"), ("status", "job")):
            with (
                self.subTest(arguments=arguments),
                self.assertRaisesRegex(CommandError, "No Virtualmin servers configured"),
            ):
                self.command(*arguments)
        self.assertFalse(VirtualminProvisioningJob.objects.exists())

    def test_status_renders_backup_restore_and_unknown_cache_states(self) -> None:
        self.assertIn("No status found for operation 'job'", self.command("status", "job"))
        for prefix, title, updated_at in (
            ("virtualmin_restore_progress_", "Restore", None),
            ("virtualmin_restore_progress_", "Restore", "2026-01-01T00:00:00+00:00"),
            ("virtualmin_backup_progress_", "Backup", None),
            ("virtualmin_backup_progress_", "Backup", "2026-01-01T00:00:00+00:00"),
        ):
            progress: dict[str, object] = {"status": "completed", "progress": 100}
            if updated_at is not None:
                progress["updated_at"] = updated_at
            cache.set(prefix + "job", progress)
            output = self.command("status", "job")
            self.assertIn(f"{title} Status for 'job'", output)
            self.assertIn("Status: completed", output)
            self.assertIn("Progress: 100%", output)
            self.assertEqual("Updated:" in output, updated_at is not None)
            cache.delete(prefix + "job")


class UsageCommandCoverageTests(VirtualminTaskTestBase):
    def command(self, *arguments: str) -> str:
        output = io.StringIO()
        call_command("sync_virtualmin_usage", *arguments, stdout=output, no_color=True)
        return output.getvalue()

    def test_server_filter_and_dry_run_leave_usage_unchanged(self) -> None:
        self.assertIn("No accounts found on server absent", self.command("--server", "absent"))
        output = self.command("--server", self.server.name, "--dry-run")
        self.assertIn("Found 1 accounts to sync", output)
        self.assertIn(f"DRY RUN: Would fetch usage data for {self.account.domain}", output)
        self.account.refresh_from_db()
        self.assertIsNone(self.account.last_sync_at)
        self.assertEqual(self.account.current_disk_usage_mb, 0)
        self.assertNotIn("Sync completed", output)

    def test_sync_persists_usage_quotas_and_timestamp_from_http(self) -> None:
        self.account.current_disk_usage_mb = 12
        self.account.current_bandwidth_usage_mb = 34
        self.account.save(update_fields=["current_disk_usage_mb", "current_bandwidth_usage_mb"])
        payload = list_domains.single_domain(domain=self.account.domain)
        payload["data"][0]["values"]["disk_quota"] = "1000 MB"
        with patch(
            "apps.provisioning.virtualmin_gateway.safe_request",
            side_effect=[http_response(payload), http_response(list_bandwidth.empty()), http_response(payload)],
        ):
            output = self.command("--server", self.server.name)
        self.account.refresh_from_db()
        self.assertEqual(self.account.current_disk_usage_mb, 150)
        self.assertEqual(self.account.current_bandwidth_usage_mb, 500)
        self.assertEqual(self.account.disk_quota_mb, 1000)
        self.assertEqual(self.account.bandwidth_quota_mb, 10000)
        self.assertIsNotNone(self.account.last_sync_at)
        self.assertIn("disk 12MB → 150MB, bandwidth 34MB → 500MB", output)
        self.assertIn("Sync completed: 1 updated, 0 errors", output)

    def test_unexpected_transport_exception_preserves_usage_and_is_reported(self) -> None:
        with patch("apps.provisioning.virtualmin_gateway.safe_request", side_effect=RuntimeError("transport broke")):
            output = self.command()
        self.account.refresh_from_db()
        self.assertEqual(self.account.current_disk_usage_mb, 0)
        self.assertIsNone(self.account.last_sync_at)
        self.assertIn("Exception - transport broke", output)
        self.assertIn("Sync completed: 0 updated, 1 errors", output)

    def test_empty_inventory_reports_no_accounts(self) -> None:
        self.account.delete()
        self.assertIn("No accounts found", self.command())

    def test_gateway_failure_preserves_usage_and_reports_error_summary(self) -> None:
        with patch("apps.provisioning.virtualmin_gateway.safe_request", return_value=http_response({}, 403)):
            output = self.command()
        self.account.refresh_from_db()
        self.assertEqual(self.account.current_disk_usage_mb, 0)
        self.assertIsNone(self.account.last_sync_at)
        self.assertIn(f"❌ {self.account.domain}:", output)
        self.assertIn("Access forbidden", output)
        self.assertIn("Sync completed: 0 updated, 1 errors", output)


class ProtectionCommandCoverageTests(VirtualminTaskTestBase):
    def command(self, *arguments: str, stdin: str = "") -> str:
        output = io.StringIO()
        with patch("sys.stdin", io.StringIO(stdin)):
            call_command("virtualmin_protection", *arguments, stdout=output, no_color=True)
        return output.getvalue()

    def test_invalid_flag_combinations_and_missing_confirmation_preserve_protection(self) -> None:
        for arguments, diagnostic in (
            (("--enable", "--disable", "--all"), "Cannot enable and disable"),
            ((), "Must specify either --enable or --disable"),
            (("--enable",), "Must specify either --all or --domain"),
            (("--disable", "--all"), "Add --confirm"),
        ):
            with self.subTest(arguments=arguments), self.assertRaisesRegex(CommandError, diagnostic):
                self.command(*arguments)
        self.account.refresh_from_db()
        self.assertTrue(self.account.protected_from_deletion)

    def test_enable_domain_and_all_persist_protection_and_report_matches(self) -> None:
        VirtualminAccount.objects.filter(pk=self.account.pk).update(protected_from_deletion=False)
        output = self.command("--enable", "--domain", self.account.domain)
        self.account.refresh_from_db()
        self.assertTrue(self.account.protected_from_deletion)
        self.assertIn("Enabled deletion protection for 1 account(s)", output)
        self.assertIn("No accounts found matching criteria", self.command("--enable", "--domain", "missing"))
        self.assertIn("Enabled deletion protection for 1 account(s)", self.command("--enable", "--all"))

    def test_disable_requires_exact_confirmation_and_persists_the_result(self) -> None:
        cancelled = self.command("--disable", "--domain", self.account.domain, "--confirm", stdin="no\n")
        self.account.refresh_from_db()
        self.assertTrue(self.account.protected_from_deletion)
        self.assertIn("Operation cancelled", cancelled)
        output = self.command("--disable", "--all", "--confirm", stdin="I really am sure I want to do this!\n")
        self.account.refresh_from_db()
        self.assertFalse(self.account.protected_from_deletion)
        self.assertIn(self.account.domain, output)
        self.assertIn("Disabled deletion protection for 1 account(s)", output)

    def test_status_reports_both_protection_states_and_empty_inventory(self) -> None:
        output = self.command("--status")
        self.assertIn(self.account.domain, output)
        self.assertIn("PROTECTED", output)
        self.assertIn("Protected: 1 | Unprotected: 0", output)
        VirtualminAccount.objects.filter(pk=self.account.pk).update(protected_from_deletion=False)
        self.assertIn("Protected: 0 | Unprotected: 1", self.command("--status"))
        self.account.delete()
        self.assertIn("No Virtualmin accounts found", self.command("--status"))

    def test_disable_missing_domain_reports_no_matches_without_prompting(self) -> None:
        output = self.command("--disable", "--domain", str(uuid4()), "--confirm")
        self.assertIn("No accounts found matching criteria", output)
        self.account.refresh_from_db()
        self.assertTrue(self.account.protected_from_deletion)
