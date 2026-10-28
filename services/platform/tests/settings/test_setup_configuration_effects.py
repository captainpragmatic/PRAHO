"""Configuration checks exercise stored settings through their actual consumers."""

import io
from io import StringIO
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import Mock, patch
from uuid import uuid4

from django.db import transaction
from django.test import TestCase, override_settings

from apps.common.encryption import DecryptionError
from apps.common.management.commands.upload_platform_backup import Command as UploadCommand
from apps.common.status_models import SystemCheckState
from apps.common.types import Ok
from apps.infrastructure.deployment_preflight import deployment_configuration_issues
from apps.provisioning.scheduled_backups import backup_configuration
from apps.provisioning.virtualmin_models import VirtualminServer
from apps.settings.models import SystemSetting
from apps.settings.services import SettingsService
from apps.settings.setup_checklist import evaluate_setup, storage_configured
from apps.settings.views import _test_node_dns_configuration


class SetupConfigurationEffectsTests(TestCase):
    def test_unreadable_secrets_keep_setup_and_repair_pages_accessible(self) -> None:
        from tests.factories.core_factories import create_admin_user  # noqa: PLC0415

        legacy = "aes:v1:bm90LXJlYWRhYmxl"
        keys = ("backup.aws_secret_access_key", "node_deployment.dns_cloudflare_api_token", "integrations.stripe_secret_key")
        self.set_value("backup.aws_access_key_id", "fixture-access")
        self.set_value("backup.s3_bucket_name", "fixture-backups")
        self.set_value("integrations.stripe_webhook_secret", "fixture-webhook")
        for key in keys:
            self.set_value(key, "fixture-secret")
            SystemSetting.objects.filter(key=key).update(value=legacy, is_sensitive=True)
            with self.assertRaises(DecryptionError):
                SettingsService.get_setting(key)
        self.assertFalse(storage_configured())
        self.client.force_login(create_admin_user(username="credential_repair_admin"))
        for path in ("/settings/", "/settings/setup/", "/settings/backup/", "/settings/node-deployment/", "/settings/stripe/"):
            with self.subTest(path=path):
                response = self.client.get(path)
                self.assertEqual(response.status_code, 200)
                self.assertNotContains(response, legacy)
                if path in {"/settings/backup/", "/settings/node-deployment/", "/settings/stripe/"}:
                    self.assertContains(response, "Stored value cannot be read")
                    unreadable = [row for section in response.context["sections"] for row in section["rows"] if row["key"] in keys]
                    self.assertTrue(unreadable)
                    for row in unreadable:
                        self.assertTrue(row["unreadable"])
                        self.assertTrue(row["modified"])
                        self.assertFalse(row["configured"])
                        self.assertIsNone(row["current"])
                if path == "/settings/":
                    self.assertGreaterEqual(response.context["modified_count"], len(keys))
                    stripe = next(state for state in response.context["integration_state"] if state["group"].slug == "stripe")
                    self.assertFalse(stripe["configured"])
                self.assertEqual(set(SystemSetting.objects.filter(key__in=keys).values_list("value", flat=True)), {legacy})
        with patch("apps.infrastructure.views.queue_deploy_node") as queue:
            response = self.client.post("/infrastructure/deployments/create/", {"environment": "stg"})
        self.assertContains(response, "Configure Cloudflare API token")
        queue.assert_not_called()
        self.assertEqual(set(SystemSetting.objects.filter(key__in=keys).values_list("value", flat=True)), {legacy})
        replacement = "replacement-fixture-secret"
        response = self.client.post(f"/settings/secret/{keys[0]}/", {"value": replacement}, content_type="application/json")
        self.assertTrue(response.json()["success"])
        self.assertNotContains(response, replacement)
        self.assertEqual(SettingsService.get_setting(keys[0]), replacement)
        self.assertEqual(SystemSetting.objects.get(key=keys[1]).value, legacy)

    def test_unrelated_read_errors_are_not_silenced_by_presentation_checks(self) -> None:
        from apps.settings.catalog import CATALOG_BY_KEY  # noqa: PLC0415
        from apps.settings.setup_checklist import _configured  # noqa: PLC0415
        from apps.settings.views import _row_context  # noqa: PLC0415

        key = "backup.aws_secret_access_key"
        with patch.object(SettingsService, "get_setting", side_effect=RuntimeError("unexpected defect")), self.assertRaises(RuntimeError):
            _configured(key)
        self.set_value(key, "fixture-secret")
        row = SystemSetting.objects.get(key=key)
        with patch.object(row, "get_typed_value", side_effect=RuntimeError("unexpected defect")), self.assertRaises(RuntimeError):
            _row_context(CATALOG_BY_KEY[key], row)

    def test_ses_setup_accepts_client_credentials_and_default_chain_without_discovery(self) -> None:
        from apps.settings.setup_checklist import _email_configured  # noqa: PLC0415

        configurations = (
            {"session_params": {}, "client_params": {"aws_access_key_id": "fixture", "aws_secret_access_key": "fixture", "region_name": "eu-west-1"}},
            {"session_params": {}, "client_params": {"region_name": "eu-west-1"}},
        )
        for configuration in configurations:
            with self.subTest(configuration=configuration), patch("apps.common.system_status_probes.email_probe_config", return_value=("ses", configuration)), patch("boto3.Session") as discovery:
                self.assertTrue(_email_configured())
                discovery.assert_not_called()
        with patch("apps.common.system_status_probes.email_probe_config", return_value=("ses", {"client_params": {"aws_access_key_id": "incomplete"}})):
            self.assertFalse(_email_configured())

    def set_value(self, key: str, value: object) -> None:
        result = SettingsService.update_setting(key, value)
        self.assertTrue(result.is_ok(), result)

    def items(self):
        return {item.key: item for section in evaluate_setup().sections for item in section.items}

    def test_malformed_endpoint_leaves_settings_accessible(self) -> None:
        from tests.factories.core_factories import create_admin_user  # noqa: PLC0415

        self.set_value("backup.s3_endpoint_url", "https://[")
        self.assertFalse(storage_configured())
        self.client.force_login(create_admin_user(username="storage_admin"))
        response = self.client.get("/settings/backup/")
        self.assertContains(response, "Backup")

    def test_smartbill_requires_company_series_and_tax_mapping(self) -> None:
        self.set_value("billing.invoice_issuer", "smartbill")
        self.set_value("integrations.smartbill_email", "billing@hosting.test")
        self.set_value("integrations.smartbill_token", "fixture-token")
        self.assertFalse(self.items()["issuer"].configured)
        self.set_value("integrations.smartbill_cif", "RO12345674")
        self.set_value("integrations.smartbill_invoice_series", "INV")
        self.set_value("integrations.smartbill_tax_names", {"S:21.00": "Standard"})
        self.assertTrue(self.items()["issuer"].configured)

    @override_settings(EMAIL_BACKEND="anymail.backends.sendgrid.EmailBackend", DEFAULT_FROM_EMAIL="notify@hosting.test", ANYMAIL={})
    def test_email_api_backend_without_credentials_is_incomplete(self) -> None:
        self.set_value("company.email_noreply", "notify@hosting.test")
        self.assertFalse(self.items()["email"].configured)
        with override_settings(ANYMAIL={"SENDGRID_API_KEY": "fixture-token"}):
            self.assertTrue(self.items()["email"].configured)

    def test_setup_cache_failure_keeps_saved_node_and_later_commit_callback(self) -> None:
        later = Mock()
        with patch("apps.settings.setup_checklist.cache.delete", side_effect=RuntimeError("cache unavailable")), self.captureOnCommitCallbacks(execute=True):
            node = VirtualminServer.objects.create(name="Cache test", hostname="cache.example.test", api_username="root", encrypted_api_password=b"")
            transaction.on_commit(later)
        self.assertTrue(VirtualminServer.objects.filter(pk=node.pk).exists())
        later.assert_called_once()

    def test_platform_enabled_flag_controls_stream_preflight_without_claiming(self) -> None:
        self.set_value("backup.platform_offsite_enabled", False)
        output = StringIO()
        UploadCommand(stdout=output).handle(check_enabled=True)
        self.assertEqual(output.getvalue().strip(), "disabled")
        UploadCommand(stdout=StringIO()).handle()
        self.assertFalse(SystemCheckState.objects.filter(check_key="platform_backup").exists())
        self.set_value("backup.platform_offsite_enabled", True)
        output = StringIO()
        UploadCommand(stdout=output).handle(check_enabled=True)
        self.assertEqual(output.getvalue().strip(), "enabled")

    def test_platform_command_publishes_to_the_current_configured_bucket(self) -> None:
        self.set_value("backup.platform_offsite_enabled", True)
        self.set_value("backup.aws_access_key_id", "fixture-access")
        self.set_value("backup.aws_secret_access_key", "fixture-secret")
        objects = {}
        client = Mock()

        uploads = {}
        client.create_multipart_upload.side_effect = lambda **_kw: {"UploadId": str(uuid4())}

        def upload_part(**kwargs):
            uploads.setdefault(kwargs["UploadId"], []).append(kwargs["Body"])
            return {"ETag": str(kwargs["PartNumber"])}

        def complete(**kwargs):
            objects[kwargs["Bucket"], kwargs["Key"]] = b"".join(uploads.pop(kwargs["UploadId"]))

        client.upload_part.side_effect = upload_part
        client.complete_multipart_upload.side_effect = complete
        client.get_object.side_effect = lambda **kwargs: {"Body": io.BytesIO(objects[kwargs["Bucket"], kwargs["Key"]])}
        with TemporaryDirectory() as directory, patch("apps.common.management.commands.upload_platform_backup.backup_storage_client", return_value=client):
            database, media = Path(directory) / "pair.dump", Path(directory) / "pair.media.tar.gz"
            database.write_bytes(b"database")
            media.write_bytes(b"documents")
            self.set_value("backup.s3_bucket_name", "fixture-first-bucket")
            UploadCommand(stdout=StringIO()).handle(database=database, media=media)
            self.assertEqual(client.put_object.call_args.kwargs["Bucket"], "fixture-first-bucket")
            self.set_value("backup.s3_bucket_name", "fixture-second-bucket")
            UploadCommand(stdout=StringIO()).handle(database=database, media=media)
            self.assertEqual(client.put_object.call_args.kwargs["Bucket"], "fixture-second-bucket")
        self.assertEqual(SystemCheckState.objects.get(check_key="platform_backup").level, "green")

    def test_deployment_prerequisites_follow_enabled_flag_and_dns_suffix(self) -> None:
        self.set_value("node_deployment.enabled", False)
        self.set_value("node_deployment.dns_default_zone", "")
        keys = {item.key for item in deployment_configuration_issues()}
        self.assertTrue({"enabled", "dns"} <= keys)
        self.set_value("node_deployment.enabled", True)
        self.set_value("node_deployment.dns_default_zone", "nodes.hosting.test")
        keys = {item.key for item in deployment_configuration_issues()}
        self.assertFalse({"enabled", "dns"} & keys)

    def test_dns_check_uses_stored_zone_and_token_with_no_mutation(self) -> None:
        self.set_value("node_deployment.dns_cloudflare_api_token", "fixture-token")
        self.set_value("node_deployment.dns_cloudflare_zone_id", "a" * 32)
        self.set_value("node_deployment.dns_default_zone", "nodes.hosting.test")
        with patch("apps.infrastructure.dns_gateway.CloudflareDnsGateway.get_zone_name", return_value=Ok("hosting.test")) as lookup:
            self.assertTrue(_test_node_dns_configuration()[0])
        lookup.assert_called_once_with("a" * 32)
        with patch("apps.infrastructure.dns_gateway.CloudflareDnsGateway.get_zone_name", return_value=Ok("other.test")):
            self.assertFalse(_test_node_dns_configuration()[0])

    def test_stripe_requires_enabled_flag_and_complete_credentials(self) -> None:
        self.set_value("integrations.stripe_secret_key", "sk_test_fixture")
        self.set_value("integrations.stripe_publishable_key", "pk_test_fixture")
        self.set_value("integrations.stripe_webhook_secret", "whsec_fixture")
        self.set_value("integrations.stripe_enabled", False)
        self.assertFalse(self.items()["payments"].configured)
        self.set_value("integrations.stripe_enabled", True)
        self.assertTrue(self.items()["payments"].configured)

    def test_hosting_configuration_rejects_invalid_schedule_and_disabled_or_legacy_mode(self) -> None:
        self.set_value("backup.aws_access_key_id", "fixture-access")
        self.set_value("backup.aws_secret_access_key", "fixture-secret")
        self.set_value("backup.s3_bucket_name", "fixture-bucket")
        self.set_value("node_deployment.backup_storage", "platform")
        self.set_value("node_deployment.backup_enabled", True)
        self.set_value("node_deployment.backup_schedule", "30 3 * * *")
        self.assertEqual(backup_configuration(), (True, "30 3 * * *"))
        self.assertTrue(self.items()["hosting_backup"].configured)
        self.set_value("node_deployment.backup_schedule", "broken")
        self.assertFalse(backup_configuration()[0])
        self.assertFalse(self.items()["hosting_backup"].configured)
        self.set_value("node_deployment.backup_schedule", "30 3 * * *")
        self.set_value("node_deployment.backup_enabled", False)
        self.assertFalse(backup_configuration()[0])
        self.set_value("node_deployment.backup_enabled", True)
        self.set_value("node_deployment.backup_storage", "local")
        self.assertFalse(backup_configuration()[0])
