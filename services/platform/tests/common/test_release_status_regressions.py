"""Existing configuration edits and runner registration must supersede old evidence."""

from concurrent.futures import ThreadPoolExecutor
from threading import Event
from unittest.mock import patch
from uuid import uuid4

from django.core.cache import cache
from django.core.management.base import CommandError
from django.db import connection, connections, transaction
from django.test import TestCase, TransactionTestCase, override_settings

from apps.common import system_status as status
from apps.common.management.commands.upload_platform_backup import Command
from apps.common.status_models import SystemCheckState
from apps.settings.models import SystemSetting
from apps.settings.services import SettingsService
from config.settings.test import LOCMEM_TEST_CACHE


@override_settings(CACHES=LOCMEM_TEST_CACHE)
class ExistingSettingEvidenceTests(TestCase):
    def setUp(self) -> None:
        cache.clear()
        self.addCleanup(cache.clear)

    def test_rejected_backup_releases_claim_before_storage_is_restored(self) -> None:
        key = "backup.s3_bucket_name"
        SettingsService.update_setting(key, "original-fixture-backups").unwrap()
        command = Command()
        run_id = uuid4()
        claim = command._claim(run_id, start=True)
        SettingsService.update_setting(key, "replacement-fixture-backups").unwrap()
        with self.assertRaisesMessage(CommandError, "superseded"):
            command._report(claim, run_id, success=True)
        row = SystemCheckState.objects.get(pk=claim.state_id)
        self.assertIsNone(row.claim_token)
        self.assertIsNone(row.lease_until)
        self.assertNotEqual(row.level, "green")
        SettingsService.update_setting(key, "original-fixture-backups").unwrap()
        retry = command._claim(uuid4(), start=True)
        self.assertNotEqual(retry.token, claim.token)

    def test_replacing_existing_credential_invalidates_green_cache(self) -> None:
        key = "integrations.stripe_secret_key"
        SettingsService.update_setting(key, "sk_test_original_fixture").unwrap()
        green = status.SubsystemStatus("Stripe", status.StatusLevel.GREEN, "Verified", key="stripe")
        with patch.object(status, "check_all_subsystems", return_value=[green]):
            status.run_status_refresh(force=True)
        self.assertEqual(status.get_cached_status().results[0].level, status.StatusLevel.GREEN)
        revision = SystemSetting.objects.get(key=key).revision
        SettingsService.update_setting(key, "sk_test_replaced_fixture").unwrap()
        self.assertEqual(SystemSetting.objects.get(key=key).revision, revision)
        self.assertNotEqual(status.get_cached_status().results[0].level, status.StatusLevel.GREEN)

    def test_existing_setting_changed_during_probe_cannot_publish_success(self) -> None:
        key = "integrations.stripe_secret_key"
        SettingsService.update_setting(key, "sk_test_original_fixture").unwrap()

        def probe():
            SettingsService.update_setting(key, "sk_test_replaced_fixture").unwrap()
            return [status.SubsystemStatus("Stripe", status.StatusLevel.GREEN, "Verified", key="stripe")]

        with patch.object(status, "check_all_subsystems", side_effect=probe):
            status.run_status_refresh(force=True)
        owner = SystemCheckState.objects.get(check_key="status_refresh")
        self.assertNotEqual(owner.level, "green")
        self.assertIsNone(owner.last_success_at)
        self.assertFalse(SystemCheckState.objects.filter(check_key="stripe", level="green").exists())

    def test_persisted_setting_metadata_changes_also_invalidate_identity(self) -> None:
        key = "node_deployment.enabled"
        SettingsService.update_setting(key, True).unwrap()
        for fields in ({"is_active": False}, {"default_value": False}, {"data_type": "string"}):
            with self.subTest(fields=fields):
                previous = status.runtime_input_identity()
                SystemSetting.objects.filter(key=key).update(**fields)
                self.assertNotEqual(status.runtime_input_identity(), previous)


class BackupRegistrationRaceTests(TransactionTestCase):
    def test_completion_preserves_runner_registered_while_waiting_for_lock(self) -> None:
        command = Command()
        command._register("native", "0 2 * * *", "UTC", enabled=True)
        run_id = uuid4()
        claim = command._claim(run_id, start=True)

        def register():
            command._register("native", "30 4 * * *", "Europe/Bucharest", enabled=False)

        if connection.vendor == "postgresql":
            waiting = Event()

            def report():
                def observe_lock(execute, sql, params, many, context):
                    if "FOR UPDATE" in sql and "common_system_check_state" in sql:
                        waiting.set()
                    return execute(sql, params, many, context)

                try:
                    with connection.execute_wrapper(observe_lock):
                        command._report(claim, run_id, success=True)
                finally:
                    connections.close_all()

            with ThreadPoolExecutor(max_workers=1) as pool:
                with transaction.atomic():
                    SystemCheckState.objects.select_for_update().get(pk=claim.state_id)
                    pending = pool.submit(report)
                    self.assertTrue(waiting.wait(timeout=10))
                    register()
                pending.result(timeout=10)
        else:
            register()
            command._report(claim, run_id, success=True)
        row = SystemCheckState.objects.get(pk=claim.state_id)
        self.assertEqual(row.details["schedule"], "30 4 * * *")
        self.assertEqual(row.details["schedule_timezone"], "Europe/Bucharest")
        self.assertFalse(row.details["runner_enabled"])
        self.assertTrue(row.details["configuration_applied"])
        self.assertEqual(row.details["run_id"], str(run_id))
        self.assertIn("offsite_completed_at", row.details)
        self.assertEqual(row.level, "green")
