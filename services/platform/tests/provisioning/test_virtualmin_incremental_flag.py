"""provisioning.incremental_backups_enabled gates creating bases and differentials, nothing else.

Readers ship before writers: turning the flag off stops new chain backups, while restores,
standalone backups and the existing chain state are untouched.
"""

from __future__ import annotations

from io import StringIO
from unittest.mock import patch

from django.core.management import call_command
from django.core.management.base import CommandError

from apps.provisioning.virtualmin_backup_service import BackupConfig, RestoreConfig
from apps.provisioning.virtualmin_models import VirtualminProvisioningJob, VirtualminServer
from apps.provisioning.virtualmin_service import VirtualminBackupManagementService
from apps.settings.services import SettingsService
from tests.provisioning.test_virtualmin_account_exclusion import ExclusionCase
from tests.provisioning.test_virtualmin_chain_state import ChainFixtures


class IncrementalBackupFlagTests(ChainFixtures, ExclusionCase):
    def setUp(self) -> None:
        super().setUp()
        self.account = self._account()
        self.management = VirtualminBackupManagementService(self.server)

    def set_flag(self, value: bool) -> None:
        self.assertTrue(SettingsService.update_setting("provisioning.incremental_backups_enabled", value).is_ok())

    def test_the_flag_defaults_off_and_refuses_every_way_to_create_a_chain_backup(self) -> None:
        self.assertFalse(SettingsService.get_boolean_setting("provisioning.incremental_backups_enabled", False))
        self.live_chain(self.account, epoch=2)
        with patch("django_q.tasks.async_task"):
            attempts = (
                self.management.take_base_backup(self.account),
                self.management.take_differential_backup(self.account),
                self.management.create_backup_job(self.account, BackupConfig(chain_role="base")),
                self.management.create_backup_job(self.account, BackupConfig(chain_role="differential")),
            )
        for attempt in attempts:
            self.assertTrue(attempt.is_err(), attempt)
            self.assertIn("disabled", attempt.unwrap_err())
        self.assertEqual(VirtualminProvisioningJob.objects.filter(parameters__has_key="chain_token").count(), 0)
        self.account.refresh_from_db()
        self.assertEqual(self.account.chain_epoch, 2, "a refused base must not clear the chain")

    def test_with_the_flag_on_the_entry_points_admit_the_right_role(self) -> None:
        self.set_flag(True)
        with patch("django_q.tasks.async_task"):
            base = self.management.take_base_backup(self.account).unwrap()
        self.assertEqual(base.parameters["chain_role"], "base")
        VirtualminProvisioningJob.objects.filter(pk=base.pk).update(status="failed")
        self.live_chain(self.account, epoch=5)
        with patch("django_q.tasks.async_task"):
            differential = self.management.take_differential_backup(self.account).unwrap()
        self.assertEqual(differential.parameters["chain_role"], "differential")

    def test_turning_the_flag_off_leaves_restore_standalone_backups_and_the_chain_alone(self) -> None:
        self.set_flag(False)
        base = self.live_chain(self.account, epoch=2)
        with patch("django_q.tasks.async_task"):
            self.assertTrue(self.management.create_backup_job(self.account).is_ok())
        VirtualminProvisioningJob.objects.all().update(status="completed")
        self.account.refresh_from_db()
        self.assertEqual((self.account.chain_base_id, self.account.chain_epoch), (base.pk, 2))
        with patch("django_q.tasks.async_task"):
            restore = self.management.create_restore_job(self.account, RestoreConfig(backup_id="b-1"))
        self.assertTrue(restore.is_ok(), restore)

    def test_the_pair_restore_follows_the_flag_in_the_service_and_the_cli(self) -> None:
        self.set_flag(False)
        with patch("django_q.tasks.async_task"):
            direct = self.management.create_pair_restore_job(self.account, "base-1", "diff-1", force_restore=True)
        self.assertTrue(direct.is_err(), direct)
        self.assertIn("disabled", direct.unwrap_err())
        arguments = ("restore", self.account.domain, "base-1", "--differential-backup-id", "diff-1", "--force-restore")
        with self.assertRaises(CommandError) as raised:
            call_command("virtualmin_backup", *arguments, stdout=StringIO())
        self.assertIn("disabled", str(raised.exception))
        self.assertFalse(VirtualminProvisioningJob.objects.filter(operation="restore_domain").exists())

    def test_the_cli_pair_restore_refuses_another_target_server(self) -> None:
        self.set_flag(True)
        other = VirtualminServer.objects.create(
            name="other-node", hostname="other-node.example.com", api_username="root", status="active"
        )
        arguments = (
            "restore",
            self.account.domain,
            "base-1",
            "--differential-backup-id",
            "diff-1",
            "--force-restore",
            "--target-server",
            other.hostname,
        )
        with self.assertRaises(CommandError) as raised:
            call_command("virtualmin_backup", *arguments, stdout=StringIO())
        self.assertIn("account's own server", str(raised.exception))
        self.assertFalse(VirtualminProvisioningJob.objects.filter(operation="restore_domain").exists())
