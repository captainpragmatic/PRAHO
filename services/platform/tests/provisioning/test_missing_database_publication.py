"""A database Virtualmin registers but MariaDB dropped reaches staff, and clears itself once it is gone (#776).

Only an accepted reading changes what Platform believes; a rejected one never adds or clears a name.
"""

from datetime import timedelta
from unittest.mock import patch
from uuid import uuid4

from django.db import transaction
from django.urls import reverse
from django.utils import timezone

from apps.provisioning import virtualmin_usage_service as usage
from apps.provisioning.virtualmin_backup_service import VirtualminBackupService
from apps.provisioning.virtualmin_models import VirtualminAccount
from apps.provisioning.virtualmin_usage_models import AccountUsageState, UsageReading
from tests.provisioning.test_cov_virtualmin_views_servers import VirtualminViewsFixture
from tests.provisioning.test_virtualmin_migration_service import MigrationTestBase


class MissingDatabasePublicationTests(MigrationTestBase):
    def setUp(self):
        super().setUp()
        self.settings_values["provisioning.usage_sync_enabled"] = True
        usage.current_state(self.account)
        # Readings here are backdated to order them; the owner scope began before all of them.
        AccountUsageState.objects.filter(account=self.account).update(
            gauge_not_before=timezone.now() - timedelta(hours=1)
        )
        self.installation = str(uuid4())

    def publish(self, *, missing=None, at=None, **changes):
        at = at or timezone.now()
        record = {
            "domain": self.account.domain,
            "username": self.account.virtualmin_username,
            "domain_id": "12345",
            "scan_started_at": at.isoformat(),
            "scan_finished_at": at.isoformat(),
            "disk_files_bytes": 300 * 1024**2,
            "disk_db_bytes": 20 * 1024**2,
            "databases": 1,
            "mailboxes": 0,
            "segments": [],
            **changes,
        }
        if missing is not None:
            record["missing_databases"] = missing
        payload = {"version": 1, "installation": self.installation, "observed_at": at.isoformat(), "records": [record]}
        return usage.publish_snapshot(self.server.pk, payload, usage.capture(self.server))

    def missing(self):
        return AccountUsageState.objects.get(account=self.account).missing_databases

    def test_an_accepted_reading_records_the_named_databases(self):
        self.assertEqual(self.publish(missing=["gone", "old_shop"]), 1)
        self.assertEqual(self.missing(), ["gone", "old_shop"])

    def test_a_later_accepted_reading_without_them_clears_the_note(self):
        start = timezone.now() - timedelta(minutes=10)
        self.assertEqual(self.publish(missing=["gone"], at=start), 1)
        self.assertEqual(self.publish(missing=[], at=start + timedelta(minutes=5)), 1)
        self.assertEqual(self.missing(), [])
        self.publish(missing=["gone"], at=start + timedelta(minutes=6))
        self.publish(at=start + timedelta(minutes=7))  # An older collector that reports nothing: none missing.
        self.assertEqual(self.missing(), [])

    def test_a_rejected_reading_never_changes_the_list(self):
        start = timezone.now() - timedelta(minutes=10)
        self.assertEqual(self.publish(missing=["gone"], at=start), 1)
        # Older than the accepted reading, and an invalid measurement: neither is accepted.
        self.assertEqual(self.publish(missing=[], at=start - timedelta(minutes=1)), 0)
        self.assertEqual(self.publish(missing=[], at=start + timedelta(minutes=1), disk_files_bytes=True), 0)
        self.assertEqual(self.missing(), ["gone"])

    def test_an_invalid_list_rejects_the_whole_reading(self):
        for value in (
            ["bad name"],
            ["gone", "gone"],
            "gone",
            [7],
            [{}],
            [[]],
            [f"db{n}" for n in range(33)],
            None,
            {"a": 1},
        ):
            with self.subTest(value=value):
                self.assertEqual(self.publish(missing_databases=value), 0)
                self.assertEqual(self.missing(), [])

    def test_anything_that_invalidates_the_reading_clears_its_list(self):
        def chain_epoch():
            type(self.account).objects.filter(pk=self.account.pk).update(chain_epoch=self.account.chain_epoch + 1)
            self.account.refresh_from_db()
            with transaction.atomic():
                usage.locked_state(self.account.pk)

        for name, invalidate in (
            ("owner reset", lambda: usage.reset_owner_scope(self.account.pk)),
            ("gauge invalidation", lambda: usage.invalidate_gauge(self.account.pk)),
            ("restore epoch", chain_epoch),
            # Last: the next publication would bring the state back to the account's own server.
            ("server move", lambda: usage.move_interval(self.account.pk, self.target.pk)),
        ):
            with self.subTest(name):
                AccountUsageState.objects.filter(account=self.account).update(
                    gauge_not_before=timezone.now() - timedelta(hours=1)
                )
                self.assertEqual(self.publish(missing=["gone"], at=timezone.now() - timedelta(minutes=1)), 1)
                with transaction.atomic():
                    invalidate()
                self.assertEqual(self.missing(), [])


class MissingDatabaseStaffNoteTests(VirtualminViewsFixture):
    def page(self):
        return self.client.get(reverse("provisioning:virtualmin_account_detail", args=[self.account.pk]))

    def note(self, names):
        state = usage.current_state(self.account)
        state.missing_databases = names
        state.disk_reading = UsageReading.objects.create(
            account=self.account,
            owner_scope=state.owner_scope,
            sync_token=uuid4(),
            server_id_snapshot=self.account.server_id,
            chain_epoch=self.account.chain_epoch,
            taken_at=timezone.now(),
            period_start=timezone.now(),
            period_end=timezone.now(),
            period_timezone="UTC",
        )
        state.save(update_fields=["missing_databases", "disk_reading"])

    def test_staff_see_each_dropped_database_and_the_cleanup(self):
        self.note(["gone", "old_shop"])
        content = self.page().content.decode()
        self.assertIn("gone", content)
        self.assertIn("old_shop", content)
        self.assertIn("virtualmin delete-database", content)
        self.assertIn(self.account.domain, content)

    def test_no_note_once_the_account_moved_past_its_reading(self):
        # Before anything syncs the usage state again: a restore's new chain epoch, another server or another
        # owner already makes the reading stale, and its advice could delete a database the restore recreated.
        self.note(["gone"])
        content = self.page().content.decode()
        self.assertIn("virtualmin delete-database", content)
        for change in ("chain_epoch", "server", "owner"):
            with self.subTest(change):
                state = AccountUsageState.objects.get(account=self.account)
                reading = state.disk_reading
                if change == "chain_epoch":
                    UsageReading.objects.filter(pk=reading.pk).update(chain_epoch=self.account.chain_epoch + 1)
                elif change == "server":
                    UsageReading.objects.filter(pk=reading.pk).update(server_id_snapshot=uuid4())
                else:
                    UsageReading.objects.filter(pk=reading.pk).update(owner_scope=uuid4())
                self.assertNotIn("virtualmin delete-database", self.page().content.decode())
                self.note(["gone"])

    def test_a_restore_admitted_while_the_page_renders_hides_the_note(self):
        # The page loads the account first, then lists backups over the network; a restore admitted meanwhile
        # moves the stored chain epoch, and the note must judge the account as it is now, not as first loaded.
        self.note(["gone"])
        real = VirtualminBackupService.list_backups

        def restore_admitted(service, **kwargs):
            VirtualminAccount.objects.filter(pk=self.account.pk).update(chain_epoch=self.account.chain_epoch + 1)
            return real(service, **kwargs)

        with patch.object(VirtualminBackupService, "list_backups", autospec=True, side_effect=restore_admitted):
            self.assertNotIn("virtualmin delete-database", self.page().content.decode())

    def test_no_note_without_the_reading_it_came_from(self):
        state = usage.current_state(self.account)
        state.missing_databases = ["gone"]
        state.disk_reading = None
        state.save(update_fields=["missing_databases", "disk_reading"])
        self.assertNotIn("virtualmin delete-database", self.page().content.decode())

    def test_no_note_while_nothing_is_missing(self):
        usage.current_state(self.account)
        self.assertNotIn("virtualmin delete-database", self.page().content.decode())
