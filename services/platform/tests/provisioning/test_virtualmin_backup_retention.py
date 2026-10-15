"""Retention and deletion honour differential lineage.

A differential holds only what changed since its base, so a base is needed for as long as any
differential naming it is kept. Lineage is read from every manifest in storage, never from a
filtered listing; deletion is serialised with the account's restore admission; and a manifest
that cannot be read or understood stops the deletion rather than being treated as "no lineage".
"""

from __future__ import annotations

import hashlib
from datetime import timedelta
from tempfile import TemporaryDirectory
from typing import Any
from unittest import skipUnless
from unittest.mock import patch

from django.db import connection
from django.db.models.query import QuerySet
from django.test.utils import CaptureQueriesContext
from django.utils import timezone

from apps.provisioning.virtualmin_backup_service import VirtualminBackupService
from apps.provisioning.virtualmin_models import VirtualminAccount, VirtualminProvisioningJob
from apps.settings.services import SettingsService
from tests.provisioning.test_cov_provisioning_backups_storage import MemoryS3
from tests.provisioning.test_virtualmin_tasks import VirtualminTaskTestBase


class LineageFixture(VirtualminTaskTestBase):
    def setUp(self) -> None:
        super().setUp()
        spool = TemporaryDirectory()
        self.addCleanup(spool.cleanup)
        for key, value in (("backup.s3_bucket_name", "coverage-backups"), ("provisioning.migration_spool_dir", spool.name)):
            self.assertTrue(SettingsService.update_setting(key, value).is_ok())
        self.s3 = MemoryS3()
        self.backups = VirtualminBackupService(self.server)
        transport = patch("apps.provisioning.virtualmin_backup_service.boto3.client", return_value=self.s3)
        transport.start()
        self.addCleanup(transport.stop)

    def metadata(self, backup_id: str, role: str = "standalone", *, base: str = "", age_days: int = 1, **extra: Any) -> dict[str, Any]:
        metadata: dict[str, Any] = {
            "backup_id": backup_id,
            "domain": self.account.domain,
            "praho_service_id": str(self.account.service_id),
            "backup_type": "full",
            "status": "completed",
            "created_at": (timezone.now() - timedelta(days=age_days)).isoformat(),
            "archive_name": "virtualmin_backup_" + "a" * 32 + ".tar.gz",
            "checksum_sha256": hashlib.sha256(b"archive").hexdigest(),
        }
        if role != "standalone":
            metadata |= {"manifest_version": 1, "chain_role": role}
        if base:
            metadata["base_backup_id"] = base
        return metadata | extra

    def store(self, backup_id: str, role: str = "standalone", **kwargs: Any) -> None:
        self.s3.manifest(backup_id, self.metadata(backup_id, role, **kwargs))

    def stored(self) -> set[str]:
        return {key.split("/")[1] for key in self.s3.objects}


class BaseDeletionTests(LineageFixture):
    def test_a_base_named_by_a_retained_differential_cannot_be_deleted(self) -> None:
        self.store("base-1", "base")
        self.store("diff-1", "differential", base="base-1")
        result = self.backups.delete_backup("base-1")
        self.assertTrue(result.is_err(), result)
        self.assertIn("diff-1", result.unwrap_err())
        self.assertEqual(self.stored(), {"base-1", "diff-1"})

    def test_lineage_is_found_without_the_list_filters(self) -> None:
        # None of these would appear in an account-scoped, age-limited, full-backup listing.
        hidden = {
            "older than retention": {"age_days": 400},
            "another service id": {"praho_service_id": "another-service"},
            "no service id": {"praho_service_id": None},
            "not a full backup type": {"backup_type": "config_only"},
        }
        for label, overrides in hidden.items():
            with self.subTest(case=label):
                self.s3.objects.clear()
                self.store("base-1", "base")
                self.store("diff-1", "differential", base="base-1", **overrides)
                result = self.backups.delete_backup("base-1")
                self.assertTrue(result.is_err(), result)
                self.assertEqual(self.stored(), {"base-1", "diff-1"})

    def test_a_base_is_deletable_once_no_differential_names_it(self) -> None:
        self.store("base-1", "base")
        self.store("base-2", "base")
        self.store("diff-2", "differential", base="base-2")
        self.assertTrue(self.backups.delete_backup("diff-2").is_ok())
        self.assertTrue(self.backups.delete_backup("base-1").is_ok())
        self.assertTrue(self.backups.delete_backup("base-2").is_ok())
        self.assertEqual(self.stored(), set())

    def test_differentials_and_standalone_backups_delete_freely(self) -> None:
        self.store("base-1", "base")
        self.store("diff-1", "differential", base="base-1")
        self.store("plain-1")
        self.assertTrue(self.backups.delete_backup("diff-1").is_ok())
        self.assertTrue(self.backups.delete_backup("plain-1").is_ok())
        self.assertEqual(self.stored(), {"base-1"})

    def test_an_unreadable_or_unknown_manifest_stops_the_deletion(self) -> None:
        cases = {
            "target manifest is not json": lambda: self.s3.objects.update({"virtualmin-backups/base-1/metadata.json": b"{bad"}),
            "target manifest is missing": lambda: self.s3.objects.pop("virtualmin-backups/base-1/metadata.json"),
            "target has an unknown version": lambda: self.store("base-1", "base", manifest_version=99),
            "target has an unknown role": lambda: self.store("base-1", "base", chain_role="mirror"),
            "another manifest is not json": lambda: self.s3.objects.update({"virtualmin-backups/other/metadata.json": b"{bad"}),
            "another manifest has an unknown version": lambda: self.store("other", "differential", base="base-1", manifest_version=99),
            "another manifest is not an object": lambda: self.s3.objects.update({"virtualmin-backups/other/metadata.json": b"[1]"}),
        }
        for label, break_it in cases.items():
            with self.subTest(case=label):
                self.s3.objects.clear()
                self.store("base-1", "base")
                self.store("other", "differential", base="elsewhere")
                break_it()
                before = dict(self.s3.objects)
                result = self.backups.delete_backup("base-1")
                self.assertTrue(result.is_err(), result)
                self.assertEqual(self.s3.objects, before, "nothing may be deleted")

    def test_a_storage_error_while_reading_lineage_stops_the_deletion(self) -> None:
        self.store("base-1", "base")
        self.store("other", "differential", base="elsewhere")
        self.s3.failure = "get"
        result = self.backups.delete_backup("base-1")
        self.assertTrue(result.is_err(), result)
        self.assertEqual(self.stored(), {"base-1", "other"})

    def test_a_missing_backup_is_still_reported_as_not_found(self) -> None:
        self.assertEqual(self.backups.delete_backup("nope").unwrap_err(), "Backup nope not found")


class PinnedDeletionTests(LineageFixture):
    def restore_job(self, status: str, **parameters: str) -> VirtualminProvisioningJob:
        return VirtualminProvisioningJob.objects.create(
            operation="restore_domain", account=self.account, server=self.server, status=status, parameters=parameters
        )

    def test_a_backup_an_active_restore_names_cannot_be_deleted(self) -> None:
        for status in ("pending", "running", "attention"):
            with self.subTest(status=status):
                self.store("plain-1")
                job = self.restore_job(status, backup_id="plain-1")
                result = self.backups.delete_backup("plain-1")
                self.assertTrue(result.is_err(), result)
                self.assertEqual(self.stored(), {"plain-1"})
                job.delete()

    def test_both_members_of_a_pair_restore_are_pinned(self) -> None:
        self.store("base-1", "base")
        self.store("diff-1", "differential", base="base-1")
        job = self.restore_job("running", restore_mode="pair", base_backup_id="base-1", differential_backup_id="diff-1")
        for backup_id in ("diff-1", "base-1"):
            with self.subTest(backup_id=backup_id):
                self.assertTrue(self.backups.delete_backup(backup_id).is_err())
        job.delete()
        self.assertTrue(self.backups.delete_backup("diff-1").is_ok())

    def test_the_safety_backup_of_a_restore_in_attention_cannot_be_deleted(self) -> None:
        # The safety backup is the only way back from a half-restored domain.
        for status in ("pending", "running", "attention"):
            with self.subTest(status=status):
                self.store("safety-1")
                job = self.restore_job(status, backup_id="plain-1", safety_backup_id="safety-1")
                result = self.backups.delete_backup("safety-1")
                self.assertTrue(result.is_err(), result)
                self.assertIn("restore that has not finished", result.unwrap_err())
                self.assertEqual(self.stored(), {"safety-1"})
                job.delete()
        self.assertTrue(self.backups.delete_backup("safety-1").is_ok())

    def test_finished_restores_do_not_pin(self) -> None:
        self.store("plain-1")
        for status in ("failed", "completed", "cancelled"):
            self.restore_job(status, backup_id="plain-1")
        self.assertTrue(self.backups.delete_backup("plain-1").is_ok())

    def test_the_live_chain_base_cannot_be_deleted(self) -> None:
        self.store("base-1", "base")
        base_job = VirtualminProvisioningJob.objects.create(
            operation="backup_domain",
            account=self.account,
            server=self.server,
            status="completed",
            result={"backup_id": "base-1"},
        )
        VirtualminAccount.objects.filter(pk=self.account.pk).update(chain_base=base_job, chain_base_fingerprint="a" * 64 + ":1")
        result = self.backups.delete_backup("base-1")
        self.assertTrue(result.is_err(), result)
        self.assertIn("live", result.unwrap_err())
        VirtualminAccount.objects.filter(pk=self.account.pk).update(chain_base=None, chain_base_fingerprint="")
        self.assertTrue(self.backups.delete_backup("base-1").is_ok())

    def test_deletion_holds_the_account_lock_while_it_deletes(self) -> None:
        self.store("plain-1")
        locked_models: list[str] = []
        real = QuerySet.select_for_update

        def spy(queryset: QuerySet[Any], *args: Any, **kwargs: Any) -> QuerySet[Any]:
            locked_models.append(queryset.model.__name__)
            return real(queryset, *args, **kwargs)

        atomic_during_delete: list[bool] = []
        real_delete = self.s3.delete_objects

        def delete_objects(**kwargs: object) -> dict[str, object]:
            atomic_during_delete.append(connection.in_atomic_block)
            return real_delete(**kwargs)

        with (
            patch.object(self.s3, "delete_objects", side_effect=delete_objects),
            patch.object(QuerySet, "select_for_update", autospec=True, side_effect=spy),
        ):
            self.assertTrue(self.backups.delete_backup("plain-1").is_ok())
        self.assertEqual(locked_models, ["VirtualminAccount"])
        self.assertEqual(atomic_during_delete, [True], "the pin check and the delete share one locked transaction")


class AccountLockQueryTests(LineageFixture):
    """The account lock is taken on the account row alone (a join to the nullable chain base is rejected)."""

    def locking_query(self) -> str:
        with CaptureQueriesContext(connection) as queries:
            self.backups.delete_backup("plain-1")
        accounts = [
            entry["sql"] for entry in queries.captured_queries if 'FROM "provisioning_virtualmin_accounts"' in entry["sql"]
        ]
        self.assertTrue(accounts, "the delete read the owning account")
        return accounts[0]

    def test_the_lock_query_joins_no_table(self) -> None:
        # PostgreSQL: "FOR UPDATE cannot be applied to the nullable side of an outer join".
        self.store("plain-1")
        self.assertNotIn("JOIN", self.locking_query())

    @skipUnless(connection.vendor == "postgresql", "Requires PostgreSQL row locks; exercised in Integration CI")
    def test_a_delete_is_not_rejected_by_the_database(self) -> None:
        self.store("plain-1")
        result = self.backups.delete_backup("plain-1")
        self.assertTrue(result.is_ok(), result)

    @skipUnless(connection.vendor == "postgresql", "Requires PostgreSQL row locks; exercised in Integration CI")
    def test_the_live_base_is_refused_for_its_own_reason_not_the_databases(self) -> None:
        self.store("base-1", "base")
        base_job = VirtualminProvisioningJob.objects.create(
            operation="backup_domain",
            account=self.account,
            server=self.server,
            status="completed",
            result={"backup_id": "base-1"},
        )
        VirtualminAccount.objects.filter(pk=self.account.pk).update(
            chain_base=base_job, chain_base_fingerprint="a" * 64 + ":1"
        )
        result = self.backups.delete_backup("base-1")
        self.assertTrue(result.is_err(), result)
        self.assertIn("live base", result.unwrap_err())


class RetentionTests(LineageFixture):
    def test_retention_keeps_the_base_of_a_retained_differential(self) -> None:
        self.store("base-1", "base", age_days=60)
        self.store("diff-1", "differential", base="base-1", age_days=2)
        self.store("old-plain", age_days=60)
        listed = {item["backup_id"] for item in self.backups.list_backups(self.account, max_age_days=30).unwrap()}
        self.assertEqual(listed, {"diff-1", "base-1"}, "the old base is extended; the unrelated old backup expires")

    def test_a_base_whose_differentials_have_all_expired_expires_with_them(self) -> None:
        self.store("base-1", "base", age_days=60)
        self.store("diff-1", "differential", base="base-1", age_days=45)
        self.assertEqual(self.backups.list_backups(self.account, max_age_days=30).unwrap(), [])
