"""Bridge admission and a completed migration rerun share Account -> Servers -> Migration order."""

from datetime import timedelta
from threading import Event
from unittest import skipUnless
from unittest.mock import patch
from uuid import uuid4

from django.db import connection, transaction
from django.test import TransactionTestCase
from django.utils import timezone

from apps.provisioning.migration_bridge_cleanup import _claim
from apps.provisioning.virtualmin_migration_models import MigrationBridge, VirtualminMigration
from apps.provisioning.virtualmin_migration_service import VirtualminMigrationService
from apps.provisioning.virtualmin_models import VirtualminAccount, VirtualminServer
from tests.common.postgres_locking import backend_pid, database_worker, wait_for_blocker
from tests.provisioning import test_virtualmin_tasks as fixtures


@skipUnless(connection.vendor == "postgresql", "Requires PostgreSQL actual waits and deadlock detection")
class BridgeCleanupLockTests(TransactionTestCase):
    def setUp(self) -> None:
        self.enterContext(patch("django_q.tasks.async_task"))
        fixtures.VirtualminTaskTestBase.setUp(self)
        self.target = VirtualminServer.objects.create(name="Bridge target", hostname="bridge-target.example.test",
                                                     api_username="praho-acl", legacy_security_admission=True)
        self.migration = VirtualminMigration.objects.create(account=self.account, source_server=self.server,
            target_server=self.target, status="completed", archive_name="bridge.tar.gz")
        self.bridge = MigrationBridge.objects.create(migration=self.migration, source_server=self.server,
            target_server=self.target, domain=self.account.domain,
            evidence={"expires_at": (timezone.now() - timedelta(seconds=1)).isoformat()})
        self.bridge.activate()
        self.bridge.save()
        VirtualminAccount.objects.filter(pk=self.account.pk).update(server=self.target)

    def test_completed_migration_rerun_and_cleanup_do_not_deadlock(self) -> None:
        start = Event()
        owner = backend_pid()
        observed = []

        def claim():
            assert start.wait(10)
            return _claim(str(self.migration.pk), str(uuid4()))

        with database_worker(claim) as (pid, pending):
            def pause_after_servers(execute, sql, params, many, context):
                result = execute(sql, params, many, context)
                if not observed and VirtualminServer._meta.db_table in sql and "FOR UPDATE" in sql:
                    start.set()
                    observed.append(wait_for_blocker(pid, owner, pending, table="provisioning_virtualmin"))
                return result

            try:
                with connection.execute_wrapper(pause_after_servers):
                    result = VirtualminMigrationService().run(self.migration.pk)
            finally:
                start.set()
            claimed, action = pending.result(timeout=30)
        self.assertTrue(result.is_ok(), result)
        self.assertEqual(result.unwrap()["action"], "completed")
        self.assertEqual(action, "claimed")
        self.assertEqual(claimed.pk, self.bridge.pk)
        self.assertIn(VirtualminAccount._meta.db_table, observed[0])

    def test_same_bridge_claims_serialize_and_keep_first_lease(self) -> None:
        start = Event()
        owner = backend_pid()
        first_token = str(uuid4())

        def second():
            assert start.wait(10)
            return _claim(str(self.migration.pk), str(uuid4()))

        with database_worker(second) as (pid, pending):
            try:
                with transaction.atomic():
                    first, action = _claim(str(self.migration.pk), first_token)
                    self.assertEqual(action, "claimed")
                    start.set()
                    wait_for_blocker(pid, owner, pending, table=VirtualminAccount._meta.db_table)
            finally:
                start.set()
            self.assertEqual(pending.result(timeout=30), (None, "busy"))
        self.bridge.refresh_from_db()
        self.assertEqual(self.bridge.evidence["lease_token"], first_token)
        self.assertEqual(first.pk, self.bridge.pk)

    def test_unfinished_hint_locks_only_bridge_and_keeps_terminal_precedence(self) -> None:
        VirtualminMigration.objects.filter(pk=self.migration.pk).update(status="pending")  # fsm-bypass: unfinished fixture
        for status, expected in (("active", "waiting"), ("failed", "failed")):
            MigrationBridge.objects.filter(pk=self.bridge.pk).update(status=status)  # fsm-bypass: terminal fixture

            def claim():
                statements = []

                def observe(execute, sql, params, many, context):
                    if "FOR UPDATE" in sql:
                        statements.append(sql)
                    return execute(sql, params, many, context)

                with connection.execute_wrapper(observe):
                    result = _claim(str(self.migration.pk), str(uuid4()))
                return result, statements

            with transaction.atomic():
                VirtualminAccount.objects.select_for_update().get(pk=self.account.pk)
                list(VirtualminServer.objects.select_for_update().filter(pk__in=[self.server.pk, self.target.pk]))
                VirtualminMigration.objects.select_for_update().get(pk=self.migration.pk)
                with database_worker(claim) as (_, pending):
                    result, statements = pending.result(timeout=5)
            self.assertEqual(result, (None, expected))
            self.assertEqual(len(statements), 1)
            self.assertIn(MigrationBridge._meta.db_table, statements[0])
            self.assertNotIn(VirtualminMigration._meta.db_table, statements[0])

    def test_changed_hint_returns_waiting_and_releases_locks_inside_outer_atomic(self) -> None:
        replacement = VirtualminServer.objects.create(name="Changed target", hostname="changed.example.test", api_username="praho-acl")
        start, claimed, finish = Event(), Event(), Event()
        result = []
        owner = backend_pid()

        def claim():
            assert start.wait(10)
            with transaction.atomic():
                result.append(_claim(str(self.migration.pk), str(uuid4())))
                claimed.set()
                assert finish.wait(15)
            return result[0]

        with database_worker(claim) as (pid, pending):
            try:
                with transaction.atomic():
                    VirtualminAccount.objects.select_for_update().get(pk=self.account.pk)
                    start.set()
                    wait_for_blocker(pid, owner, pending, table=VirtualminAccount._meta.db_table)
                    VirtualminMigration.objects.filter(pk=self.migration.pk).update(target_server=replacement)
                self.assertTrue(claimed.wait(10))
                self.assertEqual(result, [(None, "waiting")])

                def probe():
                    with transaction.atomic():
                        VirtualminAccount.objects.select_for_update(nowait=True).get(pk=self.account.pk)
                        list(VirtualminServer.objects.select_for_update(nowait=True).filter(pk__in=[self.server.pk, self.target.pk]))
                        VirtualminMigration.objects.select_for_update(nowait=True).get(pk=self.migration.pk)
                        return MigrationBridge.objects.select_for_update(nowait=True).get(pk=self.bridge.pk).pk

                with database_worker(probe) as (_, probe_result):
                    self.assertEqual(probe_result.result(timeout=5), self.bridge.pk)
            finally:
                start.set()
                finish.set()
            self.assertEqual(pending.result(timeout=20), (None, "waiting"))
