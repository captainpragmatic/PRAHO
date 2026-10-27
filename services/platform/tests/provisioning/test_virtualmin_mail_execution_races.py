"""Independent PostgreSQL connections serialize mail claims and stale checkpoints."""

import threading
import time
from concurrent.futures import ThreadPoolExecutor

from django.db import close_old_connections, connection, transaction
from django.test import TransactionTestCase, override_settings
from django.utils import timezone

from apps.provisioning import virtualmin_mail_execution as execution
from apps.provisioning.virtualmin_mail_models import VirtualminMailOperation
from apps.provisioning.virtualmin_models import VirtualminAccount
from tests.provisioning.test_virtualmin_mail_execution import MailExecutionFixture

_SECONDS = 15


@override_settings(DISABLE_AUDIT_SIGNALS=True, AUDIT_CHAIN_ENABLED=False)
class MailExecutionPostgresRaceTests(MailExecutionFixture, TransactionTestCase):
    def setUp(self):
        if connection.vendor != "postgresql":
            self.skipTest("Mail execution contention requires PostgreSQL row locks")
        super().setUp()
        with connection.cursor() as cursor:
            cursor.execute("SELECT pg_backend_pid()")
            self.main_pid = cursor.fetchone()[0]

    def _thread(self, action, pids, ready, done):
        close_old_connections()
        try:
            with connection.cursor() as cursor:
                cursor.execute("SET lock_timeout = '15s'")
                cursor.execute("SET statement_timeout = '15s'")
                cursor.execute("SELECT pg_backend_pid()")
                pids.append(cursor.fetchone()[0])
            ready.set()
            return action()
        finally:
            done.set()
            connection.close()

    def _waits_for_account(self, identifier, done):
        deadline = time.monotonic() + _SECONDS
        while time.monotonic() < deadline and not done.is_set():
            with connection.cursor() as cursor:
                cursor.execute(
                    "SELECT wait_event_type, pg_blocking_pids(pid) FROM pg_stat_activity WHERE pid = %s", [identifier]
                )
                row = cursor.fetchone()
            if row and row[0] == "Lock" and self.main_pid in row[1]:
                return True
            done.wait(0.01)
        return False

    def _race(self, first, second):
        pids, ready, done = [], threading.Event(), threading.Event()
        with ThreadPoolExecutor(max_workers=1) as executor:
            with transaction.atomic():
                VirtualminAccount.objects.select_for_update(no_key=True).get(pk=self.account.pk)
                waiting = executor.submit(self._thread, second, pids, ready, done)
                self.assertTrue(ready.wait(_SECONDS), "The independent connection never became ready")
                self.assertNotEqual(pids[0], self.main_pid)
                self.assertTrue(
                    self._waits_for_account(pids[0], done), "Execution did not wait on the actual account row"
                )
                winner = first()
            follower = waiting.result(timeout=_SECONDS)
        for boundary in self.boundaries:
            boundary.assert_not_called()
        return winner, follower

    def test_concurrent_claims_grant_exactly_one_execution_token(self):
        first, second = self._race(
            lambda: execution.claim_mail_operation(self.operation.pk),
            lambda: execution.claim_mail_operation(self.operation.pk),
        )
        self.assertTrue(first.is_ok(), first)
        self.assertEqual(second.unwrap_err(), "mail_execution_busy")
        self.operation.refresh_from_db()
        self.assertEqual(self.operation.lease_token, first.unwrap().token)
        self.assertEqual(self.operation.status, "running")
        self.assertEqual(self.operation.configuration.mode, "external")

    def test_expiry_parking_wins_over_a_blocked_old_workers_checkpoint(self):
        lease = execution.claim_mail_operation(self.operation.pk).unwrap()
        prepared = execution.checkpoint_mail_operation(
            lease, checkpoint="preflight", evidence={"domain_id": "123456"}
        ).unwrap()
        VirtualminMailOperation.objects.filter(pk=self.operation.pk).update(
            lease_expires_at=timezone.now() - timezone.timedelta(seconds=1)
        )
        parked, stale = self._race(
            lambda: execution.claim_mail_operation(self.operation.pk),
            lambda: execution.checkpoint_mail_operation(prepared, checkpoint="native_inflight", evidence={}),
        )
        self.assertEqual(parked.unwrap_err(), "mail_execution_requires_review")
        self.assertEqual(stale.unwrap_err(), "mail_execution_lease_lost")
        self.operation.refresh_from_db()
        self.assertEqual(self.operation.status, "needs_review")
        self.assertEqual(self.operation.checkpoint, "preflight")
        self.assertEqual(self.operation.result["evidence"], {"domain_id": "123456"})
        self.assertIsNone(self.operation.lease_token)
        self.assertEqual(self.operation.configuration.mode, "external")
