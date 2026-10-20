"""Chain linking runs after commit and leaves durable, authenticated recovery work."""

from concurrent.futures import ThreadPoolExecutor
from unittest import skipUnless
from unittest.mock import patch

from django.db import DatabaseError, connection, connections, transaction
from django.test import TestCase, TransactionTestCase, override_settings
from django.utils import timezone

from apps.audit import tasks
from apps.audit.models import AuditChainHead, AuditChainLink, AuditEvent, audit_mutation_allowed
from apps.audit.services import AuditIntegrityService
from apps.audit.signals import _link_committed_event


@override_settings(AUDIT_CHAIN_ENABLED=True)
class DeferredChainTests(TestCase):
    def setUp(self) -> None:
        AuditChainHead.objects.update_or_create(pk=1, defaults={"backfill_complete": True})

    def event(self) -> AuditEvent:
        return AuditEvent.objects.create(action="login_success", category="authentication", severity="low")

    @override_settings(AUDIT_CHAIN_REQUIRE=True)
    def test_recent_pending_work_is_normal_but_stale_work_is_critical(self) -> None:
        with self.captureOnCommitCallbacks(execute=False):
            event = self.event()
        now = timezone.now()
        findings = AuditIntegrityService._verify_chain_ledger(now - timezone.timedelta(days=1), now)
        pending = [finding for finding in findings if finding["type"] == "chain_link_pending"]
        self.assertEqual(pending[0]["severity"], "info")
        self.assertFalse(any(finding["severity"] == "critical" for finding in findings))
        with patch("apps.audit.services.timezone.now", return_value=now + timezone.timedelta(minutes=6)):
            findings = AuditIntegrityService._verify_chain_ledger(event.timestamp, now)
        pending = [finding for finding in findings if finding["type"] == "chain_link_pending"]
        self.assertEqual(pending[0]["severity"], "critical")

    @override_settings(AUDIT_CHAIN_REQUIRE=True)
    def test_forged_pending_work_cannot_obtain_the_normal_latency_grace(self) -> None:
        now = timezone.now()
        for change in ({"description": "forged evidence"}, {"timestamp": now + timezone.timedelta(days=365)}):
            with self.subTest(change=change), self.captureOnCommitCallbacks(execute=False):
                event = self.event()
                with audit_mutation_allowed("test_forged_pending"):
                    AuditEvent.objects.filter(pk=event.pk).update(**change)
                findings = AuditIntegrityService._verify_chain_ledger(now - timezone.timedelta(days=1), now)
                pending = [
                    finding
                    for finding in findings
                    if finding["type"] == "chain_link_pending" and str(event.pk) in finding["description"]
                ]
                self.assertEqual(pending[0]["severity"], "critical")
                self.assertTrue(
                    any(
                        finding["type"] == "chain_link_missing_for_event" and str(event.pk) in finding["description"]
                        for finding in findings
                    )
                )

    def test_business_transaction_does_not_link_before_commit(self) -> None:
        with self.captureOnCommitCallbacks(execute=True), transaction.atomic():
            event = self.event()
            self.assertTrue(event.metadata.get("chain_link_pending"))
            self.assertFalse(AuditChainLink.objects.filter(event=event).exists())
        self.assertEqual(AuditChainLink.objects.filter(event=event).count(), 1)
        event.refresh_from_db()
        self.assertFalse(event.metadata.get("chain_link_pending"))

    def test_bulk_created_events_follow_the_same_commit_boundary(self) -> None:
        with self.captureOnCommitCallbacks(execute=True):
            events = AuditEvent.objects.bulk_create(
                [AuditEvent(action="login_success", category="authentication", severity="low") for _ in range(3)]
            )
            self.assertTrue(all(event.metadata.get("chain_link_pending") for event in events))
            self.assertFalse(AuditChainLink.objects.exists())
        self.assertEqual(AuditChainLink.objects.count(), 3)

    def test_rolled_back_creation_leaves_no_recovery_work(self) -> None:
        with (
            self.captureOnCommitCallbacks(execute=True),
            self.assertRaisesMessage(ValueError, "rollback"),
            transaction.atomic(),
        ):
            event = self.event()
            raise ValueError("rollback")
        self.assertFalse(AuditEvent.objects.filter(pk=event.pk).exists())
        self.assertFalse(AuditChainLink.objects.exists())

    def test_recovery_repairs_callback_failure_once(self) -> None:
        with (
            patch.object(AuditIntegrityService, "append_chain_link", side_effect=DatabaseError("head unavailable")),
            self.captureOnCommitCallbacks(execute=True),
        ):
            event = self.event()
        event.refresh_from_db()
        self.assertTrue(event.metadata.get("chain_link_pending"))
        tasks.recover_pending_chain_links()
        tasks.recover_pending_chain_links()
        self.assertEqual(AuditChainLink.objects.filter(event=event).count(), 1)
        event.refresh_from_db()
        self.assertFalse(event.metadata.get("chain_link_pending"))

    def test_recovery_refuses_to_certify_tampered_evidence(self) -> None:
        with self.captureOnCommitCallbacks(execute=False):
            event = self.event()
        with audit_mutation_allowed("test_tampering"):
            AuditEvent.objects.filter(pk=event.pk).update(description="changed after signing")
        tasks.recover_pending_chain_links()
        self.assertFalse(AuditChainLink.objects.filter(event=event).exists())
        event.refresh_from_db()
        self.assertTrue(event.metadata.get("chain_link_pending"))


@skipUnless(connection.vendor == "postgresql", "Requires separate PostgreSQL connections")
@override_settings(AUDIT_CHAIN_ENABLED=True)
class DeferredChainLockTests(TransactionTestCase):
    def test_failed_callback_read_does_not_poison_its_callers_transaction(self) -> None:
        with patch("apps.audit.signals.on_commit"):
            event = AuditEvent.objects.create(action="login_success", category="authentication", severity="low")

        def failed_read():
            with connection.cursor() as cursor:
                cursor.execute("SELECT 1 / 0")

        with transaction.atomic():
            with patch("django.db.models.query.QuerySet.first", side_effect=failed_read):
                self.assertFalse(_link_committed_event(event.pk))
            with connection.cursor() as cursor:
                cursor.execute("SELECT 1")
                self.assertEqual(cursor.fetchone(), (1,))
        event.refresh_from_db()
        self.assertTrue(event.metadata.get("chain_link_pending"))

    def test_overlapping_recovery_workers_append_only_once(self) -> None:
        AuditChainHead.objects.update_or_create(pk=1, defaults={"backfill_complete": True})
        with patch("apps.audit.signals.on_commit"):
            event = AuditEvent.objects.create(action="login_success", category="authentication", severity="low")

        def recover() -> None:
            try:
                tasks.recover_pending_chain_links()
            finally:
                connections.close_all()

        with ThreadPoolExecutor(max_workers=2) as pool:
            futures = [pool.submit(recover), pool.submit(recover)]
            for future in futures:
                future.result(timeout=5)
        self.assertEqual(AuditChainLink.objects.filter(event=event).count(), 1)
        self.assertEqual(AuditChainHead.objects.get(pk=1).last_sequence, 1)
        event.refresh_from_db()
        self.assertFalse(event.metadata.get("chain_link_pending"))

    def test_business_transaction_does_not_hold_the_global_chain_head(self) -> None:
        AuditChainHead.objects.update_or_create(pk=1, defaults={"backfill_complete": True})

        def can_lock_head() -> bool:
            try:
                with transaction.atomic():
                    AuditChainHead.objects.select_for_update(nowait=True).get(pk=1)
                return True
            except DatabaseError:
                return False
            finally:
                connections.close_all()

        with transaction.atomic():
            AuditEvent.objects.create(action="login_success", category="authentication", severity="low")
            with ThreadPoolExecutor(max_workers=1) as pool:
                self.assertTrue(pool.submit(can_lock_head).result(timeout=3))
