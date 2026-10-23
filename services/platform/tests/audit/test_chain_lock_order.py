"""Chain linking and anonymization never write over each other's evidence (#751 follow-up, M14).

The chain linker held the chain head lock but read the event without a lock, then wrote back the metadata it
had read. An anonymization that committed in between had its scrub undone: the person's data came back
and the row's MAC no longer matched. Every read-modify-write of an event's evidence now locks the chain
head, then the event, and writes from what it read under the lock.
"""

from __future__ import annotations

import threading
import time
from unittest.mock import patch

from django.db import connection
from django.test import TransactionTestCase, override_settings

from apps.audit.models import AuditChainHead, AuditChainLink, AuditEvent
from apps.audit.services import AuditIntegrityService, AuditRetentionService


@override_settings(AUDIT_CHAIN_ENABLED=True)
class ChainAnonymizationRaceTests(TransactionTestCase):
    def test_an_anonymization_during_a_link_keeps_its_scrub_and_a_valid_mac(self) -> None:
        if connection.vendor != "postgresql":
            self.skipTest("row locks need PostgreSQL")
        # Created while the chain is still backfilling: its post-commit link is skipped, so it stays pending.
        AuditChainHead.objects.update_or_create(pk=1, defaults={"backfill_complete": False})
        event = AuditEvent.objects.create(
            action="login_success",
            category="authentication",
            severity="low",
            metadata={"user_email": "person@example.com"},
        )
        AuditChainHead.objects.filter(pk=1).update(backfill_complete=True)
        self.assertFalse(AuditChainLink.objects.filter(event=event).exists())
        read_done, resume = threading.Event(), threading.Event()
        verify = AuditIntegrityService._verify_hash_chain

        def pause_after_the_read(events: list[AuditEvent]) -> object:
            if not read_done.is_set():
                read_done.set()
                resume.wait(10)
            return verify(events)

        def link() -> None:
            try:
                with patch.object(AuditIntegrityService, "_verify_hash_chain", side_effect=pause_after_the_read):
                    AuditIntegrityService.append_chain_link(AuditEvent.objects.get(pk=event.pk))
            finally:
                connection.close()

        def anonymize() -> None:
            try:
                AuditRetentionService._anonymize_events([AuditEvent.objects.get(pk=event.pk)])
            finally:
                connection.close()

        linker = threading.Thread(target=link)
        linker.start()
        self.assertTrue(read_done.wait(10))
        scrubber = threading.Thread(target=anonymize)
        scrubber.start()
        time.sleep(0.5)  # Unlocked, the anonymization commits here, before the linker writes
        resume.set()
        linker.join(10)
        scrubber.join(10)

        stored = AuditEvent.objects.get(pk=event.pk)
        self.assertNotIn("user_email", stored.metadata, "the anonymization's scrub stands")
        self.assertEqual(AuditIntegrityService._verify_hash_chain([stored]), [], "the row's MAC still verifies")


class ChainPendingIndexTests(TransactionTestCase):
    """Chain recovery's scan of pending events uses its partial index on PostgreSQL (#751 follow-up, M16)."""

    def test_the_recovery_scan_can_use_the_pending_index(self) -> None:
        if connection.vendor != "postgresql":
            self.skipTest("a PostgreSQL-only partial index")
        from django.db import transaction  # noqa: PLC0415

        query = AuditEvent.objects.filter(metadata__chain_link_pending=True).order_by("timestamp", "pk")
        with transaction.atomic(), connection.cursor() as cursor:
            cursor.execute("SET LOCAL enable_seqscan = off")  # A tiny test table would otherwise be scanned
            plan = query.explain()

        self.assertIn("audit_events_chain_pending_idx", plan)
