"""An event the chain refuses no longer blocks the ones behind it (#751 follow-up, H3).

Recovery links pending events oldest first. An event whose MAC no longer verifies is refused, so it
stayed pending at the head of every batch, and nothing behind it was ever linked. A refused event now
carries a reserved quarantine marker (outside the MAC): recovery skips it, and the verifier still
reports it as unlinked.
"""

from __future__ import annotations

from django.test import TestCase, override_settings
from django.utils import timezone

from apps.audit import tasks
from apps.audit.models import AuditChainHead, AuditChainLink, AuditEvent, audit_mutation_allowed
from apps.audit.services import AuditIntegrityService


@override_settings(AUDIT_CHAIN_ENABLED=True)
class ChainQuarantineTests(TestCase):
    def setUp(self) -> None:
        super().setUp()
        AuditChainHead.objects.update_or_create(pk=1, defaults={"backfill_complete": True})

    def _pending(self) -> AuditEvent:
        with self.captureOnCommitCallbacks(execute=False):  # Its post-commit link never runs: recovery's work
            return AuditEvent.objects.create(action="login_success", category="authentication", severity="low")

    def test_a_poisoned_oldest_event_no_longer_blocks_the_next_ones(self) -> None:
        poisoned, first, second = (self._pending() for _ in range(3))
        with audit_mutation_allowed("test_poison"):
            AuditEvent.objects.filter(pk=poisoned.pk).update(description="tampered evidence")

        for _ in range(3):
            tasks.recover_pending_chain_links(batch_size=1)

        linked = set(AuditChainLink.objects.filter(is_tombstone=False).values_list("event_id", flat=True))
        self.assertEqual(linked, {first.pk, second.pk}, "the events behind the refused one are linked")
        now = timezone.now()
        findings = AuditIntegrityService._verify_chain_ledger(now - timezone.timedelta(days=1), now)
        self.assertTrue(
            any(str(poisoned.pk) in finding["description"] for finding in findings),
            "the refused event is still reported",
        )

    def test_an_event_that_verifies_again_is_not_quarantined(self) -> None:
        from apps.audit.signals import _quarantine_chain_link  # noqa: PLC0415

        event = self._pending()  # Re-stamped since the refusal: it verifies when the quarantine looks

        _quarantine_chain_link(event.pk, None)

        self.assertNotIn("chain_link_quarantined", AuditEvent.objects.get(pk=event.pk).metadata)

    def test_a_caller_cannot_quarantine_an_event_by_supplying_the_marker(self) -> None:
        with self.captureOnCommitCallbacks(execute=False):
            forged = AuditEvent.objects.create(
                action="login_success",
                category="authentication",
                severity="low",
                metadata={"chain_link_quarantined": True},
            )

        tasks.recover_pending_chain_links(batch_size=1)

        self.assertNotIn("chain_link_quarantined", AuditEvent.objects.get(pk=forged.pk).metadata)
        self.assertTrue(AuditChainLink.objects.filter(event=forged).exists(), "a caller cannot hide an event")


@override_settings(AUDIT_CHAIN_ENABLED=True)
class AnonymizedPendingEventTests(TestCase):
    """Anonymizing an event keeps its chain markers (#751 follow-up, M15).

    The anonymization rebuilt metadata from its allowlist, dropping chain_link_pending: an event anonymized
    before its link was appended was never linked at all.
    """

    def setUp(self) -> None:
        super().setUp()
        AuditChainHead.objects.update_or_create(pk=1, defaults={"backfill_complete": True})

    def test_an_event_anonymized_while_pending_is_still_linked(self) -> None:
        from apps.audit.services import AuditRetentionService  # noqa: PLC0415

        with self.captureOnCommitCallbacks(execute=False):
            event = AuditEvent.objects.create(action="login_success", category="authentication", severity="low")

        AuditRetentionService._anonymize_events([AuditEvent.objects.get(pk=event.pk)])
        tasks.recover_pending_chain_links(batch_size=1)

        self.assertTrue(AuditChainLink.objects.filter(event_id=event.pk).exists(), "the anonymized event is linked")
