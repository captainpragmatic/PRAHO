"""
Tests for audit event tamper detection (#217).

`_verify_hash_chain` read metadata["integrity_hash"] and skipped the comparison when it was
absent — and nothing ever wrote it, so the stored hash was always missing, the mismatch branch was
unreachable, and every integrity check reported compliant regardless of how rows had been altered.
"""

from __future__ import annotations

from django.contrib.contenttypes.models import ContentType
from django.test import TestCase

from apps.audit.models import AuditEvent
from apps.audit.services import AuditIntegrityService
from apps.users.models import User


class AuditEventIntegrityHashTestCase(TestCase):
    """#217: a created audit event carries a hash, and a mutated one is detected."""

    def setUp(self) -> None:
        self.user = User.objects.create_user(email="auditor@example.com", password="testpass123")
        self.content_type = ContentType.objects.get_for_model(User)

    def _event(self, description: str = "Original description") -> AuditEvent:
        return AuditEvent.objects.create(
            user=self.user,
            action="login_success",
            category="authentication",
            severity="low",
            content_type=self.content_type,
            object_id=str(self.user.id),
            description=description,
            ip_address="192.168.1.1",
        )

    def test_created_event_is_stamped_with_an_integrity_hash(self) -> None:
        """Nothing wrote integrity_hash before — it appeared at exactly one line, the read."""
        event = self._event()

        event.refresh_from_db()
        self.assertIn("integrity_hash", event.metadata)
        self.assertEqual(event.metadata["integrity_hash"], AuditIntegrityService._calculate_event_hash(event))

    def test_untampered_event_verifies_clean(self) -> None:
        event = self._event()
        event.refresh_from_db()

        issues = AuditIntegrityService._verify_hash_chain([event])

        self.assertEqual(issues, [])

    def test_tampered_event_is_detected(self) -> None:
        """The whole point of #217: rewriting an audit row must be caught.

        Before the fix this returned zero issues no matter what was changed.
        """
        event = self._event()
        event.refresh_from_db()

        # Rewrite history the way an attacker would: straight to the column, no signal.
        AuditEvent.objects.filter(pk=event.pk).update(description="TAMPERED — this never happened")
        event.refresh_from_db()

        issues = AuditIntegrityService._verify_hash_chain([event])

        self.assertEqual(len(issues), 1)
        self.assertEqual(issues[0]["type"], "hash_mismatch")
        self.assertEqual(issues[0]["severity"], "critical")

    def test_hashed_era_event_with_a_stripped_hash_is_critical(self) -> None:
        """Deleting the hash must not buy an attacker a clean report.

        The version marker survives independently, so a row written after hashing began is still
        known to need one.
        """
        event = self._event()
        event.refresh_from_db()
        metadata = dict(event.metadata)
        del metadata["integrity_hash"]
        AuditEvent.objects.filter(pk=event.pk).update(metadata=metadata)
        event.refresh_from_db()

        issues = AuditIntegrityService._verify_hash_chain([event])

        self.assertEqual(len(issues), 1)
        self.assertEqual(issues[0]["type"], "missing_integrity_hash")
        self.assertEqual(issues[0]["severity"], "critical")

    def test_legacy_event_is_reported_unverifiable_not_tampered(self) -> None:
        """Rows written before #217 have no hash and never will.

        They are genuinely unverifiable — but reporting thousands of them as critical would bury
        a real mismatch, so they are info-level instead.
        """
        event = self._event()
        AuditEvent.objects.filter(pk=event.pk).update(metadata={})
        event.refresh_from_db()

        issues = AuditIntegrityService._verify_hash_chain([event])

        self.assertEqual(len(issues), 1)
        self.assertEqual(issues[0]["type"], "unverifiable_legacy_event")
        self.assertEqual(issues[0]["severity"], "info")

    def test_hash_survives_a_legitimate_metadata_read(self) -> None:
        """Non-regression: the hash covers event fields, not the metadata blob itself."""
        event = self._event()
        event.refresh_from_db()
        original_hash = event.metadata["integrity_hash"]

        self.assertEqual(AuditIntegrityService._calculate_event_hash(event), original_hash)
