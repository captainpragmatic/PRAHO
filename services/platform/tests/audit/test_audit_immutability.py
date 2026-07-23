"""
Tests for the AuditEvent immutability guard, the restamp cutover command, and #385.

The guard makes "immutable audit trail" a raised exception instead of a docstring:
every ORM mutation API on AuditEvent raises AuditImmutabilityError unless the call
site entered the audit_mutation_allowed() escape hatch with an auditable reason.
"""

from __future__ import annotations

from datetime import UTC, datetime
from decimal import Decimal
from io import StringIO

from django.contrib.contenttypes.models import ContentType
from django.core.management import call_command
from django.test import TestCase
from django.utils.translation import gettext_lazy

from apps.audit.models import AuditEvent, AuditImmutabilityError, audit_mutation_allowed
from apps.audit.services import AuditContext, AuditEventData, AuditIntegrityService, AuditService
from apps.users.models import User


class AuditEventImmutabilityGuardTestCase(TestCase):
    """Every mutation API is blocked; the escape hatch unblocks and restores state."""

    def setUp(self) -> None:
        self.user = User.objects.create_user(email="guard@example.com", password="testpass123")
        self.content_type = ContentType.objects.get_for_model(User)
        self.event = AuditEvent.objects.create(
            user=self.user,
            action="login_success",
            category="authentication",
            severity="low",
            content_type=self.content_type,
            object_id=str(self.user.id),
            description="guard test",
        )

    def test_queryset_update_is_blocked(self) -> None:
        with self.assertRaises(AuditImmutabilityError):
            AuditEvent.objects.filter(pk=self.event.pk).update(description="rewritten")

    def test_queryset_delete_is_blocked(self) -> None:
        with self.assertRaises(AuditImmutabilityError):
            AuditEvent.objects.filter(pk=self.event.pk).delete()

    def test_queryset_bulk_update_is_blocked(self) -> None:
        self.event.description = "rewritten"
        with self.assertRaises(AuditImmutabilityError):
            AuditEvent.objects.bulk_update([self.event], ["description"])

    def test_instance_save_on_existing_row_is_blocked(self) -> None:
        self.event.description = "rewritten"
        with self.assertRaises(AuditImmutabilityError):
            self.event.save()

    def test_instance_delete_is_blocked(self) -> None:
        with self.assertRaises(AuditImmutabilityError):
            self.event.delete()

    def test_creation_is_always_allowed(self) -> None:
        event = AuditEvent.objects.create(
            user=self.user,
            action="login_success",
            category="authentication",
            severity="low",
            content_type=self.content_type,
            object_id=str(self.user.id),
            description="append-only means append works",
        )
        self.assertIsNotNone(event.pk)

    def test_escape_hatch_allows_and_restores(self) -> None:
        with audit_mutation_allowed("test fixture"):
            updated = AuditEvent.objects.filter(pk=self.event.pk).update(description="allowed")
        self.assertEqual(updated, 1)
        # Outside the context the guard is back
        with self.assertRaises(AuditImmutabilityError):
            AuditEvent.objects.filter(pk=self.event.pk).update(description="blocked again")

    def test_escape_hatch_nests(self) -> None:
        with audit_mutation_allowed("outer"), audit_mutation_allowed("inner"):
            AuditEvent.objects.filter(pk=self.event.pk).update(description="nested")
        with self.assertRaises(AuditImmutabilityError):
            AuditEvent.objects.filter(pk=self.event.pk).update(description="blocked")

    def test_user_deletion_cascade_survives_the_guard(self) -> None:
        """Django's SET_NULL cascade runs on _base_manager, deliberately unguarded -
        deleting a user must not explode on their audit trail."""
        victim = User.objects.create_user(email="cascade@example.com", password="x")
        event = AuditEvent.objects.create(
            user=victim,
            action="login_success",
            category="authentication",
            severity="low",
            content_type=self.content_type,
            object_id=str(victim.id),
            description="cascade test",
        )
        victim.delete()
        event.refresh_from_db()
        self.assertIsNone(event.user_id)


class RestampCommandTestCase(TestCase):
    """The v1->v2 cutover vehicle: batched, idempotent, self-asserting."""

    def setUp(self) -> None:
        self.user = User.objects.create_user(email="restamp@example.com", password="testpass123")
        self.content_type = ContentType.objects.get_for_model(User)

    def _events(self, count: int) -> list[AuditEvent]:
        return [
            AuditEvent.objects.create(
                user=self.user,
                action="login_success",
                category="authentication",
                severity="low",
                content_type=self.content_type,
                object_id=str(self.user.id),
                description=f"event {i}",
            )
            for i in range(count)
        ]

    def _strip_to_v1(self, events: list[AuditEvent]) -> None:
        with audit_mutation_allowed("test fixture"):
            for event in events:
                event.refresh_from_db()
                AuditEvent.objects.filter(pk=event.pk).update(
                    metadata={
                        "integrity_hash": AuditIntegrityService._calculate_event_hash(event),
                        "integrity_hash_version": 1,
                    }
                )

    def test_restamp_upgrades_v1_rows_and_they_verify(self) -> None:
        events = self._events(5)
        self._strip_to_v1(events)

        out = StringIO()
        call_command("restamp_audit_integrity", "--batch-size=2", stdout=out)

        for event in events:
            event.refresh_from_db()
            self.assertEqual(event.metadata["integrity_hash_version"], AuditIntegrityService.HASH_VERSION)
            self.assertIn("integrity_key_id", event.metadata)
        self.assertEqual(AuditIntegrityService._verify_hash_chain([*events]), [])
        self.assertIn("all rows now carry v2 markers", out.getvalue())

    def test_restamp_is_idempotent(self) -> None:
        self._events(3)  # already stamped v2 at creation

        out = StringIO()
        call_command("restamp_audit_integrity", stdout=out)
        self.assertIn("Nothing to restamp", out.getvalue())

    def test_dry_run_modifies_nothing(self) -> None:
        events = self._events(2)
        self._strip_to_v1(events)

        out = StringIO()
        call_command("restamp_audit_integrity", "--dry-run", stdout=out)

        self.assertIn("2 to restamp", out.getvalue())
        for event in events:
            event.refresh_from_db()
            self.assertEqual(event.metadata["integrity_hash_version"], 1)


class SerializedEvidenceTestCase(TestCase):
    """#385: raw Decimal/datetime/lazy-proxy evidence must not kill the audit INSERT."""

    def setUp(self) -> None:
        self.user = User.objects.create_user(email="evidence@example.com", password="testpass123")

    def test_log_event_survives_unserializable_evidence(self) -> None:
        event = AuditService.log_event(
            AuditEventData(
                event_type="update",
                content_object=self.user,
                old_values={
                    "amount": Decimal("19.99"),
                    "when": datetime(2026, 1, 1, tzinfo=UTC),
                    "label": gettext_lazy("Yes"),
                },
                new_values={"amount": Decimal("21.00")},
                description="evidence serialization",
            ),
            AuditContext(user=self.user),
        )

        event.refresh_from_db()
        self.assertEqual(event.old_values["amount"], "19.99")
        self.assertEqual(event.new_values["amount"], "21.00")
        self.assertEqual(event.old_values["label"], "Yes")
        self.assertIn("2026-01-01", event.old_values["when"])
