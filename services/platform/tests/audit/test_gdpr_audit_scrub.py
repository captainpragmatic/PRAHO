"""GDPR anonymisation removes the person from the audit log without destroying others' evidence.

The person's own events that no law requires are fully scrubbed. Everything else that concerns
them keeps its content and loses only their identifiers: financial and contract evidence, events
a staff member performed on them, and their own actions on other people's data.
"""

from __future__ import annotations

import json
from datetime import timedelta
from typing import Any

from django.contrib.auth import get_user_model
from django.contrib.contenttypes.models import ContentType
from django.test import TestCase
from django.utils import timezone

from apps.audit.models import AuditEvent, AuditRetentionPolicy, audit_mutation_allowed
from apps.audit.services import AuditIntegrityService, AuditRetentionService, GDPRDeletionService
from apps.orders.models import Order, OrderStatusHistory
from apps.settings.services import SettingsService
from tests.factories.billing_factories import create_currency
from tests.factories.core_factories import create_individual_customer

User = get_user_model()

EMAIL = "ana.erasure@example.test"
PHONE = "+40722111333"


def _row_text(event: AuditEvent) -> str:
    return "\n".join(
        [
            event.description,
            json.dumps(event.metadata, default=str),
            json.dumps(event.old_values, default=str),
            json.dumps(event.new_values, default=str),
            str(event.ip_address or ""),
            event.user_agent or "",
        ]
    )


class GDPRAuditScrubTests(TestCase):
    def setUp(self) -> None:
        # The founding account is usually pk 1: erasing a person with that id must stay on them.
        self.person = User.objects.create_user(
            id=1, email=EMAIL, password="x-pass-123", first_name="Ana", last_name="Erasure", phone=PHONE
        )
        self.staff = User.objects.create_user(
            email="staff.keeper@example.test", password="x-pass-123", is_staff=True, staff_role="admin"
        )
        self.other = User.objects.create_user(email="bob.other@example.test", password="x-pass-123")
        self.user_type = ContentType.objects.get_for_model(User)

    def event(self, action: str, *, actor: Any = None, about: Any = None, **fields: Any) -> AuditEvent:
        subject = about if about is not None else actor
        return AuditEvent.objects.create(
            action=action,
            category=fields.pop("category", "account_management"),
            severity="low",
            user=actor,
            content_type=self.user_type if subject is not None else None,
            object_id=str(subject.pk) if subject is not None else "",
            description=fields.pop("description", f"{action} event"),
            ip_address=fields.pop("ip_address", None),
            user_agent=fields.pop("user_agent", ""),
            old_values=fields.pop("old_values", {}),
            new_values=fields.pop("new_values", {}),
            metadata=fields.pop("metadata", {}),
        )

    def erase(self, user: Any) -> None:
        GDPRDeletionService._anonymize_user_records(User.objects.get(pk=user.pk))

    def snapshot(self, event: AuditEvent) -> tuple[Any, ...]:
        event.refresh_from_db()
        return (event.user_id, event.description, event.metadata, event.old_values, event.new_values, event.ip_address)

    def test_erasing_user_one_touches_only_their_events(self) -> None:
        self.assertEqual(self.person.pk, 1)
        objectless = self.event("system_job_run", description="Nightly job")
        staff_own = self.event("login_success", actor=self.staff, ip_address="203.0.113.9")
        other_own = self.event("profile_updated", actor=self.other)
        untouched = {event.pk: self.snapshot(event) for event in (objectless, staff_own, other_own)}
        login = self.event("login_success", actor=self.person, ip_address="198.51.100.7")

        self.erase(self.person)

        for event in (objectless, staff_own, other_own):
            self.assertEqual(self.snapshot(event), untouched[event.pk], event.action)
        login.refresh_from_db()
        self.assertIsNone(login.user)
        self.assertIsNone(login.ip_address)

    def test_anonymisation_leaves_no_identifier_and_keeps_others_evidence(self) -> None:
        own_login = self.event(
            "login_success",
            actor=self.person,
            ip_address="198.51.100.7",
            user_agent="Mozilla/5.0",
            metadata={"user_email": EMAIL, "ip_address": "198.51.100.7", "user_agent": "Mozilla/5.0"},
        )
        staff_reset = self.event(
            "2fa_admin_reset",
            actor=self.staff,
            about=self.person,
            ip_address="203.0.113.9",
            description=f"2FA reset for {EMAIL} by support",
        )
        actor_only = self.event(
            "customer_note_added",
            actor=self.person,
            about=self.other,
            description=f"Note on {self.other.email} written by {EMAIL}",
            new_values={"email": self.other.email},
        )
        with audit_mutation_allowed("test fixture"):
            AuditEvent.objects.filter(pk=actor_only.pk).update(request_id="req-ana-123")
        # A security event names the person only in its metadata, with no actor and no object.
        security_probe = AuditEvent.objects.create(
            action="security_event",
            category="security_event",
            severity="low",
            description="Security event: product_list_access",
            metadata={"user_email": EMAIL},
        )
        held_invoice = self.event(
            "invoice_issued",
            actor=self.person,
            category="business_operation",
            new_values={"amount_cents": self.person.pk, "email": EMAIL},
            metadata={"user_email": EMAIL},
        )
        consent = self.event(
            "order_terms_accepted",
            actor=self.person,
            category="business_operation",
            description=f"Checkout terms accepted by {EMAIL}",
            new_values={"terms_document": "terms-v3"},
        )
        marked_but_full = self.event(
            "profile_updated", actor=self.person, metadata={"anonymized": True, "user_email": EMAIL}
        )

        self.erase(self.person)

        for event in (own_login, staff_reset, actor_only, held_invoice, consent, marked_but_full, security_probe):
            event.refresh_from_db()
            text = _row_text(event).lower()
            for identifier in (EMAIL, "ana", "erasure", PHONE, "198.51.100.7", "mozilla"):
                self.assertNotIn(identifier.lower(), text, f"{event.action} still holds {identifier}")
        # A staff member's action keeps its actor and network, and its evidence.
        self.assertEqual(staff_reset.user_id, self.staff.pk)
        self.assertEqual(staff_reset.ip_address, "203.0.113.9")
        self.assertIn("2FA reset for", staff_reset.description)
        # The person's note on someone else keeps that person's evidence, not the author.
        self.assertIsNone(actor_only.user_id)
        self.assertEqual(actor_only.request_id, "")
        self.assertIn(self.other.email, actor_only.description)
        self.assertEqual(actor_only.new_values, {"email": self.other.email})
        # Held evidence keeps amounts and structure; a number equal to the person's id is not theirs.
        self.assertEqual(held_invoice.new_values["amount_cents"], self.person.pk)
        self.assertEqual(consent.new_values, {"terms_document": "terms-v3"})
        self.assertIn("Checkout terms accepted", consent.description)
        # A row only marked anonymized is fully scrubbed.
        self.assertEqual(marked_but_full.description, AuditRetentionService.ANONYMIZED_DESCRIPTION)
        events = list(AuditEvent.objects.all())
        self.assertEqual(AuditIntegrityService._verify_hash_chain(events), [])

    def test_an_email_from_before_a_change_is_removed(self) -> None:
        # The authentication log records the actor's own address; the change event only the new one.
        self.event("login_success", actor=self.person, metadata={"user_email": "previous.addr@example.test"})
        self.person.email = "current.addr@example.test"
        self.person.save(update_fields=["email"])
        staff_note = self.event(
            "staff_note", actor=self.staff, about=self.person, description="Ticket from previous.addr@example.test"
        )

        self.erase(self.person)

        staff_note.refresh_from_db()
        self.assertNotIn("previous.addr@example.test", staff_note.description)
        self.assertEqual(staff_note.user_id, self.staff.pk)

    def test_an_empty_name_and_a_second_erasure_touch_no_one_else(self) -> None:
        nameless = User.objects.create_user(email="nameless@example.test", password="x-pass-123")
        others = [self.event("staff_note", actor=self.staff, about=self.other, description="Account review done")]
        before = {event.pk: self.snapshot(event) for event in others}

        self.erase(nameless)
        self.erase(nameless)

        for event in others:
            self.assertEqual(self.snapshot(event), before[event.pk])


class ClaimsHoldTests(TestCase):
    def setUp(self) -> None:
        self.person = User.objects.create_user(email="claims@example.test", password="x-pass-123")
        AuditRetentionPolicy.objects.create(
            name="compliance delete", category="compliance", retention_days=1096, action="delete", is_active=True
        )

    def checkout_evidence(self, when: Any) -> AuditEvent:
        event = AuditEvent.objects.create(
            action="early_performance_requested",
            category="compliance",
            severity="low",
            user=self.person,
            description="Early start requested at checkout",
        )
        with audit_mutation_allowed("test fixture"):
            AuditEvent.objects.filter(pk=event.pk).update(timestamp=when)
        return event

    def test_scheduled_deletion_keeps_checkout_evidence_until_the_claims_hold_expires(self) -> None:
        now = timezone.now()
        event = self.checkout_evidence(now - timedelta(days=1100))

        AuditRetentionService.apply_retention_policies(now=now)
        self.assertTrue(AuditEvent.objects.filter(pk=event.pk).exists())

        AuditRetentionService.apply_retention_policies(now=now + timedelta(days=1100))
        self.assertFalse(AuditEvent.objects.filter(pk=event.pk).exists())

    def test_the_claims_period_follows_its_setting(self) -> None:
        now = timezone.now()
        event = self.checkout_evidence(now - timedelta(days=1100))
        self.assertEqual(AuditRetentionService.claims_retention_cutoff(now), now - timedelta(days=2190))
        self.assertTrue(AuditRetentionService.is_held_for_claims(event, now))
        SettingsService.update_setting("audit.legal_claims_retention_days", 1000)
        event.refresh_from_db()
        self.assertEqual(AuditRetentionService.claims_retention_cutoff(now), now - timedelta(days=1000))
        self.assertFalse(AuditRetentionService.is_held_for_claims(event, now))

        AuditRetentionService.apply_retention_policies(now=now)

        self.assertFalse(AuditEvent.objects.filter(pk=event.pk).exists())

    def test_retention_scrubs_a_row_only_marked_anonymized(self) -> None:
        AuditRetentionPolicy.objects.create(
            name="privacy anonymise", category="privacy", retention_days=30, action="anonymize", is_active=True
        )
        event = AuditEvent.objects.create(
            action="profile_updated",
            category="privacy",
            severity="low",
            user=self.person,
            description=f"Profile of {self.person.email}",
            metadata={"anonymized": True},
        )
        with audit_mutation_allowed("test fixture"):
            AuditEvent.objects.filter(pk=event.pk).update(timestamp=timezone.now() - timedelta(days=60))

        AuditRetentionService.apply_retention_policies()

        event.refresh_from_db()
        self.assertEqual(event.description, AuditRetentionService.ANONYMIZED_DESCRIPTION)
        self.assertIsNone(event.user_id)

    def test_full_deletion_keeps_contract_evidence(self) -> None:
        user_type = ContentType.objects.get_for_model(User)
        terms = AuditEvent.objects.create(
            action="terms_accepted",
            category="compliance",
            severity="low",
            user=self.person,
            content_type=user_type,
            object_id=str(self.person.pk),
            description="Terms v3 accepted",
        )
        request = GDPRDeletionService.create_deletion_request(user=self.person, deletion_type="delete").unwrap()

        self.assertTrue(GDPRDeletionService.process_deletion_request(request).is_ok())

        self.assertFalse(User.objects.filter(pk=self.person.pk).exists())
        terms.refresh_from_db()
        self.assertEqual(terms.description, "Terms v3 accepted")
        self.assertIsNone(terms.user_id)

    def test_a_paid_order_cancelled_later_keeps_its_evidence(self) -> None:
        AuditRetentionPolicy.objects.create(
            name="operations delete", category="business_operation", retention_days=30, action="delete", is_active=True
        )
        order = Order.objects.create(
            customer=create_individual_customer(email="claims@example.test"), currency=create_currency()
        )
        OrderStatusHistory.objects.create(order=order, old_status="awaiting_payment", new_status="paid")
        Order.objects.filter(pk=order.pk).update(status="cancelled")
        event = AuditEvent.objects.create(
            action="order_status_changed",
            category="business_operation",
            severity="low",
            content_type=ContentType.objects.get_for_model(Order),
            object_id=str(order.pk),
            description="Order paid",
        )
        with audit_mutation_allowed("test fixture"):
            AuditEvent.objects.filter(pk=event.pk).update(timestamp=timezone.now() - timedelta(days=60))

        AuditRetentionService.apply_retention_policies()

        self.assertTrue(AuditEvent.objects.filter(pk=event.pk).exists())

    def test_retention_finishes_a_row_left_half_anonymized(self) -> None:
        AuditRetentionPolicy.objects.create(
            name="privacy anonymise", category="privacy", retention_days=30, action="anonymize", is_active=True
        )
        event = AuditEvent.objects.create(
            action="profile_updated",
            category="privacy",
            severity="low",
            user=self.person,
            ip_address="198.51.100.7",
            session_key="s" * 32,
            description=AuditRetentionService.ANONYMIZED_DESCRIPTION,
            old_values={"anonymized": True},
            new_values={"anonymized": True},
            metadata={"anonymized": True},
        )
        with audit_mutation_allowed("test fixture"):
            AuditEvent.objects.filter(pk=event.pk).update(timestamp=timezone.now() - timedelta(days=60))
        status = AuditRetentionService.get_retention_status()
        self.assertEqual(status["privacy"]["compliance_status"], "action_required")

        AuditRetentionService.apply_retention_policies()

        event.refresh_from_db()
        self.assertIsNone(event.user_id)
        self.assertIsNone(event.ip_address)
        self.assertEqual(event.session_key, "")
