"""
Tests for the generic FSM transition audit receiver (ADR-0034 / W8).

Every django-fsm transition produces exactly one audit event: model-specific
status-diffing handlers own their senders (skip-list), the generic receiver owns
the rest. The DISABLE_AUDIT_SIGNALS flag follows billing's guarded contract.
"""

from __future__ import annotations

from django.contrib.contenttypes.models import ContentType
from django.test import TestCase, override_settings

from apps.audit.models import AuditEvent
from apps.audit.signals import FSM_AUDIT_SENDER_SKIPLIST
from apps.billing.proforma_models import ProformaInvoice
from tests.factories.billing_factories import create_customer


def _make_proforma() -> ProformaInvoice:
    from apps.billing.models import Currency, ProformaSequence  # noqa: PLC0415  # Deferred: test-local

    currency, _ = Currency.objects.get_or_create(code="RON", defaults={"symbol": "lei", "decimals": 2})
    ProformaSequence.objects.get_or_create(scope="default")
    return ProformaInvoice.objects.create(
        customer=create_customer(),
        currency=currency,
        number=f"PRO-{ProformaInvoice.objects.count() + 1:06d}",
        total_cents=10000,
        subtotal_cents=8100,
        tax_cents=1900,
    )


class GenericFsmTransitionAuditTestCase(TestCase):
    def _transition_events(self, proforma: ProformaInvoice) -> list[AuditEvent]:
        ct = ContentType.objects.get_for_model(ProformaInvoice)
        return list(AuditEvent.objects.filter(content_type=ct, object_id=str(proforma.pk), action="status_changed"))

    def test_transition_emits_exactly_one_generic_event(self) -> None:
        proforma = _make_proforma()
        proforma.send_proforma()

        events = self._transition_events(proforma)
        self.assertEqual(len(events), 1)
        event = events[0]
        self.assertEqual(event.old_values, {"status": "draft"})
        self.assertEqual(event.new_values, {"status": "sent"})
        self.assertEqual(event.metadata["fsm_transition"], "send_proforma")
        self.assertEqual(event.actor_type, "system")

    @override_settings(DISABLE_AUDIT_SIGNALS=True, TESTING=True)
    def test_flag_with_testing_skips(self) -> None:
        proforma = _make_proforma()
        proforma.send_proforma()
        self.assertEqual(self._transition_events(proforma), [])

    @override_settings(DISABLE_AUDIT_SIGNALS=True, TESTING=False)
    def test_flag_without_testing_logs_critical_and_continues(self) -> None:
        """W8: in production the flag is a misconfiguration - audit anyway."""
        proforma = _make_proforma()
        with self.assertLogs("apps.audit.signals", level="CRITICAL"):
            proforma.send_proforma()
        self.assertEqual(len(self._transition_events(proforma)), 1)


class FsmSkiplistTestCase(TestCase):
    """Each skip-list entry exists because a model-specific handler already audits
    that sender's transitions - the generic receiver must stay silent for them."""

    def test_skiplist_matches_the_status_diffing_handlers(self) -> None:
        self.assertEqual(
            FSM_AUDIT_SENDER_SKIPLIST,
            frozenset({"orders.order", "tickets.ticket", "billing.payment", "domains.domain"}),
        )

    def test_ticket_transition_produces_no_generic_event(self) -> None:
        """tickets/signals.py owns Ticket status audit - one event per transition,
        and it is the model-specific one, not status_changed."""
        from apps.tickets.models import SupportCategory, Ticket  # noqa: PLC0415  # Deferred: test-local

        category = SupportCategory.objects.create(name="General", name_en="General")
        ticket = Ticket.objects.create(
            customer=create_customer(),
            category=category,
            title="FSM audit test",
            description="skiplist pin",
            contact_email="fsm@example.com",
        )
        ct = ContentType.objects.get_for_model(Ticket)
        generic = AuditEvent.objects.filter(content_type=ct, object_id=str(ticket.pk), action="status_changed")
        self.assertEqual(generic.count(), 0)
