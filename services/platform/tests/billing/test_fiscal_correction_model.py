"""The invariants a fiscal correction obligation holds on its own, whoever writes it."""

from __future__ import annotations

from django.core.exceptions import ValidationError
from django.db import IntegrityError, transaction
from django.test import TestCase

from apps.audit.models import AuditEvent
from apps.billing.fiscal_correction_models import (
    REASON_NO_FISCAL_DOCUMENT,
    STATE_ATTACHED,
    STATE_NOT_REQUIRED,
    FiscalCorrection,
)
from apps.promotions.models import TenderRefundCommand
from tests.billing import _fiscal_correction_helpers as h


class FiscalCorrectionModelTests(TestCase):
    def setUp(self) -> None:
        # The completion hook must not create rows these tests count, so the refunds stay pending.
        self.owner = h.customer()
        self.invoice = h.issued_invoice(self.owner)
        self.refund = h.pending_refund(invoice=self.invoice)
        self.other_refund = h.pending_refund(invoice=self.invoice)
        self.command = TenderRefundCommand.objects.create(
            invoice=self.invoice,
            customer=self.owner,
            amount_cents=self.invoice.total_cents,
            operation_key="fiscal-model-command",
            reason="test",
        )

    def _refused(self, **fields: object) -> None:
        with self.assertRaises(IntegrityError), transaction.atomic():
            FiscalCorrection.objects.create(**fields)

    def test_a_correction_has_exactly_one_source(self) -> None:
        self._refused(original=self.invoice)
        self._refused(original=self.invoice, source_refund=self.refund, source_command=self.command)

    def test_one_refund_owns_at_most_one_correction(self) -> None:
        FiscalCorrection.objects.create(original=self.invoice, source_refund=self.refund)
        self._refused(original=self.invoice, source_refund=self.refund)

    def test_one_command_owns_at_most_one_correction(self) -> None:
        FiscalCorrection.objects.create(original=self.invoice, source_command=self.command)
        self._refused(original=self.invoice, source_command=self.command)

    def test_only_a_not_required_outcome_may_lack_an_original(self) -> None:
        self._refused(source_refund=self.refund)
        FiscalCorrection.objects.create(
            source_refund=self.refund, state=STATE_NOT_REQUIRED, not_required_reason=REASON_NO_FISCAL_DOCUMENT
        )

    def test_a_not_required_outcome_says_why(self) -> None:
        self._refused(original=self.invoice, source_refund=self.refund, state=STATE_NOT_REQUIRED)

    def test_attached_requires_a_credit_note(self) -> None:
        self._refused(original=self.invoice, source_refund=self.refund, state=STATE_ATTACHED)

    def test_the_source_cannot_be_repointed_once_set(self) -> None:
        correction = FiscalCorrection.objects.create(original=self.invoice, source_refund=self.refund)
        correction.source_refund = self.other_refund
        with self.assertRaises(ValidationError):
            correction.save()
        correction.refresh_from_db()
        self.assertEqual(correction.source_refund_id, self.refund.pk)

    def test_the_original_cannot_be_repointed_once_set(self) -> None:
        other_invoice = h.issued_invoice(self.owner)
        correction = FiscalCorrection.objects.create(original=self.invoice, source_refund=self.refund)
        correction.original = other_invoice
        with self.assertRaises(ValidationError):
            correction.save(update_fields=["original"])
        correction.refresh_from_db()
        self.assertEqual(correction.original_id, self.invoice.pk)

    def test_the_bulk_update_path_cannot_repoint_a_link_either(self) -> None:
        other_invoice = h.issued_invoice(self.owner)
        FiscalCorrection.objects.create(original=self.invoice, source_refund=self.refund)
        with self.assertRaises(ValidationError):
            FiscalCorrection.objects.filter(source_refund=self.refund).update(original=other_invoice)
        with self.assertRaises(ValidationError):
            FiscalCorrection.objects.filter(source_refund=self.refund).update(source_refund_id=self.other_refund.pk)
        self.assertEqual(FiscalCorrection.objects.get(source_refund=self.refund).original_id, self.invoice.pk)

    def test_every_change_is_audited(self) -> None:
        correction = FiscalCorrection.objects.create(original=self.invoice, source_refund=self.refund)
        event = AuditEvent.objects.filter(action="fiscal_correction_created").latest("timestamp")
        self.assertEqual(event.object_id, str(correction.pk))
        self.assertEqual(event.new_values["source_refund_id"], str(self.refund.pk))
