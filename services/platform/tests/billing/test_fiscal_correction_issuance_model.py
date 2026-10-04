"""The issuance invariants a fiscal correction holds on its own, whoever writes it (ADR-0053).

An allocation is frozen once written, the communication date is set once, a credit note exists
exactly while the correction is attached or issued, and e-Factura is tracked only for an issued note.
"""

from __future__ import annotations

from datetime import timedelta

from django.core.exceptions import ValidationError
from django.db import IntegrityError, transaction
from django.test import TestCase
from django.utils import timezone
from django_fsm import TransitionNotAllowed

from apps.billing.fiscal_correction_models import (
    EFACTURA_PENDING,
    STATE_ALLOCATED,
    STATE_COMMUNICATED,
    STATE_FAILED,
    STATE_ISSUED,
    FiscalCorrection,
)
from apps.billing.invoice_models import DOCUMENT_KIND_CREDIT_NOTE, Invoice
from tests.billing import _fiscal_correction_helpers as h
from tests.billing._storno_helpers import StornoTestCase


class FiscalCorrectionIssuanceModelTests(TestCase):
    def setUp(self) -> None:
        owner = h.customer()
        self.invoice = h.issued_invoice(owner)
        self.correction = FiscalCorrection.objects.create(
            original=self.invoice, source_refund=h.pending_refund(invoice=self.invoice)
        )

    def _allocated(self) -> FiscalCorrection:
        self.correction.allocate(base_cents=826, tax_cents=174, discount_cents=0, at=timezone.now())
        self.correction.save()
        return self.correction

    def _refused(self, **fields: object) -> None:
        with self.assertRaises(IntegrityError), transaction.atomic():
            FiscalCorrection.objects.filter(pk=self.correction.pk).update(**fields)

    def test_an_allocation_is_stored_signed_and_whole(self) -> None:
        self._refused(state=STATE_ALLOCATED)
        self._refused(allocated_at=timezone.now())

        correction = self._allocated()

        self.assertEqual(
            (correction.base_cents, correction.tax_cents, correction.discount_cents, correction.total_cents),
            (-826, -174, 0, -1000),
        )

    def test_an_allocation_cannot_be_rewritten_by_save_or_by_update(self) -> None:
        correction = self._allocated()

        correction.total_cents = -1100
        with self.assertRaises(ValidationError):
            correction.save()
        with self.assertRaises(ValidationError):
            FiscalCorrection.objects.filter(pk=correction.pk).update(base_cents=-900)
        correction.refresh_from_db()
        self.assertEqual(correction.total_cents, -1000)

    def test_an_allocated_correction_cannot_be_allocated_again_or_closed_as_not_required(self) -> None:
        correction = self._allocated()
        correction.fail(code="issuance_error", error="boom")
        correction.save()

        with self.assertRaises(TransitionNotAllowed):
            correction.allocate(base_cents=1, tax_cents=0, discount_cents=0, at=timezone.now())
        with self.assertRaises(TransitionNotAllowed):
            correction.mark_not_required("covered_by_collections")

    def test_only_a_correction_settled_by_a_note_may_hold_one(self) -> None:
        note = h.issued_invoice(self.invoice.customer)
        self._allocated()

        self._refused(credit_note=note)
        self._refused(state=STATE_ISSUED)

    def test_communicated_carries_its_date_and_only_communicated_may(self) -> None:
        self._refused(communicated_at=timezone.now(), fiscal_date=timezone.localdate())
        self._refused(state=STATE_COMMUNICATED)

    def test_the_communication_date_is_set_once(self) -> None:
        correction = self._allocated()
        note = Invoice.objects.create(
            customer=self.invoice.customer,
            currency=self.invoice.currency,
            number="CN-MODEL-1",
            document_kind=DOCUMENT_KIND_CREDIT_NOTE,
            reverses_invoice=self.invoice,
            subtotal_cents=-826,
            tax_cents=-174,
            total_cents=-1000,
        )
        note.issue()
        note.save()
        correction.record_issued(note)
        correction.save()
        sent_at = timezone.now()
        correction.record_communicated(at=sent_at, fiscal_date=timezone.localdate(sent_at))
        correction.save()

        with self.assertRaises(TransitionNotAllowed):
            correction.record_communicated(at=timezone.now(), fiscal_date=timezone.localdate())
        correction.communicated_at = sent_at + timedelta(days=1)
        with self.assertRaises(ValidationError):
            correction.save()
        with self.assertRaises(ValidationError):
            FiscalCorrection.objects.filter(pk=correction.pk).update(
                fiscal_date=timezone.localdate() + timedelta(days=1)
            )
        correction.refresh_from_db()
        self.assertEqual(correction.communicated_at, sent_at)

    def test_efactura_is_tracked_only_for_an_issued_note(self) -> None:
        self._allocated()

        self._refused(efactura_status=EFACTURA_PENDING)


class AllocationNullAmountTests(StornoTestCase):
    def test_an_allocation_timestamp_without_its_amounts_is_refused(self) -> None:
        original = self.original()
        correction = self.refund(original, self.collected(original, original.total_cents), 1000)

        with self.assertRaises(IntegrityError), transaction.atomic():
            FiscalCorrection.objects.filter(pk=correction.pk).update(
                state=STATE_FAILED, allocated_at=timezone.now(), vat_residue_cents=0
            )
        self.assertNotEqual(FiscalCorrection.objects.get(pk=correction.pk).state, STATE_ALLOCATED)
