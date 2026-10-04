"""Version 3 VAT evidence: the decision a credit note restates, signed the way the note is.

A built-in credit note carries its original's decision (scenario, category, identity, VIES proof)
under the original's own evidence version, plus what makes it a correction: its signed amounts,
the number it reverses and when the original's decision was taken. The reader accepts that shape
on a credit note only, with amounts equal to the note's totals.
"""

from __future__ import annotations

from copy import deepcopy
from typing import Any

from django.test import TestCase

from apps.billing.invoice_models import DOCUMENT_KIND_CREDIT_NOTE, Invoice
from apps.billing.tax_evidence import (
    CREDIT_NOTE_EVIDENCE_VERSION,
    TaxEvidenceError,
    capture_credit_note_evidence,
    evidence_rules_version,
    read_vat_evidence,
)
from tests.billing import _fiscal_correction_helpers as h

V2_DECISION: dict[str, Any] = {
    "version": 2,
    "scenario": "romania_b2b",
    "category": "S",
    "country_code": "RO",
    "vat_number": "",
    "is_business": True,
    "vat_rate_percent": "21",
    "subtotal_cents": 10000,
    "tax_cents": 2100,
    "total_cents": 12100,
    "calculated_at": "2026-09-01T09:00:00+00:00",
    "evidence_max_age_days": 30,
    "vies": None,
}


class CreditNoteEvidenceTests(TestCase):
    def setUp(self) -> None:
        self.owner = h.customer()

    def _original(self, evidence: dict[str, Any]) -> Invoice:
        invoice = h.issued_invoice(self.owner, issue=False)
        Invoice.objects.filter(pk=invoice.pk).update(vat_evidence=evidence)
        invoice.refresh_from_db()
        invoice.issue()
        invoice.save()
        return invoice

    def _note(self, original: Invoice, evidence: dict[str, Any], *, totals: tuple[int, int, int]) -> Invoice:
        subtotal, tax, total = totals
        return Invoice.objects.create(
            customer=self.owner,
            currency=original.currency,
            document_kind=DOCUMENT_KIND_CREDIT_NOTE,
            reverses_invoice=original,
            subtotal_cents=subtotal,
            tax_cents=tax,
            total_cents=total,
            vat_evidence=evidence,
        )

    def test_a_note_restates_its_originals_decision_with_its_own_signed_amounts(self) -> None:
        original = self._original(V2_DECISION)

        evidence = capture_credit_note_evidence(original, subtotal_cents=-826, tax_cents=-174, total_cents=-1000)
        decision = read_vat_evidence(self._note(original, evidence, totals=(-826, -174, -1000)))

        assert decision is not None
        self.assertEqual(evidence["version"], CREDIT_NOTE_EVIDENCE_VERSION)
        self.assertEqual(evidence["document_kind"], DOCUMENT_KIND_CREDIT_NOTE)
        self.assertEqual(evidence["reverses_number"], original.number)
        self.assertEqual(evidence["reverses_calculated_at"], V2_DECISION["calculated_at"])
        self.assertEqual((evidence["original_version"], evidence["evidence_max_age_days"]), (2, 30))
        self.assertEqual((decision.subtotal_cents, decision.tax_cents, decision.total_cents), (-826, -174, -1000))
        self.assertEqual((decision.category, decision.scenario.value), ("S", "romania_b2b"))

    def test_a_v1_originals_proof_keeps_its_version(self) -> None:
        """Version 1 judged VIES proof by its own expiry; version 2 by a maximum age. The note must
        be judged by the rules its original was written under, not by the note's own version."""
        v1 = {key: value for key, value in V2_DECISION.items() if key != "evidence_max_age_days"} | {"version": 1}
        original = self._original(v1)

        evidence = capture_credit_note_evidence(original, subtotal_cents=-100, tax_cents=-21, total_cents=-121)

        self.assertEqual(evidence["original_version"], 1)
        self.assertNotIn("evidence_max_age_days", evidence)
        self.assertEqual(evidence_rules_version(evidence), 1)
        self.assertEqual(evidence_rules_version(V2_DECISION), 2)

    def test_v3_is_refused_on_anything_but_a_credit_note(self) -> None:
        """Zero amounts on both sides, so only the document's kind can refuse it."""
        original = self._original(V2_DECISION)
        evidence = capture_credit_note_evidence(original, subtotal_cents=0, tax_cents=0, total_cents=0)
        invoice = Invoice.objects.create(customer=self.owner, currency=original.currency, vat_evidence=evidence)

        with self.assertRaises(TaxEvidenceError):
            read_vat_evidence(invoice)

    def test_v3_is_refused_on_a_proforma(self) -> None:
        from apps.billing.proforma_models import ProformaInvoice  # noqa: PLC0415

        original = self._original(V2_DECISION)
        proforma = ProformaInvoice(
            subtotal_cents=0,
            tax_cents=0,
            total_cents=0,
            vat_evidence=capture_credit_note_evidence(original, subtotal_cents=0, tax_cents=0, total_cents=0),
        )

        with self.assertRaises(TaxEvidenceError):
            read_vat_evidence(proforma)

    def test_v3_amounts_must_be_the_notes_own_totals(self) -> None:
        original = self._original(V2_DECISION)
        evidence = capture_credit_note_evidence(original, subtotal_cents=-100, tax_cents=-21, total_cents=-121)

        with self.assertRaises(TaxEvidenceError):
            read_vat_evidence(self._note(original, evidence, totals=(-200, -42, -242)))

    def test_v3_amounts_cannot_be_positive(self) -> None:
        original = self._original(V2_DECISION)
        evidence = capture_credit_note_evidence(original, subtotal_cents=-100, tax_cents=-21, total_cents=-121)
        flipped = deepcopy(evidence) | {"subtotal_cents": 100, "tax_cents": 21, "total_cents": 121}
        note = self._note(original, evidence, totals=(-100, -21, -121))
        Invoice.objects.filter(pk=note.pk).update(vat_evidence=flipped)
        note.refresh_from_db()

        with self.assertRaises(TaxEvidenceError):
            read_vat_evidence(note)

    def test_an_original_without_evidence_gives_a_note_without_evidence(self) -> None:
        original = h.issued_invoice(self.owner)

        self.assertEqual(capture_credit_note_evidence(original, subtotal_cents=-1, tax_cents=0, total_cents=-1), {})
