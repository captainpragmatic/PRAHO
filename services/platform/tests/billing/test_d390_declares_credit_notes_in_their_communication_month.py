"""A storno credit note is a negative D390 line in the month it reached the customer (#541, option B).

OPANAF 705/2020 places a credit note in the period it was communicated, not in its original's.
So a June invoice refunded in July is +X in June and -X in July, each month standing alone; a
refund still on its way blocks the month its correction can land in, never the original's
closed month; and a group that nets to exactly nothing is left out of the XML, which has no
zero row, while staying in every reconciliation an accountant reads.
"""

from __future__ import annotations

import csv
import io
from datetime import UTC, date, datetime, timedelta
from typing import Any
from unittest.mock import patch

from django.test import TestCase, override_settings
from django.urls import reverse
from lxml import etree

from apps.billing.d390 import (
    _MAX_BASE,
    NAMESPACE,
    D390ExportError,
    compatibility_schema,
    render_d390_xml,
    render_reconciliation_csv,
    validate_d390_xml,
)
from apps.billing.ec_sales_service import ReportingPeriod, _document_problems, aggregate_ec_services
from apps.billing.fiscal_correction_models import (
    STATE_COMMUNICATED,
    STATE_ISSUED,
    STATE_NOT_REQUIRED,
    FiscalCorrection,
)
from apps.billing.fiscal_correction_worker import _advance_allocation, _advance_communication, _advance_issuance
from apps.billing.invoice_models import DOCUMENT_KIND_CREDIT_NOTE, Invoice, InvoiceLine
from apps.billing.models import Payment, Refund
from apps.billing.tax_evidence import read_vat_evidence
from tests.billing import _fiscal_correction_helpers as h
from tests.billing.test_d390 import DECLARANT, SUPPLIER, D390FixtureMixin
from tests.factories.core_factories import create_staff_user

JUNE = ReportingPeriod(2026, 6)
JULY = ReportingPeriod(2026, 7)
AUGUST = ReportingPeriod(2026, 8)


def _at(day: date, hour: int = 10) -> datetime:
    return datetime(day.year, day.month, day.day, hour, tzinfo=UTC)


def _vies(validated_at: datetime, *, reference: str) -> dict[str, Any]:
    """A valid captured consultation of the fixtures' German partner."""
    return {
        "country_code": "DE",
        "vat_number": "136695976",
        "is_valid": True,
        "is_active": True,
        "source": "vies",
        "validated_at": validated_at.isoformat(),
        "expires_at": None,
        "consultation_reference": reference,
    }


@override_settings(**SUPPLIER)
class _CreditNoteCase(D390FixtureMixin, TestCase):
    def original(self, day: date, *, amount: int = 10000, **overrides: Any) -> Invoice:
        return self.make_invoice(amounts=(amount,), tax_point=day, issued_at=_at(day, 12), **overrides)

    def paid(self, original: Invoice, *, duplicate: bool = False) -> Payment:
        """Collected an hour after issue, so what the ledger held is dated before any refund."""
        assert original.issued_at is not None
        with patch("django.utils.timezone.now", return_value=original.issued_at + timedelta(hours=1)):
            if not duplicate:
                return h.paid(original)
            return Payment.objects.create(
                customer=original.customer,
                invoice=original,
                currency=original.currency,
                status="succeeded",
                payment_method="bank",
                amount_cents=original.total_cents,
            )

    def refund(self, original: Invoice, amount: int, *, at: datetime, payment: Payment | None = None) -> Refund:
        """A refund raised at `at`, still pending."""
        if payment is None:
            payment = self.paid(original)
        with patch("django.utils.timezone.now", return_value=at):
            return h.pending_refund(
                invoice=original,
                payment=payment,
                amount_cents=amount,
                refund_type="full" if amount >= original.total_cents else "partial",
            )

    def settle(self, refund: Refund, *, at: datetime) -> FiscalCorrection:
        """Complete the refund and issue its built-in credit note at `at`, without sending it."""
        with patch("django.utils.timezone.now", return_value=at):
            h.complete(refund)
            correction = FiscalCorrection.objects.get(source_refund_id=refund.pk)
            _advance_allocation(str(correction.pk))
            _advance_issuance(str(correction.pk))
        return FiscalCorrection.objects.get(pk=correction.pk)

    def communicate(self, correction: FiscalCorrection, *, at: datetime) -> FiscalCorrection:
        """The customer receives the note at `at`: the first send dates it for D390."""
        with (
            patch("django.utils.timezone.now", return_value=at),
            patch("apps.billing.fiscal_correction_worker._send_credit_note_email", return_value=(True, "")),
        ):
            _advance_communication(str(correction.pk))
        correction = FiscalCorrection.objects.select_related("credit_note").get(pk=correction.pk)
        assert correction.state == STATE_COMMUNICATED, correction.state
        return correction

    def credit(self, original: Invoice, amount: int, *, issued: datetime, sent: datetime) -> Invoice:
        correction = self.communicate(self.settle(self.refund(original, amount, at=issued), at=issued), at=sent)
        assert correction.credit_note is not None
        return correction.credit_note


class CreditNotesLandInTheirCommunicationMonthTests(_CreditNoteCase):
    def test_a_june_invoice_and_a_july_note_are_plus_june_and_minus_july(self) -> None:
        """Issued in June, sent in July: the sending month is the note's, whatever its tax point says."""
        original = self.original(date(2026, 6, 15))
        note = self.credit(original, 10000, issued=_at(date(2026, 6, 20)), sent=_at(date(2026, 7, 2)))
        self.assertEqual(note.tax_point_date, date(2026, 6, 20), "the note's own tax point is June")

        june = aggregate_ec_services(JUNE)
        self.assertTrue(june.can_export, june.exceptions)
        self.assertEqual([(p.country, p.rounded_ron) for p in june.partners], [("DE", 100)])
        self.assertEqual([line.invoice_id for line in june.contributions], [original.pk])

        july = aggregate_ec_services(JULY)
        self.assertTrue(july.can_export, july.exceptions)
        self.assertEqual([(p.country, p.rounded_ron) for p in july.partners], [("DE", -100)])
        self.assertEqual(
            [(line.invoice_id, line.gross_cents, line.tax_point_date) for line in july.contributions],
            [(note.pk, -10000, date(2026, 7, 2))],
        )

    def test_the_xml_validates_with_a_negative_baza(self) -> None:
        original = self.original(date(2026, 6, 15))
        self.credit(original, 10000, issued=_at(date(2026, 7, 1)), sent=_at(date(2026, 7, 1)))

        content = render_d390_xml(aggregate_ec_services(JULY), DECLARANT)

        root = etree.fromstring(content)
        compatibility_schema().assertValid(root)
        validate_d390_xml(content)
        row = root.find(f"{{{NAMESPACE}}}operatie")
        assert row is not None
        self.assertEqual(row.attrib["baza"], "-100")
        summary = root.find(f"{{{NAMESPACE}}}rezumat")
        assert summary is not None
        self.assertEqual((summary.attrib["bazaP"], summary.attrib["total_baza"]), ("-100", "-100"))
        self.assertEqual(root.attrib["totalPlata_A"], "-99", "the control sum is nrOPI plus the signed bases")

    def test_a_negative_base_beyond_fifteen_digits_or_a_zero_base_is_still_refused(self) -> None:
        """Signed now, still bounded: the limit applies to the magnitude, and zero is never a row."""
        original = self.original(date(2026, 6, 15))
        self.credit(original, 10000, issued=_at(date(2026, 7, 1)), sent=_at(date(2026, 7, 1)))
        content = render_d390_xml(aggregate_ec_services(JULY), DECLARANT)

        for base in (-(_MAX_BASE + 1), 0):
            root = etree.fromstring(content)
            # Consistent everywhere, so only the per-row bound can refuse it.
            root.find(f"{{{NAMESPACE}}}operatie").set("baza", str(base))
            summary = root.find(f"{{{NAMESPACE}}}rezumat")
            summary.set("bazaP", str(base))
            summary.set("total_baza", str(base))
            root.set("totalPlata_A", str(base + 1))
            with self.subTest(base=base), self.assertRaises(D390ExportError):
                validate_d390_xml(etree.tostring(root))

    def test_a_partial_note_in_the_same_month_nets_against_its_original(self) -> None:
        original = self.original(date(2026, 8, 5))
        note = self.credit(original, 4000, issued=_at(date(2026, 8, 20)), sent=_at(date(2026, 8, 20)))

        report = aggregate_ec_services(AUGUST)

        self.assertTrue(report.can_export, report.exceptions)
        self.assertEqual([(p.country, p.rounded_ron) for p in report.partners], [("DE", 60)])
        self.assertEqual({line.invoice_id for line in report.contributions}, {original.pk, note.pk})

    def test_a_fully_netted_group_is_left_out_of_the_xml_but_kept_in_the_reconciliation(self) -> None:
        netted = self.original(date(2026, 8, 5))
        note = self.credit(netted, 10000, issued=_at(date(2026, 8, 20)), sent=_at(date(2026, 8, 20)))
        self.make_invoice(amounts=(5000,), country="GR", vat="EL094259216", name="Example Hellas")

        report = aggregate_ec_services(AUGUST)

        self.assertTrue(report.can_export, report.exceptions)
        report.assert_reconciled()
        by_country = {partner.country: partner for partner in report.partners}
        self.assertEqual(set(by_country), {"DE", "EL"}, "the netted group stays in the report")
        self.assertTrue(by_country["DE"].fully_netted)
        self.assertEqual((by_country["DE"].base_ron, by_country["DE"].rounded_ron), (0, 0))
        self.assertEqual(
            {line.invoice_id for line in by_country["DE"].contributions}, {netted.pk, note.pk}
        )
        root = etree.fromstring(render_d390_xml(report, DECLARANT))
        rows = root.findall(f"{{{NAMESPACE}}}operatie")
        self.assertEqual([row.attrib["tara"] for row in rows], ["EL"], "a zero row is never written")
        summary = root.find(f"{{{NAMESPACE}}}rezumat")
        assert summary is not None
        self.assertEqual((summary.attrib["nrOPI"], root.attrib["totalPlata_A"]), ("1", "51"))
        records = list(csv.reader(io.StringIO(render_reconciliation_csv(report).decode("utf-8-sig"))))
        netted_rows = [row for row in records if row[0] == "fully_netted"]
        self.assertEqual([(row[5], row[14]) for row in netted_rows], [("DE", "0")])
        self.assertEqual(sum(row[0] == "included" for row in records), 3)

    def test_a_period_holding_only_a_fully_netted_group_has_nothing_to_export(self) -> None:
        original = self.original(date(2026, 8, 5))
        self.credit(original, 10000, issued=_at(date(2026, 8, 20)), sent=_at(date(2026, 8, 20)))

        report = aggregate_ec_services(AUGUST)

        report.assert_reconciled()
        self.assertFalse(report.exceptions)
        self.assertFalse(report.can_export, "no operation row is left to declare")
        with self.assertRaises(D390ExportError):
            render_d390_xml(report, DECLARANT)

    def test_the_preview_says_why_a_fully_netted_month_has_no_xml(self) -> None:
        original = self.original(date(2026, 8, 5))
        self.credit(original, 10000, issued=_at(date(2026, 8, 20)), sent=_at(date(2026, 8, 20)))
        self.client.force_login(create_staff_user(username="d390_netted", staff_role="billing"))

        response = self.client.get(reverse("billing:d390_report"), {"month": AUGUST.label})

        self.assertContains(response, "Fully netted, no XML row")
        self.assertContains(response, "There is no row to declare, so no XML is generated.")

    def test_communicating_the_note_changes_the_source_fingerprint(self) -> None:
        """The preview an export was approved from must be invalidated when a note's period settles.

        All in July, so the same original, refund and note are in the source before and after: only
        the correction's state and date differ, and only recording them can change the fingerprint.
        """
        original = self.original(date(2026, 7, 1))
        correction = self.settle(self.refund(original, 10000, at=_at(date(2026, 7, 1))), at=_at(date(2026, 7, 1)))
        before = aggregate_ec_services(JULY).source_fingerprint

        self.communicate(correction, at=_at(date(2026, 7, 2)))

        self.assertNotEqual(aggregate_ec_services(JULY).source_fingerprint, before)


class UnsettledRefundsBlockTheMonthTheirCorrectionLandsInTests(_CreditNoteCase):
    def test_a_pending_refund_blocks_its_own_month_not_the_originals_closed_one(self) -> None:
        original = self.original(date(2026, 6, 15))
        self.refund(original, 10000, at=_at(date(2026, 7, 10)))

        june = aggregate_ec_services(JUNE)
        self.assertTrue(june.can_export, june.exceptions)
        for period in (JULY, AUGUST):
            with self.subTest(period=period.label):
                report = self.assert_blocked_in(period, "outside_period_adjustment")
                self.assertEqual([exc.invoice_id for exc in report.exceptions], [original.pk])

    def test_a_completed_refund_whose_note_is_not_issued_still_blocks_its_month(self) -> None:
        original = self.original(date(2026, 6, 15))
        refund = self.refund(original, 10000, at=_at(date(2026, 7, 10)))
        with patch("django.utils.timezone.now", return_value=_at(date(2026, 7, 10))):
            h.complete(refund)
        self.assertEqual(FiscalCorrection.objects.get(source_refund_id=refund.pk).state, "pending")

        self.assertTrue(aggregate_ec_services(JUNE).can_export)
        self.assert_blocked_in(JULY, "outside_period_adjustment")

    def test_an_issued_but_uncommunicated_note_is_flagged_and_not_exported(self) -> None:
        original = self.original(date(2026, 6, 15))
        correction = self.settle(self.refund(original, 10000, at=_at(date(2026, 7, 10))), at=_at(date(2026, 7, 10)))
        self.assertEqual(correction.state, STATE_ISSUED)
        note = correction.credit_note
        assert note is not None

        self.assertTrue(aggregate_ec_services(JUNE).can_export)
        july = self.assert_blocked_in(JULY, "uncommunicated_credit_note")
        self.assertNotIn(note.pk, {line.invoice_id for line in july.contributions})
        flagged = [exc for exc in july.exceptions if exc.invoice_id == note.pk]
        self.assertEqual([exc.line_id for exc in flagged], list(note.lines.values_list("pk", flat=True)))
        self.assertTrue(all("uncommunicated_credit_note" in exc.codes for exc in flagged), flagged)

    def test_a_validated_not_required_outcome_clears_the_refund(self) -> None:
        """A duplicate payment returned: the invoice stands as issued, so nothing waits for a note."""
        original = self.original(date(2026, 6, 15))
        self.paid(original)
        duplicate = self.paid(original, duplicate=True)
        correction = self.settle(
            self.refund(original, 10000, at=_at(date(2026, 7, 10)), payment=duplicate), at=_at(date(2026, 7, 10))
        )
        self.assertEqual(correction.state, STATE_NOT_REQUIRED, correction.not_required_reason)

        for period in (JUNE, JULY):
            with self.subTest(period=period.label):
                report = aggregate_ec_services(period)
                self.assertFalse(report.exceptions)
        self.assertEqual([p.rounded_ron for p in aggregate_ec_services(JUNE).partners], [100])

    def test_a_note_with_no_correction_at_all_is_flagged_in_every_later_month(self) -> None:
        """No correction row means no communication date: the note must stay visible, never vanish.

        The selection reads a reverse one-to-one that is absent here, so it is the case the query's
        negation has to keep rather than drop.
        """
        original = self.original(date(2026, 6, 15))
        note = Invoice.objects.create(
            customer=original.customer,
            currency=original.currency,
            number="CN-UNLINKED-1",
            status="draft",
            document_kind=DOCUMENT_KIND_CREDIT_NOTE,
            reverses_invoice=original,
            subtotal_cents=-4000,
            tax_cents=0,
            total_cents=-4000,
            bill_to_name=original.bill_to_name,
            bill_to_country=original.bill_to_country,
            bill_to_tax_id=original.bill_to_tax_id,
            tax_point_date=date(2026, 7, 10),
            issued_at=_at(date(2026, 7, 10)),
        )
        InvoiceLine.objects.create(
            invoice=note,
            kind="service",
            description="Storno",
            quantity=1,
            unit_price_cents=-4000,
            tax_rate=0,
            tax_category_code="AE",
        )
        note.issue()
        note.save()
        self.assertFalse(FiscalCorrection.objects.filter(credit_note=note).exists())

        for period in (JULY, AUGUST):
            with self.subTest(period=period.label):
                report = self.assert_blocked_in(period, "uncommunicated_credit_note")
                flagged = [exc for exc in report.exceptions if exc.invoice_id == note.pk]
                self.assertEqual(len(flagged), 1, report.exceptions)
                self.assertIn("uncommunicated_credit_note", flagged[0].codes)
        self.assertNotIn(note.pk, {exc.invoice_id for exc in aggregate_ec_services(JUNE).exceptions})

    def assert_blocked_in(self, period: ReportingPeriod, code: str) -> Any:
        report = aggregate_ec_services(period)
        self.assertFalse(report.can_export)
        self.assertTrue(any(code in exc.codes for exc in report.exceptions), report.exceptions)
        report.assert_reconciled()
        return report


class ANoteIsJudgedByItsOriginalsProofTests(_CreditNoteCase):
    def test_a_v1_originals_proof_on_a_v3_note_needs_no_consultation_reference(self) -> None:
        """Version 1 predates the consultation-reference policy; the note restates that proof as it was."""
        day = date(2026, 8, 5)
        original = self.original(day, issue=False)
        original.vat_evidence["vies"] = _vies(_at(day, 11), reference="")
        original.issue()
        original.save()
        self.assertEqual(original.vat_evidence["version"], 1)
        note = self.credit(original, 4000, issued=_at(date(2026, 8, 20)), sent=_at(date(2026, 8, 20)))
        self.assertEqual((note.vat_evidence["version"], note.vat_evidence["original_version"]), (3, 1))

        problems = _document_problems(note, list(note.lines.all()), read_vat_evidence(note))

        self.assertEqual([p for p in problems if p.startswith("missing_consultation_reference")], [])
        # The same proof under version 2 rules is refused, so the assertion above is not vacuous.
        relabelled = Invoice(**{**_fields(original), "vat_evidence": {**original.vat_evidence, "version": 2}})
        self.assertIn(
            "missing_consultation_reference",
            " ".join(_document_problems(relabelled, list(original.lines.all()), read_vat_evidence(relabelled))),
        )

    def test_a_note_issued_long_after_its_original_is_neither_late_nor_stale(self) -> None:
        """The decision and its VIES proof are the original's, current when the original was decided."""
        day = date(2026, 3, 2)
        original = self.original(day, issue=False)
        original.vat_evidence["version"] = 2
        original.vat_evidence["vies"] = _vies(_at(day, 11), reference="WAPIAAAAX1")
        original.issue()
        original.save()
        later = _at(day) + timedelta(days=120)
        note = self.credit(original, 4000, issued=later, sent=later)

        problems = _document_problems(note, list(note.lines.all()), read_vat_evidence(note))

        self.assertEqual(
            [p for p in problems if p.startswith(("late_tax_decision", "conflicting_vat_validation"))], []
        )

    def test_a_note_restating_a_decision_taken_after_its_original_was_issued_is_late(self) -> None:
        """The late check still bites: it moved to the original's decision, it did not go away."""
        day = date(2026, 8, 5)
        original = self.original(day, issue=False)
        original.vat_evidence["calculated_at"] = _at(day, 18).isoformat()  # after the 12:00 issue
        original.issue()
        original.save()
        note = self.credit(original, 4000, issued=_at(date(2026, 8, 20)), sent=_at(date(2026, 8, 20)))
        self.assertEqual(note.document_kind, DOCUMENT_KIND_CREDIT_NOTE)

        problems = _document_problems(note, list(note.lines.all()), read_vat_evidence(note))

        self.assertIn("late_tax_decision", " ".join(problems))


def _fields(invoice: Invoice) -> dict[str, Any]:
    """An unsaved copy's constructor arguments: every concrete field but the key."""
    return {
        field.attname: getattr(invoice, field.attname)
        for field in invoice._meta.concrete_fields
        if field.attname != "id"
    }


class ARefundIsSettledOnlyForTheInvoiceAndPaymentItAnswersForTests(_CreditNoteCase):
    def test_a_refund_closed_with_no_fiscal_document_still_holds_its_own_month(self) -> None:
        """Linked to the invoice only through its order, so the correction never found the invoice.

        `not_required` with no original was not decided against this supply, so it settles nothing
        here: June stays clear, and July, when the refund was raised, is held.
        """
        order = h.order_for(None, h.customer("Order Owner GmbH"), total_cents=10000)
        original = self.original(date(2026, 6, 15), meta={"order_id": str(order.pk)})
        with patch("django.utils.timezone.now", return_value=_at(date(2026, 7, 10))):
            refund = h.complete(h.pending_refund(order=order, amount_cents=10000))
        correction = FiscalCorrection.objects.get(source_refund_id=refund.pk)
        self.assertEqual((correction.state, correction.original_id), (STATE_NOT_REQUIRED, None))

        self.assertTrue(aggregate_ec_services(JUNE).can_export, aggregate_ec_services(JUNE).exceptions)
        july = self.assert_blocked_in(JULY, "outside_period_adjustment")
        self.assertEqual([exc.invoice_id for exc in july.exceptions], [original.pk])

    def test_a_refunded_payment_with_no_refund_record_blocks_even_beside_a_settled_one(self) -> None:
        """Each refunded payment needs its own settled refund; another payment's does not explain it."""
        original = self.original(date(2026, 6, 15))
        self.paid(original)
        duplicate = self.paid(original, duplicate=True)
        settled = self.settle(
            self.refund(original, 10000, at=_at(date(2026, 7, 10)), payment=duplicate), at=_at(date(2026, 7, 10))
        )
        self.assertEqual(settled.state, STATE_NOT_REQUIRED)
        Payment.objects.create(
            customer=original.customer,
            invoice=original,
            currency=original.currency,
            status="refunded",
            payment_method="bank",
            amount_cents=500,
        )

        report = aggregate_ec_services(JUNE)

        self.assertFalse(report.can_export)
        self.assertIn("unresolved_fiscal_adjustment", {code for exc in report.exceptions for code in exc.codes})

    def assert_blocked_in(self, period: ReportingPeriod, code: str) -> Any:
        report = aggregate_ec_services(period)
        self.assertFalse(report.can_export)
        self.assertTrue(any(code in exc.codes for exc in report.exceptions), report.exceptions)
        report.assert_reconciled()
        return report
