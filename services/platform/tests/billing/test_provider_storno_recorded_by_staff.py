"""A SmartBill correction its API cannot issue is issued by staff at the provider and recorded here.

`/invoice/reverse` reverses only a whole invoice, once, and nothing else in the API can tie a
document to the invoice it corrects (A3 research). So a partial correction waits as
`manual_required`; staff issue the storno in SmartBill, send it, and record its number, its issue
date, the date it was sent, and where the proof of sending is kept (ADR-0053, v3 point 6). Nothing
staff enter is trusted where it can be checked against the correction's allocation.
"""

from __future__ import annotations

from dataclasses import replace
from datetime import timedelta
from typing import Any
from unittest.mock import patch

from django.core.exceptions import ValidationError
from django.test import TestCase
from django.urls import reverse
from django.utils import timezone

from apps.audit.models import AuditEvent
from apps.billing.efactura.settings import ro_local_date
from apps.billing.fiscal_correction_models import STATE_COMMUNICATED, STATE_MANUAL_REQUIRED, FiscalCorrection
from apps.billing.fiscal_correction_service import ProviderStornoRecord, record_provider_storno
from apps.billing.fiscal_correction_worker import _advance_allocation, _advance_issuance
from apps.billing.invoice_models import DOCUMENT_KIND_CREDIT_NOTE, ISSUER_SMARTBILL, Invoice
from apps.billing.issuers.models import IssuanceState, ProviderIssuance
from apps.billing.operator_controls import BillingControlActor, record_manual_provider_storno
from tests.billing import _fiscal_correction_helpers as h
from tests.factories.core_factories import create_admin_user

_EVIDENCE = "Email 'Factura storno STORNO-2001' sent to billing@customer.test"


class _ManualCorrectionCase(TestCase):
    def setUp(self) -> None:
        self.owner = h.customer()
        self.invoice = h.issued_invoice(self.owner, issuer=ISSUER_SMARTBILL, number="FCT-002000")
        payment = h.paid(self.invoice)
        refund = h.complete(
            h.pending_refund(invoice=self.invoice, payment=payment, amount_cents=5000, refund_type="partial")
        )
        correction = FiscalCorrection.objects.get(source_refund=refund)
        _advance_allocation(str(correction.pk))
        with patch("apps.billing.fiscal_correction_worker.log_security_event"):
            _advance_issuance(str(correction.pk))
        self.correction = FiscalCorrection.objects.get(pk=correction.pk)
        assert self.correction.state == STATE_MANUAL_REQUIRED, self.correction.state
        self.today = ro_local_date(timezone.now())

    def record(self, **overrides: Any) -> ProviderStornoRecord:
        """The storno as SmartBill prints it: 50.00 credited, 41.32 base and 8.68 VAT, signed."""
        entered = ProviderStornoRecord(
            series="STORNO",
            number="2001",
            issued_on=self.today,
            communicated_on=self.today,
            currency_code="RON",
            base_cents=-4132,
            tax_cents=-868,
            evidence=_EVIDENCE,
        )
        return replace(entered, **overrides)

    def refused(self, record: ProviderStornoRecord) -> dict[str, list[str]]:
        with self.assertRaises(ValidationError) as caught:
            record_provider_storno(self.correction.pk, record)
        self.correction.refresh_from_db()
        self.assertEqual(self.correction.state, STATE_MANUAL_REQUIRED)
        self.assertFalse(Invoice.objects.filter(document_kind=DOCUMENT_KIND_CREDIT_NOTE).exists())
        return caught.exception.message_dict


class RecordingAProviderStornoTests(_ManualCorrectionCase):
    def test_the_recorded_storno_settles_the_correction_dated_by_its_sending(self) -> None:
        issued_on = self.today
        sent_on = self.today

        note = record_provider_storno(self.correction.pk, self.record(issued_on=issued_on, communicated_on=sent_on))

        self.correction.refresh_from_db()
        self.assertEqual(self.correction.state, STATE_COMMUNICATED)
        self.assertEqual(self.correction.credit_note_id, note.pk)
        self.assertEqual(self.correction.fiscal_date, sent_on)
        self.assertEqual(ro_local_date(self.correction.communicated_at), sent_on)
        self.assertEqual(self.correction.communication_evidence, _EVIDENCE)
        self.assertEqual(self.correction.efactura_status, "not_due", "SmartBill files its own documents")
        self.assertEqual(note.number, "STORNO-2001")
        self.assertEqual((note.issuer_provider, note.reverses_invoice_id), (ISSUER_SMARTBILL, self.invoice.pk))
        self.assertEqual(ro_local_date(note.issued_at), issued_on)
        self.assertIsNotNone(note.locked_at)
        self.assertEqual((note.subtotal_cents, note.tax_cents, note.total_cents), (-4132, -868, -5000))
        self.assertEqual(sum(line.line_total_cents for line in note.lines.all()), -5000)
        issuance = ProviderIssuance.objects.get(invoice=note)
        self.assertEqual(
            (issuance.state, issuance.fiscal_correction_id, issuance.provider_series, issuance.provider_number),
            (IssuanceState.ISSUED.value, self.correction.pk, "STORNO", "2001"),
        )

    def test_the_amounts_must_be_the_allocation(self) -> None:
        errors = self.refused(self.record(base_cents=-4100, tax_cents=-900))

        self.assertEqual(set(errors), {"base_amount", "tax_amount"})

    def test_the_sign_staff_type_does_not_matter(self) -> None:
        note = record_provider_storno(self.correction.pk, self.record(base_cents=4132, tax_cents=868))

        self.assertEqual(note.total_cents, -5000)

    def test_the_currency_must_be_the_invoices(self) -> None:
        self.assertIn("currency_code", self.refused(self.record(currency_code="EUR")))

    def test_a_storno_cannot_predate_the_invoice_or_postdate_today(self) -> None:
        original_day = ro_local_date(self.invoice.issued_at)

        self.assertIn("issued_on", self.refused(self.record(issued_on=original_day - timedelta(days=1))))
        self.assertIn("issued_on", self.refused(self.record(issued_on=self.today + timedelta(days=1))))

    def test_it_cannot_have_been_sent_before_it_was_issued_or_in_the_future(self) -> None:
        yesterday = self.today - timedelta(days=1)
        self.assertIn(
            "communicated_on",
            self.refused(self.record(issued_on=self.today, communicated_on=yesterday)),
        )
        self.assertIn("communicated_on", self.refused(self.record(communicated_on=self.today + timedelta(days=1))))

    def test_the_number_must_be_new(self) -> None:
        self.assertIn("number", self.refused(self.record(series="", number=self.invoice.number)))

    def test_a_correction_not_waiting_for_staff_is_refused(self) -> None:
        record_provider_storno(self.correction.pk, self.record())

        with self.assertRaises(ValidationError):
            record_provider_storno(self.correction.pk, self.record(number="2002"))
        self.assertEqual(Invoice.objects.filter(document_kind=DOCUMENT_KIND_CREDIT_NOTE).count(), 1)

    def test_whoever_recorded_it_is_audited_with_their_reason(self) -> None:
        operator = create_admin_user(username="storno_operator")

        number = record_manual_provider_storno(
            correction_id=self.correction.pk,
            record=self.record(),
            actor=BillingControlActor(user=operator, reason="Partial storno issued in SmartBill Cloud", ip_address=None),
        )

        event = AuditEvent.objects.filter(user=operator, action="configuration_changed").get()
        self.assertEqual(event.new_values["credit_note_number"], number)
        self.assertEqual(event.new_values["communication_date"], self.today.isoformat())
        self.assertEqual(event.metadata["reason"], "Partial storno issued in SmartBill Cloud")


class RecordingScreenTests(_ManualCorrectionCase):
    def setUp(self) -> None:
        super().setUp()
        self.client.force_login(create_admin_user(username="storno_screen"))
        self.url = reverse("billing:provider_storno_record", args=[self.correction.pk])

    def _post(self, **overrides: str) -> Any:
        data = {
            "series": "STORNO",
            "number": "2001",
            "confirmation": "2001",
            "issued_on": self.today.isoformat(),
            "communicated_on": self.today.isoformat(),
            "currency_code": "ron",
            "base_amount": "-41.32",
            "tax_amount": "-8.68",
            "evidence": _EVIDENCE,
            "reason": "Partial storno issued in SmartBill Cloud",
        }
        data.update(overrides)
        return self.client.post(self.url, data)

    def test_the_queue_lists_the_correction_waiting_for_staff(self) -> None:
        response = self.client.get(reverse("billing:provider_reconciliation_queue"))

        self.assertContains(response, 'data-testid="manual-corrections"')
        self.assertContains(response, self.url)

    def test_the_form_shows_what_to_issue(self) -> None:
        response = self.client.get(self.url)

        self.assertContains(response, 'data-testid="correction-allocation"')
        self.assertContains(response, "-50.00")

    def test_a_valid_entry_records_the_storno(self) -> None:
        response = self._post()

        self.assertRedirects(response, reverse("billing:provider_reconciliation_queue"))
        self.correction.refresh_from_db()
        self.assertEqual(self.correction.state, STATE_COMMUNICATED)
        self.assertEqual(self.correction.credit_note.number, "STORNO-2001")

    def test_an_entry_that_does_not_match_is_shown_back_with_the_field_to_fix(self) -> None:
        response = self._post(base_amount="-41.00")

        self.assertEqual(response.status_code, 200)
        self.assertIn("base_amount", response.context["form"].errors)
        self.correction.refresh_from_db()
        self.assertEqual(self.correction.state, STATE_MANUAL_REQUIRED)

    def test_a_settled_correction_sends_staff_back_to_the_queue(self) -> None:
        self._post()

        response = self.client.get(self.url)

        self.assertRedirects(response, reverse("billing:provider_reconciliation_queue"))
