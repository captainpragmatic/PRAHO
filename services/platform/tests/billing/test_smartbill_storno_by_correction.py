"""A SmartBill invoice is stornoed through the refund's fiscal correction, never through the invoice.

`/invoice/reverse` reverses a whole document and carries no amount. So it is the right call for
exactly one case: the correction credits the whole original and nothing else has credited it. Every
other SmartBill correction, partial or a remainder after one, is issued by staff at the provider and
recorded against the correction (ADR-0053, ADR-0048).

These run as `TransactionTestCase`: a provider call refuses to run inside a transaction (ADR-0045),
and each refund's queued worker is run synchronously when its enqueue fires after commit.
"""

from __future__ import annotations

from io import StringIO
from typing import Any
from unittest.mock import MagicMock, patch

from django.core import mail
from django.core.cache import cache
from django.core.management import call_command
from django.test import TransactionTestCase

from apps.billing.fiscal_correction_models import FiscalCorrection
from apps.billing.invoice_models import DOCUMENT_KIND_CREDIT_NOTE, ISSUER_SMARTBILL, Invoice
from apps.billing.issuers.base import Issued, PreparedDocument
from apps.billing.issuers.models import ProviderIssuance
from apps.billing.models import Payment, ProformaInvoice, Refund
from apps.billing.refund_service import RefundService
from apps.common.types import Ok
from tests.billing import _fiscal_correction_helpers as h

PARTIAL_EVENT = "provider_partial_refund_needs_manual_correction"


class SmartBillStornoByCorrectionTests(TransactionTestCase):
    def setUp(self) -> None:
        cache.clear()
        call_command("setup_email_templates", stdout=StringIO())
        self.owner = h.customer()
        self.owner.primary_email = "billing@customer.test"
        self.owner.save(update_fields=["primary_email"])
        self.invoice = h.issued_invoice(self.owner, issuer=ISSUER_SMARTBILL, number="FCT-002000")

    def _provider(self) -> tuple[Any, MagicMock, Any]:
        """The SmartBill calls a storno makes, with the reversal and its PDF answered locally."""
        submit = MagicMock(return_value=Issued(number="002001", series="STORNO"))
        return (
            patch(
                "apps.billing.issuers.smartbill.issuer.SmartBillIssuer.prepare_storno",
                return_value=Ok(PreparedDocument(payload={"number": "002000"}, digest="d")),
            ),
            submit,
            patch(
                "apps.billing.issuers.smartbill.issuer.SmartBillIssuer.fetch_pdf",
                return_value=Ok(b"%PDF-1.4 provider storno"),
            ),
        )

    def _refund_invoice(self, amount_cents: int, refund_type: str) -> tuple[Any, MagicMock, MagicMock]:
        prepare, submit, fetch_pdf = self._provider()
        with (
            prepare,
            patch("apps.billing.issuers.smartbill.issuer.SmartBillIssuer.submit_storno", submit),
            fetch_pdf,
            patch("apps.billing.gateways.base.PaymentGatewayFactory.create_gateway", return_value=h.gateway(amount_cents)),
            patch("django_q.tasks.async_task", side_effect=h.run_queued_now),
            patch("apps.billing.fiscal_correction_worker.log_security_event") as security,
        ):
            result = RefundService.refund_invoice(
                self.invoice.pk,
                {"refund_type": refund_type, "amount_cents": amount_cents, "reason": "customer_request"},
            )
        return result, submit, security

    def test_order_path_full_refund_of_a_smartbill_invoice_is_stornoed(self) -> None:
        """Internal H2: an order refund names its invoice only through the order, and the payment
        names the proforma. The correction still finds the invoice, and the storno it issues is the
        correction's own document, reached by the correction and sent to the customer."""
        self.invoice.mark_as_paid()
        self.invoice.save()
        proforma = ProformaInvoice.objects.create(
            customer=self.owner,
            currency=self.invoice.currency,
            number="PRO-H2-1",
            subtotal_cents=self.invoice.subtotal_cents,
            tax_cents=self.invoice.tax_cents,
            total_cents=self.invoice.total_cents,
        )
        order = h.order_for(self.invoice, proforma=proforma)
        Payment.objects.create(
            customer=self.owner,
            proforma=proforma,
            currency=self.invoice.currency,
            status="succeeded",
            payment_method="stripe",
            amount_cents=self.invoice.total_cents,
            gateway_txn_id="pi_h2_proforma",
        )

        prepare, submit, fetch_pdf = self._provider()
        with (
            prepare,
            patch("apps.billing.issuers.smartbill.issuer.SmartBillIssuer.submit_storno", submit),
            fetch_pdf,
            patch("apps.billing.gateways.base.PaymentGatewayFactory.create_gateway", return_value=h.gateway(12100)),
            patch("django_q.tasks.async_task", side_effect=h.run_queued_now),
        ):
            result = RefundService.refund_order(
                order.pk, {"refund_type": "full", "amount_cents": 12100, "reason": "customer_request"}
            )

        self.assertTrue(result.is_ok(), result)
        correction = FiscalCorrection.objects.get(source_refund=Refund.objects.get(order=order))
        self.assertEqual(correction.state, "communicated", correction.last_error)
        credit_note = Invoice.objects.get(document_kind=DOCUMENT_KIND_CREDIT_NOTE)
        self.assertEqual(credit_note.number, "STORNO-002001")
        self.assertEqual(credit_note.reverses_invoice_id, self.invoice.pk)
        self.assertEqual(correction.credit_note_id, credit_note.pk)
        self.assertEqual(ProviderIssuance.objects.get(invoice=credit_note).fiscal_correction_id, correction.pk)
        self.assertEqual(correction.total_cents, -12100)
        submit.assert_called_once()
        # SmartBill files its own documents with ANAF; PRAHO owes no e-Factura submission for this one.
        self.assertEqual(correction.efactura_status, "not_due")
        # The customer gets the provider's own document, never a second rendering of it (ADR-0048).
        sent = [message for message in mail.outbox if message.attachments]
        self.assertEqual([attachment[1] for attachment in sent[-1].attachments], [b"%PDF-1.4 provider storno"])

    def test_a_partial_refund_of_a_smartbill_invoice_needs_a_manual_storno(self) -> None:
        """Never the whole-document reverse: it would credit the customer 121 for a 50 refund."""
        h.paid(self.invoice)

        result, submit, security = self._refund_invoice(5000, "partial")

        self.assertTrue(result.is_ok(), result)
        correction = FiscalCorrection.objects.get(original=self.invoice)
        self.assertEqual(correction.state, "manual_required")
        self.assertEqual(correction.total_cents, -5000)
        submit.assert_not_called()
        self.assertFalse(Invoice.objects.filter(document_kind=DOCUMENT_KIND_CREDIT_NOTE).exists())
        events = [call.kwargs for call in security.call_args_list if call.kwargs.get("event_type") == PARTIAL_EVENT]
        self.assertEqual([event["details"]["fiscal_correction_id"] for event in events], [str(correction.pk)])

    def test_the_remainder_after_a_partial_is_not_reversed_whole_either(self) -> None:
        """30 then the other 91. The second covers everything left, but the original was already
        credited, so a whole-document reverse would credit 121 again on top of the 30."""
        h.paid(self.invoice)
        self._refund_invoice(3000, "partial")

        result, submit, _security = self._refund_invoice(9100, "partial")

        self.assertTrue(result.is_ok(), result)
        corrections = FiscalCorrection.objects.filter(original=self.invoice).order_by("created_at")
        self.assertEqual(
            [(c.state, c.total_cents) for c in corrections],
            [("manual_required", -3000), ("manual_required", -9100)],
        )
        submit.assert_not_called()
