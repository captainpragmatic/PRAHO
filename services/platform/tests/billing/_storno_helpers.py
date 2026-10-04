"""Shared fixtures for the built-in storno tests: a numbered, evidenced original and its refunds."""

from __future__ import annotations

from datetime import timedelta
from decimal import Decimal
from io import StringIO
from typing import Any

from django.core.cache import cache
from django.core.management import call_command
from django.test import TestCase, override_settings
from django.utils import timezone

from apps.billing.fiscal_correction_models import FiscalCorrection
from apps.billing.fiscal_correction_worker import process_fiscal_correction
from apps.billing.invoice_models import ISSUER_BUILTIN, SEQUENCE_SCOPE_DEFAULT, Invoice, InvoiceLine
from apps.billing.models import Currency, Payment, Refund
from apps.billing.numbering_service import InvoiceNumberingService
from tests.billing import _fiscal_correction_helpers as h

SELLER = override_settings(
    COMPANY_NAME="Test Company SRL",
    EFACTURA_COMPANY_CUI="12345678",
    COMPANY_REGISTRATION_NUMBER="J40/1234/2020",
    COMPANY_STREET="Test Street 123",
    COMPANY_CITY="Bucharest",
    COMPANY_POSTAL_CODE="010101",
    COMPANY_COUNTRY_CODE="RO",
)


def v2_evidence(*, subtotal: int, tax: int, total: int, rate: str = "21", version: int = 2) -> dict[str, Any]:
    evidence: dict[str, Any] = {
        "version": version,
        "scenario": "romania_b2b",
        "category": "S" if Decimal(rate) else "Z",
        "country_code": "RO",
        "vat_number": "RO87654321",
        "is_business": True,
        "vat_rate_percent": rate,
        "subtotal_cents": subtotal,
        "tax_cents": tax,
        "total_cents": total,
        "calculated_at": (timezone.now() - timedelta(days=1)).isoformat(),
        "vies": None,
    }
    if version >= 2:  # noqa: PLR2004  # Version 2 introduced the maximum age.
        evidence["evidence_max_age_days"] = 30
    return evidence


class StornoTestCase(TestCase):
    """A built-in original numbered from the default series, paid, and refundable."""

    def setUp(self) -> None:
        cache.clear()
        call_command("setup_email_templates", stdout=StringIO())
        self.owner = h.customer()

    def original(  # noqa: PLR0913  # One keyword per shape of original a test needs
        self,
        *,
        lines: tuple[tuple[int, str], ...] = ((10000, "0.21"),),
        discount_cents: int = 0,
        tax_cents: int | None = None,
        evidence_version: int = 2,
        country: str = "RO",
        currency_code: str = "RON",
    ) -> Invoice:
        """Lines of (gross cents, rate); the header VAT is the sum of rounded line VAT unless given."""
        gross = sum(net for net, _rate in lines)
        line_taxes = [int((Decimal(net) * Decimal(rate)).quantize(Decimal(1))) for net, rate in lines]
        base = gross - discount_cents
        tax = sum(line_taxes) if tax_cents is None else tax_cents
        foreign = currency_code != "RON"
        currency = h.ron() if not foreign else Currency.objects.get_or_create(code=currency_code)[0]
        invoice = Invoice.objects.create(
            customer=self.owner,
            currency=currency,
            exchange_to_ron=Decimal("4.97650000") if foreign else None,
            exchange_rate_as_of=timezone.localdate() - timedelta(days=1) if foreign else None,
            exchange_rate_source="bnr" if foreign else "",
            exchange_rate_source_reference="bnr:storno-test" if foreign else "",
            number=InvoiceNumberingService.get_next_number(),
            sequence_scope=SEQUENCE_SCOPE_DEFAULT,
            status="draft",
            subtotal_cents=base,
            tax_cents=tax,
            total_cents=base + tax,
            discount_cents=discount_cents,
            issuer_provider=ISSUER_BUILTIN,
            bill_to_name="Customer SRL",
            bill_to_tax_id="RO87654321",
            bill_to_email="billing@customer.test",
            bill_to_address1="Customer Street 456",
            bill_to_city="Cluj-Napoca",
            bill_to_postal="400001",
            bill_to_country=country,
            vat_evidence=v2_evidence(
                subtotal=base,
                tax=tax,
                total=base + tax,
                rate=str(Decimal(lines[0][1]) * 100),
                version=evidence_version,
            ),
        )
        InvoiceLine.objects.bulk_create(
            [
                InvoiceLine(
                    invoice=invoice,
                    kind="service",
                    description=f"Hosting {index}",
                    quantity=Decimal("1"),
                    unit_price_cents=net,
                    tax_rate=Decimal(rate),
                    tax_cents=line_tax,
                    line_total_cents=net + line_tax,
                    sort_order=index,
                )
                for index, ((net, rate), line_tax) in enumerate(zip(lines, line_taxes, strict=True))
            ]
        )
        invoice.issue()
        invoice.save()
        return invoice

    def collected(self, invoice: Invoice, amount_cents: int, *, mark_paid: bool = True) -> Payment:
        if mark_paid:
            return h.paid(invoice, amount_cents=amount_cents)
        return Payment.objects.create(
            customer=invoice.customer,
            invoice=invoice,
            currency=invoice.currency,
            status="succeeded",
            payment_method="bank_transfer",
            amount_cents=amount_cents,
        )

    def refund(self, invoice: Invoice, payment: Payment, amount_cents: int) -> FiscalCorrection:
        """Settle a refund through the gateway convergence path; return the correction it recorded."""
        refund = h.pending_refund(
            invoice=invoice,
            payment=payment,
            amount_cents=amount_cents,
            refund_type="full" if amount_cents >= invoice.total_cents else "partial",
        )
        h.complete(refund)
        return FiscalCorrection.objects.get(source_refund=Refund.objects.get(pk=refund.pk))

    def sweep(self) -> None:
        """Run the recovery sweep with its after-commit delivery executed, as outside a test."""
        from apps.billing.fiscal_correction_worker import sweep_fiscal_correction_issuance  # noqa: PLC0415

        with self.captureOnCommitCallbacks(execute=True):
            sweep_fiscal_correction_issuance()

    def process(self, correction: FiscalCorrection) -> FiscalCorrection:
        """Run the worker the way production does: its after-commit delivery included."""
        with self.captureOnCommitCallbacks(execute=True):
            process_fiscal_correction(str(correction.pk))
        return FiscalCorrection.objects.get(pk=correction.pk)
