"""PRAHO's own issuer: the legal number comes from the local sequence.

This path is unchanged in behaviour from before the abstraction existed. It is kept
exercised deliberately — once SmartBill is active in production no invoice reaches
it, and an unexercised fallback is not a fallback. Routing it through the same
gateway the external issuer uses is what keeps it honest.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from apps.common.types import Ok, Result

from .base import (
    ConfigurationReport,
    InvoiceIssuerGateway,
    Issued,
    IssueOutcome,
    register_invoice_issuer,
)

if TYPE_CHECKING:
    from uuid import UUID

    from apps.billing.invoice_models import Invoice


class BuiltinIssuer(InvoiceIssuerGateway):
    """Allocates from `InvoiceSequence` through the locking numbering service."""

    provider = "builtin"

    def validate_configuration(self) -> Result[ConfigurationReport, str]:
        """Always configured: the sequence is created on first use.

        There is nothing to test a connection to, which is itself the point of
        keeping this provider available.
        """
        return Ok(
            ConfigurationReport(
                provider=self.provider,
                ok=True,
                checks=("Local invoice sequence requires no external configuration",),
            )
        )

    def issue_invoice(self, invoice: Invoice, *, attempt_id: UUID) -> IssueOutcome:
        """Consume the next number from the local sequence.

        Stated precisely: this adapter returns `Issued` or propagates a database
        exception. It does not return `Ambiguous`, because it has no lost-response
        failure mode of its own — but that is not a claim that local writes cannot
        have uncertain outcomes. A connection loss during commit can still leave the
        caller unsure, and a propagated database exception is NOT evidence that no
        number was consumed, so it must never be treated as a safe-to-retry rejection.

        The allocation is row-locked and participates in whatever transaction the
        caller has open, so it rolls back with that transaction. Owning the boundary
        that makes allocation and invoice persistence atomic is the caller's job,
        not this adapter's.
        """
        from apps.billing.numbering_service import InvoiceNumberingService  # noqa: PLC0415

        return Issued(number=InvoiceNumberingService.get_next_number())


register_invoice_issuer(BuiltinIssuer.provider, BuiltinIssuer)
