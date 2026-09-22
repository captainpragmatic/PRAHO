"""Which system owns a document, and therefore who may file it with ANAF.

The load-bearing invariant of the whole integration is: **one authoritative
invoice, one authoritative number, one e-Factura submission owner.** PRAHO's own
e-Factura stack stays in the repository after an external issuer is switched on,
so nothing but an explicit guard stops it from submitting a document the provider
has already filed. Two uploads of the same invoice to SPV is the failure this
module exists to make impossible.

The decision is taken per document, never from a global setting. `issuer_provider`
is stamped at creation and frozen into the fiscal snapshot, so a built-in invoice
issued before the switch keeps submitting through PRAHO forever, and a worker that
already loaded an invoice cannot have the answer change underneath it.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from apps.billing.invoice_models import ISSUER_BUILTIN

from .base import InvoiceIssuerGateway, get_invoice_issuer

if TYPE_CHECKING:
    from apps.billing.invoice_models import Invoice


class EFacturaProviderConflictError(RuntimeError):
    """Raised when something tries to file a document PRAHO does not own.

    This is a backstop, not a control-flow signal. Callers are expected to check
    `efactura_submission_denied_reason` first and decline cleanly; reaching this
    exception means a code path bypassed that check.
    """


def efactura_submission_denied_reason(invoice: Invoice) -> str | None:
    """Return why this invoice must not reach SPV from PRAHO, or None if it may.

    Returns a reason string rather than a bool so the caller can log, audit and
    surface *why* without restating the policy.
    """
    if invoice.issuer_provider != ISSUER_BUILTIN:
        return (
            f"e-Factura submission is owned by the issuing provider "
            f"({invoice.issuer_provider!r}); PRAHO must not file this document."
        )
    return None


def assert_efactura_submission_allowed(invoice: Invoice) -> None:
    """Fail closed immediately before an SPV-mutating call.

    Placed at the lowest boundary that still knows which invoice is being filed,
    so no caller — view, task, scheduled poller or signal — can route around it.
    """
    reason = efactura_submission_denied_reason(invoice)
    if reason is not None:
        raise EFacturaProviderConflictError(reason)


def resolve_issuer(invoice: Invoice) -> InvoiceIssuerGateway:
    """Return the gateway that owns this document.

    Resolved from the document's own stamped provenance, never from a global
    "current provider" setting. That is what lets a built-in invoice issued before
    a switch keep behaving like a built-in invoice forever.
    """
    return get_invoice_issuer(invoice.issuer_provider)
