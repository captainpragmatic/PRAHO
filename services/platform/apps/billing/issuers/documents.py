"""Where an invoice PDF comes from.

One chokepoint, because there are now two answers and the wrong one is subtly bad.
A locally-issued invoice is rendered by PRAHO. An externally-issued one must show
the provider's own PDF: that is the document the customer receives, the one the
accountant sees, and the one behind whatever reached ANAF. Rendering our own
version of it would be a second, unofficial rendering of a legal document that
could differ in layout or rounding from the real one.

The provider's PDF is fetched once and stored. Fetching on every download would
spend the rate-limited token on something that never changes, and would make the
customer portal depend on a third party being up.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from django.core.files.base import ContentFile
from django.db import transaction

from apps.billing.invoice_models import ISSUER_BUILTIN
from apps.common.types import Err, Ok, Result

if TYPE_CHECKING:
    from apps.billing.invoice_models import Invoice

logger = logging.getLogger(__name__)


class DocumentDeferred(Exception):  # noqa: N818  # Not an error: a scheduling instruction
    """The provider's pacing gate deferred this fetch.

    Distinct from a failure so a caller can retry later rather than telling the
    customer their invoice is unavailable. Raised rather than returned because the
    right response differs per caller: an API answers 503 with Retry-After, a queued
    email job reschedules itself.
    """

    def __init__(self, retry_at: object) -> None:
        super().__init__(f"Document fetch deferred until {retry_at}")
        self.retry_at = retry_at


def get_invoice_pdf_bytes(invoice: Invoice) -> Result[bytes, str]:
    """Return the authoritative PDF for this invoice.

    Order matters: stored bytes first, because a provider-issued document is the
    archived rendition of a legal document and must not silently change underneath
    a customer who already downloaded it. If a provider ever amends one, replacing
    the archived copy has to be a deliberate, recorded act rather than a side effect
    of someone clicking download.

    Raises `DocumentDeferred` when the provider gate defers the fetch.
    """
    if invoice.pdf_file and _may_deliver(invoice):
        try:
            with invoice.pdf_file.open("rb") as handle:
                return Ok(handle.read())
        except (OSError, ValueError) as exc:
            # Fall through and re-fetch rather than failing the customer's download.
            logger.warning(f"⚠️ [Documents] Stored PDF unreadable for invoice {invoice.pk}: {exc}")

    if invoice.issuer_provider == ISSUER_BUILTIN:
        from apps.billing.pdf_generators import generate_invoice_pdf  # noqa: PLC0415

        return Ok(generate_invoice_pdf(invoice))

    return _fetch_and_store_provider_pdf(invoice)


def _may_deliver(invoice: Invoice) -> bool:
    """Whether a stored file may be served as this invoice's document.

    Checked even on a cache hit: a stored file on an invoice whose provider never
    confirmed issuance would otherwise be served as a legal document on the strength
    of the bytes existing.
    """
    if invoice.issuer_provider == ISSUER_BUILTIN:
        return True
    issuance = getattr(invoice, "provider_issuance", None)
    return bool(issuance and issuance.provider_number)


def _fetch_and_store_provider_pdf(invoice: Invoice) -> Result[bytes, str]:
    """Fetch the provider's rendering once and keep it."""
    from apps.billing.invoice_models import Invoice as InvoiceModel  # noqa: PLC0415

    from .smartbill.client import RateGateWait  # noqa: PLC0415
    from .smartbill.issuer import SmartBillIssuer  # noqa: PLC0415

    issuance = getattr(invoice, "provider_issuance", None)
    if issuance is None or not issuance.provider_number:
        return Err("This invoice has not been issued by its provider yet")

    try:
        fetched = SmartBillIssuer().fetch_pdf(issuance.provider_series, issuance.provider_number)
    except RateGateWait as deferred:
        # Translated, not swallowed: a paced fetch is not an unavailable document,
        # and the caller decides whether to answer 503 or reschedule itself.
        raise DocumentDeferred(deferred.available_at) from deferred

    if isinstance(fetched, Err):
        return fetched
    content = fetched.unwrap()

    # Two downloads can race here, each having seen an empty cache. Re-read under a
    # lock and defer to whoever published first: one archived rendition per document,
    # and the loser's bytes are identical anyway.
    with transaction.atomic():
        current = InvoiceModel.objects.select_for_update().get(pk=invoice.pk)
        if current.pdf_file:
            logger.info(f"📄 [Documents] Another worker already stored the PDF for {current.number}")
            with current.pdf_file.open("rb") as handle:
                return Ok(handle.read())

        # `pdf_file` is not a locked fiscal-snapshot field, so this is legal on an
        # already-issued invoice — but it must go through save(update_fields=...),
        # because InvoiceQuerySet.update() refuses to touch a locked row at all.
        current.pdf_file.save(f"invoice_{current.number}.pdf", ContentFile(content), save=False)
        current.save(update_fields=["pdf_file"])

    logger.info(f"📄 [Documents] Stored provider PDF for invoice {invoice.number}")
    return Ok(content)
