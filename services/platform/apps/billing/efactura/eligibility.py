"""Canonical Romanian e-Factura eligibility and classification rules."""

from __future__ import annotations

ANONYMOUS_B2C_BUYER_ID = "0000000000000"
ROMANIAN_PERSONAL_IDENTIFIER_LENGTH = 13


def _normalized_invoice_value(invoice: object, attribute: str) -> str:
    """Return a stripped invoice snapshot value without trusting external whitespace."""
    value = getattr(invoice, attribute, "")
    return str(value or "").strip()


def _is_personal_identifier(value: str) -> bool:
    """Return whether a normalized Romanian identifier has the 13-digit CNP shape."""
    return len(value) == ROMANIAN_PERSONAL_IDENTIFIER_LENGTH and value.isascii() and value.isdecimal()


def is_romanian_b2c(invoice: object) -> bool:
    """Return whether an invoice is for a Romanian consumer.

    Law 88/2026 keeps the transaction in B2C when a natural person elects to
    provide a CNP. Romanian company fiscal identifiers do not have 13 digits.
    """
    if _normalized_invoice_value(invoice, "bill_to_country").upper() != "RO":
        return False
    tax_id = _normalized_invoice_value(invoice, "bill_to_tax_id")
    return not tax_id or _is_personal_identifier(tax_id)


def requires_b2b_efactura(invoice: object) -> bool:
    """Return whether an invoice is a Romanian B2B e-Factura document.

    Romanian B2B eligibility has no amount threshold. Fiscal-document type
    exemptions must be modelled explicitly instead of inferred from the total.
    """
    if _normalized_invoice_value(invoice, "bill_to_country").upper() != "RO":
        return False
    tax_id = _normalized_invoice_value(invoice, "bill_to_tax_id")
    return bool(tax_id) and not _is_personal_identifier(tax_id)


def requires_efactura(invoice: object) -> bool:
    """Return whether PRAHO must report the invoice through RO e-Factura.

    Ordinary Romanian B2B and B2C invoices are mandatory regardless of total.
    Transaction-type exemptions must be modelled explicitly rather than exposed
    as rollout or amount settings.
    """
    return requires_b2b_efactura(invoice) or is_romanian_b2c(invoice)
