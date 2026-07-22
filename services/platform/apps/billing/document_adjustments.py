"""Validation for document adjustments not represented in PRAHO's ledger totals."""

from __future__ import annotations

from collections.abc import Iterable, Mapping


class UnsupportedDocumentAdjustmentError(ValueError):
    """Raised when a document contains adjustment data the ledger cannot reconcile."""


def validate_no_unsupported_adjustments(*, meta: object, line_discount_cents: Iterable[int]) -> None:
    """Reject adjustment sources that are not part of persisted document arithmetic."""
    if isinstance(meta, Mapping):
        if meta.get("allowances"):
            raise UnsupportedDocumentAdjustmentError(
                "Metadata-based document allowances are unsupported; use discount_cents."
            )
        if meta.get("charges"):
            raise UnsupportedDocumentAdjustmentError("Metadata-based document charges are unsupported.")

    if any(discount_cents != 0 for discount_cents in line_discount_cents):
        raise UnsupportedDocumentAdjustmentError(
            "Line-level discounts are unsupported; use the document discount_cents field."
        )
