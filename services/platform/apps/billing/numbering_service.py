"""Atomic invoice-number resolution."""

from __future__ import annotations

from django.core.exceptions import ImproperlyConfigured
from django.db import transaction

from .invoice_models import SEQUENCE_FAMILIES, InvoiceSequence


class InvoiceNumberingService:
    """Resolve and lock the configured active sequence before consuming a number."""

    @staticmethod
    @transaction.atomic
    def get_next_number(*, scope: str = "default") -> str:
        if scope not in SEQUENCE_FAMILIES:
            raise ValueError(f"Unknown invoice sequence family: {scope}")
        try:
            sequence = InvoiceSequence.objects.select_for_update().get(scope=scope)
        except InvoiceSequence.DoesNotExist as error:
            raise ImproperlyConfigured(
                f"Invoice sequence family {scope!r} is missing; repair its configuration before issuing"
            ) from error
        return sequence.get_next_number()
