"""The consents an order request carries, for tests about something else (apps.orders.checkout_consents)."""

from __future__ import annotations

from apps.common.legal import LegalDocument, current_legal_document
from tests.helpers.legal import publish_release


def checkout_consents() -> dict[str, object]:
    """Accept the Terms of Service release in force, publishing one if none is, and ask for an early start."""
    terms = current_legal_document(LegalDocument.Kind.TERMS, "en") or publish_release()
    return {"terms_document_id": str(terms.pk), "early_start_requested": True}
