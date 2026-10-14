"""Published legal documents, as registration tests need them."""

from __future__ import annotations

from django.utils import timezone

from apps.common.legal import LegalDocument, publish_legal_document
from apps.common.utils import operator_local_date


def publish_release(**overrides: object) -> LegalDocument:
    """A release in force from today: Terms of Service in English unless overridden."""
    values: dict[str, object] = {
        "kind": "terms",
        "language": "en",
        "effective_on": operator_local_date(timezone.now()),
        "body_markdown": "Sample terms, not legal text.",
        "published_by": None,
        **overrides,
    }
    return publish_legal_document(**values).unwrap()  # type: ignore[arg-type]  # Test values, checked by publish
