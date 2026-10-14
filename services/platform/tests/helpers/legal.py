"""Published legal documents and the portal origin, as registration tests need them."""

from __future__ import annotations

from django.core.cache import cache
from django.utils import timezone

from apps.common.legal import LegalDocument, publish_legal_document
from apps.common.utils import operator_local_date
from apps.settings.models import SystemSetting


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


def set_portal_origin(origin: str) -> None:
    """The portal origin links and redirects point at; blank leaves it unset."""
    SystemSetting.objects.update_or_create(
        key="portal.public_base_url",
        defaults={
            "name": "Portal URL",
            "category": "platform",
            "data_type": "string",
            "value": origin,
            "default_value": "",
        },
    )
    cache.clear()
