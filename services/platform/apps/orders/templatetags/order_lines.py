"""Order-line template helpers."""

from __future__ import annotations

from typing import Any

from django import template

register = template.Library()


@register.simple_tag
def line_retry_refusal(item: Any) -> str:
    """Why a failed line can't be retried, or "" when it can: the rule retry_line_for_staff applies (read-only)."""
    from apps.orders.hosting_fulfilment import retry_refusal  # noqa: PLC0415  # Deferred: models import signals

    return retry_refusal(item) or ""
