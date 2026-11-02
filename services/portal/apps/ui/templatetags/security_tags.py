"""
Security-focused template tags for PRAHO Platform
Safe HTML rendering and XSS prevention utilities.
"""

from typing import Any

import bleach
from django import template
from django.utils.html import escape
from django.utils.safestring import mark_safe

register = template.Library()


@register.filter
def safe_message(value: Any) -> str:
    """
    Safely render messages with basic HTML support

    🔒 SECURITY: Only allows safe HTML tags, prevents XSS
    Use this instead of |safe for user-generated content
    """
    if not value:
        return ""

    # Allow only safe HTML tags
    allowed_tags = ["b", "i", "strong", "em", "u"]
    allowed_attributes: dict[str, list[str]] = {}

    # Clean the HTML to prevent XSS
    cleaned = bleach.clean(str(value), tags=allowed_tags, attributes=allowed_attributes, strip=True)

    return mark_safe(cleaned)  # nosec B308 B703 - Input sanitized by bleach  # noqa: S308  # nosemgrep: avoid-mark-safe — content sanitized by bleach/escape before mark_safe


@register.filter
def escape_message(value: Any) -> str:
    """
    Escape all HTML in messages for maximum security

    🔒 SECURITY: Escapes all HTML, use for untrusted content
    """
    if not value:
        return ""

    return escape(str(value))
