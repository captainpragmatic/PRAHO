"""
Security-focused template tags for PRAHO Platform
Safe HTML rendering and XSS prevention utilities.
"""

from typing import Any

import bleach
from django import template
from django.utils.html import escape, format_html
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
        return ''

    # Allow only safe HTML tags
    allowed_tags = ['b', 'i', 'strong', 'em', 'u']
    allowed_attributes: dict[str, list[str]] = {}

    # Clean the HTML to prevent XSS
    cleaned = bleach.clean(
        str(value),
        tags=allowed_tags,
        attributes=allowed_attributes,
        strip=True
    )

    return mark_safe(cleaned)  # nosec B308 B703 - Input sanitized by bleach  # noqa: S308


@register.filter
def escape_message(value: Any) -> str:
    """
    Escape all HTML in messages for maximum security
    
    🔒 SECURITY: Escapes all HTML, use for untrusted content
    """
    if not value:
        return ''

    return escape(str(value))


@register.simple_tag
def secure_alert(message: Any, alert_type: str = 'info', dismissible: bool = True) -> str:
    """
    Render a secure alert component with escaped content
    
    🔒 SECURITY: All content is escaped to prevent XSS
    """
    escaped_message = escape(str(message))

    css_classes = {
        'success': 'bg-green-900 border-green-700 text-green-100',
        'error': 'bg-red-900 border-red-700 text-red-100',
        'warning': 'bg-yellow-900 border-yellow-700 text-yellow-100',
        'info': 'bg-blue-900 border-blue-700 text-blue-100'
    }

    class_str = css_classes.get(alert_type, css_classes['info'])

    dismiss_button = ''
    if dismissible:
        dismiss_button = '''
        <button type="button" class="ml-auto -mx-1.5 -my-1.5 text-current rounded-lg p-1.5 hover:bg-current hover:bg-opacity-20 inline-flex h-8 w-8" onclick="this.parentElement.remove()">
          <span class="sr-only">Close</span>
          <svg class="w-5 h-5" fill="currentColor" viewBox="0 0 20 20">
            <path fill-rule="evenodd" d="M4.293 4.293a1 1 0 011.414 0L10 8.586l4.293-4.293a1 1 0 111.414 1.414L11.414 10l4.293 4.293a1 1 0 01-1.414 1.414L10 11.414l-4.293 4.293a1 1 0 01-1.414-1.414L8.586 10 4.293 5.707a1 1 0 010-1.414z" clip-rule="evenodd"></path>
          </svg>
        </button>
        '''

    return format_html(
        '''
        <div class="flex p-4 mb-4 border rounded-lg {}" role="alert">
          <div class="text-sm">{}</div>
          {}
        </div>
        ''',
        class_str,
        escaped_message,
        mark_safe(dismiss_button)  # nosec B308 - Static HTML button, no user input  # noqa: S308
    )
