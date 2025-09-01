"""
Notification Services for PRAHO Platform
Handles email notifications, template management, and delivery tracking.
"""

from __future__ import annotations

import logging
import re
from typing import TYPE_CHECKING, Any

from django.core.exceptions import ValidationError as DjangoValidationError
from django.utils.html import strip_tags

from apps.notifications.models import validate_template_content

if TYPE_CHECKING:
    from apps.billing.models import Invoice

logger = logging.getLogger(__name__)


# ===============================================================================
# VALIDATION FUNCTIONS
# ===============================================================================

def validate_template_context(context: dict[str, Any]) -> dict[str, Any]:
    """🔒 Validate template context for security"""
    if not context:
        return context
    
    # Check for dangerous keys that shouldn't be in templates
    dangerous_keys = [
        '__builtins__', 'eval', 'exec', 'import',
        'password', 'api_key', 'token', 'private_data'  # Sensitive data keys
    ]
    for key in context:
        if key in dangerous_keys:
            raise DjangoValidationError("Template context contains sensitive information")
    
    # Do not hard-fail on overall context size; enforce limits per value
    
    # Sanitize XSS in context values
    sanitized_context = {}
    for key, value in context.items():
        if isinstance(value, str):
            # Strip HTML tags to prevent XSS and truncate if too long
            cleaned_value = strip_tags(value)
            # Remove common XSS patterns that might remain after tag stripping
            xss_patterns = [
                r"javascript:",
                r"vbscript:",
                r"on\w+\s*=",  # inline event handlers like onerror=, onclick=
            ]
            for pattern in xss_patterns:
                cleaned_value = re.sub(pattern, "", cleaned_value, flags=re.IGNORECASE)
            # Remove alert('...') payloads entirely
            cleaned_value = re.sub(r"alert\s*\([^)]*\)", "", cleaned_value, flags=re.IGNORECASE)
            # Enforce per-value size limit of 1000 characters
            if len(cleaned_value) > 1000:
                cleaned_value = cleaned_value[:1000]
            sanitized_context[key] = cleaned_value
        else:
            sanitized_context[key] = value
    
    return sanitized_context


def render_template_safely(template_content: str, context: dict[str, Any]) -> str:
    """🔒 Render template with security validation"""
    # Validate template content first
    validate_template_content(template_content)
    
    # Validate and sanitize context
    # Track if any values were truncated by validation to append marker
    value_truncated = False
    original_context = dict(context)
    sanitized_context = validate_template_context(context)
    for _k, v in original_context.items():
        if isinstance(v, str) and len(v) > 1000:
            value_truncated = True
    
    # Simple template rendering (placeholder implementation)
    # In production, this would use Django's template engine with safety checks
    rendered = template_content
    for key, value in sanitized_context.items():
        # Handle both {{ key }} and {{key}} patterns
        rendered = rendered.replace(f"{{{{ {key} }}}}", str(value))
        rendered = rendered.replace(f"{{{{{key}}}}}", str(value))

    # Enforce output size limit (500KB) to prevent DoS; append marker
    limit = 500_000
    trunc_mark = "[truncated]"
    if len(rendered) > limit:
        keep = max(0, limit - len(trunc_mark))
        rendered = rendered[:keep] + trunc_mark
    elif value_truncated and trunc_mark not in rendered:
        # If inputs were truncated during validation, surface this in output as a marker
        rendered = f"{rendered}{trunc_mark}"

    return rendered


# ===============================================================================
# EMAIL SERVICE
# ===============================================================================


class EmailService:
    """
    Email notification service.
    Placeholder implementation for signal compatibility.
    """

    @staticmethod
    def send_invoice_created(invoice: Invoice) -> None:
        """Send invoice created notification"""
        logger.info(f"📧 [Email] Would send invoice created email for {invoice.number} to {invoice.bill_to_email}")
        # TODO: Implement actual email sending

    @staticmethod
    def send_invoice_paid(invoice: Invoice) -> None:
        """Send invoice paid notification"""
        logger.info(f"📧 [Email] Would send invoice paid email for {invoice.number} to {invoice.bill_to_email}")
        # TODO: Implement actual email sending

    @staticmethod
    def send_payment_reminder(invoice: Invoice) -> None:
        """Send payment reminder"""
        logger.info(f"📧 [Email] Would send payment reminder for {invoice.number} to {invoice.bill_to_email}")
        # TODO: Implement actual email sending

    @staticmethod
    def send_template_email(template_key: str, recipient: str, context: dict[str, Any], **kwargs: Any) -> bool:
        """Send templated email"""
        logger.info(
            f"📧 [Email] Would send {template_key} email to {recipient} with context keys: {list(context.keys())}"
        )

        # Security monitoring hook
        try:
            from apps.common import validators

            recipient_domain = recipient.split("@")[-1] if "@" in recipient else ""
            validators.log_security_event(
                event_type="template_email_send",
                details={
                    "template_key": template_key,
                    "recipient_domain": recipient_domain,
                    "context_keys": list(context.keys()),
                },
                request_ip=kwargs.get("request_ip"),
            )
        except Exception:  # pragma: no cover
            pass

        # TODO: Implement template-based email sending
        return True

    @staticmethod
    def get_safe_email_preview(template_content: str, context: dict[str, Any]) -> str:
        """Render a preview safely and truncate for UI display."""
        rendered = render_template_safely(template_content, context)
        preview_limit = 500
        if len(rendered) > preview_limit:
            return rendered[:preview_limit] + "...[preview truncated]"
        return rendered
