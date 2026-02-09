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

from apps.common import validators
from apps.notifications.models import validate_template_content

if TYPE_CHECKING:
    from apps.billing.models import Invoice

logger = logging.getLogger(__name__)

# Security constants
MAX_CONTEXT_VALUE_LENGTH = 1000  # Maximum length for template context values


# ===============================================================================
# VALIDATION FUNCTIONS
# ===============================================================================


def validate_template_context(context: dict[str, Any]) -> dict[str, Any]:
    """🔒 Validate template context for security"""
    if not context:
        return context

    # Check for dangerous keys that shouldn't be in templates
    dangerous_keys = [
        "__builtins__",
        "eval",
        "exec",
        "import",
        "password",
        "api_key",
        "token",
        "private_data",  # Sensitive data keys
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
            # Enforce per-value size limit
            if len(cleaned_value) > MAX_CONTEXT_VALUE_LENGTH:
                cleaned_value = cleaned_value[:MAX_CONTEXT_VALUE_LENGTH]
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
    for v in original_context.values():
        if isinstance(v, str) and len(v) > MAX_CONTEXT_VALUE_LENGTH:
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
    Handles sending emails for invoices, payments, and other notifications.
    """

    @staticmethod
    def _send_email(recipient: str, subject: str, body: str, html_body: str | None = None) -> bool:
        """Internal method to send email using Django's email backend."""
        from django.conf import settings  # noqa: PLC0415
        from django.core.mail import EmailMultiAlternatives  # noqa: PLC0415

        try:
            from_email = getattr(settings, "DEFAULT_FROM_EMAIL", "noreply@praho.io")

            email = EmailMultiAlternatives(
                subject=subject,
                body=body,
                from_email=from_email,
                to=[recipient],
            )

            if html_body:
                email.attach_alternative(html_body, "text/html")

            email.send(fail_silently=False)
            logger.info(f"📧 [Email] Successfully sent email to {recipient}: {subject}")
            return True

        except Exception as e:
            logger.error(f"🔥 [Email] Failed to send email to {recipient}: {e}")
            return False

    @staticmethod
    def send_invoice_created(invoice: Invoice) -> bool:
        """Send invoice created notification"""
        from django.conf import settings  # noqa: PLC0415

        recipient = invoice.bill_to_email
        if not recipient:
            logger.warning(f"⚠️ [Email] No recipient for invoice {invoice.number}")
            return False

        subject = f"New Invoice {invoice.number} from {getattr(settings, 'COMPANY_NAME', 'PRAHO Platform')}"
        body = f"""Dear Customer,

A new invoice has been created for your account.

Invoice Details:
- Invoice Number: {invoice.number}
- Amount: €{invoice.total_cents / 100:.2f}
- Due Date: {invoice.due_date.strftime('%Y-%m-%d') if hasattr(invoice, 'due_date') and invoice.due_date else 'N/A'}

Please log in to your account to view and pay this invoice.

Best regards,
{getattr(settings, 'COMPANY_NAME', 'PRAHO Platform')}
"""

        result = EmailService._send_email(recipient, subject, body)
        logger.info(f"📧 [Email] Invoice created email for {invoice.number} to {recipient}: {'sent' if result else 'failed'}")
        return result

    @staticmethod
    def send_invoice_paid(invoice: Invoice) -> bool:
        """Send invoice paid notification"""
        from django.conf import settings  # noqa: PLC0415

        recipient = invoice.bill_to_email
        if not recipient:
            logger.warning(f"⚠️ [Email] No recipient for invoice {invoice.number}")
            return False

        subject = f"Payment Received - Invoice {invoice.number}"
        body = f"""Dear Customer,

We have received your payment for invoice {invoice.number}.

Invoice Details:
- Invoice Number: {invoice.number}
- Amount Paid: €{invoice.total_cents / 100:.2f}

Thank you for your payment!

Best regards,
{getattr(settings, 'COMPANY_NAME', 'PRAHO Platform')}
"""

        result = EmailService._send_email(recipient, subject, body)
        logger.info(f"📧 [Email] Invoice paid email for {invoice.number} to {recipient}: {'sent' if result else 'failed'}")
        return result

    @staticmethod
    def send_payment_reminder(invoice: Invoice) -> bool:
        """Send payment reminder"""
        from django.conf import settings  # noqa: PLC0415

        recipient = invoice.bill_to_email
        if not recipient:
            logger.warning(f"⚠️ [Email] No recipient for invoice {invoice.number}")
            return False

        subject = f"Payment Reminder - Invoice {invoice.number}"
        body = f"""Dear Customer,

This is a reminder that invoice {invoice.number} is awaiting payment.

Invoice Details:
- Invoice Number: {invoice.number}
- Amount Due: €{invoice.total_cents / 100:.2f}
- Due Date: {invoice.due_date.strftime('%Y-%m-%d') if hasattr(invoice, 'due_date') and invoice.due_date else 'N/A'}

Please log in to your account to make a payment at your earliest convenience.

If you have already made this payment, please disregard this reminder.

Best regards,
{getattr(settings, 'COMPANY_NAME', 'PRAHO Platform')}
"""

        result = EmailService._send_email(recipient, subject, body)
        logger.info(f"📧 [Email] Payment reminder for {invoice.number} to {recipient}: {'sent' if result else 'failed'}")
        return result

    @staticmethod
    def send_template_email(template_key: str, recipient: str, context: dict[str, Any], **kwargs: Any) -> bool:
        """Send templated email"""
        from apps.notifications.models import EmailTemplate  # noqa: PLC0415

        # Security monitoring hook
        try:
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
        except Exception as e:  # pragma: no cover
            logger.debug(f"Failed to log email attempt: {e}")

        try:
            # Get template from database
            template = EmailTemplate.objects.filter(key=template_key, is_active=True).first()

            if not template:
                logger.warning(f"⚠️ [Email] Template not found: {template_key}")
                return False

            # Render template with context
            subject = render_template_safely(template.subject, context)
            body = render_template_safely(template.body, context)
            html_body = render_template_safely(template.html_body, context) if template.html_body else None

            result = EmailService._send_email(recipient, subject, body, html_body)
            logger.info(f"📧 [Email] Template email {template_key} to {recipient}: {'sent' if result else 'failed'}")
            return result

        except Exception as e:
            logger.error(f"🔥 [Email] Failed to send template email {template_key}: {e}")
            return False

    @staticmethod
    def get_safe_email_preview(template_content: str, context: dict[str, Any]) -> str:
        """Render a preview safely and truncate for UI display."""
        rendered = render_template_safely(template_content, context)
        preview_limit = 500
        if len(rendered) > preview_limit:
            return rendered[:preview_limit] + "...[preview truncated]"
        return rendered


# ===============================================================================
# NOTIFICATION SERVICE (ORCHESTRATOR)
# ===============================================================================


class NotificationService:
    """
    Central notification service for sending alerts and notifications.
    Coordinates between email, SMS, and other notification channels.
    """

    @staticmethod
    def send_admin_alert(
        subject: str,
        message: str,
        alert_type: str = "info",
        metadata: dict[str, Any] | None = None,
    ) -> bool:
        """
        Send urgent notification to admin.

        Args:
            subject: Email subject
            message: Email body
            alert_type: Type of alert ('info', 'warning', 'critical', 'dispute')
            metadata: Additional context data

        Returns:
            True if notification was sent successfully
        """
        from django.conf import settings  # noqa: PLC0415

        try:
            admin_emails = getattr(settings, "ADMIN_ALERT_EMAILS", None)
            if not admin_emails:
                # Fall back to ADMINS setting
                admins = getattr(settings, "ADMINS", [])
                admin_emails = [email for name, email in admins] if admins else []

            if not admin_emails:
                logger.warning("⚠️ [Notification] No admin email configured for alerts")
                return False

            # Format subject with alert type prefix
            type_prefixes = {
                "info": "[INFO]",
                "warning": "[WARNING]",
                "critical": "[CRITICAL]",
                "dispute": "[DISPUTE]",
            }
            prefix = type_prefixes.get(alert_type, "[ALERT]")
            full_subject = f"{prefix} {subject}"

            # Build email body
            body = f"{message}\n\n"
            if metadata:
                body += "Additional Details:\n"
                for key, value in metadata.items():
                    body += f"- {key}: {value}\n"

            # Send to all admin emails
            success_count = 0
            for admin_email in admin_emails:
                if EmailService._send_email(admin_email, full_subject, body):
                    success_count += 1

            logger.info(
                f"🔔 [Notification] Admin alert sent to {success_count}/{len(admin_emails)} recipients: {subject}"
            )
            return success_count > 0

        except Exception as e:
            logger.error(f"🔥 [Notification] Failed to send admin alert: {e}")
            return False

    @staticmethod
    def send_customer_notification(
        customer_id: str,
        notification_type: str,
        context: dict[str, Any],
    ) -> bool:
        """
        Send notification to a customer.

        Args:
            customer_id: Customer UUID
            notification_type: Type of notification (maps to template key)
            context: Template context

        Returns:
            True if notification was sent successfully
        """
        from apps.customers.models import Customer  # noqa: PLC0415

        try:
            customer = Customer.objects.get(id=customer_id)
            recipient = customer.primary_email

            if not recipient:
                logger.warning(f"⚠️ [Notification] No email for customer {customer_id}")
                return False

            return EmailService.send_template_email(notification_type, recipient, context)

        except Customer.DoesNotExist:
            logger.warning(f"⚠️ [Notification] Customer not found: {customer_id}")
            return False
        except Exception as e:
            logger.error(f"🔥 [Notification] Failed to send customer notification: {e}")
            return False
