"""
Notification Services for PRAHO Platform
Comprehensive email notification system with multi-provider support, delivery tracking,
bounce handling, and Romanian compliance.

Features:
- Multi-provider email sending (AWS SES, SendGrid, Mailgun, SMTP)
- Database-driven email templates with localization (EN/RO)
- Email logging and delivery tracking
- Bounce and complaint handling with automatic suppression
- Rate limiting and throttling
- Async email sending via Django-Q2
- Audit logging integration
- GDPR-compliant unsubscribe management
"""

from __future__ import annotations

import hashlib
import logging
import re
from dataclasses import dataclass
from datetime import timedelta
from typing import TYPE_CHECKING, Any

from django.conf import settings
from django.core.cache import cache
from django.core.exceptions import ValidationError as DjangoValidationError
from django.core.mail import EmailMessage, EmailMultiAlternatives
from django.db import transaction
from django.template import Context, Template
from django.utils import timezone
from django.utils.html import strip_tags

from apps.common import validators
from apps.notifications.models import (
    EmailCampaign,
    EmailLog,
    EmailTemplate,
    validate_template_content,
)
from apps.settings.services import SettingsService

if TYPE_CHECKING:
    from apps.billing.models import Invoice
    from apps.customers.models import Customer
    from apps.users.models import User

logger = logging.getLogger(__name__)

# Security constants
MAX_CONTEXT_VALUE_LENGTH = 1000  # Maximum length for template context values
_DEFAULT_MAX_RECIPIENTS_PER_BATCH = 50  # Maximum recipients per batch send
TEMPLATE_CACHE_PREFIX = "email_template:"
TEMPLATE_CACHE_TIMEOUT = 3600  # 1 hour
SUPPRESSION_CACHE_PREFIX = "email_suppressed:"
RATE_LIMIT_CACHE_PREFIX = "email_rate:"


# ===============================================================================
# DATA CLASSES
# ===============================================================================


@dataclass
class EmailResult:
    """Result of an email sending operation."""

    success: bool
    message_id: str | None = None
    email_log_id: str | None = None
    error: str | None = None
    provider: str | None = None


# ===============================================================================
# VALIDATION FUNCTIONS
# ===============================================================================


def validate_template_context(context: dict[str, Any]) -> dict[str, Any]:
    """Validate template context for security."""
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
    """Render template with security validation."""
    # Validate template content first
    validate_template_content(template_content)

    # Validate and sanitize context
    value_truncated = False
    original_context = dict(context)
    sanitized_context = validate_template_context(context)
    for v in original_context.values():
        if isinstance(v, str) and len(v) > MAX_CONTEXT_VALUE_LENGTH:
            value_truncated = True

    # Use Django's template engine for rendering
    try:
        template = Template(template_content)
        rendered = template.render(Context(sanitized_context))
    except Exception as e:
        logger.error(f"Template rendering error: {e}")
        # Fallback to simple string replacement
        rendered = template_content
        for key, value in sanitized_context.items():
            rendered = rendered.replace(f"{{{{ {key} }}}}", str(value))
            rendered = rendered.replace(f"{{{{{key}}}}}", str(value))

    # Enforce output size limit (500KB) to prevent DoS
    limit = 500_000
    trunc_mark = "[truncated]"
    if len(rendered) > limit:
        keep = max(0, limit - len(trunc_mark))
        rendered = rendered[:keep] + trunc_mark
    elif value_truncated and trunc_mark not in rendered:
        rendered = f"{rendered}{trunc_mark}"

    return rendered


# ===============================================================================
# EMAIL SUPPRESSION SERVICE
# ===============================================================================


class EmailSuppressionService:
    """
    Manage email suppression list for bounced/complained addresses.
    Uses database as source of truth with cache as read-through layer.
    Prevents sending to addresses that have bounced or complained.
    """

    # Cache timeout for suppression lookups (5 minutes)
    CACHE_TIMEOUT = 300

    @classmethod
    def is_suppressed(cls, email: str) -> bool:
        """
        Check if an email address is suppressed.
        Uses cache with database fallback.
        """
        email_hash = hashlib.sha256(email.lower().encode()).hexdigest()
        cache_key = f"{SUPPRESSION_CACHE_PREFIX}{email_hash}"

        # Check cache first
        cached = cache.get(cache_key)
        if cached is not None:
            return cached  # Returns True or False

        # Check database
        from apps.notifications.models import EmailSuppression

        is_suppressed = EmailSuppression.is_suppressed(email)

        # Cache the result (both positive and negative)
        cache.set(cache_key, is_suppressed, timeout=cls.CACHE_TIMEOUT)

        return is_suppressed

    @classmethod
    def suppress_email(cls, email: str, reason: str, duration_days: int | None = None) -> None:
        """
        Add an email to the suppression list.

        Args:
            email: Email address to suppress
            reason: Reason for suppression (bounce, complaint, unsubscribe)
            duration_days: How long to suppress (None = permanent)
        """
        from apps.notifications.models import EmailSuppression

        # Persist to database (source of truth)
        EmailSuppression.suppress(
            email=email,
            reason=reason,
            provider=getattr(settings, "EMAIL_PROVIDER", "smtp"),
            expires_days=duration_days,
        )

        # Update cache
        email_hash = hashlib.sha256(email.lower().encode()).hexdigest()
        cache_key = f"{SUPPRESSION_CACHE_PREFIX}{email_hash}"
        cache.set(cache_key, True, timeout=cls.CACHE_TIMEOUT)

        logger.info(f"Email suppressed: {email[:3]}***@*** - reason: {reason}")

        # Log security event
        validators.log_security_event(
            "email_suppressed",
            {"email_hash": email_hash, "reason": reason},
        )

    @classmethod
    def unsuppress_email(cls, email: str) -> bool:
        """Remove an email from the suppression list."""
        from apps.notifications.models import EmailSuppression

        email_hash = hashlib.sha256(email.lower().encode()).hexdigest()

        # Delete from database
        deleted_count, _ = EmailSuppression.objects.filter(email_hash=email_hash).delete()

        # Invalidate cache
        cache_key = f"{SUPPRESSION_CACHE_PREFIX}{email_hash}"
        cache.delete(cache_key)

        return deleted_count > 0


# ===============================================================================
# EMAIL RATE LIMITING
# ===============================================================================


class EmailRateLimiter:
    """Rate limiting for email sending to prevent abuse and stay within ESP limits."""

    @staticmethod
    def check_rate_limit(identifier: str = "global") -> tuple[bool, int]:
        """
        Check if rate limit allows sending.

        Returns:
            Tuple of (allowed: bool, remaining: int)
        """
        rate_config = getattr(settings, "EMAIL_RATE_LIMIT", {})
        max_per_minute = rate_config.get("MAX_PER_MINUTE", 50)

        cache_key = f"{RATE_LIMIT_CACHE_PREFIX}{identifier}:{timezone.now().strftime('%Y%m%d%H%M')}"
        current_count = cache.get(cache_key, 0)

        allowed = current_count < max_per_minute
        remaining = max(0, max_per_minute - current_count)

        return allowed, remaining

    @staticmethod
    def increment_counter(identifier: str = "global") -> int:
        """
        Increment the rate limit counter atomically.

        Returns the new count after incrementing.
        """
        cache_key = f"{RATE_LIMIT_CACHE_PREFIX}{identifier}:{timezone.now().strftime('%Y%m%d%H%M')}"

        # Use add() to atomically create the key if it doesn't exist
        # add() returns True if key was created, False if it already exists
        if cache.add(cache_key, 0, timeout=120):
            # Key was just created, now we can safely incr from 0
            pass

        try:
            return cache.incr(cache_key)
        except ValueError:
            # Fallback: key expired between add and incr (very rare race)
            cache.set(cache_key, 1, timeout=120)
            return 1


# ===============================================================================
# EMAIL SERVICE
# ===============================================================================


class EmailService:
    """
    Comprehensive email notification service.

    Features:
    - Multi-provider email sending (AWS SES, SendGrid, Mailgun, SMTP)
    - Database-driven templates with localization
    - Delivery tracking and logging
    - Bounce/complaint handling
    - Rate limiting
    - Async support via Django-Q2
    - Simple fallback methods for direct email sending
    """

    # ===============================================================================
    # SIMPLE EMAIL SENDING (FALLBACK)
    # ===============================================================================

    @staticmethod
    def _send_email(recipient: str, subject: str, body: str, html_body: str | None = None) -> bool:
        """Internal method to send email using Django's email backend."""
        from django.conf import settings  # noqa: PLC0415
        from django.core.mail import EmailMultiAlternatives  # noqa: PLC0415

        try:
            from_email = getattr(settings, "DEFAULT_FROM_EMAIL", None) or SettingsService.get_setting(
                "company.email_noreply", "noreply@pragmatichost.com"
            )

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

    # ===============================================================================
    # CORE EMAIL SENDING
    # ===============================================================================

    @classmethod
    def send_email(
        cls,
        to: str | list[str],
        subject: str,
        body_text: str,
        body_html: str | None = None,
        from_email: str | None = None,
        reply_to: str | None = None,
        cc: list[str] | None = None,
        bcc: list[str] | None = None,
        attachments: list[tuple[str, bytes, str]] | None = None,
        customer: Customer | None = None,
        sent_by: User | None = None,
        template_key: str | None = None,
        priority: str = "normal",
        tags: dict[str, str] | None = None,
        track_opens: bool = True,
        track_clicks: bool = True,
        async_send: bool = True,
    ) -> EmailResult:
        """
        Send an email with full tracking and logging.

        Args:
            to: Recipient email(s)
            subject: Email subject
            body_text: Plain text body
            body_html: HTML body (optional)
            from_email: Sender email (defaults to DEFAULT_FROM_EMAIL)
            reply_to: Reply-to address
            cc: CC recipients
            bcc: BCC recipients
            attachments: List of (filename, content, mimetype) tuples
            customer: Associated customer for logging
            sent_by: User who triggered the send
            template_key: Template key for logging
            priority: Email priority (low, normal, high, urgent)
            tags: ESP-specific metadata tags
            track_opens: Enable open tracking
            track_clicks: Enable click tracking
            async_send: Send asynchronously via Django-Q2

        Returns:
            EmailResult with success status and message ID
        """
        # Normalize recipients
        recipients = [to] if isinstance(to, str) else to

        # Check for suppressed addresses
        active_recipients = []
        for recipient in recipients:
            if EmailSuppressionService.is_suppressed(recipient):
                logger.info(f"Skipping suppressed email: {recipient[:3]}***")
            else:
                active_recipients.append(recipient)

        if not active_recipients:
            return EmailResult(
                success=False,
                error="All recipients are suppressed",
            )

        # Check rate limit
        allowed, remaining = EmailRateLimiter.check_rate_limit()
        if not allowed:
            logger.warning("Email rate limit exceeded")
            if async_send:
                # Queue for later sending
                return cls._queue_email_for_retry(
                    to=active_recipients,
                    subject=subject,
                    body_text=body_text,
                    body_html=body_html,
                    from_email=from_email,
                    reply_to=reply_to,
                    customer=customer,
                    sent_by=sent_by,
                    template_key=template_key,
                    priority=priority,
                )
            return EmailResult(
                success=False,
                error="Rate limit exceeded",
            )

        # Send asynchronously if requested
        if async_send:
            return cls._send_async(
                to=active_recipients,
                subject=subject,
                body_text=body_text,
                body_html=body_html,
                from_email=from_email,
                reply_to=reply_to,
                cc=cc,
                bcc=bcc,
                attachments=attachments,
                customer=customer,
                sent_by=sent_by,
                template_key=template_key,
                priority=priority,
                tags=tags,
                track_opens=track_opens,
                track_clicks=track_clicks,
            )

        # Synchronous sending
        return cls._send_now(
            to=active_recipients,
            subject=subject,
            body_text=body_text,
            body_html=body_html,
            from_email=from_email,
            reply_to=reply_to,
            cc=cc,
            bcc=bcc,
            attachments=attachments,
            customer=customer,
            sent_by=sent_by,
            template_key=template_key,
            priority=priority,
            tags=tags,
            track_opens=track_opens,
            track_clicks=track_clicks,
        )

    @classmethod
    def _send_now(
        cls,
        to: list[str],
        subject: str,
        body_text: str,
        body_html: str | None = None,
        from_email: str | None = None,
        reply_to: str | None = None,
        cc: list[str] | None = None,
        bcc: list[str] | None = None,
        attachments: list[tuple[str, bytes, str]] | None = None,
        customer: Customer | None = None,
        sent_by: User | None = None,
        template_key: str | None = None,
        priority: str = "normal",
        tags: dict[str, str] | None = None,
        track_opens: bool = True,
        track_clicks: bool = True,
    ) -> EmailResult:
        """Send email synchronously."""
        from_email = from_email or settings.DEFAULT_FROM_EMAIL
        provider = getattr(settings, "EMAIL_PROVIDER", "smtp")

        # Create email log entry
        email_log = cls._create_email_log(
            to=to[0],  # Primary recipient
            from_addr=from_email,
            reply_to=reply_to or "",
            subject=subject,
            body_text=body_text,
            body_html=body_html or "",
            template_key=template_key or "",
            customer=customer,
            sent_by=sent_by,
            priority=priority,
            provider=provider,
        )

        try:
            # Build email message
            if body_html:
                msg = EmailMultiAlternatives(
                    subject=subject,
                    body=body_text,
                    from_email=from_email,
                    to=to,
                    cc=cc,
                    bcc=bcc,
                    reply_to=[reply_to] if reply_to else None,
                )
                msg.attach_alternative(body_html, "text/html")
            else:
                msg = EmailMessage(
                    subject=subject,
                    body=body_text,
                    from_email=from_email,
                    to=to,
                    cc=cc,
                    bcc=bcc,
                    reply_to=[reply_to] if reply_to else None,
                )

            # Add attachments
            if attachments:
                for filename, content, mimetype in attachments:
                    msg.attach(filename, content, mimetype)

            # Add ESP-specific metadata for Anymail
            # These attributes are supported when using Anymail backends
            # and silently ignored with standard Django email backends
            try:
                if tags:
                    msg.tags = list(tags.keys())
                    msg.metadata = tags
                msg.track_opens = track_opens
                msg.track_clicks = track_clicks
            except AttributeError:
                # Standard Django EmailMessage doesn't support these
                pass

            # Send the email
            msg.send(fail_silently=False)

            # Update log with success
            email_log.status = "sent"
            email_log.sent_at = timezone.now()

            # Try to get message ID from anymail
            message_id = None
            if hasattr(msg, "anymail_status"):
                message_id = msg.anymail_status.message_id
                email_log.provider_id = message_id or ""
                email_log.provider_response = {
                    "status": str(msg.anymail_status.status),
                    "esp_response": getattr(msg.anymail_status, "esp_response", {}),
                }

            email_log.save()

            # Increment rate limiter
            EmailRateLimiter.increment_counter()

            logger.info(f"Email sent successfully: {subject[:50]}... to {to[0][:3]}***")

            return EmailResult(
                success=True,
                message_id=message_id,
                email_log_id=str(email_log.id),
                provider=provider,
            )

        except Exception as e:
            # Update log with failure
            email_log.status = "failed"
            email_log.provider_response = {"error": str(e)}
            email_log.save()

            logger.error(f"Email sending failed: {e}")

            return EmailResult(
                success=False,
                email_log_id=str(email_log.id),
                error=str(e),
                provider=provider,
            )

    @classmethod
    def _send_async(
        cls,
        to: list[str],
        subject: str,
        body_text: str,
        body_html: str | None = None,
        from_email: str | None = None,
        reply_to: str | None = None,
        cc: list[str] | None = None,
        bcc: list[str] | None = None,
        attachments: list[tuple[str, bytes, str]] | None = None,
        customer: Customer | None = None,
        sent_by: User | None = None,
        template_key: str | None = None,
        priority: str = "normal",
        tags: dict[str, str] | None = None,
        track_opens: bool = True,
        track_clicks: bool = True,
    ) -> EmailResult:
        """Queue email for async sending via Django-Q2."""
        from_email = from_email or settings.DEFAULT_FROM_EMAIL
        provider = getattr(settings, "EMAIL_PROVIDER", "smtp")

        # Create email log entry with queued status
        email_log = cls._create_email_log(
            to=to[0],
            from_addr=from_email,
            reply_to=reply_to or "",
            subject=subject,
            body_text=body_text,
            body_html=body_html or "",
            template_key=template_key or "",
            customer=customer,
            sent_by=sent_by,
            priority=priority,
            provider=provider,
            status="queued",
        )

        try:
            from django_q.tasks import async_task

            # Queue the email task
            task_id = async_task(
                "apps.notifications.tasks.send_email_task",
                email_log_id=str(email_log.id),
                to=to,
                subject=subject,
                body_text=body_text,
                body_html=body_html,
                from_email=from_email,
                reply_to=reply_to,
                cc=cc,
                bcc=bcc,
                # Note: attachments not supported in async mode for now
                tags=tags,
                track_opens=track_opens,
                track_clicks=track_clicks,
                task_name=f"email:{template_key or 'direct'}:{to[0][:10]}",
            )

            logger.info(f"Email queued for async sending: {subject[:50]}... (task: {task_id})")

            return EmailResult(
                success=True,
                email_log_id=str(email_log.id),
                provider=provider,
            )

        except ImportError:
            # Django-Q2 not available, fall back to sync sending
            logger.warning("Django-Q2 not available, falling back to sync email sending")
            email_log.delete()
            return cls._send_now(
                to=to,
                subject=subject,
                body_text=body_text,
                body_html=body_html,
                from_email=from_email,
                reply_to=reply_to,
                cc=cc,
                bcc=bcc,
                attachments=attachments,
                customer=customer,
                sent_by=sent_by,
                template_key=template_key,
                priority=priority,
                tags=tags,
                track_opens=track_opens,
                track_clicks=track_clicks,
            )

    @classmethod
    def _queue_email_for_retry(
        cls,
        to: list[str],
        subject: str,
        body_text: str,
        body_html: str | None = None,
        from_email: str | None = None,
        reply_to: str | None = None,
        customer: Customer | None = None,
        sent_by: User | None = None,
        template_key: str | None = None,
        priority: str = "normal",
    ) -> EmailResult:
        """Queue email for later retry due to rate limiting."""
        from_email = from_email or settings.DEFAULT_FROM_EMAIL
        provider = getattr(settings, "EMAIL_PROVIDER", "smtp")

        email_log = cls._create_email_log(
            to=to[0],
            from_addr=from_email,
            reply_to=reply_to or "",
            subject=subject,
            body_text=body_text,
            body_html=body_html or "",
            template_key=template_key or "",
            customer=customer,
            sent_by=sent_by,
            priority=priority,
            provider=provider,
            status="queued",
        )

        try:
            from django_q.tasks import async_task

            retry_config = getattr(settings, "EMAIL_RETRY", {})
            retry_delay = retry_config.get("RETRY_DELAY_SECONDS", 60)

            async_task(
                "apps.notifications.tasks.send_email_task",
                email_log_id=str(email_log.id),
                to=to,
                subject=subject,
                body_text=body_text,
                body_html=body_html,
                from_email=from_email,
                reply_to=reply_to,
                schedule=timedelta(seconds=retry_delay),
                task_name=f"email_retry:{template_key or 'direct'}:{to[0][:10]}",
            )

            return EmailResult(
                success=True,
                email_log_id=str(email_log.id),
                provider=provider,
            )

        except ImportError:
            return EmailResult(
                success=False,
                error="Cannot queue email - Django-Q2 not available",
            )

    @staticmethod
    def _create_email_log(
        to: str,
        from_addr: str,
        reply_to: str,
        subject: str,
        body_text: str,
        body_html: str,
        template_key: str,
        customer: Customer | None,
        sent_by: User | None,
        priority: str,
        provider: str,
        status: str = "sending",
    ) -> EmailLog:
        """Create an email log entry."""
        return EmailLog.objects.create(
            to_addr=to,
            from_addr=from_addr,
            reply_to=reply_to,
            subject=subject,
            body_text=body_text,
            body_html=body_html,
            template_key=template_key,
            customer=customer,
            sent_by=sent_by,
            priority=priority,
            provider=provider,
            status=status,
        )

    # ===============================================================================
    # TEMPLATE-BASED EMAIL SENDING
    # ===============================================================================

    @classmethod
    def send_template_email(
        cls,
        template_key: str,
        recipient: str,
        context: dict[str, Any],
        locale: str = "en",
        customer: Customer | None = None,
        sent_by: User | None = None,
        priority: str = "normal",
        reply_to: str | None = None,
        cc: list[str] | None = None,
        bcc: list[str] | None = None,
        attachments: list[tuple[str, bytes, str]] | None = None,
        async_send: bool = True,
        **kwargs: Any,
    ) -> EmailResult:
        """
        Send an email using a database template.

        Args:
            template_key: Template identifier (e.g., 'invoice_issued')
            recipient: Recipient email address
            context: Template context variables
            locale: Language code (en, ro)
            customer: Associated customer
            sent_by: User who triggered the send
            priority: Email priority
            reply_to: Reply-to address
            cc: CC recipients
            bcc: BCC recipients
            attachments: File attachments
            async_send: Send asynchronously

        Returns:
            EmailResult with send status
        """
        # Security logging
        try:
            recipient_domain = recipient.split("@")[-1] if "@" in recipient else ""
            validators.log_security_event(
                event_type="template_email_send",
                details={
                    "template_key": template_key,
                    "recipient_domain": recipient_domain,
                    "context_keys": list(context.keys()),
                    "locale": locale,
                },
                request_ip=kwargs.get("request_ip"),
            )
        except Exception as e:
            logger.debug(f"Failed to log email attempt: {e}")

        # Get template from cache or database
        template = cls._get_template(template_key, locale)
        if not template:
            logger.error(f"Email template not found: {template_key} ({locale})")
            return EmailResult(
                success=False,
                error=f"Template not found: {template_key} ({locale})",
            )

        # Check if template is active
        if not template.is_active:
            logger.warning(f"Email template is inactive: {template_key}")
            return EmailResult(
                success=False,
                error=f"Template is inactive: {template_key}",
            )

        try:
            # Sanitize and validate context
            safe_context = validate_template_context(context)

            # Add default context variables
            safe_context.update(
                {
                    "company_name": getattr(settings, "COMPANY_NAME", "PRAHO Platform"),
                    "company_email": getattr(settings, "COMPANY_EMAIL", "contact@pragmatichost.com"),
                    "company_website": getattr(settings, "COMPANY_WEBSITE", "https://pragmatichost.com"),
                    "current_year": timezone.now().year,
                    "unsubscribe_url": cls._generate_unsubscribe_url(recipient, template_key),
                }
            )

            # Render subject and body
            subject = render_template_safely(template.subject, safe_context)
            body_html = render_template_safely(template.body_html, safe_context)
            body_text = template.body_text
            if body_text:
                body_text = render_template_safely(body_text, safe_context)
            else:
                # Generate text version from HTML
                body_text = strip_tags(body_html)

            # Send the email
            return cls.send_email(
                to=recipient,
                subject=subject,
                body_text=body_text,
                body_html=body_html,
                reply_to=reply_to,
                cc=cc,
                bcc=bcc,
                attachments=attachments,
                customer=customer,
                sent_by=sent_by,
                template_key=template_key,
                priority=priority,
                async_send=async_send,
                tags={"template": template_key, "locale": locale, "category": template.category},
            )

        except DjangoValidationError as e:
            logger.error(f"Template validation error: {e}")
            return EmailResult(
                success=False,
                error=f"Template validation error: {e}",
            )
        except Exception as e:
            logger.exception(f"Template email sending failed: {e}")
            return EmailResult(
                success=False,
                error=str(e),
            )

    @classmethod
    def _get_template(cls, template_key: str, locale: str = "en") -> EmailTemplate | None:
        """Get email template from cache or database."""
        cache_key = f"{TEMPLATE_CACHE_PREFIX}{template_key}:{locale}"

        # Try cache first
        template = cache.get(cache_key)
        if template is not None:
            return template if template != "NOT_FOUND" else None

        # Query database
        try:
            template = EmailTemplate.objects.get(key=template_key, locale=locale)
            cache.set(cache_key, template, timeout=TEMPLATE_CACHE_TIMEOUT)
            return template
        except EmailTemplate.DoesNotExist:
            # Try fallback to English if different locale requested
            if locale != "en":
                try:
                    template = EmailTemplate.objects.get(key=template_key, locale="en")
                    cache.set(cache_key, template, timeout=TEMPLATE_CACHE_TIMEOUT)
                    return template
                except EmailTemplate.DoesNotExist:
                    pass

            # Cache the not-found result to avoid repeated queries
            cache.set(cache_key, "NOT_FOUND", timeout=300)
            return None

    @staticmethod
    def _generate_unsubscribe_url(email: str, template_key: str) -> str:
        """Generate unsubscribe URL for email."""
        import hashlib

        token = hashlib.sha256(f"{email}:{template_key}:{settings.SECRET_KEY}".encode()).hexdigest()[:32]
        base_url = getattr(settings, "COMPANY_WEBSITE", "https://pragmatichost.com")
        return f"{base_url}/email/unsubscribe/?email={email}&token={token}"

    @staticmethod
    def get_safe_email_preview(template_content: str, context: dict[str, Any]) -> str:
        """Render a preview safely and truncate for UI display."""
        rendered = render_template_safely(template_content, context)
        preview_limit = 500
        if len(rendered) > preview_limit:
            return rendered[:preview_limit] + "...[preview truncated]"
        return rendered

    # ===============================================================================
    # INVOICE & BILLING EMAIL METHODS
    # ===============================================================================

    @classmethod
    def send_invoice_created(cls, invoice: Invoice) -> EmailResult:
        """Send invoice created notification."""
        customer = invoice.customer
        locale = getattr(customer, "preferred_locale", "en") or "en"

        context = {
            "customer_name": customer.get_display_name(),
            "invoice_number": invoice.number,
            "invoice_date": invoice.created_at.strftime("%Y-%m-%d"),
            "total_amount": str(invoice.total),
            "currency": invoice.currency.code if invoice.currency else "RON",
            "due_date": invoice.due_at.strftime("%Y-%m-%d") if invoice.due_at else "N/A",
            "invoice_url": f"{settings.COMPANY_WEBSITE}/billing/invoices/{invoice.id}/",
        }

        return cls.send_template_email(
            template_key="invoice_issued",
            recipient=invoice.bill_to_email or customer.primary_email,
            context=context,
            locale=locale,
            customer=customer,
            priority="high",
        )

    @classmethod
    def send_invoice_paid(cls, invoice: Invoice) -> EmailResult:
        """Send invoice paid notification."""
        customer = invoice.customer
        locale = getattr(customer, "preferred_locale", "en") or "en"

        context = {
            "customer_name": customer.get_display_name(),
            "invoice_number": invoice.number,
            "total_amount": str(invoice.total),
            "currency": invoice.currency.code if invoice.currency else "RON",
            "paid_date": invoice.paid_at.strftime("%Y-%m-%d")
            if invoice.paid_at
            else timezone.now().strftime("%Y-%m-%d"),
            "invoice_url": f"{settings.COMPANY_WEBSITE}/billing/invoices/{invoice.id}/",
        }

        return cls.send_template_email(
            template_key="payment_received",
            recipient=invoice.bill_to_email or customer.primary_email,
            context=context,
            locale=locale,
            customer=customer,
            priority="normal",
        )

    @classmethod
    def send_payment_reminder(cls, invoice: Invoice) -> EmailResult:
        """Send payment reminder for unpaid invoice."""
        customer = invoice.customer
        locale = getattr(customer, "preferred_locale", "en") or "en"

        days_until_due = 0
        if invoice.due_at:
            days_until_due = (invoice.due_at - timezone.now()).days

        context = {
            "customer_name": customer.get_display_name(),
            "invoice_number": invoice.number,
            "total_amount": str(invoice.total),
            "currency": invoice.currency.code if invoice.currency else "RON",
            "due_date": invoice.due_at.strftime("%Y-%m-%d") if invoice.due_at else "N/A",
            "days_until_due": max(0, days_until_due),
            "payment_url": f"{settings.COMPANY_WEBSITE}/billing/pay/{invoice.id}/",
        }

        template_key = "payment_reminder" if days_until_due >= 0 else "payment_overdue"

        return cls.send_template_email(
            template_key=template_key,
            recipient=invoice.bill_to_email or customer.primary_email,
            context=context,
            locale=locale,
            customer=customer,
            priority="high",
        )

    # ===============================================================================
    # BULK EMAIL SENDING
    # ===============================================================================

    @classmethod
    def send_campaign(
        cls,
        campaign: EmailCampaign,
        recipients: list[tuple[str, dict[str, Any]]],  # List of (email, context) tuples
    ) -> dict[str, Any]:
        """
        Send an email campaign to multiple recipients.

        Args:
            campaign: The EmailCampaign model instance
            recipients: List of (email, personalized_context) tuples

        Returns:
            Dict with sent_count, failed_count, and details
        """
        template = campaign.template
        sent_count = 0
        failed_count = 0
        errors: list[dict[str, str]] = []

        # Update campaign status
        campaign.status = "sending"
        campaign.started_at = timezone.now()
        campaign.total_recipients = len(recipients)
        campaign.save()

        for email, context in recipients:
            try:
                result = cls.send_template_email(
                    template_key=template.key,
                    recipient=email,
                    context=context,
                    locale=template.locale,
                    async_send=True,  # Always async for bulk
                )

                if result.success:
                    sent_count += 1
                else:
                    failed_count += 1
                    errors.append({"email": email, "error": result.error or "Unknown error"})

            except Exception as e:
                failed_count += 1
                errors.append({"email": email, "error": str(e)})

        # Update campaign completion
        campaign.emails_sent = sent_count
        campaign.emails_failed = failed_count
        campaign.status = "sent" if failed_count == 0 else ("failed" if sent_count == 0 else "sent")
        campaign.completed_at = timezone.now()
        campaign.save()

        return {
            "sent_count": sent_count,
            "failed_count": failed_count,
            "errors": errors[:10],  # Limit error details
        }

    # ===============================================================================
    # WEBHOOK & TRACKING METHODS
    # ===============================================================================

    @classmethod
    def handle_delivery_event(
        cls,
        event_type: str,
        message_id: str,
        recipient: str,
        timestamp: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> bool:
        """
        Handle email delivery webhook event.

        Args:
            event_type: Event type (delivered, bounced, complained, opened, clicked)
            message_id: Provider message ID
            recipient: Recipient email
            timestamp: Event timestamp
            metadata: Additional event data

        Returns:
            True if event was processed successfully
        """
        try:
            # Find the email log
            email_log = EmailLog.objects.filter(provider_id=message_id).first()
            if not email_log:
                email_log = EmailLog.objects.filter(to_addr=recipient).order_by("-sent_at").first()

            if not email_log:
                logger.warning(f"No email log found for delivery event: {message_id}")
                return False

            now = timezone.now()

            if event_type == "delivered":
                email_log.status = "delivered"
                email_log.delivered_at = now

            elif event_type == "bounced":
                email_log.status = "bounced"
                # Suppress the email address for hard bounces
                EmailSuppressionService.suppress_email(recipient, "hard_bounce")

            elif event_type == "soft_bounced":
                email_log.status = "soft_bounced"
                # Check soft bounce threshold
                soft_bounce_count = EmailLog.objects.filter(
                    to_addr=recipient,
                    status="soft_bounced",
                    sent_at__gte=now - timedelta(days=7),
                ).count()
                threshold = getattr(settings, "EMAIL_DELIVERABILITY", {}).get("SOFT_BOUNCE_THRESHOLD", 3)
                if soft_bounce_count >= threshold:
                    EmailSuppressionService.suppress_email(recipient, "soft_bounce_threshold", duration_days=30)

            elif event_type == "complained":
                email_log.status = "complained"
                # Always suppress complained addresses
                EmailSuppressionService.suppress_email(recipient, "complaint")

            elif event_type == "opened":
                if not email_log.opened_at:
                    email_log.opened_at = now

            elif event_type == "clicked":
                if not email_log.clicked_at:
                    email_log.clicked_at = now

            # Store metadata
            if metadata:
                email_log.provider_response = {
                    **(email_log.provider_response or {}),
                    f"{event_type}_event": metadata,
                }

            email_log.save()

            logger.info(f"Processed {event_type} event for {recipient[:3]}***")
            return True

        except Exception as e:
            logger.exception(f"Failed to handle delivery event: {e}")
            return False

    # ===============================================================================
    # AUDIT LOGGING INTEGRATION
    # ===============================================================================

    @classmethod
    def log_email_audit_event(
        cls,
        event_type: str,
        email_log: EmailLog | None = None,
        details: dict[str, Any] | None = None,
    ) -> None:
        """Log email-related audit event."""
        try:
            from apps.audit.services import AuditEventData, AuditService

            event_data = AuditEventData(
                event_type=f"email_{event_type}",
                content_object=email_log,
                description=f"Email {event_type}: {email_log.subject if email_log else 'N/A'}",
            )
            AuditService.log_event(event_data)

        except Exception as e:
            logger.debug(f"Failed to log email audit event: {e}")


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


# ===============================================================================
# EMAIL PREFERENCE SERVICE
# ===============================================================================


class EmailPreferenceService:
    """
    Manage customer email preferences and unsubscribe handling.
    GDPR-compliant preference management.
    """

    @staticmethod
    def get_preferences(customer: Customer) -> dict[str, bool]:
        """Get email preferences for a customer."""
        return {
            "marketing": getattr(customer, "marketing_consent", True),
            "transactional": True,  # Always receive transactional emails
            "billing": True,  # Always receive billing emails
            "security": True,  # Always receive security emails
            "newsletters": getattr(customer, "newsletter_consent", False),
        }

    @staticmethod
    def update_preferences(customer: Customer, preferences: dict[str, bool]) -> None:
        """Update email preferences for a customer."""
        if "marketing" in preferences:
            customer.marketing_consent = preferences["marketing"]
        if "newsletters" in preferences:
            customer.newsletter_consent = preferences["newsletters"]
        customer.save(update_fields=["marketing_consent", "newsletter_consent"])

        # Log the preference change
        validators.log_security_event(
            "email_preferences_updated",
            {
                "customer_id": str(customer.id),
                "preferences": preferences,
            },
        )

    @staticmethod
    def can_send_category(customer: Customer, category: str) -> bool:
        """Check if we can send emails of a specific category to a customer."""
        # Transactional emails always allowed
        if category in ["billing", "provisioning", "security", "system", "compliance"]:
            return True

        # Marketing requires consent
        if category == "marketing":
            return getattr(customer, "marketing_consent", False)

        # Default to allowing
        return True

    @staticmethod
    def process_unsubscribe(email: str, token: str, category: str | None = None) -> bool:
        """
        Process an unsubscribe request.

        Args:
            email: Email address
            token: Verification token
            category: Optional specific category to unsubscribe from

        Returns:
            True if unsubscribe was successful
        """
        import hashlib
        import hmac

        from apps.customers.models import Customer

        # Verify token using timing-safe comparison
        # Check against known template keys to validate
        token_valid = False
        for template_key in ["marketing", "newsletter", "all"]:
            expected_token = hashlib.sha256(f"{email}:{template_key}:{settings.SECRET_KEY}".encode()).hexdigest()[:32]
            # Use timing-safe comparison to prevent timing attacks
            if hmac.compare_digest(token, expected_token):
                token_valid = True
                break

        if not token_valid:
            logger.warning(f"Invalid unsubscribe token for {email[:3]}***")
            return False

        # Find customer
        try:
            customer = Customer.objects.get(primary_email=email)

            if category == "marketing" or category is None:
                customer.marketing_consent = False
            if category == "newsletter" or category is None:
                customer.newsletter_consent = False

            customer.save()

            # Log the unsubscribe
            validators.log_security_event(
                "email_unsubscribe",
                {
                    "customer_id": str(customer.id),
                    "category": category or "all_marketing",
                },
            )

            logger.info(f"Processed unsubscribe for {email[:3]}***")
            return True

        except Customer.DoesNotExist:
            # Suppress the email address anyway
            EmailSuppressionService.suppress_email(email, "unsubscribe")
            return True
