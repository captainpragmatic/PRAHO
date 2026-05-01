"""
Notifications models for PRAHO Platform
Email templates and communication logging for Romanian hosting provider.
Aligned with PostgreSQL hosting panel schema v1.

Security hardening:
- Validates template and log content to prevent injection
- Optional field-level encryption for stored email bodies
- Safe previews and GDPR compliance warnings
"""

import hashlib
import logging
import re
import uuid
from datetime import timedelta
from typing import Any, ClassVar

from django.core.exceptions import ValidationError
from django.core.validators import EmailValidator
from django.db import models, transaction
from django.utils import timezone
from django.utils.translation import gettext_lazy as _

from apps.common.constants import SUBJECT_PREVIEW_DISPLAY, SUBJECT_PREVIEW_LIMIT
from apps.common.encryption import EncryptionError, decrypt_if_needed, encrypt_value, is_encrypted

# Module-level logger and encryption flag (patched in tests)
logger = logging.getLogger(__name__)
ENCRYPTION_AVAILABLE = True

# Security constants
_DEFAULT_MAX_TEMPLATE_SIZE = 100_000  # 100KB limit for templates
MAX_TEMPLATE_SIZE = _DEFAULT_MAX_TEMPLATE_SIZE
MAX_JSON_SIZE = 10_000  # 10KB limit for JSON data
MAX_JSON_DEPTH = 10  # Maximum JSON nesting depth
_DEFAULT_MAX_SUBJECT_LENGTH = 200  # Maximum subject line length
MAX_SUBJECT_LENGTH = _DEFAULT_MAX_SUBJECT_LENGTH
_DEFAULT_MAX_NAME_LENGTH = 200  # Maximum campaign name length
MAX_NAME_LENGTH = _DEFAULT_MAX_NAME_LENGTH


def get_max_template_size() -> int:
    """Get max template size from SettingsService (runtime)."""
    from apps.settings.services import (  # noqa: PLC0415  # Deferred: avoids circular import
        SettingsService,  # Circular: cross-app  # Deferred: avoids circular import
    )

    return SettingsService.get_integer_setting("notifications.max_template_size", _DEFAULT_MAX_TEMPLATE_SIZE)


def get_max_subject_length() -> int:
    """Get max subject length from SettingsService (runtime)."""
    from apps.settings.services import (  # noqa: PLC0415  # Deferred: avoids circular import
        SettingsService,  # Circular: cross-app  # Deferred: avoids circular import
    )

    return SettingsService.get_integer_setting("notifications.max_subject_length", _DEFAULT_MAX_SUBJECT_LENGTH)


def get_max_name_length() -> int:
    """Get max name length from SettingsService (runtime)."""
    from apps.settings.services import (  # noqa: PLC0415  # Deferred: avoids circular import
        SettingsService,  # Circular: cross-app  # Deferred: avoids circular import
    )

    return SettingsService.get_integer_setting("notifications.max_name_length", _DEFAULT_MAX_NAME_LENGTH)


CONTENT_PREVIEW_LENGTH = 100  # Length for content preview


# ===============================================================================
# SECURITY VALIDATION FUNCTIONS
# ===============================================================================


def validate_template_content(content: str) -> None:
    """🔒 Validate template content for security"""
    if not content:
        return

    # Size limit check - templates over 100KB are rejected
    if len(content) > MAX_TEMPLATE_SIZE:
        raise ValidationError(_("Template content too large"))

    # Disallowed tags that should be explicitly blocked
    disallowed_tags = [
        r"\{\%\s*csrf_token\s*\%\}",
        r"\{\%\s*autoescape\s+off\s*\%\}",
        r"\{\%\s*cache\b",
    ]
    for pattern in disallowed_tags:
        if re.search(pattern, content, flags=re.IGNORECASE):
            raise ValidationError(_("Template contains disallowed tags"))

    dangerous_patterns = [
        r"\{\%\s*debug\s*\%\}",  # {% debug %}
        r"\{\%\s*load\s+ssi\s*\%\}",  # {% load ssi %}
        r"\{\%\s*load\s+admin_tags\s*\%\}",  # {% load admin_tags %}
        r"\{\{\s*request\.",  # {{ request.* }}
        r"\{\{\s*user\.",  # {{ user.* }}
        r"<script[\s>]",  # <script> tags
    ]
    for pattern in dangerous_patterns:
        if re.search(pattern, content, flags=re.IGNORECASE):
            raise ValidationError(_("Template contains disallowed constructs"))


def validate_json_field(data: Any) -> None:
    """🔒 Validate JSON field data"""
    if data is None:
        return

    # Check size limit
    if len(str(data)) > MAX_JSON_SIZE:
        raise ValidationError(_("JSON content too large"))

    # Check depth limit to prevent stack overflow
    def check_depth(obj: Any, depth: int = 0) -> None:
        if depth > MAX_JSON_DEPTH:
            raise ValidationError(_("JSON nesting too deep"))

        if isinstance(obj, dict):
            for value in obj.values():
                check_depth(value, depth + 1)
        elif isinstance(obj, list):
            for item in obj:
                check_depth(item, depth + 1)

    check_depth(data)


def validate_email_subject(subject: str) -> None:
    """🔒 Validate email subject for security"""
    if not subject:
        return

    if len(subject) > MAX_SUBJECT_LENGTH:
        raise ValidationError(_("Subject too long"))

    # Check for email header injection attempts (newlines, carriage returns, null bytes)
    if re.search(r"[\r\n\x00]", subject):
        raise ValidationError(_("Subject contains invalid characters"))

    # Check for dangerous patterns
    if re.search(r"<script", subject, flags=re.IGNORECASE):
        raise ValidationError(_("Subject contains dangerous content"))


def encrypt_sensitive_content(content: str) -> str:
    """🔒 Encrypt sensitive content using AES-256-GCM encryption."""
    if not ENCRYPTION_AVAILABLE or not content:
        return content
    try:
        encrypted = encrypt_value(content)
        return encrypted if encrypted else content
    except Exception as e:
        logger.warning("Encryption failed for sensitive content, returning original: %s", e)
        return content


def decrypt_sensitive_content(encrypted_content: str) -> str:
    """🔒 Decrypt sensitive content using AES-256-GCM encryption."""
    if not ENCRYPTION_AVAILABLE or not encrypted_content:
        return encrypted_content
    try:
        return str(decrypt_if_needed(encrypted_content))
    except Exception as e:
        logger.warning("Decryption failed, returning original: %s", e)
        return encrypted_content


# ===============================================================================
# EMAIL TEMPLATE SYSTEM
# ===============================================================================


class EmailTemplate(models.Model):
    """
    Email templates for automated communications.
    Supports multilingual templates for Romanian/English customer base.
    Aligned with PostgreSQL email_template table.
    """

    # Use UUID for better security and external references
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)

    # Template identification
    key = models.CharField(
        max_length=100, help_text=_("Template identifier (e.g., 'invoice_issued', 'payment_reminder')")
    )
    locale = models.CharField(max_length=10, default="ro", help_text=_("Language/locale code (ro, en)"))

    # Template content
    subject = models.CharField(max_length=255, help_text=_("Email subject line (supports variables)"))
    body_html = models.TextField(help_text=_("HTML email body (supports Django template syntax)"))
    body_text = models.TextField(blank=True, help_text=_("Plain text fallback (auto-generated if empty)"))

    # Template metadata
    description = models.TextField(blank=True, help_text=_("Description of when this template is used"))
    variables = models.JSONField(
        default=dict, blank=True, help_text=_("Available template variables and their descriptions")
    )

    # Status and versioning
    is_active = models.BooleanField(default=True, help_text=_("Whether this template is available for use"))
    version = models.PositiveIntegerField(default=1, help_text=_("Template version for change tracking"))

    # Romanian hosting provider categories
    CATEGORY_CHOICES: ClassVar[tuple[tuple[str, Any], ...]] = (
        ("billing", _("Billing & Invoices")),
        ("dunning", _("Payment Reminders")),
        ("provisioning", _("Service Provisioning")),
        ("support", _("Support & Tickets")),
        ("welcome", _("Welcome & Onboarding")),
        ("renewal", _("Service Renewals")),
        ("suspension", _("Service Suspension")),
        ("termination", _("Service Termination")),
        ("domain", _("Domain Management")),
        ("security", _("Security Alerts")),
        ("maintenance", _("Maintenance Notifications")),
        ("marketing", _("Marketing & Promotions")),
        ("compliance", _("Legal & Compliance")),
        ("system", _("System Notifications")),
    )
    category = models.CharField(
        max_length=20, choices=CATEGORY_CHOICES, default="system", help_text=_("Template category for organization")
    )

    # Audit fields
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    created_by = models.ForeignKey(
        "users.User",
        on_delete=models.SET_NULL,
        null=True,
        related_name="created_email_templates",
        help_text=_("User who created this template"),
    )

    class Meta:
        db_table = "notification_email_templates"
        verbose_name = _("Email Template")
        verbose_name_plural = _("Email Templates")
        unique_together: ClassVar[tuple[tuple[str, ...], ...]] = (("key", "locale"),)
        indexes: ClassVar[tuple[models.Index, ...]] = (
            models.Index(fields=["key", "locale"]),
            models.Index(fields=["category", "is_active"]),
            models.Index(fields=["created_at"]),
        )
        ordering: ClassVar[tuple[str, ...]] = ("category", "key", "locale")

    def __str__(self) -> str:
        return f"{self.key} ({self.locale}): {self.subject}"

    def get_subject_display(self) -> str:
        """Truncated subject for admin display"""
        if len(self.subject) > SUBJECT_PREVIEW_LIMIT:
            return f"{self.subject[:SUBJECT_PREVIEW_DISPLAY]}..."
        return self.subject

    def clean(self) -> None:
        """Validate template content for security and JSON size."""
        dangerous_patterns = [r"\{\%\s*debug\s*\%\}", r"<script[\s>]"]
        for pattern in dangerous_patterns:
            if re.search(pattern, self.body_html or "", flags=re.IGNORECASE):
                raise ValidationError(_("Template contains disallowed constructs"))

        # Basic JSON size guard for variables
        try:
            # Very lightweight estimate without serialization
            if self.variables and len(str(self.variables)) > MAX_JSON_SIZE:
                raise ValidationError(_("Template variables too large"))
        except Exception as e:  # pragma: no cover - defensive
            raise ValidationError(_("Invalid variables JSON: %(error)s") % {"error": e}) from e

        # Log template modification for security audit
        try:
            logger.info(f"Template modified: {self.key} ({self.locale})")
        except Exception as e:  # pragma: no cover - logging shouldn't break validation
            logger.debug(f"Failed to log template modification: {e}")

    def get_sanitized_content(self) -> tuple[str, str]:
        """Return sanitized HTML and text versions (strip dangerous tags)."""
        html = self.body_html or ""
        # Remove script tags while preserving template markers
        html = re.sub(r"<script.*?>.*?</script>", "", html, flags=re.IGNORECASE | re.DOTALL)
        text = self.body_text or ""
        return html, text


# ===============================================================================
# EMAIL LOGGING & TRACKING
# ===============================================================================


class EmailLog(models.Model):
    """
    Email delivery log for audit and deliverability tracking.
    Tracks all outbound emails for compliance and debugging.
    Aligned with PostgreSQL email_log table.
    """

    # Use UUID for better security and external references
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)

    # Email identification
    customer = models.ForeignKey(
        "customers.Customer",
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="email_logs",
        help_text=_("Customer this email was sent to (if applicable)"),
    )
    to_addr = models.EmailField(validators=[EmailValidator()], help_text=_("Recipient email address"))
    from_addr = models.EmailField(blank=True, help_text=_("Sender email address (if different from default)"))
    reply_to = models.EmailField(blank=True, help_text=_("Reply-to email address"))

    # Email content
    template_key = models.CharField(max_length=100, blank=True, help_text=_("Template used to generate this email"))
    subject = models.CharField(max_length=255, help_text=_("Actual email subject sent"))
    body_text = models.TextField(blank=True, help_text=_("Plain text version of email body"))
    body_html = models.TextField(blank=True, help_text=_("HTML version of email body"))
    body_encrypted = models.BooleanField(default=True, help_text=_("Whether body fields are encrypted at rest"))

    # Delivery tracking
    STATUS_CHOICES: ClassVar[tuple[tuple[str, Any], ...]] = (
        ("queued", _("Queued")),  # Waiting to be sent
        ("sending", _("Sending")),  # Currently being processed
        ("sent", _("Sent")),  # Successfully sent to provider
        ("delivered", _("Delivered")),  # Confirmed delivered to recipient
        ("bounced", _("Bounced")),  # Hard bounce from recipient server
        ("soft_bounced", _("Soft Bounced")),  # Temporary delivery failure
        ("complained", _("Complained")),  # Marked as spam by recipient
        ("failed", _("Failed")),  # Failed to send
        ("rejected", _("Rejected")),  # Rejected by email provider
    )
    status = models.CharField(
        max_length=20, choices=STATUS_CHOICES, default="queued", help_text=_("Current delivery status")
    )

    # Provider integration
    provider = models.CharField(
        max_length=50, default="smtp", help_text=_("Email service provider (smtp, sendgrid, mailgun, etc.)")
    )
    provider_id = models.CharField(max_length=255, blank=True, help_text=_("Provider's unique message ID"))
    provider_response = models.JSONField(default=dict, blank=True, help_text=_("Raw provider response for debugging"))

    # Timing and tracking
    sent_at = models.DateTimeField(auto_now_add=True, help_text=_("When email was queued/sent"))
    delivered_at = models.DateTimeField(null=True, blank=True, help_text=_("When email was confirmed delivered"))
    opened_at = models.DateTimeField(
        null=True, blank=True, help_text=_("When email was first opened (if tracking enabled)")
    )
    clicked_at = models.DateTimeField(null=True, blank=True, help_text=_("When email links were first clicked"))

    # Additional metadata
    meta = models.JSONField(
        default=dict, blank=True, help_text=_("Additional email metadata (variables used, campaign info, etc.)")
    )

    # Romanian hosting context
    priority = models.CharField(
        max_length=10,
        choices=[
            ("low", _("Low")),
            ("normal", _("Normal")),
            ("high", _("High")),
            ("urgent", _("Urgent")),
        ],
        default="normal",
        help_text=_("Email priority level"),
    )

    # User context
    sent_by = models.ForeignKey(
        "users.User",
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="sent_emails",
        help_text=_("User who triggered this email (if manual)"),
    )

    class Meta:
        db_table = "notification_email_logs"
        verbose_name = _("Email Log")
        verbose_name_plural = _("Email Logs")
        indexes: ClassVar[tuple[models.Index, ...]] = (
            models.Index(fields=["to_addr", "-sent_at"]),
            models.Index(fields=["customer", "-sent_at"]),
            models.Index(fields=["template_key", "-sent_at"]),
            models.Index(fields=["status", "-sent_at"]),
            models.Index(fields=["provider", "-sent_at"]),
            models.Index(fields=["-sent_at"]),  # Most recent emails
        )
        ordering: ClassVar[tuple[str, ...]] = ("-sent_at",)

    def __str__(self) -> str:
        return f"{self.subject} → {self.to_addr} ({self.status})"

    def save(self, *args: Any, **kwargs: Any) -> None:
        """Encrypt body fields at rest when available."""
        if ENCRYPTION_AVAILABLE:
            original_text, original_html = self.body_text, self.body_html
            try:
                if self.body_text and not is_encrypted(self.body_text):
                    encrypted = encrypt_value(self.body_text)
                    if encrypted is None:
                        raise EncryptionError("encrypt_value returned None for non-None input")
                    self.body_text = encrypted
                if self.body_html and not is_encrypted(self.body_html):
                    encrypted = encrypt_value(self.body_html)
                    if encrypted is None:
                        raise EncryptionError("encrypt_value returned None for non-None input")
                    self.body_html = encrypted
                self.body_encrypted = True
            except Exception as e:
                # Restore both to prevent partial encryption (one encrypted, one plaintext)
                self.body_text = original_text
                self.body_html = original_html
                self.body_encrypted = False
                # Per ADR-0017: fail-open for infra failures with safeguards
                logger.error("EmailLog encryption failed; saving with body_encrypted=False: %s", e)
                logger.critical(
                    "ENCRYPTION_FAILURE_ALERT: EmailLog body will contain plaintext. "
                    "Run `manage.py reencrypt_email_logs` after resolving. to=%s subject=%s",
                    self.to_addr,
                    (self.subject or "")[:50],
                )
        else:
            logger.warning("ENCRYPTION_AVAILABLE is False; EmailLog saved without encryption")
            self.body_encrypted = False
        super().save(*args, **kwargs)

    def get_status_display_color(self) -> str:
        """Get color for status display in admin"""
        status_colors = {
            "queued": "#6B7280",  # Gray
            "sending": "#3B82F6",  # Blue
            "sent": "#10B981",  # Green
            "delivered": "#059669",  # Dark green
            "bounced": "#EF4444",  # Red
            "soft_bounced": "#F59E0B",  # Amber
            "complained": "#DC2626",  # Dark red
            "failed": "#EF4444",  # Red
            "rejected": "#DC2626",  # Dark red
        }
        return status_colors.get(self.status, "#6B7280")

    def is_successful(self) -> bool:
        """Check if email was successfully delivered"""
        return self.status in ["sent", "delivered"]

    def is_failed(self) -> bool:
        """Check if email failed to deliver"""
        return self.status in ["bounced", "failed", "rejected"]

    def clean(self) -> None:
        """Validate log content and emit basic security logging."""
        # Prevent header injection via subject
        if self.subject and ("\n" in self.subject or "\r" in self.subject):
            raise ValidationError(_("Invalid subject header"))

        # Basic JSON/meta size limit
        if self.meta and len(str(self.meta)) > MAX_JSON_SIZE:
            raise ValidationError(_("Metadata too large"))

        # Log sending activity with masked email (only on send-like statuses)
        if self.status in {"sent", "delivered"}:
            masked = (self.to_addr or "").replace("@", "@")[0:3] + "***"
            try:
                logger.info(f"Email sent to {masked}")
            except Exception as e:  # pragma: no cover - logging shouldn't break
                logger.debug(f"Failed to log email sent: {e}")

    def get_safe_content_preview(self) -> str:
        """Return a short, decrypted preview suitable for logs/UI."""
        content = self.body_text or ""
        try:
            content = decrypt_if_needed(content)
        except Exception as e:  # pragma: no cover
            logger.warning("Decryption failed, using original content: %s", e)
        preview = content[:CONTENT_PREVIEW_LENGTH]
        return preview + ("..." if len(content) > CONTENT_PREVIEW_LENGTH else "")

    def get_decrypted_body_html(self) -> str:
        """Return decrypted HTML body, handling missing encryption gracefully."""
        content = self.body_html or ""
        try:
            return str(decrypt_if_needed(content))
        except Exception as e:  # pragma: no cover
            logger.warning("Decryption of body_html failed: %s", e)
            return content

    def get_decrypted_body_text(self) -> str:
        """Return decrypted text body, handling missing encryption gracefully."""
        content = self.body_text or ""
        try:
            return str(decrypt_if_needed(content))
        except Exception as e:  # pragma: no cover
            logger.warning("Decryption of body_text failed: %s", e)
            return content


# ===============================================================================
# EMAIL CAMPAIGNS & BULK SENDING
# ===============================================================================


class EmailCampaign(models.Model):
    """
    Email campaigns for bulk notifications and marketing.
    Romanian hosting provider specific campaign management.
    """

    # Use UUID for better security and external references
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)

    # Campaign identification
    name = models.CharField(max_length=200, help_text=_("Campaign name for identification"))
    description = models.TextField(blank=True, help_text=_("Campaign description and purpose"))

    # Campaign configuration
    template = models.ForeignKey(
        EmailTemplate, on_delete=models.PROTECT, help_text=_("Email template to use for this campaign")
    )

    # Targeting
    AUDIENCE_CHOICES: ClassVar[tuple[tuple[str, Any], ...]] = (
        ("all_customers", _("All Customers")),
        ("active_customers", _("Active Customers")),
        ("inactive_customers", _("Inactive Customers")),
        ("overdue_payments", _("Overdue Payments")),
        ("trial_expiring", _("Trial Expiring")),
        ("custom_filter", _("Custom Filter")),
    )
    audience = models.CharField(
        max_length=20,
        choices=AUDIENCE_CHOICES,
        default="active_customers",
        help_text=_("Target audience for this campaign"),
    )
    audience_filter = models.JSONField(
        default=dict, blank=True, help_text=_("Custom filter criteria for audience selection")
    )

    # Campaign status
    STATUS_CHOICES: ClassVar[tuple[tuple[str, Any], ...]] = (
        ("draft", _("Draft")),  # Being prepared
        ("scheduled", _("Scheduled")),  # Scheduled for future sending
        ("sending", _("Sending")),  # Currently being sent
        ("sent", _("Sent")),  # Completed successfully
        ("paused", _("Paused")),  # Temporarily paused
        ("cancelled", _("Cancelled")),  # Cancelled before completion
        ("failed", _("Failed")),  # Failed to send
    )
    status = models.CharField(
        max_length=20, choices=STATUS_CHOICES, default="draft", help_text=_("Current campaign status")
    )

    # Scheduling
    scheduled_at = models.DateTimeField(
        null=True, blank=True, help_text=_("When to send this campaign (leave blank for immediate)")
    )
    started_at = models.DateTimeField(null=True, blank=True, help_text=_("When campaign sending actually started"))
    completed_at = models.DateTimeField(null=True, blank=True, help_text=_("When campaign sending completed"))

    # Results tracking
    total_recipients = models.PositiveIntegerField(default=0, help_text=_("Total number of recipients"))
    emails_sent = models.PositiveIntegerField(default=0, help_text=_("Number of emails successfully sent"))
    emails_failed = models.PositiveIntegerField(default=0, help_text=_("Number of emails that failed to send"))

    # Romanian business context
    is_transactional = models.BooleanField(
        default=False, help_text=_("Transactional emails (billing, service) vs. marketing")
    )
    requires_consent = models.BooleanField(
        default=True, help_text=_("Requires explicit customer consent (GDPR compliance)")
    )

    # Audit fields
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    created_by = models.ForeignKey(
        "users.User",
        on_delete=models.SET_NULL,
        null=True,
        related_name="created_email_campaigns",
        help_text=_("User who created this campaign"),
    )

    class Meta:
        db_table = "notification_email_campaigns"
        verbose_name = _("Email Campaign")
        verbose_name_plural = _("Email Campaigns")
        indexes: ClassVar[tuple[models.Index, ...]] = (
            models.Index(fields=["status", "-created_at"]),
            models.Index(fields=["scheduled_at"]),
            models.Index(fields=["-created_at"]),
        )
        ordering: ClassVar[tuple[str, ...]] = ("-created_at",)

    def __str__(self) -> str:
        return f"{self.name} ({self.get_status_display()})"

    def get_success_rate(self) -> float:
        """Calculate campaign success rate percentage"""
        if self.total_recipients == 0:
            return 0
        return round((self.emails_sent / self.total_recipients) * 100, 1)

    def can_be_sent(self) -> bool:
        """Check if campaign can be sent"""
        return self.status in ["draft", "scheduled", "paused"]

    def is_completed(self) -> bool:
        """Check if campaign is completed"""
        return self.status in ["sent", "cancelled", "failed"]

    def clean(self) -> None:
        """Validate campaign configuration and GDPR compliance hints."""
        # Size limit for audience filter
        if self.audience_filter and len(str(self.audience_filter)) > MAX_JSON_SIZE:
            raise ValidationError(_("Audience filter JSON too large"))

        # Name length constraint
        if self.name and len(self.name) > MAX_NAME_LENGTH:
            raise ValidationError(_("Campaign name too long"))

        # GDPR compliance warning for marketing without consent
        if not self.is_transactional and not self.requires_consent:
            try:
                logger.warning("GDPR compliance issue: Marketing campaign without consent configured")
            except Exception as e:  # pragma: no cover
                logger.debug(f"Failed to log GDPR warning: {e}")


# ===============================================================================
# EMAIL SUPPRESSION LIST
# ===============================================================================


class EmailSuppression(models.Model):
    """
    Email suppression list for managing bounced, complained, and unsubscribed addresses.
    Persisted suppression data for compliance and deliverability.
    """

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)

    # Suppressed email (hashed for privacy)
    email_hash = models.CharField(
        max_length=64,
        unique=True,
        db_index=True,
        help_text=_("SHA-256 hash of the suppressed email address"),
    )

    # Original email (encrypted for GDPR compliance)
    email_encrypted = models.TextField(
        blank=True,
        help_text=_("Encrypted original email (for support requests)"),
    )

    # Suppression reason
    REASON_CHOICES: ClassVar[tuple[tuple[str, str], ...]] = (
        ("hard_bounce", _("Hard Bounce")),
        ("soft_bounce_threshold", _("Soft Bounce Threshold Exceeded")),
        ("complaint", _("Spam Complaint")),
        ("unsubscribe", _("User Unsubscribed")),
        ("manual", _("Manually Suppressed")),
        ("invalid", _("Invalid Email Address")),
    )
    reason = models.CharField(
        max_length=30,
        choices=REASON_CHOICES,
        help_text=_("Reason for suppression"),
    )

    # Timing
    suppressed_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField(
        null=True,
        blank=True,
        help_text=_("When suppression expires (null = permanent)"),
    )

    # Tracking
    bounce_count = models.PositiveIntegerField(default=1)
    last_bounce_at = models.DateTimeField(null=True, blank=True)

    # Provider info
    provider = models.CharField(max_length=50, blank=True)
    provider_response = models.JSONField(default=dict, blank=True)

    class Meta:
        db_table = "notification_email_suppressions"
        verbose_name = _("Email Suppression")
        verbose_name_plural = _("Email Suppressions")
        indexes: ClassVar[tuple[models.Index, ...]] = (
            models.Index(fields=["reason"]),
            models.Index(fields=["suppressed_at"]),
            models.Index(fields=["expires_at"]),
        )

    def __str__(self) -> str:
        return f"Suppressed: {self.email_hash[:8]}... ({self.get_reason_display()})"

    @classmethod
    def suppress(
        cls,
        email: str,
        reason: str,
        provider: str = "",
        expires_days: int | None = None,
    ) -> "EmailSuppression":
        """
        Add an email to the suppression list.

        Args:
            email: Email address to suppress
            reason: Suppression reason code
            provider: Email provider that reported the issue
            expires_days: Days until suppression expires (None = permanent)
        """
        email_hash = hashlib.sha256(email.lower().encode()).hexdigest()
        expires_at = None
        if expires_days:
            expires_at = timezone.now() + timedelta(days=expires_days)

        now = timezone.now()

        # Use transaction with select_for_update to prevent TOCTOU race
        with transaction.atomic():
            # Try to get existing suppression with row lock
            existing = cls.objects.select_for_update().filter(email_hash=email_hash).first()

            if existing:
                # Update existing - increment bounce count atomically
                existing.reason = reason
                existing.provider = provider
                existing.expires_at = expires_at
                existing.bounce_count = models.F("bounce_count") + 1
                existing.last_bounce_at = now
                existing.save()
                # Refresh to get actual bounce_count value after F() expression
                existing.refresh_from_db()
                return existing
            else:
                # Create new suppression
                return cls.objects.create(
                    email_hash=email_hash,
                    reason=reason,
                    provider=provider,
                    expires_at=expires_at,
                    bounce_count=1,
                    last_bounce_at=now,
                )

    @classmethod
    def is_suppressed(cls, email: str) -> bool:
        """Check if an email is currently suppressed."""
        email_hash = hashlib.sha256(email.lower().encode()).hexdigest()

        suppression = cls.objects.filter(email_hash=email_hash).first()
        if not suppression:
            return False

        # Check if expired
        if suppression.expires_at and suppression.expires_at < timezone.now():
            suppression.delete()
            return False

        return True


# ===============================================================================
# EMAIL PREFERENCE (GDPR-Compliant)
# ===============================================================================


class EmailPreference(models.Model):
    """
    Customer email preferences for GDPR-compliant marketing and notification management.
    Tracks per-category consent and unsubscribe history.
    """

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)

    # Customer reference
    customer = models.OneToOneField(
        "customers.Customer",
        on_delete=models.CASCADE,
        related_name="email_preferences",
        help_text=_("Customer these preferences belong to"),
    )

    # Category preferences (all default to True except marketing)
    transactional = models.BooleanField(
        default=True,
        help_text=_("Receive transactional emails (invoices, receipts)"),
    )
    billing = models.BooleanField(
        default=True,
        help_text=_("Receive billing notifications (payment reminders)"),
    )
    service = models.BooleanField(
        default=True,
        help_text=_("Receive service notifications (provisioning, changes)"),
    )
    security = models.BooleanField(
        default=True,
        help_text=_("Receive security alerts (login attempts, 2FA)"),
    )
    marketing = models.BooleanField(
        default=False,
        help_text=_("Receive marketing emails (requires explicit consent)"),
    )
    newsletter = models.BooleanField(
        default=False,
        help_text=_("Receive newsletter (requires explicit consent)"),
    )
    product_updates = models.BooleanField(
        default=True,
        help_text=_("Receive product update notifications"),
    )

    # GDPR tracking
    marketing_consent_date = models.DateTimeField(
        null=True,
        blank=True,
        help_text=_("When marketing consent was given"),
    )
    marketing_consent_source = models.CharField(
        max_length=100,
        blank=True,
        help_text=_("How consent was obtained (signup, preference_center, etc.)"),
    )

    # Unsubscribe tracking
    global_unsubscribe = models.BooleanField(
        default=False,
        help_text=_("Globally unsubscribed from all non-essential emails"),
    )
    unsubscribed_at = models.DateTimeField(null=True, blank=True)
    unsubscribe_reason = models.CharField(max_length=255, blank=True)

    # Delivery preferences
    FREQUENCY_CHOICES: ClassVar[tuple[tuple[str, str], ...]] = (
        ("immediate", _("Immediate")),
        ("daily_digest", _("Daily Digest")),
        ("weekly_digest", _("Weekly Digest")),
    )
    notification_frequency = models.CharField(
        max_length=20,
        choices=FREQUENCY_CHOICES,
        default="immediate",
        help_text=_("How often to receive non-urgent notifications"),
    )

    # Audit fields
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = "notification_email_preferences"
        verbose_name = _("Email Preference")
        verbose_name_plural = _("Email Preferences")

    def __str__(self) -> str:
        return f"Email Preferences for {self.customer}"

    def can_receive(self, category: str) -> bool:
        """
        Check if customer can receive emails of a specific category.

        Transactional emails (billing, security) are always allowed.
        Marketing requires explicit consent.
        """
        # Global unsubscribe blocks everything except critical transactional
        if self.global_unsubscribe and category not in ("billing", "security", "transactional"):
            return False

        # Map category to preference field
        category_map = {
            "transactional": True,  # Always allowed
            "billing": self.billing,
            "service": self.service,
            "security": True,  # Always allowed for security
            "marketing": self.marketing,
            "newsletter": self.newsletter,
            "product_updates": self.product_updates,
            # Aliases
            "provisioning": self.service,
            "support": self.service,
            "welcome": self.transactional,
            "renewal": self.billing,
            "suspension": self.billing,
            "termination": self.billing,
            "domain": self.service,
            "maintenance": self.service,
            "compliance": True,  # Legal compliance always allowed
            "system": self.transactional,
        }

        return category_map.get(category, True)

    def update_marketing_consent(self, consent: bool, source: str = "") -> None:
        """Update marketing consent with GDPR tracking and row-level locking.

        Withdrawal preserves marketing_consent_date / marketing_consent_source
        as audit-trail evidence of when the original grant occurred (GDPR Art. 7
        "demonstrate consent" — historical grant remains demonstrable even after
        withdrawal). Only the grant branch updates those fields.
        """
        with transaction.atomic():
            locked = EmailPreference.objects.select_for_update(of=("self",)).get(pk=self.pk)
            locked.marketing = consent
            if consent:
                locked.marketing_consent_date = timezone.now()
                locked.marketing_consent_source = source
                locked.save(
                    update_fields=["marketing", "marketing_consent_date", "marketing_consent_source", "updated_at"]
                )
            else:
                # Withdrawal does NOT touch consent_date/source — keep historical grant evidence.
                locked.save(update_fields=["marketing", "updated_at"])
            # Refresh self from locked instance
            self.marketing = locked.marketing
            self.marketing_consent_date = locked.marketing_consent_date
            self.marketing_consent_source = locked.marketing_consent_source


# ===============================================================================
# UNSUBSCRIBE TOKEN (GDPR Art. 5 Data Minimization)
# ===============================================================================

TOKEN_EXPIRY_DAYS = 30


class UnsubscribeToken(models.Model):
    """
    Opaque token for email unsubscribe URLs.

    Replaces the previous pattern of embedding email addresses directly in
    unsubscribe URLs, which violated GDPR Art. 5(1)(c) data minimization.
    URLs now use only the UUID token: /email/unsubscribe/{uuid}/
    """

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    email = models.EmailField(help_text=_("Email address this token was generated for"))
    template_key = models.CharField(max_length=100, help_text=_("Template key that triggered this email"))
    created_at = models.DateTimeField(auto_now_add=True)
    used_at = models.DateTimeField(null=True, blank=True, help_text=_("When this token was consumed"))

    class Meta:
        db_table = "notification_unsubscribe_tokens"
        verbose_name = _("Unsubscribe Token")
        verbose_name_plural = _("Unsubscribe Tokens")
        indexes: ClassVar[tuple[models.Index, ...]] = (
            models.Index(fields=["email", "-created_at"]),
            models.Index(fields=["-created_at"]),
        )

    def __str__(self) -> str:
        return f"Unsubscribe {self.id} ({self.email[:3]}***)"

    def is_expired(self) -> bool:
        """Check if this token has expired."""
        return timezone.now() > self.created_at + timedelta(days=TOKEN_EXPIRY_DAYS)

    def consume(self) -> bool:
        """Mark token as consumed. Returns False if already used or expired.

        Caller must hold a select_for_update() lock on this row (or be inside
        an atomic block that does) to prevent TOCTOU races.
        """
        if self.used_at is not None:
            return False
        if self.is_expired():
            return False
        self.used_at = timezone.now()
        self.save(update_fields=["used_at"])
        return True
