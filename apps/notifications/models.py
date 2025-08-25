"""
Notifications models for PRAHO Platform
Email templates and communication logging for Romanian hosting provider.
Aligned with PostgreSQL hosting panel schema v1.
"""

import uuid
from typing import Any, Optional

from django.core.validators import EmailValidator
from django.db import models
from django.utils.translation import gettext_lazy as _

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
        max_length=100,
        help_text=_("Template identifier (e.g., 'invoice_issued', 'payment_reminder')")
    )
    locale = models.CharField(
        max_length=10,
        default='ro',
        help_text=_("Language/locale code (ro, en)")
    )

    # Template content
    subject = models.CharField(
        max_length=255,
        help_text=_("Email subject line (supports variables)")
    )
    body_html = models.TextField(
        help_text=_("HTML email body (supports Django template syntax)")
    )
    body_text = models.TextField(
        blank=True,
        help_text=_("Plain text fallback (auto-generated if empty)")
    )

    # Template metadata
    description = models.TextField(
        blank=True,
        help_text=_("Description of when this template is used")
    )
    variables = models.JSONField(
        default=dict,
        blank=True,
        help_text=_("Available template variables and their descriptions")
    )

    # Status and versioning
    is_active = models.BooleanField(
        default=True,
        help_text=_("Whether this template is available for use")
    )
    version = models.PositiveIntegerField(
        default=1,
        help_text=_("Template version for change tracking")
    )

    # Romanian hosting provider categories
    CATEGORY_CHOICES = [
        ('billing', _('Billing & Invoices')),
        ('dunning', _('Payment Reminders')),
        ('provisioning', _('Service Provisioning')),
        ('support', _('Support & Tickets')),
        ('welcome', _('Welcome & Onboarding')),
        ('renewal', _('Service Renewals')),
        ('suspension', _('Service Suspension')),
        ('termination', _('Service Termination')),
        ('domain', _('Domain Management')),
        ('security', _('Security Alerts')),
        ('maintenance', _('Maintenance Notifications')),
        ('marketing', _('Marketing & Promotions')),
        ('compliance', _('Legal & Compliance')),
        ('system', _('System Notifications')),
    ]
    category = models.CharField(
        max_length=20,
        choices=CATEGORY_CHOICES,
        default='system',
        help_text=_("Template category for organization")
    )

    # Audit fields
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    created_by = models.ForeignKey(
        'users.User',
        on_delete=models.SET_NULL,
        null=True,
        related_name='created_email_templates',
        help_text=_("User who created this template")
    )

    class Meta:
        db_table = 'email_template'
        verbose_name = _('Email Template')
        verbose_name_plural = _('Email Templates')
        unique_together = [['key', 'locale']]
        indexes = [
            models.Index(fields=['key', 'locale']),
            models.Index(fields=['category', 'is_active']),
            models.Index(fields=['created_at']),
        ]
        ordering = ['category', 'key', 'locale']

    def __str__(self) -> str:
        return f"{self.key} ({self.locale}): {self.subject}"

    def get_subject_display(self) -> str:
        """Truncated subject for admin display"""
        if len(self.subject) > 50:
            return f"{self.subject[:47]}..."
        return self.subject


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
        'customers.Customer',
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='email_logs',
        help_text=_("Customer this email was sent to (if applicable)")
    )
    to_addr = models.EmailField(
        validators=[EmailValidator()],
        help_text=_("Recipient email address")
    )
    from_addr = models.EmailField(
        blank=True,
        help_text=_("Sender email address (if different from default)")
    )
    reply_to = models.EmailField(
        blank=True,
        help_text=_("Reply-to email address")
    )

    # Email content
    template_key = models.CharField(
        max_length=100,
        blank=True,
        help_text=_("Template used to generate this email")
    )
    subject = models.CharField(
        max_length=255,
        help_text=_("Actual email subject sent")
    )
    body_text = models.TextField(
        blank=True,
        help_text=_("Plain text version of email body")
    )
    body_html = models.TextField(
        blank=True,
        help_text=_("HTML version of email body")
    )

    # Delivery tracking
    STATUS_CHOICES = [
        ('queued', _('Queued')),           # Waiting to be sent
        ('sending', _('Sending')),         # Currently being processed
        ('sent', _('Sent')),              # Successfully sent to provider
        ('delivered', _('Delivered')),     # Confirmed delivered to recipient
        ('bounced', _('Bounced')),        # Hard bounce from recipient server
        ('soft_bounced', _('Soft Bounced')), # Temporary delivery failure
        ('complained', _('Complained')),   # Marked as spam by recipient
        ('failed', _('Failed')),          # Failed to send
        ('rejected', _('Rejected')),      # Rejected by email provider
    ]
    status = models.CharField(
        max_length=20,
        choices=STATUS_CHOICES,
        default='queued',
        help_text=_("Current delivery status")
    )

    # Provider integration
    provider = models.CharField(
        max_length=50,
        default='smtp',
        help_text=_("Email service provider (smtp, sendgrid, mailgun, etc.)")
    )
    provider_id = models.CharField(
        max_length=255,
        blank=True,
        help_text=_("Provider's unique message ID")
    )
    provider_response = models.JSONField(
        default=dict,
        blank=True,
        help_text=_("Raw provider response for debugging")
    )

    # Timing and tracking
    sent_at = models.DateTimeField(
        auto_now_add=True,
        help_text=_("When email was queued/sent")
    )
    delivered_at = models.DateTimeField(
        null=True,
        blank=True,
        help_text=_("When email was confirmed delivered")
    )
    opened_at = models.DateTimeField(
        null=True,
        blank=True,
        help_text=_("When email was first opened (if tracking enabled)")
    )
    clicked_at = models.DateTimeField(
        null=True,
        blank=True,
        help_text=_("When email links were first clicked")
    )

    # Additional metadata
    meta = models.JSONField(
        default=dict,
        blank=True,
        help_text=_("Additional email metadata (variables used, campaign info, etc.)")
    )

    # Romanian hosting context
    priority = models.CharField(
        max_length=10,
        choices=[
            ('low', _('Low')),
            ('normal', _('Normal')),
            ('high', _('High')),
            ('urgent', _('Urgent')),
        ],
        default='normal',
        help_text=_("Email priority level")
    )

    # User context
    sent_by = models.ForeignKey(
        'users.User',
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='sent_emails',
        help_text=_("User who triggered this email (if manual)")
    )

    class Meta:
        db_table = 'email_log'
        verbose_name = _('Email Log')
        verbose_name_plural = _('Email Logs')
        indexes = [
            models.Index(fields=['to_addr', '-sent_at']),
            models.Index(fields=['customer', '-sent_at']),
            models.Index(fields=['template_key', '-sent_at']),
            models.Index(fields=['status', '-sent_at']),
            models.Index(fields=['provider', '-sent_at']),
            models.Index(fields=['-sent_at']),  # Most recent emails
        ]
        ordering = ['-sent_at']

    def __str__(self) -> str:
        return f"{self.subject} → {self.to_addr} ({self.status})"

    def get_status_display_color(self) -> str:
        """Get color for status display in admin"""
        status_colors = {
            'queued': '#6B7280',      # Gray
            'sending': '#3B82F6',     # Blue
            'sent': '#10B981',        # Green
            'delivered': '#059669',   # Dark green
            'bounced': '#EF4444',     # Red
            'soft_bounced': '#F59E0B', # Amber
            'complained': '#DC2626',  # Dark red
            'failed': '#EF4444',      # Red
            'rejected': '#DC2626',    # Dark red
        }
        return status_colors.get(self.status, '#6B7280')

    def is_successful(self) -> bool:
        """Check if email was successfully delivered"""
        return self.status in ['sent', 'delivered']

    def is_failed(self) -> bool:
        """Check if email failed to deliver"""
        return self.status in ['bounced', 'failed', 'rejected']


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
    name = models.CharField(
        max_length=200,
        help_text=_("Campaign name for identification")
    )
    description = models.TextField(
        blank=True,
        help_text=_("Campaign description and purpose")
    )

    # Campaign configuration
    template = models.ForeignKey(
        EmailTemplate,
        on_delete=models.PROTECT,
        help_text=_("Email template to use for this campaign")
    )

    # Targeting
    AUDIENCE_CHOICES = [
        ('all_customers', _('All Customers')),
        ('active_customers', _('Active Customers')),
        ('inactive_customers', _('Inactive Customers')),
        ('overdue_payments', _('Overdue Payments')),
        ('trial_expiring', _('Trial Expiring')),
        ('custom_filter', _('Custom Filter')),
    ]
    audience = models.CharField(
        max_length=20,
        choices=AUDIENCE_CHOICES,
        default='active_customers',
        help_text=_("Target audience for this campaign")
    )
    audience_filter = models.JSONField(
        default=dict,
        blank=True,
        help_text=_("Custom filter criteria for audience selection")
    )

    # Campaign status
    STATUS_CHOICES = [
        ('draft', _('Draft')),           # Being prepared
        ('scheduled', _('Scheduled')),   # Scheduled for future sending
        ('sending', _('Sending')),       # Currently being sent
        ('sent', _('Sent')),            # Completed successfully
        ('paused', _('Paused')),        # Temporarily paused
        ('cancelled', _('Cancelled')),   # Cancelled before completion
        ('failed', _('Failed')),        # Failed to send
    ]
    status = models.CharField(
        max_length=20,
        choices=STATUS_CHOICES,
        default='draft',
        help_text=_("Current campaign status")
    )

    # Scheduling
    scheduled_at = models.DateTimeField(
        null=True,
        blank=True,
        help_text=_("When to send this campaign (leave blank for immediate)")
    )
    started_at = models.DateTimeField(
        null=True,
        blank=True,
        help_text=_("When campaign sending actually started")
    )
    completed_at = models.DateTimeField(
        null=True,
        blank=True,
        help_text=_("When campaign sending completed")
    )

    # Results tracking
    total_recipients = models.PositiveIntegerField(
        default=0,
        help_text=_("Total number of recipients")
    )
    emails_sent = models.PositiveIntegerField(
        default=0,
        help_text=_("Number of emails successfully sent")
    )
    emails_failed = models.PositiveIntegerField(
        default=0,
        help_text=_("Number of emails that failed to send")
    )

    # Romanian business context
    is_transactional = models.BooleanField(
        default=False,
        help_text=_("Transactional emails (billing, service) vs. marketing")
    )
    requires_consent = models.BooleanField(
        default=True,
        help_text=_("Requires explicit customer consent (GDPR compliance)")
    )

    # Audit fields
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    created_by = models.ForeignKey(
        'users.User',
        on_delete=models.SET_NULL,
        null=True,
        related_name='created_campaigns',
        help_text=_("User who created this campaign")
    )

    class Meta:
        db_table = 'email_campaign'
        verbose_name = _('Email Campaign')
        verbose_name_plural = _('Email Campaigns')
        indexes = [
            models.Index(fields=['status', '-created_at']),
            models.Index(fields=['scheduled_at']),
            models.Index(fields=['-created_at']),
        ]
        ordering = ['-created_at']

    def __str__(self) -> str:
        return f"{self.name} ({self.get_status_display()})"

    def get_success_rate(self) -> float:
        """Calculate campaign success rate percentage"""
        if self.total_recipients == 0:
            return 0
        return round((self.emails_sent / self.total_recipients) * 100, 1)

    def can_be_sent(self) -> bool:
        """Check if campaign can be sent"""
        return self.status in ['draft', 'scheduled', 'paused']

    def is_completed(self) -> bool:
        """Check if campaign is completed"""
        return self.status in ['sent', 'cancelled', 'failed']
