"""
Support ticket models for PRAHO Platform
Romanian hosting provider customer support system.
"""

from typing import Any

from django.contrib.contenttypes.fields import GenericForeignKey
from django.contrib.contenttypes.models import ContentType
from django.db import models
from django.utils.translation import gettext_lazy as _


class SupportCategory(models.Model):
    """Support ticket categories"""

    name = models.CharField(max_length=100, verbose_name=_('Category Name'))
    name_en = models.CharField(max_length=100, verbose_name=_('Name (EN)'))
    description = models.TextField(blank=True, verbose_name=_('Description'))

    # Romanian specific categories
    icon = models.CharField(max_length=50, default='help-circle', verbose_name=_('Icon'))
    color = models.CharField(max_length=7, default='#3B82F6', verbose_name=_('Color'))

    # Service level
    sla_response_hours = models.PositiveIntegerField(
        default=24,
        verbose_name=_('SLA Response (hours)')
    )
    sla_resolution_hours = models.PositiveIntegerField(
        default=72,
        verbose_name=_('SLA Resolution (hours)')
    )

    # Auto-assignment
    auto_assign_to = models.ForeignKey(
        'users.User',
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        limit_choices_to={'role__in': ['support', 'admin']},
        verbose_name=_('Auto Assign To')
    )

    is_active = models.BooleanField(default=True, verbose_name=_('Active'))
    sort_order = models.PositiveIntegerField(default=0, verbose_name=_('Sort Order'))

    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = 'support_categories'
        verbose_name = _('Support Category')
        verbose_name_plural = _('Support Categories')
        ordering = ['sort_order', 'name']

    def __str__(self) -> str:
        return self.name


class Ticket(models.Model):
    """Customer support ticket"""

    STATUS_CHOICES = [
        ('new', _('New')),
        ('open', _('Open')),
        ('pending', _('Pending')),
        ('resolved', _('Resolved')),
        ('closed', _('Closed')),
        ('cancelled', _('Cancelled')),
    ]

    PRIORITY_CHOICES = [
        ('low', _('Low')),
        ('normal', _('Normal')),
        ('high', _('High')),
        ('urgent', _('Urgent')),
        ('critical', _('Critical')),
    ]

    SOURCE_CHOICES = [
        ('web', _('Website')),
        ('email', _('Email')),
        ('phone', _('Phone')),
        ('chat', _('Chat')),
        ('api', _('API')),
        ('internal', _('Internal')),
    ]

    # Ticket identification
    ticket_number = models.CharField(
        max_length=20,
        unique=True,
        verbose_name=_('Ticket Number')
    )

    # Basic info
    title = models.CharField(max_length=200, verbose_name=_('Title'))
    description = models.TextField(verbose_name=_('Description'))

    # Customer and assignment
    customer = models.ForeignKey(
        'customers.Customer',
        on_delete=models.CASCADE,
        related_name='tickets',
        verbose_name=_('Customer')
    )
    contact_person = models.CharField(
        max_length=100,
        blank=True,
        verbose_name=_('Contact Person')
    )
    contact_email = models.EmailField(verbose_name=_('Contact Email'))
    contact_phone = models.CharField(max_length=20, blank=True, verbose_name=_('Contact Phone'))

    # Classification
    category = models.ForeignKey(
        SupportCategory,
        on_delete=models.SET_NULL,
        null=True,
        verbose_name=_('Category')
    )
    priority = models.CharField(
        max_length=20,
        choices=PRIORITY_CHOICES,
        default='normal',
        verbose_name=_('Priority')
    )
    status = models.CharField(
        max_length=20,
        choices=STATUS_CHOICES,
        default='new',
        verbose_name=_('Status')
    )
    source = models.CharField(
        max_length=20,
        choices=SOURCE_CHOICES,
        default='web',
        verbose_name=_('Source')
    )

    # Assignment
    assigned_to = models.ForeignKey(
        'users.User',
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        limit_choices_to={'role__in': ['support', 'admin', 'manager']},
        related_name='assigned_tickets',
        verbose_name=_('Assigned To')
    )
    assigned_at = models.DateTimeField(null=True, blank=True, verbose_name=_('Assigned At'))

    # Service relation
    related_service = models.ForeignKey(
        'provisioning.Service',
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='tickets',
        verbose_name=_('Related Service')
    )

    # Generic relation for other objects
    content_type = models.ForeignKey(ContentType, on_delete=models.CASCADE, null=True, blank=True)
    object_id = models.PositiveIntegerField(null=True, blank=True)
    related_object = GenericForeignKey('content_type', 'object_id')

    # SLA tracking
    sla_response_due = models.DateTimeField(null=True, blank=True)
    sla_resolution_due = models.DateTimeField(null=True, blank=True)
    first_response_at = models.DateTimeField(null=True, blank=True)
    resolved_at = models.DateTimeField(null=True, blank=True)

    # Time tracking
    estimated_hours = models.DecimalField(
        max_digits=5,
        decimal_places=2,
        null=True,
        blank=True,
        verbose_name=_('Estimated Hours')
    )
    actual_hours = models.DecimalField(
        max_digits=5,
        decimal_places=2,
        default=0,
        verbose_name=_('Actual Hours')
    )

    # Customer satisfaction
    satisfaction_rating = models.PositiveIntegerField(
        null=True,
        blank=True,
        verbose_name=_('Satisfaction Rating (1-5)')
    )
    satisfaction_comment = models.TextField(blank=True, verbose_name=_('Satisfaction Comment'))

    # Flags
    is_escalated = models.BooleanField(default=False, verbose_name=_('Escalated'))
    is_public = models.BooleanField(default=True, verbose_name=_('Public for Customer'))
    requires_customer_response = models.BooleanField(
        default=False,
        verbose_name=_('Requires Customer Response')
    )

    # Audit
    created_at = models.DateTimeField(auto_now_add=True, verbose_name=_('Created At'))
    updated_at = models.DateTimeField(auto_now=True, verbose_name=_('Updated At'))
    created_by = models.ForeignKey(
        'users.User',
        on_delete=models.SET_NULL,
        null=True,
        related_name='created_tickets'
    )

    class Meta:
        db_table = 'tickets'
        verbose_name = _('Support Ticket')
        verbose_name_plural = _('Support Tickets')
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['customer', 'status']),
            models.Index(fields=['assigned_to', 'status']),
            models.Index(fields=['status', 'priority']),
            models.Index(fields=['category']),
            models.Index(fields=['ticket_number']),
        ]

    def __str__(self) -> str:
        return f"#{self.ticket_number}: {self.title}"

    def save(self, *args: Any, **kwargs: Any) -> None:
        if not self.ticket_number:
            self.ticket_number = self._generate_ticket_number()

        # Set SLA deadlines
        if not self.sla_response_due and self.category:
            from datetime import timedelta

            from django.utils import timezone

            self.sla_response_due = timezone.now() + timedelta(
                hours=self.category.sla_response_hours
            )
            self.sla_resolution_due = timezone.now() + timedelta(
                hours=self.category.sla_resolution_hours
            )

        super().save(*args, **kwargs)

    def _generate_ticket_number(self) -> str:
        """Generate unique ticket number"""
        from django.utils import timezone
        year = timezone.now().year

        # Get last ticket number for this year
        last_ticket = Ticket.objects.filter(
            ticket_number__startswith=f"TK{year}"
        ).order_by('ticket_number').last()

        if last_ticket:
            last_num = int(last_ticket.ticket_number.split('-')[1])
            next_num = last_num + 1
        else:
            next_num = 1

        return f"TK{year}-{next_num:05d}"

    @property
    def is_sla_breach_response(self) -> bool:
        """Check if SLA response time is breached"""
        if not self.sla_response_due or self.first_response_at:
            return False

        from django.utils import timezone
        return timezone.now() > self.sla_response_due

    @property
    def is_sla_breach_resolution(self) -> bool:
        """Check if SLA resolution time is breached"""
        if not self.sla_resolution_due or self.resolved_at:
            return False

        from django.utils import timezone
        return timezone.now() > self.sla_resolution_due

    def get_priority_color(self) -> str:
        """Get color for priority display"""
        colors = {
            'low': '#10B981',      # Green
            'normal': '#3B82F6',   # Blue
            'high': '#F59E0B',     # Amber
            'urgent': '#EF4444',   # Red
            'critical': '#7C2D12', # Dark red
        }
        return colors.get(self.priority, '#6B7280')

    def get_status_color(self) -> str:
        """Get color for status display"""
        colors = {
            'new': '#8B5CF6',      # Purple
            'open': '#3B82F6',     # Blue
            'pending': '#F59E0B',  # Amber
            'resolved': '#10B981', # Green
            'closed': '#6B7280',   # Gray
            'cancelled': '#EF4444', # Red
        }
        return colors.get(self.status, '#6B7280')


class TicketComment(models.Model):
    """Comments/replies on support tickets"""

    COMMENT_TYPE_CHOICES = [
        ('customer', _('Customer')),
        ('support', _('Support')),
        ('internal', _('Internal')),
        ('system', _('System')),
    ]

    ticket = models.ForeignKey(
        Ticket,
        on_delete=models.CASCADE,
        related_name='comments',
        verbose_name=_('Ticket')
    )

    content = models.TextField(verbose_name=_('Content'))
    comment_type = models.CharField(
        max_length=20,
        choices=COMMENT_TYPE_CHOICES,
        default='support',
        verbose_name=_('Comment Type')
    )

    # Author (can be staff or customer)
    author = models.ForeignKey(
        'users.User',
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        verbose_name=_('Author')
    )
    author_name = models.CharField(
        max_length=100,
        blank=True,
        verbose_name=_('Author Name')
    )
    author_email = models.EmailField(blank=True, verbose_name=_('Author Email'))

    # Visibility
    is_public = models.BooleanField(default=True, verbose_name=_('Public'))
    is_solution = models.BooleanField(default=False, verbose_name=_('Is Solution'))

    # Time tracking
    time_spent = models.DecimalField(
        max_digits=5,
        decimal_places=2,
        default=0,
        verbose_name=_('Time Spent (hours)')
    )

    created_at = models.DateTimeField(auto_now_add=True, verbose_name=_('Created At'))
    updated_at = models.DateTimeField(auto_now=True, verbose_name=_('Updated At'))

    class Meta:
        db_table = 'ticket_comments'
        verbose_name = _('Ticket Comment')
        verbose_name_plural = _('Ticket Comments')
        ordering = ['created_at']
        indexes = [
            models.Index(fields=['ticket', 'created_at']),
            models.Index(fields=['comment_type']),
            models.Index(fields=['is_public']),
        ]

    def __str__(self) -> str:
        return f"Comment pe {self.ticket.ticket_number} de {self.get_author_name()}"

    def get_author_name(self) -> str:
        """Get comment author name"""
        if self.author:
            return self.author.get_full_name()
        return self.author_name or 'Anonim'


class TicketAttachment(models.Model):
    """File attachments for tickets"""

    ticket = models.ForeignKey(
        Ticket,
        on_delete=models.CASCADE,
        related_name='attachments',
        verbose_name=_('Ticket')
    )
    comment = models.ForeignKey(
        TicketComment,
        on_delete=models.CASCADE,
        null=True,
        blank=True,
        related_name='attachments',
        verbose_name=_('Comment')
    )

    file = models.FileField(
        upload_to='tickets/attachments/',
        verbose_name=_('File')
    )
    filename = models.CharField(max_length=255, verbose_name=_('Filename'))
    file_size = models.PositiveIntegerField(verbose_name=_('File Size'))
    content_type = models.CharField(max_length=100, verbose_name=_('Content Type'))

    # Security
    is_safe = models.BooleanField(default=True, verbose_name=_('Safe'))
    virus_scan_result = models.CharField(max_length=50, blank=True)

    uploaded_by = models.ForeignKey(
        'users.User',
        on_delete=models.SET_NULL,
        null=True,
        verbose_name=_('Uploaded By')
    )
    uploaded_at = models.DateTimeField(auto_now_add=True, verbose_name=_('Uploaded At'))

    class Meta:
        db_table = 'ticket_attachments'
        verbose_name = _('Ticket Attachment')
        verbose_name_plural = _('Ticket Attachments')
        ordering = ['uploaded_at']
        indexes = [
            models.Index(fields=['ticket']),
            models.Index(fields=['comment']),
        ]

    def __str__(self) -> str:
        return f"{self.filename} - {self.ticket.ticket_number}"

    def get_file_size_display(self) -> str:
        """Human readable file size"""
        size: float = float(self.file_size)
        for unit in ['B', 'KB', 'MB', 'GB']:
            if size < 1024.0:
                return f"{size:.1f} {unit}"
            size /= 1024.0
        return f"{size:.1f} TB"


class TicketWorklog(models.Model):
    """Work time tracking for tickets"""

    ticket = models.ForeignKey(
        Ticket,
        on_delete=models.CASCADE,
        related_name='worklogs',
        verbose_name=_('Ticket')
    )

    user = models.ForeignKey(
        'users.User',
        on_delete=models.CASCADE,
        verbose_name=_('User')
    )

    description = models.TextField(verbose_name=_('Activity Description'))
    time_spent = models.DecimalField(
        max_digits=5,
        decimal_places=2,
        verbose_name=_('Time Spent (hours)')
    )

    # Billing
    is_billable = models.BooleanField(default=False, verbose_name=_('Billable'))
    hourly_rate = models.DecimalField(
        max_digits=8,
        decimal_places=2,
        null=True,
        blank=True,
        verbose_name=_('Hourly Rate')
    )

    work_date = models.DateField(verbose_name=_('Work Date'))
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = 'ticket_worklogs'
        verbose_name = _('Ticket Worklog')
        verbose_name_plural = _('Ticket Worklogs')
        ordering = ['-work_date']
        indexes = [
            models.Index(fields=['ticket', 'work_date']),
            models.Index(fields=['user', 'work_date']),
            models.Index(fields=['is_billable']),
        ]

    def __str__(self) -> str:
        return f"{self.user.get_full_name()} - {self.time_spent}h pe {self.ticket.ticket_number}"

    @property
    def total_cost(self) -> float:
        """Calculate total cost if billable"""
        if self.is_billable and self.hourly_rate:
            return float(self.time_spent * self.hourly_rate)
        return 0.0
