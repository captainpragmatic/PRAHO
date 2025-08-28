"""
Audit models for tracking all system changes.
Implements Romanian compliance requirements and security audit trails.
"""

import uuid
from typing import ClassVar

from django.contrib.auth import get_user_model
from django.contrib.contenttypes.fields import GenericForeignKey
from django.contrib.contenttypes.models import ContentType
from django.db import models

User = get_user_model()


class AuditEvent(models.Model):
    """Immutable audit log for all system changes."""

    ACTION_CHOICES: ClassVar[tuple[tuple[str, str], ...]] = (
        ('create', 'Create'),
        ('update', 'Update'),
        ('delete', 'Delete'),
        ('login', 'Login'),
        ('logout', 'Logout'),
        ('access', 'Access'),
        ('export', 'Export'),
        ('import', 'Import'),
        # 2FA Security Events
        ('2fa_enabled', '2FA Enabled'),
        ('2fa_disabled', '2FA Disabled'),
        ('2fa_admin_reset', '2FA Admin Reset'),
        ('2fa_backup_codes_generated', '2FA Backup Codes Generated'),
        ('2fa_backup_codes_viewed', '2FA Backup Codes Viewed'),
        ('2fa_backup_code_used', '2FA Backup Code Used'),
        ('2fa_secret_regenerated', '2FA Secret Regenerated'),
        ('2fa_verification_success', '2FA Verification Success'),
        ('2fa_verification_failed', '2FA Verification Failed'),
        ('2fa_setup_started', '2FA Setup Started'),
        ('2fa_setup_completed', '2FA Setup Completed'),
    )

    # Unique event ID
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)

    # When and where
    timestamp = models.DateTimeField(auto_now_add=True, db_index=True)
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    user_agent = models.TextField(blank=True)

    # Who
    user = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True)
    actor_type = models.CharField(max_length=20, default='user')  # user, system, api

    # What
    action = models.CharField(max_length=30, choices=ACTION_CHOICES, db_index=True)

    # What object (generic foreign key)
    # Support both integer and UUID primary keys (CharField for mixed PK types)
    content_type = models.ForeignKey(ContentType, on_delete=models.CASCADE)
    object_id = models.CharField(max_length=36, db_index=True)  # 36 chars for UUIDs, integers fit fine
    content_object = GenericForeignKey('content_type', 'object_id')

    # Changes
    old_values = models.JSONField(default=dict, blank=True)
    new_values = models.JSONField(default=dict, blank=True)

    # Context
    description = models.TextField(blank=True)
    request_id = models.CharField(max_length=36, blank=True, db_index=True)
    session_key = models.CharField(max_length=40, blank=True)

    # Additional metadata
    metadata = models.JSONField(default=dict, blank=True)

    class Meta:
        db_table = 'audit_event'
        ordering: ClassVar[tuple[str, ...]] = ('-timestamp',)
        indexes: ClassVar[tuple[models.Index, ...]] = (
            models.Index(fields=['user', '-timestamp']),
            models.Index(fields=['content_type', 'object_id', '-timestamp']),
            models.Index(fields=['action', '-timestamp']),
            models.Index(fields=['request_id']),
        )

    def __str__(self) -> str:
        return f"{self.action} on {self.content_type} by {self.user or 'System'}"


class DataExport(models.Model):
    """Track GDPR data exports and similar compliance operations."""

    STATUS_CHOICES: ClassVar[tuple[tuple[str, str], ...]] = (
        ('pending', 'Pending'),
        ('processing', 'Processing'),
        ('completed', 'Completed'),
        ('failed', 'Failed'),
    )

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)

    # Request details
    requested_by = models.ForeignKey(User, on_delete=models.CASCADE)
    requested_at = models.DateTimeField(auto_now_add=True)

    # Export scope
    export_type = models.CharField(max_length=50)  # gdpr, audit, billing, etc.
    scope = models.JSONField(default=dict)  # What data to export

    # Processing
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='pending')
    started_at = models.DateTimeField(null=True, blank=True)
    completed_at = models.DateTimeField(null=True, blank=True)

    # Results
    file_path = models.CharField(max_length=255, blank=True, default='')
    file_size = models.PositiveIntegerField(null=True, blank=True)
    record_count = models.PositiveIntegerField(null=True, blank=True)

    # Security
    expires_at = models.DateTimeField()  # Auto-delete after this date
    download_count = models.PositiveIntegerField(default=0)

    # Error handling
    error_message = models.TextField(blank=True)

    class Meta:
        db_table = 'audit_data_export'
        ordering: ClassVar[tuple[str, ...]] = ('-requested_at',)

    def __str__(self) -> str:
        return f"{self.export_type} export by {self.requested_by}"


class ComplianceLog(models.Model):
    """Log compliance-related activities for Romanian regulations."""

    COMPLIANCE_TYPE_CHOICES: ClassVar[tuple[tuple[str, str], ...]] = (
        ('gdpr_consent', 'GDPR Consent'),
        ('gdpr_deletion', 'GDPR Data Deletion'),
        ('vat_validation', 'VAT Number Validation'),
        ('efactura_submission', 'e-Factura Submission'),
        ('data_retention', 'Data Retention Policy'),
        ('security_incident', 'Security Incident'),
    )

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)

    # Compliance details
    compliance_type = models.CharField(max_length=30, choices=COMPLIANCE_TYPE_CHOICES)
    reference_id = models.CharField(max_length=100, db_index=True)  # External ID

    # When and who
    timestamp = models.DateTimeField(auto_now_add=True, db_index=True)
    user = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True)

    # What happened
    description = models.TextField()
    status = models.CharField(max_length=20)  # success, failed, pending

    # Evidence and metadata
    evidence = models.JSONField(default=dict, blank=True)
    metadata = models.JSONField(default=dict, blank=True)

    class Meta:
        db_table = 'audit_compliance_log'
        ordering: ClassVar[tuple[str, ...]] = ('-timestamp',)
        indexes: ClassVar[tuple[models.Index, ...]] = (
            models.Index(fields=['compliance_type', '-timestamp']),
            models.Index(fields=['reference_id']),
            models.Index(fields=['status', '-timestamp']),
        )

    def __str__(self) -> str:
        return f"{self.compliance_type}: {self.reference_id}"
