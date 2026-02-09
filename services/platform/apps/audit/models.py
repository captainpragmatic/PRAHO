"""
Audit models for tracking all system changes.
Implements Romanian compliance requirements and security audit trails.
"""

from __future__ import annotations

import uuid
from typing import Any, ClassVar, TypedDict

from django.contrib.auth import get_user_model
from django.contrib.contenttypes.fields import GenericForeignKey
from django.contrib.contenttypes.models import ContentType
from django.db import models

User = get_user_model()

# ===============================================================================
# TypedDict Definitions for JSON Fields
# ===============================================================================


class AuditMetadata(TypedDict, total=False):
    """Metadata for audit events and investigations"""

    ip_address: str
    user_agent: str
    request_id: str
    session_key: str
    severity: str
    tags: list[str]


class AuditEvidence(TypedDict, total=False):
    """Evidence collected for audit investigations"""

    file_paths: list[str]
    screenshots: list[str]
    logs: dict[str, Any]
    network_data: dict[str, Any]
    system_state: dict[str, Any]


class RemediationAction(TypedDict):
    """Remediation action structure"""

    action_type: str
    description: str
    automated: bool
    completed: bool
    completed_at: str | None


class AuditEvent(models.Model):
    """Immutable audit log for all system changes."""

    # ======================================================================
    # AUDIT EVENT CATEGORIES (Security Classification)
    # ======================================================================
    CATEGORY_CHOICES: ClassVar[tuple[tuple[str, str], ...]] = (
        ("authentication", "Authentication"),
        ("authorization", "Authorization"),
        ("account_management", "Account Management"),
        ("data_protection", "Data Protection"),
        ("security_event", "Security Event"),
        ("business_operation", "Business Operation"),
        ("system_admin", "System Administration"),
        ("compliance", "Compliance"),
        ("privacy", "Privacy"),
        ("integration", "Integration"),
    )

    # Security severity levels for threat analysis
    SEVERITY_CHOICES: ClassVar[tuple[tuple[str, str], ...]] = (
        ("low", "Low"),
        ("medium", "Medium"),
        ("high", "High"),
        ("critical", "Critical"),
    )

    ACTION_CHOICES: ClassVar[tuple[tuple[str, str], ...]] = (
        # ======================================================================
        # GENERIC CRUD OPERATIONS
        # ======================================================================
        ("create", "Create"),
        ("update", "Update"),
        ("delete", "Delete"),
        ("view", "View"),
        ("access", "Access"),
        ("export", "Export"),
        ("import", "Import"),
        # ======================================================================
        # AUTHENTICATION EVENTS (ISO 27001, NIST Standards)
        # ======================================================================
        ("login_success", "Login Success"),
        ("login_failed", "Login Failed"),
        ("login_failed_password", "Login Failed - Invalid Password"),
        ("login_failed_user_not_found", "Login Failed - User Not Found"),
        ("login_failed_account_locked", "Login Failed - Account Locked"),
        ("login_failed_2fa", "Login Failed - 2FA Verification"),
        ("logout_manual", "Manual Logout"),
        ("logout_session_expired", "Session Expired Logout"),
        ("logout_concurrent_session", "Concurrent Session Logout"),
        ("logout_security_event", "Security Event Logout"),
        ("account_locked", "Account Locked"),
        ("account_unlocked", "Account Unlocked"),
        ("session_rotation", "Session Rotation"),
        ("session_terminated", "Session Terminated"),
        # ======================================================================
        # PASSWORD MANAGEMENT (NIST SP 800-63B)
        # ======================================================================
        ("password_changed", "Password Changed"),
        ("password_reset_requested", "Password Reset Requested"),
        ("password_reset_completed", "Password Reset Completed"),
        ("password_reset_failed", "Password Reset Failed"),
        ("password_strength_weak", "Weak Password Attempted"),
        ("password_compromised", "Compromised Password Detected"),
        ("password_expired", "Password Expired"),
        ("password_policy_violation", "Password Policy Violation"),
        # ======================================================================
        # 2FA/MFA SECURITY EVENTS (NIST SP 800-63B)
        # ======================================================================
        ("2fa_enabled", "2FA Enabled"),
        ("2fa_disabled", "2FA Disabled"),
        ("2fa_admin_reset", "2FA Admin Reset"),
        ("2fa_backup_codes_generated", "2FA Backup Codes Generated"),
        ("2fa_backup_codes_viewed", "2FA Backup Codes Viewed"),
        ("2fa_backup_code_used", "2FA Backup Code Used"),
        ("2fa_secret_regenerated", "2FA Secret Regenerated"),
        ("2fa_verification_success", "2FA Verification Success"),
        ("2fa_verification_failed", "2FA Verification Failed"),
        ("2fa_setup_started", "2FA Setup Started"),
        ("2fa_setup_completed", "2FA Setup Completed"),
        ("2fa_recovery_used", "2FA Recovery Code Used"),
        ("2fa_device_registered", "2FA Device Registered"),
        ("2fa_device_removed", "2FA Device Removed"),
        # ======================================================================
        # PROFILE & ACCOUNT MANAGEMENT (GDPR Article 12-22)
        # ======================================================================
        ("profile_updated", "Profile Updated"),
        ("profile_picture_changed", "Profile Picture Changed"),
        ("email_changed", "Email Address Changed"),
        ("email_verification_requested", "Email Verification Requested"),
        ("email_verification_completed", "Email Verification Completed"),
        ("phone_updated", "Phone Number Updated"),
        ("phone_verification_requested", "Phone Verification Requested"),
        ("phone_verification_completed", "Phone Verification Completed"),
        ("name_changed", "Name Changed"),
        ("language_preference_changed", "Language Preference Changed"),
        ("timezone_changed", "Timezone Changed"),
        ("emergency_contact_updated", "Emergency Contact Updated"),
        # ======================================================================
        # PRIVACY & CONSENT (GDPR Articles 6, 7, 13, 14)
        # ======================================================================
        ("privacy_settings_changed", "Privacy Settings Changed"),
        ("marketing_consent_granted", "Marketing Consent Granted"),
        ("marketing_consent_withdrawn", "Marketing Consent Withdrawn"),
        ("gdpr_consent_granted", "GDPR Consent Granted"),
        ("gdpr_consent_withdrawn", "GDPR Consent Withdrawn"),
        ("data_processing_consent_changed", "Data Processing Consent Changed"),
        ("cookie_consent_updated", "Cookie Consent Updated"),
        ("privacy_policy_accepted", "Privacy Policy Accepted"),
        ("terms_of_service_accepted", "Terms of Service Accepted"),
        # ======================================================================
        # NOTIFICATION PREFERENCES
        # ======================================================================
        ("notification_settings_changed", "Notification Settings Changed"),
        ("email_notifications_toggled", "Email Notifications Toggled"),
        ("sms_notifications_toggled", "SMS Notifications Toggled"),
        ("push_notifications_toggled", "Push Notifications Toggled"),
        ("notification_frequency_changed", "Notification Frequency Changed"),
        # ======================================================================
        # AUTHORIZATION EVENTS (RBAC/ABAC)
        # ======================================================================
        ("role_assigned", "Role Assigned"),
        ("role_removed", "Role Removed"),
        ("permission_granted", "Permission Granted"),
        ("permission_revoked", "Permission Revoked"),
        ("access_denied", "Access Denied"),
        ("privilege_escalation_attempt", "Privilege Escalation Attempt"),
        ("staff_role_changed", "Staff Role Changed"),
        ("customer_role_changed", "Customer Role Changed"),
        # ======================================================================
        # CUSTOMER RELATIONSHIP MANAGEMENT
        # ======================================================================
        ("customer_membership_created", "Customer Membership Created"),
        ("customer_membership_updated", "Customer Membership Updated"),
        ("customer_membership_deleted", "Customer Membership Deleted"),
        ("primary_customer_changed", "Primary Customer Changed"),
        ("customer_access_granted", "Customer Access Granted"),
        ("customer_access_revoked", "Customer Access Revoked"),
        ("customer_context_switched", "Customer Context Switched"),
        # ======================================================================
        # API & INTEGRATION EVENTS
        # ======================================================================
        ("api_key_generated", "API Key Generated"),
        ("api_key_regenerated", "API Key Regenerated"),
        ("api_key_revoked", "API Key Revoked"),
        ("api_key_used", "API Key Used"),
        ("api_access_denied", "API Access Denied"),
        ("webhook_configured", "Webhook Configured"),
        ("webhook_updated", "Webhook Updated"),
        ("webhook_removed", "Webhook Removed"),
        # ======================================================================
        # SECURITY EVENTS (ISO 27001 A.12.4)
        # ======================================================================
        ("security_incident_detected", "Security Incident Detected"),
        ("suspicious_activity", "Suspicious Activity"),
        ("brute_force_attempt", "Brute Force Attempt"),
        ("ip_blocked", "IP Address Blocked"),
        ("ip_unblocked", "IP Address Unblocked"),
        ("rate_limit_exceeded", "Rate Limit Exceeded"),
        ("malicious_request", "Malicious Request Detected"),
        ("security_scan_detected", "Security Scan Detected"),
        # ======================================================================
        # DATA PROTECTION EVENTS (GDPR)
        # ======================================================================
        ("data_export_requested", "Data Export Requested"),
        ("data_export_completed", "Data Export Completed"),
        ("data_export_downloaded", "Data Export Downloaded"),
        ("data_deletion_requested", "Data Deletion Requested"),
        ("data_deletion_completed", "Data Deletion Completed"),
        ("data_anonymization_completed", "Data Anonymization Completed"),
        ("data_breach_detected", "Data Breach Detected"),
        ("data_breach_contained", "Data Breach Contained"),
        ("data_breach_reported", "Data Breach Reported"),
        # ======================================================================
        # BUSINESS OPERATIONS (Romanian Compliance)
        # ======================================================================
        ("invoice_accessed", "Invoice Accessed"),
        ("invoice_downloaded", "Invoice Downloaded"),
        ("payment_method_added", "Payment Method Added"),
        ("payment_method_updated", "Payment Method Updated"),
        ("payment_method_removed", "Payment Method Removed"),
        ("billing_address_updated", "Billing Address Updated"),
        ("tax_information_updated", "Tax Information Updated"),
        ("order_placed", "Order Placed"),
        ("order_cancelled", "Order Cancelled"),
        ("service_activated", "Service Activated"),
        ("service_suspended", "Service Suspended"),
        ("support_ticket_created", "Support Ticket Created"),
        ("support_ticket_updated", "Support Ticket Updated"),
        ("support_ticket_closed", "Support Ticket Closed"),
        # ======================================================================
        # BILLING & INVOICE EVENTS (Romanian e-Factura Compliance)
        # ======================================================================
        ("proforma_created", "Proforma Created"),
        ("proforma_converted", "Proforma Converted to Invoice"),
        ("proforma_expired", "Proforma Expired"),
        ("invoice_created", "Invoice Created"),
        ("invoice_issued", "Invoice Issued"),
        ("invoice_sent", "Invoice Sent"),
        ("invoice_paid", "Invoice Paid"),
        ("invoice_partially_paid", "Invoice Partially Paid"),
        ("invoice_overdue", "Invoice Overdue"),
        ("invoice_voided", "Invoice Voided"),
        ("invoice_refunded", "Invoice Refunded"),
        ("invoice_status_changed", "Invoice Status Changed"),
        ("invoice_number_generated", "Invoice Number Generated"),
        ("invoice_pdf_generated", "Invoice PDF Generated"),
        ("invoice_xml_generated", "Invoice XML Generated"),
        ("efactura_submitted", "e-Factura Submitted"),
        ("efactura_accepted", "e-Factura Accepted"),
        ("efactura_rejected", "e-Factura Rejected"),
        ("vat_calculation_applied", "VAT Calculation Applied"),
        ("tax_rule_applied", "Tax Rule Applied"),
        ("currency_conversion_applied", "Currency Conversion Applied"),
        # ======================================================================
        # PAYMENT PROCESSING EVENTS
        # ======================================================================
        ("payment_initiated", "Payment Initiated"),
        ("payment_processing", "Payment Processing"),
        ("payment_succeeded", "Payment Succeeded"),
        ("payment_failed", "Payment Failed"),
        ("payment_refunded", "Payment Refunded"),
        ("payment_partially_refunded", "Payment Partially Refunded"),
        ("payment_retry_scheduled", "Payment Retry Scheduled"),
        ("payment_retry_attempted", "Payment Retry Attempted"),
        ("payment_retry_succeeded", "Payment Retry Succeeded"),
        ("payment_retry_failed", "Payment Retry Failed"),
        ("payment_retry_exhausted", "Payment Retry Exhausted"),
        ("payment_method_changed", "Payment Method Changed"),
        ("payment_gateway_error", "Payment Gateway Error"),
        ("payment_fraud_detected", "Payment Fraud Detected"),
        ("payment_chargeback_received", "Payment Chargeback Received"),
        ("dunning_email_sent", "Dunning Email Sent"),
        ("collection_run_started", "Collection Run Started"),
        ("collection_run_completed", "Collection Run Completed"),
        # ======================================================================
        # CREDIT & BALANCE MANAGEMENT
        # ======================================================================
        ("credit_added", "Credit Added"),
        ("credit_used", "Credit Used"),
        ("credit_adjusted", "Credit Adjusted"),
        ("credit_expired", "Credit Expired"),
        ("balance_low_warning", "Balance Low Warning"),
        ("balance_insufficient", "Balance Insufficient"),
        ("credit_limit_changed", "Credit Limit Changed"),
        ("credit_hold_applied", "Credit Hold Applied"),
        ("credit_hold_released", "Credit Hold Released"),
        # ======================================================================
        # ORDER MANAGEMENT EVENTS
        # ======================================================================
        ("order_created", "Order Created"),
        ("order_updated", "Order Updated"),
        ("order_status_changed", "Order Status Changed"),
        ("order_item_added", "Order Item Added"),
        ("order_item_removed", "Order Item Removed"),
        ("order_item_updated", "Order Item Updated"),
        ("order_quantity_changed", "Order Quantity Changed"),
        ("order_pricing_updated", "Order Pricing Updated"),
        ("order_submitted", "Order Submitted"),
        ("order_confirmed", "Order Confirmed"),
        ("order_processing", "Order Processing"),
        ("order_completed", "Order Completed"),
        ("order_cancelled_customer", "Order Cancelled by Customer"),
        ("order_cancelled_admin", "Order Cancelled by Admin"),
        ("order_failed", "Order Failed"),
        ("order_refund_requested", "Order Refund Requested"),
        ("order_refund_approved", "Order Refund Approved"),
        ("order_refund_processed", "Order Refund Processed"),
        ("order_discount_applied", "Order Discount Applied"),
        ("order_discount_removed", "Order Discount Removed"),
        ("order_tax_calculated", "Order Tax Calculated"),
        ("order_shipping_updated", "Order Shipping Updated"),
        ("order_notes_updated", "Order Notes Updated"),
        # ======================================================================
        # PROVISIONING & SERVICE EVENTS
        # ======================================================================
        ("provisioning_started", "Provisioning Started"),
        ("provisioning_in_progress", "Provisioning In Progress"),
        ("provisioning_completed", "Provisioning Completed"),
        ("provisioning_failed", "Provisioning Failed"),
        ("provisioning_retried", "Provisioning Retried"),
        ("service_configuration_updated", "Service Configuration Updated"),
        ("domain_associated", "Domain Associated"),
        ("domain_dissociated", "Domain Dissociated"),
        ("service_credentials_generated", "Service Credentials Generated"),
        ("service_access_granted", "Service Access Granted"),
        ("service_access_revoked", "Service Access Revoked"),
        # ======================================================================
        # SYSTEM & ADMINISTRATIVE EVENTS
        # ======================================================================
        ("system_maintenance_started", "System Maintenance Started"),
        ("system_maintenance_completed", "System Maintenance Completed"),
        ("backup_created", "Backup Created"),
        ("backup_restored", "Backup Restored"),
        ("configuration_changed", "Configuration Changed"),
        ("user_impersonation_started", "User Impersonation Started"),
        ("user_impersonation_ended", "User Impersonation Ended"),
        ("bulk_operation_started", "Bulk Operation Started"),
        ("bulk_operation_completed", "Bulk Operation Completed"),
        # ======================================================================
<<<<<<< HEAD
        # INFRASTRUCTURE & NODE DEPLOYMENT EVENTS
        # ======================================================================
        ("node_deployment_created", "Node Deployment Created"),
        ("node_deployment_started", "Node Deployment Started"),
        ("node_deployment_terraform_init", "Terraform Initialized"),
        ("node_deployment_terraform_apply", "Terraform Applied"),
        ("node_deployment_ansible_run", "Ansible Playbook Executed"),
        ("node_deployment_validated", "Node Validation Completed"),
        ("node_deployment_registered", "Node Registered"),
        ("node_deployment_completed", "Node Deployment Completed"),
        ("node_deployment_failed", "Node Deployment Failed"),
        ("node_deployment_retry", "Node Deployment Retry"),
        ("node_destroy_started", "Node Destruction Started"),
        ("node_destroy_completed", "Node Destruction Completed"),
        ("node_destroy_failed", "Node Destruction Failed"),
        ("cloud_provider_created", "Cloud Provider Created"),
        ("cloud_provider_updated", "Cloud Provider Updated"),
        ("cloud_provider_deleted", "Cloud Provider Deleted"),
        ("node_size_created", "Node Size Created"),
        ("node_size_updated", "Node Size Updated"),
        ("node_region_toggled", "Node Region Toggled"),
        ("infrastructure_ssh_key_generated", "SSH Key Generated"),
        ("infrastructure_ssh_key_revoked", "SSH Key Revoked"),
=======
        # PROMOTIONS & COUPONS EVENTS
        # ======================================================================
        # Campaign management
        ("promotion_campaign_created", "Promotion Campaign Created"),
        ("promotion_campaign_updated", "Promotion Campaign Updated"),
        ("promotion_campaign_activated", "Promotion Campaign Activated"),
        ("promotion_campaign_paused", "Promotion Campaign Paused"),
        ("promotion_campaign_cancelled", "Promotion Campaign Cancelled"),
        ("promotion_campaign_completed", "Promotion Campaign Completed"),
        # Coupon management
        ("coupon_created", "Coupon Created"),
        ("coupon_updated", "Coupon Updated"),
        ("coupon_deleted", "Coupon Deleted"),
        ("coupon_activated", "Coupon Activated"),
        ("coupon_deactivated", "Coupon Deactivated"),
        ("coupon_expired", "Coupon Expired"),
        ("coupon_depleted", "Coupon Usage Limit Reached"),
        ("coupon_batch_created", "Coupon Batch Created"),
        # Coupon redemption
        ("coupon_redemption_initiated", "Coupon Redemption Initiated"),
        ("coupon_redemption_applied", "Coupon Redemption Applied"),
        ("coupon_redemption_failed", "Coupon Redemption Failed"),
        ("coupon_redemption_reversed", "Coupon Redemption Reversed"),
        ("coupon_validation_failed", "Coupon Validation Failed"),
        # Promotion rules
        ("promotion_rule_created", "Promotion Rule Created"),
        ("promotion_rule_updated", "Promotion Rule Updated"),
        ("promotion_rule_activated", "Promotion Rule Activated"),
        ("promotion_rule_deactivated", "Promotion Rule Deactivated"),
        ("promotion_rule_applied", "Promotion Rule Applied"),
        # Gift cards
        ("gift_card_created", "Gift Card Created"),
        ("gift_card_activated", "Gift Card Activated"),
        ("gift_card_redeemed", "Gift Card Redeemed"),
        ("gift_card_refunded", "Gift Card Refunded"),
        ("gift_card_adjusted", "Gift Card Balance Adjusted"),
        ("gift_card_expired", "Gift Card Expired"),
        ("gift_card_cancelled", "Gift Card Cancelled"),
        ("gift_card_depleted", "Gift Card Depleted"),
        ("gift_card_status_changed", "Gift Card Status Changed"),
        ("gift_card_transaction", "Gift Card Transaction"),
        # Referrals
        ("referral_code_created", "Referral Code Created"),
        ("referral_code_updated", "Referral Code Updated"),
        ("referral_created", "Referral Created"),
        ("referral_qualified", "Referral Qualified"),
        ("referral_rewarded", "Referral Rewarded"),
        ("referral_expired", "Referral Expired"),
        ("referral_cancelled", "Referral Cancelled"),
        ("referral_updated", "Referral Updated"),
        # Loyalty program
        ("loyalty_program_created", "Loyalty Program Created"),
        ("loyalty_program_updated", "Loyalty Program Updated"),
        ("loyalty_tier_created", "Loyalty Tier Created"),
        ("loyalty_tier_updated", "Loyalty Tier Updated"),
        ("loyalty_member_enrolled", "Loyalty Member Enrolled"),
        ("loyalty_tier_changed", "Loyalty Tier Changed"),
        ("loyalty_points_earned", "Loyalty Points Earned"),
        ("loyalty_points_redeemed", "Loyalty Points Redeemed"),
        ("loyalty_points_expired", "Loyalty Points Expired"),
        ("loyalty_points_adjusted", "Loyalty Points Adjusted"),
        ("loyalty_points_bonus", "Loyalty Points Bonus"),
        ("loyalty_points_refunded", "Loyalty Points Refunded"),
        ("loyalty_tier_bonus", "Loyalty Tier Bonus"),
        ("loyalty_transaction", "Loyalty Transaction"),
>>>>>>> origin/claude/promotions-coupons-system-RK7WI
    )

    # Unique event ID
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)

    # When and where
    timestamp = models.DateTimeField(auto_now_add=True, db_index=True)
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    user_agent = models.TextField(blank=True)

    # Who
    user = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True)
    actor_type = models.CharField(max_length=20, default="user")  # user, system, api

    # What
    action = models.CharField(max_length=50, choices=ACTION_CHOICES, db_index=True)  # Increased from 30 to 50

    # Categorization and severity for security analysis
    category = models.CharField(max_length=30, choices=CATEGORY_CHOICES, default="business_operation", db_index=True)
    severity = models.CharField(max_length=10, choices=SEVERITY_CHOICES, default="low", db_index=True)

    # Risk assessment flags
    is_sensitive = models.BooleanField(default=False, db_index=True)  # PII, financial, or security sensitive
    requires_review = models.BooleanField(default=False, db_index=True)  # Flagged for manual review

    # What object (generic foreign key)
    # Support both integer and UUID primary keys (CharField for mixed PK types)
    content_type = models.ForeignKey(ContentType, on_delete=models.CASCADE)
    object_id = models.CharField(max_length=36, db_index=True)  # 36 chars for UUIDs, integers fit fine
    content_object = GenericForeignKey("content_type", "object_id")

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
        db_table = "audit_event"
        ordering: ClassVar[tuple[str, ...]] = ("-timestamp",)
        indexes: ClassVar[tuple[models.Index, ...]] = (
            # Core performance indexes
            models.Index(fields=["user", "-timestamp"]),
            models.Index(fields=["content_type", "object_id", "-timestamp"]),
            models.Index(fields=["action", "-timestamp"]),
            models.Index(fields=["request_id"]),
            # Security analysis indexes
            models.Index(fields=["category", "-timestamp"], name="idx_audit_category_time"),
            models.Index(fields=["severity", "-timestamp"], name="idx_audit_severity_time"),
            models.Index(fields=["is_sensitive", "-timestamp"], name="idx_audit_sensitive_time"),
            models.Index(fields=["requires_review", "-timestamp"], name="idx_audit_review_time"),
            # Combined security indexes for threat detection
            models.Index(fields=["category", "severity", "-timestamp"], name="idx_audit_cat_sev_time"),
            models.Index(fields=["user", "category", "-timestamp"], name="idx_audit_user_cat_time"),
            models.Index(fields=["ip_address", "severity", "-timestamp"], name="idx_audit_ip_sev_time"),
            # Authentication-specific indexes for performance
            models.Index(fields=["user", "action", "-timestamp"], name="idx_audit_user_action_time"),
            models.Index(fields=["ip_address", "action", "-timestamp"], name="idx_audit_ip_action_time"),
            models.Index(fields=["session_key", "-timestamp"], name="idx_audit_session_time"),
            models.Index(fields=["actor_type", "action", "-timestamp"], name="idx_audit_actor_action_time"),
            # Compliance and reporting indexes
            models.Index(fields=["user", "category", "is_sensitive", "-timestamp"], name="idx_audit_compliance"),
            models.Index(fields=["timestamp", "category"], name="idx_audit_time_cat"),  # For time-based reporting
        )

    def __str__(self) -> str:
        return f"{self.action} on {self.content_type} by {self.user or 'System'}"


class DataExport(models.Model):
    """Track GDPR data exports and similar compliance operations."""

    STATUS_CHOICES: ClassVar[tuple[tuple[str, str], ...]] = (
        ("pending", "Pending"),
        ("processing", "Processing"),
        ("completed", "Completed"),
        ("failed", "Failed"),
    )

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)

    # Request details
    requested_by = models.ForeignKey(User, on_delete=models.CASCADE)
    requested_at = models.DateTimeField(auto_now_add=True)

    # Export scope
    export_type = models.CharField(max_length=50)  # gdpr, audit, billing, etc.
    scope = models.JSONField(default=dict)  # What data to export

    # Processing
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default="pending")
    started_at = models.DateTimeField(null=True, blank=True)
    completed_at = models.DateTimeField(null=True, blank=True)

    # Results
    file_path = models.CharField(max_length=255, blank=True, default="")
    file_size = models.PositiveIntegerField(null=True, blank=True)
    record_count = models.PositiveIntegerField(null=True, blank=True)

    # Security
    expires_at = models.DateTimeField()  # Auto-delete after this date
    download_count = models.PositiveIntegerField(default=0)

    # Error handling
    error_message = models.TextField(blank=True)

    class Meta:
        db_table = "audit_data_export"
        ordering: ClassVar[tuple[str, ...]] = ("-requested_at",)

    def __str__(self) -> str:
        return f"{self.export_type} export by {self.requested_by}"


class AuditIntegrityCheck(models.Model):
    """Track audit data integrity verification for tamper detection."""

    STATUS_CHOICES: ClassVar[tuple[tuple[str, str], ...]] = (
        ("healthy", "Healthy"),
        ("warning", "Warning"),
        ("compromised", "Compromised"),
    )

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)

    # Check details
    check_type = models.CharField(max_length=50, db_index=True)  # hash_verification, sequence_check, gap_detection
    checked_at = models.DateTimeField(auto_now_add=True, db_index=True)
    period_start = models.DateTimeField(db_index=True)
    period_end = models.DateTimeField(db_index=True)

    # Results
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default="healthy")
    records_checked = models.PositiveIntegerField(default=0)
    issues_found = models.PositiveIntegerField(default=0)

    # Findings
    findings = models.JSONField(default=list, blank=True)  # List of detected issues
    hash_chain = models.TextField(blank=True)  # Cryptographic hash chain

    # Metadata
    metadata = models.JSONField(default=dict, blank=True)

    class Meta:
        db_table = "audit_integrity_check"
        ordering: ClassVar[tuple[str, ...]] = ("-checked_at",)
        indexes: ClassVar[tuple[models.Index, ...]] = (
            models.Index(fields=["check_type", "-checked_at"]),
            models.Index(fields=["status", "-checked_at"]),
            models.Index(fields=["period_start", "period_end"]),
        )

    def __str__(self) -> str:
        return f"{self.check_type} check: {self.status} ({self.issues_found} issues)"


class AuditRetentionPolicy(models.Model):
    """Define retention policies for different types of audit events."""

    RETENTION_ACTION_CHOICES: ClassVar[tuple[tuple[str, str], ...]] = (
        ("archive", "Archive to Cold Storage"),
        ("delete", "Permanent Deletion"),
        ("anonymize", "Anonymize Sensitive Data"),
    )

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)

    # Policy definition
    name = models.CharField(max_length=100, unique=True)
    description = models.TextField(blank=True)
    category = models.CharField(max_length=30, choices=AuditEvent.CATEGORY_CHOICES)
    severity = models.CharField(max_length=10, choices=AuditEvent.SEVERITY_CHOICES, blank=True)

    # Retention rules
    retention_days = models.PositiveIntegerField()  # Days to keep in active storage
    action = models.CharField(max_length=20, choices=RETENTION_ACTION_CHOICES, default="archive")

    # Compliance requirements
    legal_basis = models.CharField(max_length=200, blank=True)  # Romanian law reference
    is_mandatory = models.BooleanField(default=False)  # Cannot be overridden

    # Policy status
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    created_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True)

    class Meta:
        db_table = "audit_retention_policy"
        ordering: ClassVar[tuple[str, ...]] = ("name",)
        indexes: ClassVar[tuple[models.Index, ...]] = (
            models.Index(fields=["category", "severity"]),
            models.Index(fields=["is_active", "retention_days"]),
        )

    def __str__(self) -> str:
        return f"{self.name} ({self.retention_days} days)"


class AuditSearchQuery(models.Model):
    """Save commonly used audit search queries for staff efficiency."""

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)

    # Query details
    name = models.CharField(max_length=100)
    description = models.TextField(blank=True)
    query_params = models.JSONField(default=dict)  # Serialized search parameters

    # Usage tracking
    created_by = models.ForeignKey(User, on_delete=models.CASCADE)
    created_at = models.DateTimeField(auto_now_add=True)
    last_used_at = models.DateTimeField(null=True, blank=True)
    usage_count = models.PositiveIntegerField(default=0)

    # Sharing
    is_shared = models.BooleanField(default=False)  # Available to all staff
    shared_with: models.ManyToManyField = models.ManyToManyField(User, related_name="shared_audit_queries", blank=True)  # type: ignore[type-arg]

    class Meta:
        db_table = "audit_search_query"
        ordering: ClassVar[tuple[str, ...]] = ("-last_used_at", "name")
        indexes: ClassVar[tuple[models.Index, ...]] = (
            models.Index(fields=["created_by", "-created_at"]),
            models.Index(fields=["is_shared", "-usage_count"]),
        )

    def __str__(self) -> str:
        return f"{self.name} by {self.created_by.email}"


class AuditAlert(models.Model):
    """Track security and compliance alerts generated from audit analysis."""

    ALERT_TYPE_CHOICES: ClassVar[tuple[tuple[str, str], ...]] = (
        ("security_incident", "Security Incident"),
        ("compliance_violation", "Compliance Violation"),
        ("data_integrity", "Data Integrity Issue"),
        ("suspicious_activity", "Suspicious Activity"),
        ("performance_anomaly", "Performance Anomaly"),
        ("retention_violation", "Retention Policy Violation"),
    )

    SEVERITY_CHOICES: ClassVar[tuple[tuple[str, str], ...]] = (
        ("info", "Informational"),
        ("warning", "Warning"),
        ("high", "High Priority"),
        ("critical", "Critical"),
    )

    STATUS_CHOICES: ClassVar[tuple[tuple[str, str], ...]] = (
        ("active", "Active"),
        ("acknowledged", "Acknowledged"),
        ("investigating", "Under Investigation"),
        ("resolved", "Resolved"),
        ("false_positive", "False Positive"),
    )

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)

    # Alert details
    alert_type = models.CharField(max_length=30, choices=ALERT_TYPE_CHOICES, db_index=True)
    severity = models.CharField(max_length=10, choices=SEVERITY_CHOICES, db_index=True)
    title = models.CharField(max_length=200)
    description = models.TextField()

    # Status tracking
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default="active", db_index=True)
    created_at = models.DateTimeField(auto_now_add=True, db_index=True)
    updated_at = models.DateTimeField(auto_now=True)
    resolved_at = models.DateTimeField(null=True, blank=True)

    # Assignment
    assigned_to = models.ForeignKey(
        User, on_delete=models.SET_NULL, null=True, blank=True, related_name="assigned_audit_alerts"
    )
    acknowledged_by = models.ForeignKey(
        User, on_delete=models.SET_NULL, null=True, blank=True, related_name="acknowledged_audit_alerts"
    )
    acknowledged_at = models.DateTimeField(null=True, blank=True)

    # Related data
    related_events = models.ManyToManyField(AuditEvent, blank=True)  # Events that triggered this alert
    affected_users = models.ManyToManyField(  # type: ignore[var-annotated]
        User, blank=True, related_name="audit_alerts"
    )  # Users affected by this alert

    # Evidence and context
    evidence = models.JSONField(default=dict, blank=True)
    metadata = models.JSONField(default=dict, blank=True)

    # Resolution
    resolution_notes = models.TextField(blank=True)
    remediation_actions = models.JSONField(default=list, blank=True)

    class Meta:
        db_table = "audit_alert"
        ordering: ClassVar[tuple[str, ...]] = ("-created_at",)
        indexes: ClassVar[tuple[models.Index, ...]] = (
            models.Index(fields=["alert_type", "-created_at"]),
            models.Index(fields=["severity", "status", "-created_at"]),
            models.Index(fields=["assigned_to", "status"]),
            models.Index(fields=["status", "-created_at"]),
        )

    def __str__(self) -> str:
        return f"{self.get_severity_display()} {self.get_alert_type_display()}: {self.title}"


class ComplianceLog(models.Model):
    """Log compliance-related activities for Romanian regulations."""

    COMPLIANCE_TYPE_CHOICES: ClassVar[tuple[tuple[str, str], ...]] = (
        ("gdpr_consent", "GDPR Consent"),
        ("gdpr_deletion", "GDPR Data Deletion"),
        ("vat_validation", "VAT Number Validation"),
        ("efactura_submission", "e-Factura Submission"),
        ("data_retention", "Data Retention Policy"),
        ("security_incident", "Security Incident"),
        ("audit_integrity", "Audit Data Integrity"),
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
        db_table = "audit_compliance_log"
        ordering: ClassVar[tuple[str, ...]] = ("-timestamp",)
        indexes: ClassVar[tuple[models.Index, ...]] = (
            models.Index(fields=["compliance_type", "-timestamp"]),
            models.Index(fields=["reference_id"]),
            models.Index(fields=["status", "-timestamp"]),
        )

    def __str__(self) -> str:
        return f"{self.compliance_type}: {self.reference_id}"


<<<<<<< HEAD
class SIEMHashChainState(models.Model):
    """
    Track SIEM hash chain state for tamper-proof logging.

    This model maintains the cryptographic hash chain state
    to ensure log integrity and detect tampering.
    """

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)

    # Chain state
    sequence_number = models.BigIntegerField(default=0, db_index=True)
    last_hash = models.CharField(max_length=128, blank=True)
    last_event_id = models.UUIDField(null=True, blank=True)
=======
class CookieConsent(models.Model):
    """
    Track cookie consent preferences for GDPR compliance.
    Stores both authenticated user consent and anonymous visitor consent via cookie ID.
    """

    CONSENT_STATUS_CHOICES: ClassVar[tuple[tuple[str, str], ...]] = (
        ("pending", "Pending"),
        ("accepted_all", "Accepted All"),
        ("accepted_essential", "Essential Only"),
        ("customized", "Customized"),
        ("withdrawn", "Withdrawn"),
    )

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)

    # User identification (one of these should be set)
    user = models.ForeignKey(
        User, on_delete=models.CASCADE, null=True, blank=True, related_name="cookie_consents"
    )
    cookie_id = models.CharField(
        max_length=64, blank=True, db_index=True, help_text="Anonymous visitor identifier from cookie"
    )

    # Consent status
    status = models.CharField(max_length=20, choices=CONSENT_STATUS_CHOICES, default="pending")

    # Individual category consents
    essential_cookies = models.BooleanField(default=True, help_text="Always required")
    functional_cookies = models.BooleanField(default=False)
    analytics_cookies = models.BooleanField(default=False)
    marketing_cookies = models.BooleanField(default=False)

    # Metadata
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    user_agent = models.TextField(blank=True)
>>>>>>> origin/claude/gdpr-compliance-audit-4heye

    # Timestamps
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

<<<<<<< HEAD
    # Configuration
    hash_algorithm = models.CharField(max_length=20, default="sha256")
    is_active = models.BooleanField(default=True)

    class Meta:
        db_table = "audit_siem_hash_chain_state"
        ordering: ClassVar[tuple[str, ...]] = ("-updated_at",)

    def __str__(self) -> str:
        return f"HashChain #{self.sequence_number} ({self.hash_algorithm})"


class ComplianceReportRecord(models.Model):
    """Track generated compliance reports for audit trail."""

    REPORT_TYPE_CHOICES: ClassVar[tuple[tuple[str, str], ...]] = (
        ("security_summary", "Security Summary"),
        ("access_review", "Access Review"),
        ("authentication_audit", "Authentication Audit"),
        ("data_access_audit", "Data Access Audit"),
        ("compliance_violations", "Compliance Violations"),
        ("gdpr_compliance", "GDPR Compliance"),
        ("romanian_fiscal_compliance", "Romanian Fiscal Compliance"),
        ("log_integrity", "Log Integrity"),
        ("retention_compliance", "Retention Compliance"),
    )

    FRAMEWORK_CHOICES: ClassVar[tuple[tuple[str, str], ...]] = (
        ("iso27001", "ISO 27001"),
        ("soc2", "SOC 2"),
        ("gdpr", "GDPR"),
        ("romanian_fiscal", "Romanian Fiscal"),
        ("e_factura", "e-Factura"),
        ("nist", "NIST"),
        ("pci_dss", "PCI DSS"),
    )

    STATUS_CHOICES: ClassVar[tuple[tuple[str, str], ...]] = (
        ("compliant", "Compliant"),
        ("partial", "Partial Compliance"),
        ("non_compliant", "Non-Compliant"),
    )

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)

    # Report identification
    report_type = models.CharField(max_length=50, choices=REPORT_TYPE_CHOICES, db_index=True)
    framework = models.CharField(max_length=30, choices=FRAMEWORK_CHOICES, blank=True, db_index=True)

    # Period covered
    period_start = models.DateTimeField()
    period_end = models.DateTimeField()

    # Generation info
    generated_at = models.DateTimeField(auto_now_add=True, db_index=True)
    generated_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True)

    # Results
    overall_status = models.CharField(max_length=20, choices=STATUS_CHOICES, db_index=True)
    compliance_score = models.DecimalField(max_digits=5, decimal_places=2)
    total_events = models.PositiveIntegerField(default=0)
    total_violations = models.PositiveIntegerField(default=0)
    critical_findings = models.PositiveIntegerField(default=0)

    # Report storage
    file_path = models.CharField(max_length=500, blank=True)
    file_format = models.CharField(max_length=10, default="json")

    # Summary data
    sections_summary = models.JSONField(default=list, blank=True)
    violations_summary = models.JSONField(default=list, blank=True)

    class Meta:
        db_table = "audit_compliance_report"
        ordering: ClassVar[tuple[str, ...]] = ("-generated_at",)
        indexes: ClassVar[tuple[models.Index, ...]] = (
            models.Index(fields=["report_type", "-generated_at"]),
            models.Index(fields=["framework", "-generated_at"]),
            models.Index(fields=["overall_status", "-generated_at"]),
            models.Index(fields=["period_start", "period_end"]),
        )

    def __str__(self) -> str:
        return f"{self.report_type} report ({self.overall_status}) - {self.generated_at.date()}"


class SIEMExportLog(models.Model):
    """Track SIEM export operations for monitoring."""

    STATUS_CHOICES: ClassVar[tuple[tuple[str, str], ...]] = (
        ("pending", "Pending"),
        ("in_progress", "In Progress"),
        ("completed", "Completed"),
        ("failed", "Failed"),
    )

    FORMAT_CHOICES: ClassVar[tuple[tuple[str, str], ...]] = (
        ("cef", "CEF (ArcSight/Splunk)"),
        ("leef", "LEEF (IBM QRadar)"),
        ("json", "JSON (ELK/Graylog)"),
        ("syslog", "Syslog (RFC 5424)"),
        ("ocsf", "OCSF"),
    )

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)

    # Export details
    export_format = models.CharField(max_length=10, choices=FORMAT_CHOICES)
    destination = models.CharField(max_length=255)  # Host:port or file path

    # Period
    period_start = models.DateTimeField()
    period_end = models.DateTimeField()

    # Status
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default="pending")
    started_at = models.DateTimeField(null=True, blank=True)
    completed_at = models.DateTimeField(null=True, blank=True)

    # Results
    events_exported = models.PositiveIntegerField(default=0)
    events_failed = models.PositiveIntegerField(default=0)
    bytes_transferred = models.BigIntegerField(default=0)

    # Error handling
    error_message = models.TextField(blank=True)
    retry_count = models.PositiveIntegerField(default=0)

    # Metadata
    metadata = models.JSONField(default=dict, blank=True)

    class Meta:
        db_table = "audit_siem_export_log"
        ordering: ClassVar[tuple[str, ...]] = ("-started_at",)
        indexes: ClassVar[tuple[models.Index, ...]] = (
            models.Index(fields=["status", "-started_at"]),
            models.Index(fields=["export_format", "-started_at"]),
        )

    def __str__(self) -> str:
        return f"SIEM Export ({self.export_format}) - {self.status}"
=======
    # Consent version (for tracking policy updates)
    consent_version = models.CharField(max_length=20, default="1.0")

    class Meta:
        db_table = "audit_cookie_consent"
        ordering: ClassVar[tuple[str, ...]] = ("-updated_at",)
        indexes: ClassVar[tuple[models.Index, ...]] = (
            models.Index(fields=["user", "-updated_at"]),
            models.Index(fields=["cookie_id", "-updated_at"]),
            models.Index(fields=["status", "-created_at"]),
        )

    def __str__(self) -> str:
        identifier = self.user.email if self.user else f"cookie:{self.cookie_id[:8]}..."
        return f"Cookie consent: {identifier} ({self.status})"

    @property
    def has_analytics_consent(self) -> bool:
        """Check if analytics cookies are consented."""
        return self.status in ("accepted_all", "customized") and self.analytics_cookies

    @property
    def has_functional_consent(self) -> bool:
        """Check if functional cookies are consented."""
        return self.status in ("accepted_all", "customized") and self.functional_cookies

    @property
    def has_marketing_consent(self) -> bool:
        """Check if marketing cookies are consented."""
        return self.status in ("accepted_all", "customized") and self.marketing_cookies
>>>>>>> origin/claude/gdpr-compliance-audit-4heye
