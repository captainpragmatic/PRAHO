"""
Audit models for tracking all system changes.
Implements Romanian compliance requirements and security audit trails.
"""

from __future__ import annotations

import uuid
from collections.abc import Collection, Iterable, Iterator
from contextlib import contextmanager
from contextvars import ContextVar
from typing import TYPE_CHECKING, Any, ClassVar, TypedDict

from django.contrib.auth import get_user_model
from django.contrib.contenttypes.fields import GenericForeignKey
from django.contrib.contenttypes.models import ContentType
from django.db import models, transaction
from django.utils import timezone
from django.utils.translation import gettext_lazy as _

from .session_digest import digest_session_identifiers, session_key_digest

if TYPE_CHECKING:
    from django.utils.functional import _StrPromise

User = get_user_model()

USER_AGENT_MAX_LENGTH = 500

# ===============================================================================
# AUDIT EVENT IMMUTABILITY GUARD (ADR-0016 / ADR-0043)
# ===============================================================================

# A ContextVar, not a threading.local: asyncio tasks and copied contexts each keep their own
# value, and a new thread starts with an empty context, so the permission never leaks sideways.
_audit_mutation_reason: ContextVar[str | None] = ContextVar("audit_mutation_reason", default=None)


class AuditImmutabilityError(Exception):
    """Raised when AuditEvent rows are mutated outside audit_mutation_allowed()."""


@contextmanager
def audit_mutation_allowed(reason: str) -> Iterator[None]:
    """Escape hatch for the audit immutability guard.

    AuditEvent rows are append-only evidence. Every legitimate mutator enters this
    context at its call site with an auditable reason (GDPR anonymization/erasure,
    retention enforcement, integrity stamping/restamping, password-reset cleanup);
    any other ORM mutation raises AuditImmutabilityError. The guard is an ORM-layer
    defense - raw SQL and _base_manager (framework FK cascades) bypass it, which is
    what the integrity MAC exists to catch.

    The reason is what makes the mutation auditable, so a blank one is refused
    instead of unlocking the guard anonymously.
    """
    if not reason or not reason.strip():
        raise ValueError("audit_mutation_allowed() requires a non-blank reason")
    token = _audit_mutation_reason.set(reason)
    try:
        yield
    finally:
        _audit_mutation_reason.reset(token)


def _mutation_allowed() -> bool:
    return bool(_audit_mutation_reason.get())


class AuditEventQuerySet(models.QuerySet["AuditEvent"]):
    """QuerySet that blocks bulk mutation of audit evidence outside the escape hatch."""

    def update(self, **kwargs: Any) -> int:
        self._guard("update()")
        return super().update(**kwargs)

    def bulk_update(self, objs: Iterable[AuditEvent], fields: Iterable[str], batch_size: int | None = None) -> int:
        self._guard("bulk_update()")
        return super().bulk_update(objs, fields, batch_size=batch_size)

    def delete(self) -> tuple[int, dict[str, int]]:
        self._guard("delete()")
        return super().delete()

    def bulk_create(  # noqa: PLR0913 - Django's signature
        self,
        objs: Iterable[AuditEvent],
        batch_size: int | None = None,
        ignore_conflicts: bool = False,
        update_conflicts: bool = False,
        update_fields: Collection[str] | None = None,
        unique_fields: Collection[str] | None = None,
    ) -> list[AuditEvent]:
        """Insert events exactly as save() would: digested, stamped and chained.

        bulk_create sends no pre_save or post_save, so it used to skip the integrity MAC and the
        chain link. A conflict mode is refused: an upsert rewrites an existing row, and ignoring a
        conflict would give an existing id a second chain link.
        """
        if ignore_conflicts or update_conflicts or update_fields or unique_fields:
            raise AuditImmutabilityError(
                "AuditEvent.bulk_create cannot ignore or update conflicts: audit rows are append-only"
            )
        from .person_events import note_erasure_write  # noqa: PLC0415  # Deferred: app registry
        from .signals import (  # noqa: PLC0415  # Deferred: signals imports this module
            append_audit_event_chain_link,
            stamp_audit_event_integrity_hash,
        )

        events = list(objs)
        for event in events:
            (event.session_key, event.description, event.metadata, event.old_values, event.new_values) = (
                digest_session_identifiers(
                    session_key=event.session_key,
                    description=event.description,
                    metadata=event.metadata,
                    old_values=event.old_values,
                    new_values=event.new_values,
                )
            )
            event.user_agent = (event.user_agent or "")[:USER_AGENT_MAX_LENGTH]
            stamp_audit_event_integrity_hash(sender=AuditEvent, instance=event)
        created = super().bulk_create(events, batch_size=batch_size)
        # One transaction, so the chain head is locked once for the whole batch.
        with transaction.atomic():
            for event in created:
                append_audit_event_chain_link(sender=AuditEvent, instance=event, created=True)
                note_erasure_write(event)
        return created

    @staticmethod
    def _guard(operation: str) -> None:
        if not _mutation_allowed():
            raise AuditImmutabilityError(
                f"AuditEvent is append-only; {operation} requires the audit_mutation_allowed() escape hatch"
            )


class AuditLedgerImmutabilityError(Exception):
    """Raised when the audit chain ledger (AuditChainLink) is mutated at all (#313)."""


class AuditChainLinkQuerySet(models.QuerySet["AuditChainLink"]):
    """QuerySet that blocks ALL mutation of chain links — no escape hatch.

    Unlike AuditEvent (which is re-stamped/anonymized/retention-deleted via
    audit_mutation_allowed), a chain link is never legitimately rewritten: any
    UPDATE/DELETE against it is definitionally a chain-rewrite attack. Only INSERT
    is legal. A retention delete of the underlying event is recorded as a NEW
    tombstone link, not a mutation of an existing one.
    """

    def update(self, **kwargs: Any) -> int:
        raise AuditLedgerImmutabilityError("AuditChainLink is append-only; update() is never permitted")

    def bulk_update(self, objs: Iterable[AuditChainLink], fields: Iterable[str], batch_size: int | None = None) -> int:
        raise AuditLedgerImmutabilityError("AuditChainLink is append-only; bulk_update() is never permitted")

    def delete(self) -> tuple[int, dict[str, int]]:
        raise AuditLedgerImmutabilityError("AuditChainLink is append-only; delete() is never permitted")


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

    ACTION_CHOICES: ClassVar[tuple[tuple[str, str | _StrPromise], ...]] = (
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
        ("legal_document_published", "Legal Document Published"),
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
        ("anaf_lookup_completed", "ANAF Lookup Completed"),
        ("anaf_lookup_deferred", "ANAF Lookup Deferred"),
        ("order_placed", "Order Placed"),
        ("order_terms_accepted", "Order Terms Accepted"),
        ("early_performance_requested", "Early Performance Requested"),
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
        ("collection_run_failed", "Collection Run Failed"),
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
        ("status_changed", "Status Changed"),
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
        ("node_drain_started", "Node Drain Started"),
        ("node_drain_completed", "Node Drain Completed"),
        ("node_drain_paused", "Node Drain Paused"),
        ("node_drain_cancelled", "Node Drain Cancelled"),
        ("node_drain_finalized", "Node Drain Finalized"),
        ("virtualmin_server_autofail_deferred", "Virtualmin Server Auto-fail Deferred"),
        ("virtualmin_server_health_alert", "Virtualmin Server Health Alert"),
        ("virtualmin_migration_started", "Virtualmin Migration Started"),
        ("virtualmin_migration_completed", "Virtualmin Migration Completed"),
        ("virtualmin_migration_failed", "Virtualmin Migration Failed"),
        ("virtualmin_migration_needs_review", "Virtualmin Migration Needs Review"),
        ("virtualmin_migration_rolled_back", "Virtualmin Migration Rolled Back"),
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
        ("setting_override_cleared", _("Setting override cleared")),
        ("user_impersonation_started", "User Impersonation Started"),
        ("user_impersonation_ended", "User Impersonation Ended"),
        ("bulk_operation_started", "Bulk Operation Started"),
        ("bulk_operation_completed", "Bulk Operation Completed"),
        # ======================================================================
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
        # ======================================================================
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
        ("coupon_reversal_failed_on_cancellation", "Coupon Reversal Failed on Cancellation"),
        ("gift_card_reversal_failed_on_cancellation", "Gift Card Reversal Failed on Cancellation"),
        ("coupon_reversal_failed_on_refund", "Coupon Reversal Failed on Refund"),
        ("gift_card_reversal_failed_on_refund", "Gift Card Reversal Failed on Refund"),
        (
            "promotion_release_blocked_anomalous_payments",
            "Promotion Release Blocked by Anomalous Payments",
        ),
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
        # ======================================================================
        # WRITTEN BY PLATFORM CODE, REGISTERED BY THE VOCABULARY GUARD
        # tests/audit/test_audit_action_vocabulary.py fails when code writes an action not listed here.
        # ======================================================================
        ("account_hostname_assigned", "Account hostname assigned"),
        ("account_hostname_retired", "Account hostname retired"),
        ("account_unlocked_automatic", "Account unlocked automatic"),
        ("api_token_created", "Api token created"),
        ("api_token_deleted", "Api token deleted"),
        ("auto_payment_created", "Auto payment created"),
        ("auto_payment_failed", "Auto payment failed"),
        ("automatic_payment_reservation_abandoned", "Automatic payment reservation abandoned"),
        ("backup_domain_failed", "Backup domain failed"),
        ("billing_cycle_closed", "Billing cycle closed"),
        ("billing_workflow_completed", "Billing workflow completed"),
        ("bulk_grandfathering_applied", "Bulk grandfathering applied"),
        ("coupon_redemption_updated", "Coupon redemption updated"),
        ("credit_ledger_created", "Credit ledger created"),
        ("credit_ledger_deleted", "Credit ledger deleted"),
        ("credit_ledger_updated", "Credit ledger updated"),
        ("credit_score_reverted", "Credit score reverted"),
        ("credit_score_updated", "Credit score updated"),
        ("customer_address_created", "Customer address created"),
        ("customer_address_updated", "Customer address updated"),
        ("customer_analytics_updated", "Customer analytics updated"),
        ("customer_billing_profile_created", "Customer billing profile created"),
        ("customer_billing_profile_updated", "Customer billing profile updated"),
        ("customer_created", "Customer created"),
        ("customer_deleted", "Customer deleted"),
        ("customer_feedback_processed", "Customer feedback processed"),
        ("customer_hard_deletion_attempted", "Customer hard deletion attempted"),
        ("customer_ltv_adjusted", "Customer ltv adjusted"),
        ("customer_note_created", "Customer note created"),
        ("customer_onboarding_started", "Customer onboarding started"),
        ("customer_payment_method_changed", "Customer payment method changed"),
        ("customer_payment_method_created", "Customer payment method created"),
        ("customer_payment_method_deleted", "Customer payment method deleted"),
        ("customer_payment_method_updated", "Customer payment method updated"),
        ("customer_reactivation_email_sent", "Customer reactivation email sent"),
        ("customer_registration_success", "Customer registration success"),
        ("customer_services_suspended", "Customer services suspended"),
        ("customer_stats_updated", "Customer stats updated"),
        ("customer_status_changed", "Customer status changed"),
        ("customer_tax_profile_created", "Customer tax profile created"),
        ("customer_tax_profile_updated", "Customer tax profile updated"),
        ("customer_updated", "Customer updated"),
        ("customer_user_created", "Customer user created"),
        ("customer_welcome_email_failed", "Customer welcome email failed"),
        ("customer_welcome_email_sent", "Customer welcome email sent"),
        ("d390_export", "D390 export"),
        ("daily_billing_completed", "Daily billing completed"),
        ("dns_fallback", "Dns fallback"),
        ("domain_availability_unconfirmed", "Domain availability unconfirmed"),
        ("domain_deleted", "Domain deleted"),
        ("domain_expired_webhook", "Domain expired webhook"),
        ("domain_lock_changed", "Domain lock changed"),
        ("domain_operation_review_required", "Domain operation review required"),
        ("domain_order_created", "Domain order created"),
        ("domain_order_updated", "Domain order updated"),
        ("domain_recorded_by_staff", "Domain recorded by staff"),
        ("domain_refusal_recorded_by_staff", "Domain refusal recorded by staff"),
        ("domain_registered", "Domain registered"),
        ("domain_registration_completed", "Domain registration completed"),
        ("domain_renewed_webhook", "Domain renewed webhook"),
        ("domain_status_changed", "Domain status changed"),
        ("domain_suspended_webhook", "Domain suspended webhook"),
        ("domain_transfer_code_received", "Domain transfer code received"),
        ("domain_transfer_code_revealed", "Domain transfer code revealed"),
        ("domain_transfer_completed", "Domain transfer completed"),
        ("domain_transfer_completed_webhook", "Domain transfer completed webhook"),
        ("domain_updated", "Domain updated"),
        ("drift_accepted", "Drift accepted"),
        ("drift_auto_resolved", "Drift auto resolved"),
        ("drift_detected", "Drift detected"),
        ("drift_dismissed", "Drift dismissed"),
        ("drift_remediation_applied", "Drift remediation applied"),
        ("drift_remediation_approved", "Drift remediation approved"),
        ("drift_remediation_failed", "Drift remediation failed"),
        ("drift_remediation_rejected", "Drift remediation rejected"),
        ("drift_remediation_requested", "Drift remediation requested"),
        ("drift_remediation_scheduled", "Drift remediation scheduled"),
        ("drift_rollback_triggered", "Drift rollback triggered"),
        ("drift_scan_completed", "Drift scan completed"),
        ("drift_scan_started", "Drift scan started"),
        ("dunning_process_started", "Dunning process started"),
        ("efactura_file_downloaded", "Efactura file downloaded"),
        ("efactura_oauth_token_created", "Efactura oauth token created"),
        ("efactura_oauth_token_deleted", "Efactura oauth token deleted"),
        ("efactura_oauth_token_updated", "Efactura oauth token updated"),
        ("efactura_submission_attempted", "Efactura submission attempted"),
        ("efactura_submission_failed", "Efactura submission failed"),
        ("email_bounced", "Email bounced"),
        ("email_complained", "Email complained"),
        ("email_failed", "Email failed"),
        ("email_sent", "Email sent"),
        ("email_suppressed", "Email suppressed"),
        ("email_suppression_added", "Email suppression added"),
        ("email_suppression_removed", "Email suppression removed"),
        ("email_suppression_updated", "Email suppression updated"),
        ("email_template_deleted", "Email template deleted"),
        ("email_template_updated", "Email template updated"),
        ("email_webhook_invalid_signature", "Email webhook invalid signature"),
        ("expired_trials_processed", "Expired trials processed"),
        ("external_sync_completed", "External sync completed"),
        ("financial_document_access_denied", "Financial document access denied"),
        ("financial_document_accessed", "Financial document accessed"),
        ("fiscal_correction_created", "Fiscal correction created"),
        ("fiscal_correction_deleted", "Fiscal correction deleted"),
        ("fiscal_correction_updated", "Fiscal correction updated"),
        ("fx_rate_conflict", "Fx rate conflict"),
        ("fx_rate_error", "Fx rate error"),
        ("fx_rate_fetch_failed", "Fx rate fetch failed"),
        ("fx_rate_fetched", "Fx rate fetched"),
        ("fx_rate_provenance_promoted", "Fx rate provenance promoted"),
        ("fx_rate_recorded", "Fx rate recorded"),
        ("gift_card_code_revealed", "Gift card code revealed"),
        ("gift_card_delivery_requested", "Gift card delivery requested"),
        ("gift_card_refund_reviewed", "Gift card refund reviewed"),
        ("grace_periods_processed", "Grace periods processed"),
        ("grandfathering_expired", "Grandfathering expired"),
        ("illegal_invoice_deletion", "Illegal invoice deletion"),
        ("integration_connection_test", "Integration connection test"),
        ("invitation_email_sent", "Invitation email sent"),
        ("invitation_sent", "Invitation sent"),
        ("invoice_created_from_order", "Invoice created from order"),
        ("invoice_edited", "Invoice edited"),
        ("invoice_metrics_updated", "Invoice metrics updated"),
        ("invoice_payment_attempt_created", "Invoice payment attempt created"),
        ("invoice_provider_issue_attempted", "Invoice provider issue attempted"),
        ("invoice_provider_issue_failed", "Invoice provider issue failed"),
        ("invoice_provider_issued", "Invoice provider issued"),
        ("invoice_provider_outcome_unknown", "Invoice provider outcome unknown"),
        ("invoice_refund_completed", "Invoice refund completed"),
        ("invoice_refund_recorded", "Invoice refund recorded"),
        ("invoice_refund_service_action", "Invoice refund service action"),
        ("invoice_sequence_increment", "Invoice sequence increment"),
        ("invoice_validation", "Invoice validation"),
        ("large_credit_limit_increase", "Large credit limit increase"),
        ("login_new_location", "Login new location"),
        ("metering_new_usage_blocked", "Metering new usage blocked"),
        ("metering_suspension_applied", "Metering suspension applied"),
        ("metering_throttle_applied", "Metering throttle applied"),
        ("method_error", "Method error"),
        ("method_success", "Method success"),
        ("node_maintenance_completed", "Node maintenance completed"),
        ("node_maintenance_failed", "Node maintenance failed"),
        ("node_maintenance_started", "Node maintenance started"),
        ("node_reboot_completed", "Node reboot completed"),
        ("node_reboot_failed", "Node reboot failed"),
        ("node_start_completed", "Node start completed"),
        ("node_start_failed", "Node start failed"),
        ("node_stop_completed", "Node stop completed"),
        ("node_stop_failed", "Node stop failed"),
        ("node_stop_started", "Node stop started"),
        ("node_upgrade_completed", "Node upgrade completed"),
        ("node_upgrade_failed", "Node upgrade failed"),
        ("node_upgrade_started", "Node upgrade started"),
        ("notification_preference_created", "Notification preference created"),
        ("notification_preference_updated", "Notification preference updated"),
        ("order_confirmed_auto", "Order confirmed auto"),
        ("order_deleted", "Order deleted"),
        ("order_edit", "Order edit"),
        ("order_flagged_for_review", "Order flagged for review"),
        ("order_invoice_linked", "Order invoice linked"),
        ("order_item_deleted", "Order item deleted"),
        ("order_item_fulfilled_by_staff", "Order item fulfilled by staff"),
        ("order_marked_paid", "Order marked paid"),
        ("order_payment_confirmed", "Order payment confirmed"),
        ("order_payment_failed", "Order payment failed"),
        ("order_proforma_unavailable", "Order proforma unavailable"),
        ("order_refund", "Order refund"),
        ("order_timeout_cancelled", "Order timeout cancelled"),
        ("order_vat_calculation", "Order vat calculation"),
        ("payment_deleted", "Payment deleted"),
        ("payment_gateway_fact_mismatch", "Payment gateway fact mismatch"),
        ("payment_gateway_id_recovered", "Payment gateway id recovered"),
        ("payment_gateway_refund", "Payment gateway refund"),
        ("payment_gateway_refund_failed", "Payment gateway refund failed"),
        ("payment_intent_created_direct", "Payment intent created direct"),
        ("payment_method_changed_non_draft", "Payment method changed non draft"),
        ("payment_recorded_on_proforma", "Payment recorded on proforma"),
        ("payment_reminders_cancelled", "Payment reminders cancelled"),
        ("payment_reminders_scheduled", "Payment reminders scheduled"),
        ("payment_status_changed", "Payment status changed"),
        ("pending_registration_confirmed", "Pending registration confirmed"),
        ("portal_password_changed", "Portal password changed"),
        ("price_grandfathering_created", "Price grandfathering created"),
        ("price_grandfathering_deleted", "Price grandfathering deleted"),
        ("price_grandfathering_updated", "Price grandfathering updated"),
        ("product_availability_changed", "Product availability changed"),
        ("product_create_attempt", "Product create attempt"),
        ("product_created", "Product created"),
        ("product_detail_access", "Product detail access"),
        ("product_list_access", "Product list access"),
        ("product_price_create_attempt", "Product price create attempt"),
        ("product_price_created", "Product price created"),
        ("product_price_delete_attempt", "Product price delete attempt"),
        ("product_price_deleted", "Product price deleted"),
        ("product_price_edit_attempt", "Product price edit attempt"),
        ("product_price_updated", "Product price updated"),
        ("product_price_validation_failed", "Product price validation failed"),
        ("product_pricing_access", "Product pricing access"),
        ("product_pricing_changed", "Product pricing changed"),
        ("product_status_changed", "Product status changed"),
        ("product_validation_failed", "Product validation failed"),
        ("proforma_converted_to_invoice", "Proforma converted to invoice"),
        ("proforma_created_from_order", "Proforma created from order"),
        ("proforma_number_generated", "Proforma number generated"),
        ("proforma_updated", "Proforma updated"),
        ("proforma_validation", "Proforma validation"),
        ("provider_issuance_deleted", "Provider issuance deleted"),
        ("provider_partial_refund_needs_manual_correction", "Provider partial refund needs manual correction"),
        ("provisioning_cancelled", "Provisioning cancelled"),
        ("provisioning_task_created", "Provisioning task created"),
        ("provisioning_task_deleted", "Provisioning task deleted"),
        ("provisioning_task_updated", "Provisioning task updated"),
        ("recurring_payment_authorization_created", "Recurring payment authorization created"),
        ("recurring_payment_authorization_deleted", "Recurring payment authorization deleted"),
        ("recurring_payment_authorization_updated", "Recurring payment authorization updated"),
        ("recurring_payment_submission_created", "Recurring payment submission created"),
        ("recurring_payment_submission_deleted", "Recurring payment submission deleted"),
        ("recurring_payment_submission_updated", "Recurring payment submission updated"),
        ("refund_model_created", "Refund model created"),
        ("refund_model_deleted", "Refund model deleted"),
        ("refund_model_updated", "Refund model updated"),
        ("refund_processed", "Refund processed"),
        ("refund_reconciliation_gap", "Refund reconciliation gap"),
        ("refund_retry", "Refund retry"),
        ("registrar_api_credentials_updated", "Registrar api credentials updated"),
        ("registrar_api_domain_availability_check", "Registrar api domain availability check"),
        ("registrar_api_domain_lock", "Registrar api domain lock"),
        ("registrar_api_domain_registration", "Registrar api domain registration"),
        ("registrar_api_domain_renewal", "Registrar api domain renewal"),
        ("registrar_api_domain_transfer", "Registrar api domain transfer"),
        ("registrar_api_nameserver_update", "Registrar api nameserver update"),
        ("registrar_created", "Registrar created"),
        ("registrar_updated", "Registrar updated"),
        ("registrar_webhook_invalid_signature", "Registrar webhook invalid signature"),
        ("registrar_webhook_processing_error", "Registrar webhook processing error"),
        ("registration_system_error", "Registration system error"),
        ("restore_domain_failed", "Restore domain failed"),
        ("review_gate_cancel_unauthorized", "Review gate cancel unauthorized"),
        ("review_gate_unauthorized_attempt", "Review gate unauthorized attempt"),
        ("security_bnr_outbound_blocked", "Security bnr outbound blocked"),
        ("server_registered", "Server registered"),
        ("server_status_changed", "Server status changed"),
        ("service_created", "Service created"),
        ("service_created_from_order", "Service created from order"),
        ("service_domain_bound", "Service domain bound"),
        ("service_group_created", "Service group created"),
        ("service_group_deleted", "Service group deleted"),
        ("service_group_updated", "Service group updated"),
        ("service_marked_for_review", "Service marked for review"),
        ("service_plan_created", "Service plan created"),
        ("service_plan_status_changed", "Service plan status changed"),
        ("service_status_changed", "Service status changed"),
        ("service_status_updated", "Service status updated"),
        ("services_deleted_on_cancellation", "Services deleted on cancellation"),
        ("services_suspended_on_cancellation", "Services suspended on cancellation"),
        ("session_rotated_2fa_change", "Session rotated 2fa change"),
        ("session_rotated_password_change", "Session rotated password change"),
        ("session_timeout_updated", "Session timeout updated"),
        ("sessions_revoked_password_reset", "Sessions revoked password reset"),
        ("setting_update_failed", "Setting update failed"),
        ("settings_cache_refresh", "Settings cache refresh"),
        ("settings_export", "Settings export"),
        ("settings_export_full", "Settings export full"),
        ("settings_imported", "Settings imported"),
        ("subscription_activated", "Subscription activated"),
        ("subscription_cancelled", "Subscription cancelled"),
        ("subscription_cancelled_nonpayment", "Subscription cancelled nonpayment"),
        ("subscription_created", "Subscription created"),
        ("subscription_currency_transition_created", "Subscription currency transition created"),
        ("subscription_currency_transition_updated", "Subscription currency transition updated"),
        ("subscription_dunning_recovered", "Subscription dunning recovered"),
        ("subscription_model_created", "Subscription model created"),
        ("subscription_model_deleted", "Subscription model deleted"),
        ("subscription_model_updated", "Subscription model updated"),
        ("subscription_paused", "Subscription paused"),
        ("subscription_payment_failed", "Subscription payment failed"),
        ("subscription_price_grandfathered", "Subscription price grandfathered"),
        ("subscription_reactivated", "Subscription reactivated"),
        ("subscription_resumed", "Subscription resumed"),
        ("subscription_suspended_nonpayment", "Subscription suspended nonpayment"),
        ("subscription_trial_converted", "Subscription trial converted"),
        ("subscription_trial_started", "Subscription trial started"),
        ("suspicious_activity_detected", "Suspicious activity detected"),
        ("suspicious_ip_activity", "Suspicious ip activity"),
        ("suspicious_login_pattern", "Suspicious login pattern"),
        ("tax_profile_cnp_set", "Tax profile cnp set"),
        ("tax_profile_created", "Tax profile created"),
        ("tax_rule_created", "Tax rule created"),
        ("tax_rule_updated", "Tax rule updated"),
        ("template_access", "Template access"),
        ("template_email_send", "Template email send"),
        ("ticket_attachment_downloaded", "Ticket attachment downloaded"),
        ("ticket_status_agent_started_work", "Ticket status agent started work"),
        ("ticket_status_awaiting_customer_response", "Ticket status awaiting customer response"),
        ("ticket_status_customer_responded", "Ticket status customer responded"),
        ("ticket_status_customer_responded_unassigned", "Ticket status customer responded unassigned"),
        ("tld_created", "Tld created"),
        ("tld_registrar_assignment_created", "Tld registrar assignment created"),
        ("tld_registrar_assignment_updated", "Tld registrar assignment updated"),
        ("tld_updated", "Tld updated"),
        ("usage_aggregation_rated", "Usage aggregation rated"),
        ("usage_alert_created", "Usage alert created"),
        ("usage_events_batch_processed", "Usage events batch processed"),
        ("usage_invoice_created", "Usage invoice created"),
        ("user_linked_to_customer", "User linked to customer"),
        ("validation_failed", "Validation failed"),
        ("vat_validation_completed", "Vat validation completed"),
        ("vies_evidence_refused", "Vies evidence refused"),
        ("virtualmin_account_activate_failed", "Virtualmin account activate failed"),
        ("virtualmin_account_created", "Virtualmin account created"),
        ("virtualmin_account_delete_failed", "Virtualmin account delete failed"),
        ("virtualmin_account_deleted", "Virtualmin account deleted"),
        ("virtualmin_account_hold_reenable_failed", "Virtualmin account hold reenable failed"),
        ("virtualmin_account_hold_restore_safety_failed", "Virtualmin account hold restore safety failed"),
        ("virtualmin_account_provisioned_successfully", "Virtualmin account provisioned successfully"),
        ("virtualmin_account_server_migrated", "Virtualmin account server migrated"),
        ("virtualmin_account_status_changed", "Virtualmin account status changed"),
        ("virtualmin_account_suspend_failed", "Virtualmin account suspend failed"),
        ("virtualmin_account_toggle_protection_failed", "Virtualmin account toggle protection failed"),
        ("virtualmin_account_updated", "Virtualmin account updated"),
        ("virtualmin_accounts_sync_failed", "Virtualmin accounts sync failed"),
        ("virtualmin_activation_refused_untrusted_cert", "Virtualmin activation refused untrusted cert"),
        ("virtualmin_auto_provisioning_critical_error", "Virtualmin auto provisioning critical error"),
        ("virtualmin_auto_provisioning_scheduled", "Virtualmin auto provisioning scheduled"),
        ("virtualmin_backup_form_failed", "Virtualmin backup form failed"),
        ("virtualmin_cert_pin_set_manually", "Virtualmin cert pin set manually"),
        ("virtualmin_chain_backup_alert", "Virtualmin chain backup alert"),
        ("virtualmin_chain_backup_failed", "Virtualmin chain backup failed"),
        ("virtualmin_chain_schedule_deferred", "Virtualmin chain schedule deferred"),
        ("virtualmin_connection_test_failed", "Virtualmin connection test failed"),
        ("virtualmin_health_check_failed", "Virtualmin health check failed"),
        ("virtualmin_job_node_lost_failed", "Virtualmin job node lost failed"),
        ("virtualmin_job_resolve_failed", "Virtualmin job resolve failed"),
        ("virtualmin_job_retry_failed", "Virtualmin job retry failed"),
        ("virtualmin_migrate_form_failed", "Virtualmin migrate form failed"),
        ("virtualmin_migration_resolve_failed", "Virtualmin migration resolve failed"),
        ("virtualmin_pair_release_abandoned", "Virtualmin pair release abandoned"),
        ("virtualmin_parameter_encryption_failed", "Virtualmin parameter encryption failed"),
        ("virtualmin_parameter_validation_failed", "Virtualmin parameter validation failed"),
        ("virtualmin_provisioning_critical_error", "Virtualmin provisioning critical error"),
        ("virtualmin_provisioning_execution_failed", "Virtualmin provisioning execution failed"),
        ("virtualmin_provisioning_failed", "Virtualmin provisioning failed"),
        ("virtualmin_provisioning_job_created", "Virtualmin provisioning job created"),
        ("virtualmin_restore_form_failed", "Virtualmin restore form failed"),
        ("virtualmin_restore_hold_decision", "Virtualmin restore hold decision"),
        ("virtualmin_restore_pair_form_failed", "Virtualmin restore pair form failed"),
        ("virtualmin_server_capacity_exceeded", "Virtualmin server capacity exceeded"),
        ("virtualmin_task_account_already_exists", "Virtualmin task account already exists"),
        ("virtualmin_task_parameter_decryption_failed", "Virtualmin task parameter decryption failed"),
        ("virtualmin_task_scheduling_failed", "Virtualmin task scheduling failed"),
        ("virtualmin_task_service_not_found", "Virtualmin task service not found"),
        ("virtualmin_task_validation_failed", "Virtualmin task validation failed"),
        ("virtualmin_usage_collected", "Virtualmin usage collected"),
        ("webauthn_credential_created", "Webauthn credential created"),
        ("webauthn_credential_deleted", "Webauthn credential deleted"),
        ("webauthn_credential_updated", "Webauthn credential updated"),
        ("webhook_delivery_failure", "Webhook delivery failure"),
        ("webhook_delivery_success", "Webhook delivery success"),
        ("webhook_retry_exhausted", "Webhook retry exhausted"),
        ("welcome_email_failed", "Welcome email failed"),
        ("welcome_email_sent", "Welcome email sent"),
        ("welcome_invite_rate_limited", "Welcome invite rate limited"),
        ("whois_privacy_changed", "Whois privacy changed"),
        ("whois_privacy_changed_webhook", "Whois privacy changed webhook"),
        ("node_drain_failed", "Node drain failed"),
        ("node_drain_pending", "Node drain pending"),
        ("node_drain_running", "Node drain running"),
        ("payment_cancelled", "Payment cancelled"),
        ("payment_disputed", "Payment disputed"),
        ("payment_pending", "Payment pending"),
        ("virtualmin_provisioning_job_attention", "Virtualmin provisioning job attention"),
        ("virtualmin_provisioning_job_cancelled", "Virtualmin provisioning job cancelled"),
        ("virtualmin_provisioning_job_completed", "Virtualmin provisioning job completed"),
        ("virtualmin_provisioning_job_failed", "Virtualmin provisioning job failed"),
        ("virtualmin_provisioning_job_pending", "Virtualmin provisioning job pending"),
        ("virtualmin_provisioning_job_running", "Virtualmin provisioning job running"),
    )

    # Unique event ID
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)

    # When and where
    #
    # default= rather than auto_now_add= (#313, point 4). auto_now_add populates the field
    # inside _save_table, i.e. AFTER the pre_save signal, so a pre_save receiver would MAC
    # over timestamp=None; the integrity stamp was therefore forced into post_save as a
    # second write. With a plain default the value exists as soon as the instance does, so
    # create and stamp collapse into a single INSERT. Behaviour is otherwise identical for
    # callers that omit timestamp — and callers that PASS one are now honoured rather than
    # silently overridden, which is what several tests already assumed.
    timestamp = models.DateTimeField(default=timezone.now, db_index=True)
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
    # PROTECT: cascading a ContentType delete must never silently erase audit evidence.
    # remove_stale_contenttypes requires an explicit retention decision first (ADR-0043).
    # An event about no particular object (a login, a security signal, a nightly job) has none:
    # it is never filed under a user, so selecting a person's events by object stays truthful.
    content_type = models.ForeignKey(ContentType, on_delete=models.PROTECT, null=True, blank=True)
    object_id = models.CharField(max_length=36, db_index=True, blank=True)  # 36 chars for UUIDs, integers fit fine
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

    objects: ClassVar[models.Manager[AuditEvent]] = AuditEventQuerySet.as_manager()

    class Meta:
        # base_manager_name deliberately NOT set to "objects": Django's deletion
        # collector runs FK cascades (User SET_NULL) through _base_manager, which must
        # stay a plain Manager or every user deletion would trip the guard. user_id is
        # outside the v2 MAC payload precisely so that cascade cannot break stamps.
        db_table = "audit_events"
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

    def save(self, *args: Any, **kwargs: Any) -> None:
        if not self._state.adding and not _mutation_allowed():
            raise AuditImmutabilityError(
                "AuditEvent is append-only; save() on an existing row requires audit_mutation_allowed()"
            )
        if self._state.adding:
            # Only the start of a user agent is evidence; the rest is a fingerprint nobody needs.
            self.user_agent = (self.user_agent or "")[:USER_AGENT_MAX_LENGTH]
            # A new row: digest every session identifier before super().save(), whose pre_save
            # receiver stamps the integrity MAC over the digested values (ADR-0043).
            (self.session_key, self.description, self.metadata, self.old_values, self.new_values) = (
                digest_session_identifiers(
                    session_key=self.session_key,
                    description=self.description,
                    metadata=self.metadata,
                    old_values=self.old_values,
                    new_values=self.new_values,
                )
            )
        else:
            # An existing row is re-stamped by its scrub before save(), so only the column, which
            # the MAC does not cover, may change here.
            self.session_key = session_key_digest(self.session_key)
        super().save(*args, **kwargs)

    def delete(self, *args: Any, **kwargs: Any) -> tuple[int, dict[str, int]]:
        if not _mutation_allowed():
            raise AuditImmutabilityError(
                "AuditEvent is append-only; delete() requires the audit_mutation_allowed() escape hatch"
            )
        return super().delete(*args, **kwargs)


class AuditChainHead(models.Model):
    """Single-row cursor for the audit hash chain (#313).

    Holds the last assigned sequence and last chain MAC. Appenders take
    SELECT ... FOR UPDATE on this row (pk=1) so sequence assignment and prev-link
    binding are strictly serialized. Unlike AuditChainLink this row is legitimately
    mutable (it advances on every append), so it uses a plain manager with no guard.
    """

    id = models.PositiveSmallIntegerField(primary_key=True, default=1, editable=False)
    last_sequence = models.BigIntegerField(default=0)
    last_chain_mac = models.CharField(max_length=64, blank=True, default="")
    backfill_complete = models.BooleanField(
        default=False, help_text=_("Live appends stay gated until the historical backfill has run.")
    )
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = "audit_chain_head"

    def __str__(self) -> str:
        return f"AuditChainHead(seq={self.last_sequence}, backfilled={self.backfill_complete})"


class AuditChainLink(models.Model):
    """Append-only hash-chain ledger over audit events (#313).

    One link per audit event (plus tombstone links for retention-deleted events),
    ordered by a serially assigned `sequence` — the AuditEvent PK is a random UUID
    and its timestamp is non-unique, so neither can order the chain. Never
    anonymized and never retention-deleted; see AuditChainLinkQuerySet.
    """

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    sequence = models.BigIntegerField(unique=True, db_index=True)
    # SET_NULL (like AuditEvent.user): a retention delete of the event detaches the FK via the
    # deletion collector (base manager) without tripping the append-only guard. The link is NOT
    # rewritten — the chain preimage is built entirely from the stable identity columns copied
    # below at append time, so verification survives the event's deletion (a null event just
    # means "this event was later retention-deleted"; event_id_str + the copies still verify).
    event = models.ForeignKey(AuditEvent, on_delete=models.SET_NULL, null=True, blank=True, related_name="chain_links")
    # Stable identity snapshot — the chain MAC is computed over THESE, never the live FK, so an
    # anonymization re-stamp or a retention delete of the event cannot change what the link committed to.
    event_id_str = models.CharField(max_length=36, db_index=True)
    event_timestamp = models.DateTimeField()
    event_action = models.CharField(max_length=50)
    event_content_type_id = models.IntegerField(null=True, blank=True)
    event_object_id = models.CharField(max_length=36, blank=True, default="")
    event_v2_mac = models.CharField(max_length=64, blank=True, default="")
    chain_mac = models.CharField(max_length=64)
    prev_chain_mac = models.CharField(max_length=64, blank=True, default="")
    key_id = models.CharField(max_length=8)
    is_tombstone = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True, db_index=True)

    objects: ClassVar[models.Manager[AuditChainLink]] = AuditChainLinkQuerySet.as_manager()

    class Meta:
        db_table = "audit_chain_links"
        ordering: ClassVar[tuple[str, ...]] = ("sequence",)
        constraints: ClassVar[tuple[models.BaseConstraint, ...]] = (
            # One live (non-tombstone) link per event — idempotency backstop for the
            # backfill and the append signal.
            models.UniqueConstraint(
                fields=["event"],
                condition=models.Q(is_tombstone=False),
                name="audit_chain_one_link_per_event",
            ),
        )

    def __str__(self) -> str:
        kind = "tombstone" if self.is_tombstone else "link"
        return f"AuditChainLink(seq={self.sequence}, {kind}, event={self.event_id_str})"

    def save(self, *args: Any, **kwargs: Any) -> None:
        if not self._state.adding:
            raise AuditLedgerImmutabilityError("AuditChainLink is append-only; save() on an existing row is forbidden")
        super().save(*args, **kwargs)

    def delete(self, *args: Any, **kwargs: Any) -> tuple[int, dict[str, int]]:
        raise AuditLedgerImmutabilityError("AuditChainLink is append-only; delete() is never permitted")


class AuditChainAnchorQuerySet(models.QuerySet["AuditChainAnchor"]):
    """Append-only, same doctrine as AuditChainLinkQuerySet — an anchor is never rewritten."""

    def update(self, **kwargs: Any) -> int:
        raise AuditLedgerImmutabilityError("AuditChainAnchor is append-only; update() is never permitted")

    def bulk_update(
        self, objs: Iterable[AuditChainAnchor], fields: Iterable[str], batch_size: int | None = None
    ) -> int:
        raise AuditLedgerImmutabilityError("AuditChainAnchor is append-only; bulk_update() is never permitted")

    def delete(self) -> tuple[int, dict[str, int]]:
        raise AuditLedgerImmutabilityError("AuditChainAnchor is append-only; delete() is never permitted")


class AuditChainAnchor(models.Model):
    """Local record of a chain head published to an external sink (#313).

    Chaining detects insert/reorder/mid-chain deletion, but NOT tail truncation: lop off the
    last N links and update the head row and the remaining chain walks clean. The fix must
    live somewhere the database attacker does not control, so each anchor run publishes
    (sequence, head MAC, link count) to an external sink under the SEPARATE "audit-anchor"
    key domain.

    THIS ROW IS NOT THE CONTROL — it is a local convenience copy, in the same database an
    attacker would own, and they can delete it alongside the links. The evidence is what the
    sink holds. Verification compares the sink's highest anchor against the live chain: a
    chain that no longer reaches an anchored sequence has been truncated.
    """

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    sequence = models.BigIntegerField(db_index=True)
    head_chain_mac = models.CharField(max_length=64)
    link_count = models.BigIntegerField()
    # MAC over the anchored tuple under the audit-anchor domain. What the sink records, and
    # what makes a forged anchor line detectable by whoever holds the anchor key.
    anchor_mac = models.CharField(max_length=64)
    key_id = models.CharField(max_length=8)
    sink = models.CharField(max_length=32)
    anchored_at = models.DateTimeField(auto_now_add=True, db_index=True)

    objects: ClassVar[models.Manager[AuditChainAnchor]] = AuditChainAnchorQuerySet.as_manager()

    class Meta:
        db_table = "audit_chain_anchors"
        ordering: ClassVar[tuple[str, ...]] = ("-sequence",)

    def __str__(self) -> str:
        return f"AuditChainAnchor(seq={self.sequence}, sink={self.sink})"

    def save(self, *args: Any, **kwargs: Any) -> None:
        if not self._state.adding:
            raise AuditLedgerImmutabilityError(
                "AuditChainAnchor is append-only; save() on an existing row is forbidden"
            )
        super().save(*args, **kwargs)

    def delete(self, *args: Any, **kwargs: Any) -> tuple[int, dict[str, int]]:
        raise AuditLedgerImmutabilityError("AuditChainAnchor is append-only; delete() is never permitted")


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
    # SET_NULL, not CASCADE: deleting a user must not erase the GDPR compliance
    # record that an export of their data was made (W7).
    requested_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True)
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
        db_table = "audit_data_exports"
        ordering: ClassVar[tuple[str, ...]] = ("-requested_at",)

    def __str__(self) -> str:
        return f"{self.export_type} export by {self.requested_by_display}"

    @property
    def requested_by_display(self) -> str:
        return self.requested_by.email if self.requested_by else "deleted user"

    @property
    def is_downloadable(self) -> bool:
        """Completed, with its file, and inside the download window."""
        return self.status == "completed" and bool(self.file_path) and timezone.now() <= self.expires_at


class AuditIntegrityCheck(models.Model):
    """Track audit data integrity verification for tamper detection."""

    STATUS_CHOICES: ClassVar[tuple[tuple[str, str], ...]] = (
        ("healthy", "Healthy"),
        ("warning", "Warning"),
        ("compromised", "Compromised"),
        # The check itself failed to run - distinct from a clean or tampered result;
        # dashboards must count these instead of defaulting to healthy (W3).
        ("error", "Error"),
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
        db_table = "audit_integrity_checks"
        ordering: ClassVar[tuple[str, ...]] = ("-checked_at",)
        indexes: ClassVar[tuple[models.Index, ...]] = (
            models.Index(fields=["check_type", "-checked_at"]),
            models.Index(fields=["status", "-checked_at"]),
            models.Index(fields=["period_start", "period_end"]),
        )

    def __str__(self) -> str:
        return f"{self.check_type} check: {self.status} ({self.issues_found} issues)"


# What a mandatory retention policy may not lose outside the escape hatch: its period, and its
# being active and mandatory at all. Other fields (description, legal_basis) stay editable.
_MANDATORY_POLICY_GUARDED_FIELDS = frozenset({"retention_days", "is_active", "is_mandatory"})


class AuditRetentionPolicyQuerySet(models.QuerySet["AuditRetentionPolicy"]):
    """Bulk writes that could weaken a mandatory policy need the audit_mutation_allowed() escape hatch.

    update() also covers bulk_update(), which Django runs as update() calls. A bulk write is not
    compared row by row, so it needs the hatch for a guarded field of a mandatory row even when it
    would raise the period. Non-mandatory policies and unguarded fields are free. loaddata (raw
    save_base) and historical models in migrations bypass the ORM guards by design.
    """

    def update(self, **kwargs: Any) -> int:
        if _MANDATORY_POLICY_GUARDED_FIELDS & kwargs.keys():
            self._guard_mandatory("update()")
        return super().update(**kwargs)

    def delete(self) -> tuple[int, dict[str, int]]:
        self._guard_mandatory("delete()")
        return super().delete()

    def bulk_create(  # noqa: PLR0913 - Django's signature
        self,
        objs: Iterable[AuditRetentionPolicy],
        batch_size: int | None = None,
        ignore_conflicts: bool = False,
        update_conflicts: bool = False,
        update_fields: Collection[str] | None = None,
        unique_fields: Collection[str] | None = None,
    ) -> list[AuditRetentionPolicy]:
        # An upsert rewrites whichever row it collides with, mandatory or not.
        if update_conflicts and _MANDATORY_POLICY_GUARDED_FIELDS & set(update_fields or ()) and not _mutation_allowed():
            raise AuditImmutabilityError(
                "An upsert of retention_days, is_active or is_mandatory requires the "
                "audit_mutation_allowed() escape hatch"
            )
        return super().bulk_create(
            objs,
            batch_size=batch_size,
            ignore_conflicts=ignore_conflicts,
            update_conflicts=update_conflicts,
            update_fields=update_fields,
            unique_fields=unique_fields,
        )

    def _guard_mandatory(self, operation: str) -> None:
        if not _mutation_allowed() and self.filter(is_mandatory=True).exists():
            raise AuditImmutabilityError(
                f"Mandatory retention policies cannot be changed by {operation} outside the "
                "audit_mutation_allowed() escape hatch"
            )


class AuditRetentionPolicy(models.Model):
    """Define retention policies for different types of audit events."""

    # "archive" was removed deliberately: it only flipped a metadata flag while claiming
    # cold storage, a silent no-op. Real cold-storage archive is future work (ADR-0043).
    RETENTION_ACTION_CHOICES: ClassVar[tuple[tuple[str, str], ...]] = (
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
    action = models.CharField(max_length=20, choices=RETENTION_ACTION_CHOICES, default="anonymize")

    # Compliance requirements
    legal_basis = models.CharField(max_length=200, blank=True)  # Romanian law reference
    is_mandatory = models.BooleanField(default=False)  # Cannot be overridden

    # Policy status
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    created_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True)

    objects = AuditRetentionPolicyQuerySet.as_manager()

    class Meta:
        db_table = "audit_retention_policies"
        ordering: ClassVar[tuple[str, ...]] = ("name",)
        indexes: ClassVar[tuple[models.Index, ...]] = (
            models.Index(fields=["category", "severity"]),
            models.Index(fields=["is_active", "retention_days"]),
        )
        constraints: ClassVar[tuple[models.BaseConstraint, ...]] = (
            # A mandatory policy that is inactive would be a legal requirement quietly
            # switched off - the DB refuses the state outright (W6).
            models.CheckConstraint(
                condition=models.Q(is_mandatory=False) | models.Q(is_active=True),
                name="audit_retention_mandatory_implies_active",
            ),
            # Exactly one active policy may claim a (category, severity) slot; the seeder
            # resolves conflicts deterministically instead of racing at apply time.
            models.UniqueConstraint(
                fields=("category", "severity"),
                condition=models.Q(is_active=True),
                name="audit_retention_one_active_per_scope",
            ),
        )

    def __str__(self) -> str:
        return f"{self.name} ({self.retention_days} days)"

    def save(self, *args: Any, **kwargs: Any) -> None:
        if self.pk is not None and not _mutation_allowed():
            self._guard_mandatory_write(kwargs.get("update_fields"))
        super().save(*args, **kwargs)

    def _guard_mandatory_write(self, update_fields: Iterable[str] | None) -> None:
        """Refuse deactivating, demoting or shortening a mandatory policy.

        The stored row decides, not _state.adding: save(force_update=True) on a fresh instance
        updates it. Only the fields this save writes are judged. The seeder lowers a period after a
        deliberate seed change inside the escape hatch; nothing else may.

        The check reads the row without a lock. Two concurrent saves both compare against the period
        stored before either of them, so the result is never shorter than that period; only the
        order of two racing raises is unprotected. No application code writes policies.
        """
        original = type(self)._default_manager.filter(pk=self.pk).values("is_mandatory", "retention_days").first()
        if original is None or not original["is_mandatory"]:
            return
        written = _MANDATORY_POLICY_GUARDED_FIELDS & (
            _MANDATORY_POLICY_GUARDED_FIELDS if update_fields is None else set(update_fields)
        )
        values = {name: getattr(self, name) for name in written}
        if any(hasattr(value, "resolve_expression") for value in values.values()):
            raise AuditImmutabilityError(
                "A mandatory retention policy's retention_days, is_active or is_mandatory cannot be "
                "written as an expression outside the audit_mutation_allowed() escape hatch"
            )
        if ("is_active" in values and not values["is_active"]) or (
            "is_mandatory" in values and not values["is_mandatory"]
        ):
            raise AuditImmutabilityError(
                "Mandatory retention policies cannot be deactivated or demoted outside "
                "the audit_mutation_allowed() escape hatch"
            )
        if "retention_days" in values and values["retention_days"] < original["retention_days"]:
            raise AuditImmutabilityError(
                f"Mandatory retention policies cannot be shortened (from {original['retention_days']} to "
                f"{values['retention_days']} days) outside the audit_mutation_allowed() escape hatch"
            )

    def delete(self, *args: Any, **kwargs: Any) -> tuple[int, dict[str, int]]:
        # The stored flag decides: clearing is_mandatory in memory does not make the row deletable.
        if not _mutation_allowed() and (
            self.is_mandatory or type(self)._default_manager.filter(pk=self.pk, is_mandatory=True).exists()
        ):
            raise AuditImmutabilityError(
                "Mandatory retention policies cannot be deleted outside the audit_mutation_allowed() escape hatch"
            )
        return super().delete(*args, **kwargs)


class FileIntegrityBaseline(models.Model):
    """Durable baseline hash for one monitored file (W10).

    Replaces the evictable-cache baselines: a cache flush used to silently re-baseline
    every monitored file, which is exactly when an attacker would want it to. Rows are
    written ONLY by an explicit rebaseline (deploy runbook step), never during checks.
    """

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    path = models.CharField(max_length=500, unique=True)  # relative to BASE_DIR
    sha256 = models.CharField(max_length=64)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = "audit_file_integrity_baselines"
        ordering: ClassVar[tuple[str, ...]] = ("path",)

    def __str__(self) -> str:
        return f"{self.path} ({self.sha256[:12]}...)"


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
    shared_with: models.ManyToManyField = models.ManyToManyField(User, related_name="shared_audit_queries", blank=True)

    class Meta:
        db_table = "audit_search_queries"
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

    SEVERITY_CHOICES: ClassVar[tuple[tuple[str, str | _StrPromise], ...]] = (
        ("info", _("Informational")),
        ("warning", _("Warning")),
        ("high", _("High Priority")),
        ("critical", _("Critical")),
    )

    STATUS_CHOICES: ClassVar[tuple[tuple[str, str | _StrPromise], ...]] = (
        ("active", _("Active")),
        ("acknowledged", _("Acknowledged")),
        ("investigating", _("Under Investigation")),
        ("resolved", _("Resolved")),
        ("false_positive", _("False Positive")),
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
        db_table = "audit_alerts"
        ordering: ClassVar[tuple[str, ...]] = ("-created_at",)
        indexes: ClassVar[tuple[models.Index, ...]] = (
            models.Index(fields=["alert_type", "-created_at"]),
            models.Index(fields=["severity", "status", "-created_at"]),
            models.Index(fields=["assigned_to", "status"]),
            models.Index(fields=["status", "-created_at"]),
        )

    def __str__(self) -> str:
        return f"{self.get_severity_display()} {self.get_alert_type_display()}: {self.title}"


class AuditEventReview(models.Model):
    """Manual sign-off that a flagged AuditEvent has been looked at (#400).

    A COMPANION row rather than reviewed_by/reviewed_at columns on AuditEvent, so the
    evidence stays genuinely append-only. Marking an event reviewed is a routine,
    user-driven action; storing it on AuditEvent would mean entering
    ``audit_mutation_allowed()`` on every click, putting ordinary workflow alongside
    GDPR erasure and retention deletion in the escape hatch and eroding the invariant
    the guard exists to protect (ADR-0016 / ADR-0043).

    It also keeps the tamper-evidence story honest: the v2 integrity MAC covers an
    explicit field list on AuditEvent, so new columns there would be silently
    un-MAC'd. Review state lives here, where being ordinary mutable data with its own
    row is expected rather than ambiguous.

    Deletion behaviour follows the direction the rows actually depend on. A review is
    an annotation *about* an event: it has no meaning once the event is gone, and it is
    not itself audit evidence. ``PROTECT`` on ``audit_event`` would invert that — the
    annotation would veto the deletion of the thing it annotates, so the two sanctioned
    removal paths (retention deletion, ``services.py``; GDPR erasure of a user's events)
    would raise ``ProtectedError`` the moment any reviewed event fell in scope, and a
    GDPR erasure request would become unfulfillable. ``CASCADE`` lets those paths
    complete and takes the now-orphaned annotation with them.

    ``reviewed_by`` is ``SET_NULL`` for the same reason: deleting a staff account must
    not be blocked by, nor silently erase, the reviews they signed off. The review
    survives with a null reviewer rather than vetoing the user deletion.
    """

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)

    audit_event = models.OneToOneField(
        AuditEvent,
        on_delete=models.CASCADE,
        related_name="review",
        verbose_name=_("Audit Event"),
    )
    reviewed_by = models.ForeignKey(
        User,
        on_delete=models.SET_NULL,
        null=True,
        related_name="audit_event_reviews",
        verbose_name=_("Reviewed By"),
    )
    reviewed_at = models.DateTimeField(auto_now_add=True, db_index=True, verbose_name=_("Reviewed At"))
    notes = models.TextField(blank=True, verbose_name=_("Notes"))

    class Meta:
        db_table = "audit_event_reviews"
        verbose_name = _("Audit Event Review")
        verbose_name_plural = _("Audit Event Reviews")
        ordering: ClassVar[tuple[str, ...]] = ("-reviewed_at",)
        indexes: ClassVar[tuple[models.Index, ...]] = (models.Index(fields=["reviewed_by", "-reviewed_at"]),)

    def __str__(self) -> str:
        return f"Review of {self.audit_event_id} by {self.reviewed_by_id}"


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
        db_table = "audit_compliance_logs"
        ordering: ClassVar[tuple[str, ...]] = ("-timestamp",)
        indexes: ClassVar[tuple[models.Index, ...]] = (
            models.Index(fields=["compliance_type", "-timestamp"]),
            models.Index(fields=["reference_id"]),
            models.Index(fields=["status", "-timestamp"]),
        )

    def __str__(self) -> str:
        return f"{self.compliance_type}: {self.reference_id}"


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
        db_table = "audit_compliance_reports"
        ordering: ClassVar[tuple[str, ...]] = ("-generated_at",)
        indexes: ClassVar[tuple[models.Index, ...]] = (
            models.Index(fields=["report_type", "-generated_at"]),
            models.Index(fields=["framework", "-generated_at"]),
            models.Index(fields=["overall_status", "-generated_at"]),
            models.Index(fields=["period_start", "period_end"]),
        )

    def __str__(self) -> str:
        return f"{self.report_type} report ({self.overall_status}) - {self.generated_at.date()}"


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
    user = models.ForeignKey(User, on_delete=models.CASCADE, null=True, blank=True, related_name="cookie_consents")
    cookie_id = models.CharField(
        max_length=64, blank=True, db_index=True, help_text=_("Anonymous visitor identifier from cookie")
    )

    # Consent status
    status = models.CharField(max_length=20, choices=CONSENT_STATUS_CHOICES, default="pending")

    # Individual category consents
    essential_cookies = models.BooleanField(default=True, help_text=_("Always required"))
    functional_cookies = models.BooleanField(default=False)
    analytics_cookies = models.BooleanField(default=False)
    marketing_cookies = models.BooleanField(default=False)

    # Metadata
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    user_agent = models.TextField(blank=True)

    # Timestamps
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    # The Cookie Policy release in force when the choice was made (ADR-0062), and its number;
    # empty while none is published.
    cookie_document = models.ForeignKey(
        "common.LegalDocument", null=True, blank=True, on_delete=models.PROTECT, related_name="+"
    )
    consent_version = models.CharField(max_length=20, blank=True, default="")

    class Meta:
        db_table = "audit_cookie_consents"
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
