"""
Customer signals for PRAHO Platform
Comprehensive customer lifecycle management with Romanian compliance.

Includes:
- Customer creation, updates, and status changes
- Tax profile modifications (CUI, VAT compliance)
- Billing profile updates (payment terms, credit limits)
- Address management and versioning
- Payment method lifecycle
- Customer note tracking
- GDPR compliance events
- Romanian business compliance logging
"""

import logging
from typing import Any

from django.conf import settings
from django.db import transaction
from django.db.models.signals import post_save, pre_delete, pre_save
from django.dispatch import receiver
from django.utils import timezone

from apps.audit.services import (
    AuditContext,
    AuditEventData,
    AuditService,
    ComplianceEventRequest,
)
from apps.common.validators import log_security_event
from apps.settings.services import SettingsService

from .contact_models import CustomerAddress, CustomerNote, CustomerPaymentMethod
from .customer_models import Customer
from .profile_models import CustomerBillingProfile, CustomerTaxProfile

logger = logging.getLogger(__name__)

# ===============================================================================
# BUSINESS CONSTANTS
# ===============================================================================

# Default business thresholds for Romanian compliance — authoritative source is SettingsService
_DEFAULT_LARGE_CREDIT_LIMIT_THRESHOLD = 10000  # 10,000 RON threshold for credit limit alerts
_DEFAULT_EXTENDED_PAYMENT_TERMS_THRESHOLD = 60  # 60 days - Romanian law threshold

# ===============================================================================
# CUSTOMER CORE MODEL SIGNALS
# ===============================================================================


@receiver(post_save, sender=Customer)
def handle_customer_created_or_updated(
    sender: type[Customer], instance: Customer, created: bool, **kwargs: Any
) -> None:
    """
    Handle customer creation and updates.

    Triggers:
    - Audit logging for all customer changes
    - Profile creation for new customers
    - GDPR compliance tracking
    - Status change notifications
    - Romanian compliance verification
    """
    try:
        # Get previous values for audit trail
        old_values = getattr(instance, "_original_customer_values", {}) if not created else {}
        new_values = {
            "name": instance.name,
            "customer_type": instance.customer_type,
            "status": instance.status,
            "company_name": instance.company_name,
            "primary_email": instance.primary_email,
            "primary_phone": instance.primary_phone,
        }

        # Enhanced customer audit logging
        if not getattr(settings, "DISABLE_AUDIT_SIGNALS", False):
            from apps.audit.services import CustomersAuditService

            event_type = "customer_created" if created else "customer_updated"

            CustomersAuditService.log_customer_event(
                event_type=event_type,
                customer=instance,
                user=getattr(instance, "_audit_user", None),
                context=AuditContext(actor_type="system"),
                old_values=old_values,
                new_values=new_values,
                description=f"Customer {instance.get_display_name()} {'created' if created else 'updated'}",
            )

        if created:
            # New customer created
            _handle_new_customer_creation(instance)
            logger.info(f"👤 [Customer] Created {instance.get_display_name()} ({instance.customer_type})")

        else:
            # Customer updated - check for important changes
            old_status = old_values.get("status")
            if old_status and old_status != instance.status:
                _handle_customer_status_change(instance, old_status, instance.status)

            # Check for GDPR consent changes
            old_consent = old_values.get("data_processing_consent")
            if old_consent is not None and old_consent != instance.data_processing_consent:
                _handle_gdpr_consent_change(instance, old_consent, instance.data_processing_consent)

            # Check for marketing consent changes
            old_marketing = old_values.get("marketing_consent")
            if old_marketing is not None and old_marketing != instance.marketing_consent:
                _handle_marketing_consent_change(instance, old_marketing, instance.marketing_consent)

        # Romanian compliance verification for companies
        if instance.customer_type == Customer.CustomerType.COMPANY and instance.company_name:
            _verify_romanian_company_compliance(instance)

    except Exception as e:
        logger.exception(f"🔥 [Customer Signal] Failed to handle customer save: {e}")


@receiver(pre_save, sender=Customer)
def store_original_customer_values(sender: type[Customer], instance: Customer, **kwargs: Any) -> None:
    """Store original customer values for audit trail"""
    try:
        # Short-circuit for meta-only updates (credit scores, stats, onboarding state)
        # These internal cache values don't need audit trail comparison
        update_fields = kwargs.get("update_fields")
        if update_fields and set(update_fields).issubset({"meta", "updated_at"}):
            return

        if instance.pk:
            try:
                original = Customer.all_objects.get(pk=instance.pk)
                instance._original_customer_values = {
                    "status": original.status,
                    "customer_type": original.customer_type,
                    "company_name": original.company_name,
                    "primary_email": original.primary_email,
                    "primary_phone": original.primary_phone,
                    "data_processing_consent": original.data_processing_consent,
                    "marketing_consent": original.marketing_consent,
                    "industry": original.industry,
                    "assigned_account_manager": original.assigned_account_manager,
                }
            except Customer.DoesNotExist:
                instance._original_customer_values = {}
    except Exception as e:
        logger.exception(f"🔥 [Customer Signal] Failed to store original values: {e}")


@receiver(pre_delete, sender=Customer)
def handle_customer_deletion(sender: type[Customer], instance: Customer, **kwargs: Any) -> None:
    """
    Handle customer deletion (soft delete compliance).

    Romanian compliance: Customer data must be archived, not permanently deleted
    unless explicit GDPR deletion request.
    """
    try:
        # Verify this is a soft delete, not hard delete
        if not instance.is_deleted:
            logger.warning(f"⚠️ [Customer] Hard deletion attempted for {instance.get_display_name()}")

            # Log critical compliance event
            log_security_event(
                "customer_hard_deletion_attempted",
                {
                    "customer_id": str(instance.id),
                    "customer_name": instance.get_display_name(),
                    "customer_type": instance.customer_type,
                    "primary_email": instance.primary_email,
                },
            )

        # Audit the deletion
        event_data = AuditEventData(
            event_type="customer_deleted",
            content_object=instance,
            description=f"Customer {'soft' if instance.is_deleted else 'hard'} deleted: {instance.get_display_name()}",
        )
        AuditService.log_event(event_data)

        logger.info(f"🗑️ [Customer] Customer deletion logged: {instance.get_display_name()}")

    except Exception as e:
        logger.exception(f"🔥 [Customer Signal] Failed to handle customer deletion: {e}")


# ===============================================================================
# CUSTOMER TAX PROFILE SIGNALS
# ===============================================================================


@receiver(post_save, sender=CustomerTaxProfile)
def handle_tax_profile_changes(
    sender: type[CustomerTaxProfile], instance: CustomerTaxProfile, created: bool, **kwargs: Any
) -> None:
    """
    Handle tax profile creation/updates.

    Triggers:
    - Romanian compliance validation (CUI, VAT)
    - EU VAT validation for reverse charge
    - Compliance logging for tax authorities
    """
    try:
        event_type = "customer_tax_profile_created" if created else "customer_tax_profile_updated"

        old_values = getattr(instance, "_original_tax_values", {}) if not created else {}
        new_values = {
            "cui": instance.cui,
            "vat_number": instance.vat_number,
            "is_vat_payer": instance.is_vat_payer,
            "vat_rate": float(instance.vat_rate),
            "reverse_charge_eligible": instance.reverse_charge_eligible,
        }

        # Enhanced tax profile audit logging
        if not getattr(settings, "DISABLE_AUDIT_SIGNALS", False):
            from apps.audit.services import CustomersAuditService

            CustomersAuditService.log_tax_profile_event(
                event_type=event_type,
                tax_profile=instance,
                user=getattr(instance, "_audit_user", None),
                context=AuditContext(actor_type="system"),
                old_values=old_values,
                new_values=new_values,
                description=f"Tax profile {'created' if created else 'updated'} for {instance.customer.get_display_name()}",
            )

        # Romanian compliance validation
        if instance.cui:
            _validate_romanian_cui(instance)

        # VAT number validation for EU customers
        if instance.vat_number and instance.vat_number.startswith(("RO", "DE", "FR", "IT")):
            _trigger_vat_validation(instance)

        # Compliance logging for Romanian tax authorities
        if instance.cui and instance.cui.startswith("RO"):
            compliance_request = ComplianceEventRequest(
                compliance_type="romanian_tax_registration",
                reference_id=instance.cui,
                description=f"Romanian tax profile {'registered' if created else 'updated'}: {instance.cui}",
                status="success",
                evidence={
                    "cui": instance.cui,
                    "is_vat_payer": instance.is_vat_payer,
                    "vat_rate": float(instance.vat_rate),
                    "customer_id": str(instance.customer.id),
                },
            )
            AuditService.log_compliance_event(compliance_request)

        logger.info(
            f"🏛️ [Customer] Tax profile {'created' if created else 'updated'}: {instance.customer.get_display_name()}"
        )

    except Exception as e:
        logger.exception(f"🔥 [Customer Signal] Failed to handle tax profile change: {e}")


@receiver(pre_save, sender=CustomerTaxProfile)
def store_original_tax_values(sender: type[CustomerTaxProfile], instance: CustomerTaxProfile, **kwargs: Any) -> None:
    """Store original tax profile values for comparison"""
    try:
        update_fields = kwargs.get("update_fields")
        if update_fields and set(update_fields).issubset({"updated_at"}):
            return

        if instance.pk:
            try:
                original = CustomerTaxProfile.objects.get(pk=instance.pk)
                instance._original_tax_values = {
                    "cui": getattr(original, "cui", None),
                    "vat_number": getattr(original, "vat_number", None),
                    "is_vat_payer": getattr(original, "is_vat_payer", None),
                    "vat_rate": float(getattr(original, "vat_rate", 0)),
                    "reverse_charge_eligible": getattr(original, "reverse_charge_eligible", None),
                }
            except CustomerTaxProfile.DoesNotExist:
                instance._original_tax_values = {}
    except Exception as e:
        logger.exception(f"🔥 [Customer Signal] Failed to store original tax values: {e}")


# ===============================================================================
# CUSTOMER BILLING PROFILE SIGNALS
# ===============================================================================


@receiver(post_save, sender=CustomerBillingProfile)
def handle_billing_profile_changes(
    sender: type[CustomerBillingProfile], instance: CustomerBillingProfile, created: bool, **kwargs: Any
) -> None:
    """
    Handle billing profile creation/updates.

    Triggers:
    - Credit limit monitoring and alerts
    - Payment terms changes for Romanian law compliance
    - Currency preference updates
    - Billing automation configuration
    """
    try:
        event_type = "customer_billing_profile_created" if created else "customer_billing_profile_updated"

        old_values = getattr(instance, "_original_billing_values", {}) if not created else {}
        new_values = {
            "payment_terms": instance.payment_terms,
            "credit_limit": float(instance.credit_limit),
            "preferred_currency": instance.preferred_currency,
            "auto_payment_enabled": instance.auto_payment_enabled,
        }

        # Enhanced billing profile audit logging
        if not getattr(settings, "DISABLE_AUDIT_SIGNALS", False):
            from apps.audit.services import CustomersAuditService

            CustomersAuditService.log_billing_profile_event(
                event_type=event_type,
                billing_profile=instance,
                user=getattr(instance, "_audit_user", None),
                context=AuditContext(actor_type="system"),
                old_values=old_values,
                new_values=new_values,
                description=f"Billing profile {'created' if created else 'updated'} for {instance.customer.get_display_name()}",
            )

        if not created:
            # Check for credit limit changes
            old_credit_limit = old_values.get("credit_limit", 0)
            if old_credit_limit != float(instance.credit_limit):
                _handle_credit_limit_change(instance, old_credit_limit, float(instance.credit_limit))

            # Check for payment terms changes (Romanian compliance)
            old_payment_terms = old_values.get("payment_terms", 0)
            if old_payment_terms != instance.payment_terms:
                _handle_payment_terms_change(instance, old_payment_terms, instance.payment_terms)

        logger.info(
            f"💰 [Customer] Billing profile {'created' if created else 'updated'}: {instance.customer.get_display_name()}"
        )

    except Exception as e:
        logger.exception(f"🔥 [Customer Signal] Failed to handle billing profile change: {e}")


@receiver(pre_save, sender=CustomerBillingProfile)
def store_original_billing_values(
    sender: type[CustomerBillingProfile], instance: CustomerBillingProfile, **kwargs: Any
) -> None:
    """Store original billing profile values for comparison"""
    try:
        update_fields = kwargs.get("update_fields")
        if update_fields and set(update_fields).issubset({"updated_at"}):
            return

        if instance.pk:
            try:
                original = CustomerBillingProfile.objects.get(pk=instance.pk)
                instance._original_billing_values = {
                    "payment_terms": getattr(original, "payment_terms", None),
                    "credit_limit": float(getattr(original, "credit_limit", 0)),
                    "preferred_currency": getattr(original, "preferred_currency", None),
                    "auto_payment_enabled": getattr(original, "auto_payment_enabled", None),
                }
            except CustomerBillingProfile.DoesNotExist:
                instance._original_billing_values = {}
    except Exception as e:
        logger.exception(f"🔥 [Customer Signal] Failed to store original billing values: {e}")


# ===============================================================================
# CUSTOMER ADDRESS SIGNALS
# ===============================================================================


@receiver(post_save, sender=CustomerAddress)
def handle_address_changes(
    sender: type[CustomerAddress], instance: CustomerAddress, created: bool, **kwargs: Any
) -> None:
    """
    Handle customer address creation/updates.

    Triggers:
    - Address validation and verification
    - Versioning management
    - Romanian postal system integration
    - Compliance logging for legal addresses
    """
    try:
        event_type = "customer_address_created" if created else "customer_address_updated"

        # Enhanced address audit logging
        if not getattr(settings, "DISABLE_AUDIT_SIGNALS", False):
            from apps.audit.services import CustomersAuditService

            old_values = getattr(instance, "_original_address_values", {}) if not created else {}
            new_values = {
                "is_primary": instance.is_primary,
                "is_billing": instance.is_billing,
                "label": instance.label,
                "address_line1": instance.address_line1,
                "city": instance.city,
                "county": instance.county,
                "postal_code": instance.postal_code,
                "country": instance.country,
                "is_current": instance.is_current,
                "is_validated": instance.is_validated,
            }

            address_role = "primary" if instance.is_primary else ("billing" if instance.is_billing else "other")
            CustomersAuditService.log_address_event(
                event_type=event_type,
                address=instance,
                user=getattr(instance, "_audit_user", None),
                context=AuditContext(actor_type="system"),
                old_values=old_values,
                new_values=new_values,
                description=f"Address ({address_role}) {'created' if created else 'updated'} for {instance.customer.get_display_name()}",
            )

        # Address validation for Romanian addresses
        if instance.country == "România" and not instance.is_validated:
            _trigger_romanian_address_validation(instance)

        # NOTE: _ensure_single_current_address was removed in 0017 migration.
        # With boolean role flags (is_primary / is_billing), a customer legitimately
        # has multiple active (is_current=True) addresses simultaneously — one per role.
        # The model's save() enforces flag exclusivity; is_current tracks versioning
        # per address record, not per customer.

        logger.info(
            f"🏠 [Customer] Address {'created' if created else 'updated'}: {instance.customer.get_display_name()}"
        )

    except Exception as e:
        logger.exception(f"🔥 [Customer Signal] Failed to handle address change: {e}")


@receiver(pre_save, sender=CustomerAddress)
def store_original_address_values(sender: type[CustomerAddress], instance: CustomerAddress, **kwargs: Any) -> None:
    """Store original address values for comparison"""
    try:
        update_fields = kwargs.get("update_fields")
        if update_fields and set(update_fields).issubset({"updated_at", "is_current"}):
            return

        if instance.pk:
            try:
                original = CustomerAddress.objects.get(pk=instance.pk)
                instance._original_address_values = {
                    "is_primary": getattr(original, "is_primary", None),
                    "is_billing": getattr(original, "is_billing", None),
                    "label": getattr(original, "label", None),
                    "address_line1": getattr(original, "address_line1", None),
                    "city": getattr(original, "city", None),
                    "county": getattr(original, "county", None),
                    "postal_code": getattr(original, "postal_code", None),
                    "country": getattr(original, "country", None),
                    "is_current": getattr(original, "is_current", None),
                    "is_validated": getattr(original, "is_validated", None),
                }
            except CustomerAddress.DoesNotExist:
                instance._original_address_values = {}
    except Exception as e:
        logger.exception(f"🔥 [Customer Signal] Failed to store original address values: {e}")


# ===============================================================================
# CUSTOMER PAYMENT METHOD SIGNALS
# ===============================================================================


@receiver(post_save, sender=CustomerPaymentMethod)
def handle_payment_method_changes(
    sender: type[CustomerPaymentMethod], instance: CustomerPaymentMethod, created: bool, **kwargs: Any
) -> None:
    """
    Handle customer payment method creation/updates.

    Triggers:
    - Payment method validation
    - Stripe integration sync
    - Default payment method management
    - Security logging for payment changes
    """
    try:
        event_type = "customer_payment_method_created" if created else "customer_payment_method_updated"

        # Enhanced payment method audit logging
        if not getattr(settings, "DISABLE_AUDIT_SIGNALS", False):
            from apps.audit.services import CustomersAuditService

            old_values = getattr(instance, "_original_payment_values", {}) if not created else {}
            new_values = {
                "method_type": instance.method_type,
                "display_name": instance.display_name,
                "last_four": instance.last_four,
                "is_default": instance.is_default,
                "is_active": instance.is_active,
                # Don't log sensitive payment details
                "stripe_payment_method_id": "***" if instance.stripe_payment_method_id else None,
            }

            CustomersAuditService.log_payment_method_event(
                event_type=event_type,
                payment_method=instance,
                user=getattr(instance, "_audit_user", None),
                context=AuditContext(actor_type="system"),
                old_values=old_values,
                new_values=new_values,
                description=f"Payment method {instance.method_type} {'created' if created else 'updated'} for {instance.customer.get_display_name()}",
            )

        # Security logging for payment method changes
        log_security_event(
            "customer_payment_method_changed",
            {
                "customer_id": str(instance.customer.id),
                "method_type": instance.method_type,
                "is_default": instance.is_default,
                "action": "created" if created else "updated",
            },
        )

        # Note: Default payment method deduplication handled in CustomerPaymentMethod.save()

        # Stripe integration validation
        if instance.method_type == "stripe_card" and instance.stripe_payment_method_id:
            _validate_stripe_payment_method(instance)

        logger.info(
            f"💳 [Customer] Payment method {instance.method_type} {'created' if created else 'updated'}: {instance.customer.get_display_name()}"
        )

    except Exception as e:
        logger.exception(f"🔥 [Customer Signal] Failed to handle payment method change: {e}")


@receiver(pre_save, sender=CustomerPaymentMethod)
def store_original_payment_values(
    sender: type[CustomerPaymentMethod], instance: CustomerPaymentMethod, **kwargs: Any
) -> None:
    """Store original payment method values for comparison"""
    try:
        update_fields = kwargs.get("update_fields")
        if update_fields and set(update_fields).issubset({"updated_at", "is_default", "is_active"}):
            return

        if instance.pk:
            try:
                original = CustomerPaymentMethod.objects.get(pk=instance.pk)
                instance._original_payment_values = {
                    "method_type": getattr(original, "method_type", None),
                    "display_name": getattr(original, "display_name", None),
                    "is_default": getattr(original, "is_default", None),
                    "is_active": getattr(original, "is_active", None),
                }
            except CustomerPaymentMethod.DoesNotExist:
                instance._original_payment_values = {}
    except Exception as e:
        logger.exception(f"🔥 [Customer Signal] Failed to store original payment values: {e}")


@receiver(pre_delete, sender=CustomerPaymentMethod)
def handle_payment_method_deletion(
    sender: type[CustomerPaymentMethod], instance: CustomerPaymentMethod, **kwargs: Any
) -> None:
    """Handle payment method deletion with security logging"""
    try:
        # Security logging for payment method deletion
        log_security_event(
            "customer_payment_method_deleted",
            {
                "customer_id": str(instance.customer.id),
                "method_type": instance.method_type,
                "display_name": instance.display_name,
                "was_default": instance.is_default,
            },
        )

        # Audit the deletion
        event_data = AuditEventData(
            event_type="customer_payment_method_deleted",
            content_object=instance,
            description=f"Payment method deleted: {instance.display_name} for {instance.customer.get_display_name()}",
        )
        AuditService.log_event(event_data)

        logger.info(f"🗑️ [Customer] Payment method deleted: {instance.display_name}")

    except Exception as e:
        logger.exception(f"🔥 [Customer Signal] Failed to handle payment method deletion: {e}")


# ===============================================================================
# CUSTOMER NOTE SIGNALS
# ===============================================================================


@receiver(post_save, sender=CustomerNote)
def handle_customer_note_changes(
    sender: type[CustomerNote], instance: CustomerNote, created: bool, **kwargs: Any
) -> None:
    """
    Handle customer note creation/updates.

    Triggers:
    - Customer interaction tracking
    - Important note alerts
    - Complaint/compliment processing
    """
    try:
        if created:
            # Enhanced customer note audit logging
            if not getattr(settings, "DISABLE_AUDIT_SIGNALS", False):
                from apps.audit.services import CustomersAuditService

                CustomersAuditService.log_note_event(
                    event_type="customer_note_created",
                    note=instance,
                    user=instance.created_by,
                    context=AuditContext(actor_type="user" if instance.created_by else "system"),
                    description=f"Note created: {instance.title} for {instance.customer.get_display_name()}",
                )

            # Handle important notes
            if instance.is_important:
                _handle_important_note(instance)

            # Handle complaints/compliments
            if instance.note_type in ["complaint", "compliment"]:
                _handle_feedback_note(instance)

            logger.info(f"📝 [Customer] Note created: {instance.title} ({instance.note_type})")

    except Exception as e:
        logger.exception(f"🔥 [Customer Signal] Failed to handle customer note: {e}")


# ===============================================================================
# BUSINESS LOGIC FUNCTIONS
# ===============================================================================


def _handle_new_customer_creation(customer: Customer) -> None:
    """Handle new customer creation tasks."""
    try:
        # Do not auto-create tax/billing profiles here.
        # Profiles are created explicitly by dedicated workflows (registration/forms/API/services)
        # and may legitimately be absent for newly created customers.

        # Send welcome email after the transaction commits so the customer row is visible to the mailer.
        transaction.on_commit(lambda inst=customer: _send_customer_welcome_email(inst))

        # Trigger customer onboarding workflow after transaction commits.
        transaction.on_commit(lambda inst=customer: _trigger_customer_onboarding(inst))

    except Exception as e:
        logger.exception(f"🔥 [Customer Signal] New customer creation handling failed: {e}")


def _handle_customer_status_change(customer: Customer, old_status: str, new_status: str) -> None:
    """Handle customer status changes"""
    try:
        logger.info(f"🔄 [Customer] Status change {customer.get_display_name()}: {old_status} → {new_status}")

        # Security event for status changes
        log_security_event(
            "customer_status_changed",
            {
                "customer_id": str(customer.id),
                "customer_name": customer.get_display_name(),
                "old_status": old_status,
                "new_status": new_status,
            },
        )

        # Handle specific status transitions
        if new_status == Customer.CustomerStatus.ACTIVE and old_status == Customer.CustomerStatus.PROSPECT:
            _handle_customer_activation(customer)
        elif new_status == Customer.CustomerStatus.SUSPENDED:
            _handle_customer_suspension(customer, old_status)
        elif new_status == Customer.CustomerStatus.INACTIVE and old_status == Customer.CustomerStatus.ACTIVE:
            _handle_customer_deactivation(customer)

    except Exception as e:
        logger.exception(f"🔥 [Customer Signal] Status change handling failed: {e}")


def _handle_gdpr_consent_change(customer: Customer, old_consent: bool, new_consent: bool) -> None:
    """Handle GDPR consent changes"""
    try:
        consent_action = "granted" if new_consent else "withdrawn"

        # Log compliance event
        compliance_request = ComplianceEventRequest(
            compliance_type="gdpr_consent",
            reference_id=f"customer_{customer.id}",
            description=f"GDPR data processing consent {consent_action}",
            status="success",
            evidence={
                "customer_id": str(customer.id),
                "old_consent": old_consent,
                "new_consent": new_consent,
                "consent_date": timezone.now().isoformat(),
            },
        )
        AuditService.log_compliance_event(compliance_request)

        # Update consent timestamp
        if new_consent and not customer.gdpr_consent_date:
            Customer.objects.filter(pk=customer.pk).update(gdpr_consent_date=timezone.now())

        logger.info(f"🛡️ [Customer] GDPR consent {consent_action}: {customer.get_display_name()}")

    except Exception as e:
        logger.exception(f"🔥 [Customer Signal] GDPR consent change failed: {e}")


def _handle_marketing_consent_change(customer: Customer, old_consent: bool, new_consent: bool) -> None:
    """Handle marketing consent changes.

    GDPR Art. 7(3) requires consent withdrawal to always succeed. The audit
    call is wrapped in a nested transaction.atomic() savepoint so a DatabaseError
    inside log_compliance_event (e.g., OperationalError) rolls back only the
    savepoint — without it, the connection enters InFailedSqlTransaction state
    and forces a rollback of the outer transaction (the consent change itself).
    A plain try/except is not enough: catching the Python exception does not
    recover the connection.
    """
    consent_action = "granted" if new_consent else "withdrawn"

    compliance_request = ComplianceEventRequest(
        compliance_type="marketing_consent",
        reference_id=f"customer_{customer.id}",
        description=f"Marketing consent {consent_action}",
        status="success",
        evidence={"customer_id": str(customer.id), "old_consent": old_consent, "new_consent": new_consent},
    )

    try:
        with transaction.atomic():
            AuditService.log_compliance_event(compliance_request)
    except Exception as e:
        logger.exception(f"🔥 [Customer Signal] Marketing consent audit failed: {e}")
        return

    logger.info(f"📧 [Customer] Marketing consent {consent_action}: {customer.get_display_name()}")


def _verify_romanian_company_compliance(customer: Customer) -> None:
    """Verify Romanian company compliance requirements"""
    try:
        if customer.customer_type == Customer.CustomerType.COMPANY:
            # Check if tax profile exists and has CUI
            tax_profile = customer.get_tax_profile()
            if not tax_profile or not tax_profile.cui:
                logger.warning(f"⚠️ [Customer] Romanian company missing CUI: {customer.get_display_name()}")

                # Create compliance alert
                compliance_request = ComplianceEventRequest(
                    compliance_type="romanian_compliance_warning",
                    reference_id=f"customer_{customer.id}",
                    description="Romanian company missing required CUI",
                    status="warning",
                    evidence={"customer_type": customer.customer_type, "missing": "cui"},
                )
                AuditService.log_compliance_event(compliance_request)

    except Exception as e:
        logger.exception(f"🔥 [Customer Signal] Romanian compliance verification failed: {e}")


def _validate_romanian_cui(tax_profile: CustomerTaxProfile) -> None:
    """Validate Romanian CUI format and registration"""
    try:
        if tax_profile.cui and tax_profile.cui.startswith("RO"):
            # Validate CUI format
            if tax_profile.validate_cui():
                logger.info(f"✅ [Customer] Valid Romanian CUI: {tax_profile.cui}")
            else:
                logger.warning(f"❌ [Customer] Invalid Romanian CUI format: {tax_profile.cui}")

                # Log compliance violation
                compliance_request = ComplianceEventRequest(
                    compliance_type="cui_validation_failed",
                    reference_id=tax_profile.cui,
                    description=f"Invalid CUI format: {tax_profile.cui}",
                    status="validation_failed",
                    evidence={"cui": tax_profile.cui, "customer_id": str(tax_profile.customer.id)},
                )
                AuditService.log_compliance_event(compliance_request)

    except Exception as e:
        logger.exception(f"🔥 [Customer Signal] CUI validation failed: {e}")


def _trigger_vat_validation(tax_profile: CustomerTaxProfile) -> None:
    """Queue VAT number validation via VIES after transaction commits."""
    try:
        from django_q.tasks import async_task

        transaction.on_commit(
            lambda tax_profile_id=str(tax_profile.id): async_task(
                "apps.billing.tasks.validate_vat_number", tax_profile_id
            )
        )
        logger.info(f"🏛️ [Customer] VAT validation queued: {tax_profile.vat_number}")
    except ImportError:
        logger.info(f"🏛️ [Customer] Would validate VAT: {tax_profile.vat_number}")


def _handle_credit_limit_change(billing_profile: CustomerBillingProfile, old_limit: float, new_limit: float) -> None:
    """Handle customer credit limit changes"""
    try:
        change_type = "increased" if new_limit > old_limit else "decreased"
        change_amount = abs(new_limit - old_limit)

        logger.info(
            f"💰 [Customer] Credit limit {change_type} by {change_amount:.2f} RON: {billing_profile.customer.get_display_name()}"
        )

        # Alert for significant credit limit increases
        large_credit_threshold = SettingsService.get_integer_setting(
            "billing.large_credit_limit_threshold", _DEFAULT_LARGE_CREDIT_LIMIT_THRESHOLD
        )
        if change_type == "increased" and change_amount > large_credit_threshold:
            log_security_event(
                "large_credit_limit_increase",
                {
                    "customer_id": str(billing_profile.customer.id),
                    "old_limit": old_limit,
                    "new_limit": new_limit,
                    "increase_amount": change_amount,
                },
            )

    except Exception as e:
        logger.exception(f"🔥 [Customer Signal] Credit limit change handling failed: {e}")


def _handle_payment_terms_change(billing_profile: CustomerBillingProfile, old_terms: int, new_terms: int) -> None:
    """Handle payment terms changes for Romanian compliance"""
    try:
        logger.info(
            f"📅 [Customer] Payment terms changed from {old_terms} to {new_terms} days: {billing_profile.customer.get_display_name()}"
        )

        # Romanian law: payment terms > 60 days for companies require justification
        extended_terms_threshold = SettingsService.get_integer_setting(
            "billing.extended_payment_terms_threshold", _DEFAULT_EXTENDED_PAYMENT_TERMS_THRESHOLD
        )
        if (
            new_terms > extended_terms_threshold
            and billing_profile.customer.customer_type == Customer.CustomerType.COMPANY
        ):
            compliance_request = ComplianceEventRequest(
                compliance_type="extended_payment_terms",
                reference_id=f"customer_{billing_profile.customer.id}",
                description=f"Extended payment terms: {new_terms} days",
                status="success",
                evidence={
                    "customer_id": str(billing_profile.customer.id),
                    "old_terms": old_terms,
                    "new_terms": new_terms,
                    "customer_type": billing_profile.customer.customer_type,
                },
            )
            AuditService.log_compliance_event(compliance_request)

    except Exception as e:
        logger.exception(f"🔥 [Customer Signal] Payment terms change handling failed: {e}")


def _trigger_romanian_address_validation(address: CustomerAddress) -> None:
    """Trigger Romanian address validation"""
    try:
        # Queue Romanian postal validation
        logger.info(
            f"🏠 [Customer] Romanian address validation would be triggered for {address.city}, {address.county}"
        )

        # Future: integrate with Romanian postal service API
        # For now, just log the intent

    except Exception as e:
        logger.exception(f"🔥 [Customer Signal] Romanian address validation failed: {e}")


def _verify_primary_address_compliance(address: CustomerAddress) -> None:
    """Verify primary address compliance for Romanian companies"""
    try:
        if address.is_primary and address.country == "România":
            # Romanian companies must have primary address in Romania
            compliance_request = ComplianceEventRequest(
                compliance_type="primary_address_compliance",
                reference_id=f"customer_{address.customer.id}",
                description=f"Primary address registered: {address.city}, {address.county}",
                status="success",
                evidence={
                    "address_id": str(address.id),
                    "city": address.city,
                    "county": address.county,
                    "postal_code": address.postal_code,
                },
            )
            AuditService.log_compliance_event(compliance_request)

    except Exception as e:
        logger.exception(f"🔥 [Customer Signal] Primary address compliance verification failed: {e}")


def _validate_stripe_payment_method(payment_method: CustomerPaymentMethod) -> None:
    """Validate Stripe payment method"""
    try:
        # Future: validate with Stripe API
        logger.info(f"💳 [Customer] Would validate Stripe payment method: {payment_method.display_name}")

    except Exception as e:
        logger.exception(f"🔥 [Customer Signal] Stripe payment method validation failed: {e}")


def _handle_important_note(note: CustomerNote) -> None:
    """Handle important customer notes."""
    try:
        # Send notification to account manager after transaction commits.
        if note.customer.assigned_account_manager:
            transaction.on_commit(lambda n=note: _send_important_note_notification(n))

        logger.info(f"🚨 [Customer] Important note created: {note.title}")

    except Exception as e:
        logger.exception(f"🔥 [Customer Signal] Important note handling failed: {e}")


def _handle_feedback_note(note: CustomerNote) -> None:
    """Enqueue feedback processing task after transaction commits."""
    try:
        from django_q.tasks import async_task

        transaction.on_commit(
            lambda note_id=str(note.id): async_task("apps.customers.tasks.process_customer_feedback", note_id)
        )
        logger.info(f"🗣️ [Customer] Customer {note.note_type} recorded: {note.title}")
    except ImportError:
        logger.info(
            "📝 [Customer] Feedback processing skipped (task runner not available)",
            extra={"note_id": note.id, "customer_id": note.customer_id},
        )


def _handle_customer_activation(customer: Customer) -> None:
    """Handle customer activation from prospect to active."""
    try:
        logger.info(f"✅ [Customer] Customer activated: {customer.get_display_name()}")

        # Send activation welcome email after transaction commits.
        transaction.on_commit(lambda inst=customer: _send_customer_activation_email(inst))

        # Enable services if any were pending — after transaction commits so status is visible.
        transaction.on_commit(lambda inst=customer: _activate_customer_services(inst))

    except Exception as e:
        logger.exception(f"🔥 [Customer Signal] Customer activation failed: {e}")


def _handle_customer_suspension(customer: Customer, old_status: str) -> None:
    """Handle customer suspension."""
    try:
        logger.warning(f"⚠️ [Customer] Customer suspended: {customer.get_display_name()}")

        # Suspend related services after transaction commits so status is visible.
        transaction.on_commit(lambda inst=customer: _suspend_customer_services(inst))

        # Send suspension notification after transaction commits.
        transaction.on_commit(lambda inst=customer: _send_customer_suspension_email(inst))

    except Exception as e:
        logger.exception(f"🔥 [Customer Signal] Customer suspension failed: {e}")


def _handle_customer_deactivation(customer: Customer) -> None:
    """Handle customer deactivation."""
    try:
        logger.info(f"💤 [Customer] Customer deactivated: {customer.get_display_name()}")

        # Send deactivation notification after transaction commits.
        transaction.on_commit(lambda inst=customer: _send_customer_deactivation_email(inst))

    except Exception as e:
        logger.exception(f"🔥 [Customer Signal] Customer deactivation failed: {e}")


# ===============================================================================
# EMAIL NOTIFICATION FUNCTIONS
# ===============================================================================


def _send_customer_welcome_email(customer: Customer) -> None:
    """Send welcome email to new customers"""
    try:
        from apps.notifications.services import EmailService

        EmailService.send_template_email(
            template_key="customer_welcome",
            recipient=customer.primary_email,
            context={"customer": customer},
            priority="normal",
        )
    except Exception as e:
        logger.exception(f"🔥 [Customer] Failed to send welcome email: {e}")


def _send_customer_activation_email(customer: Customer) -> None:
    """Send activation confirmation email"""
    try:
        from apps.notifications.services import EmailService

        EmailService.send_template_email(
            template_key="customer_activated",
            recipient=customer.primary_email,
            context={"customer": customer},
            priority="high",
        )
    except Exception as e:
        logger.exception(f"🔥 [Customer] Failed to send activation email: {e}")


def _send_customer_suspension_email(customer: Customer) -> None:
    """Send suspension notification email"""
    try:
        from apps.notifications.services import EmailService

        EmailService.send_template_email(
            template_key="customer_suspended",
            recipient=customer.primary_email,
            context={"customer": customer},
            priority="high",
        )
    except Exception as e:
        logger.exception(f"🔥 [Customer] Failed to send suspension email: {e}")


def _send_customer_deactivation_email(customer: Customer) -> None:
    """Send deactivation notification email"""
    try:
        from apps.notifications.services import EmailService

        EmailService.send_template_email(
            template_key="customer_deactivated", recipient=customer.primary_email, context={"customer": customer}
        )
    except Exception as e:
        logger.exception(f"🔥 [Customer] Failed to send deactivation email: {e}")


def _send_important_note_notification(note: CustomerNote) -> None:
    """Send notification about important customer note"""
    try:
        from apps.notifications.services import EmailService

        if note.customer.assigned_account_manager:
            EmailService.send_template_email(
                template_key="important_customer_note",
                recipient=note.customer.assigned_account_manager.email,
                context={"note": note, "customer": note.customer},
                priority="high",
            )
    except Exception as e:
        logger.exception(f"🔥 [Customer] Failed to send important note notification: {e}")


def _trigger_customer_onboarding(customer: Customer) -> None:
    """Queue customer onboarding workflow after transaction commits."""
    try:
        from django_q.tasks import async_task

        # Called via transaction.on_commit() from _handle_new_customer_creation — already deferred.
        async_task("apps.customers.tasks.start_customer_onboarding", str(customer.id))
        logger.info(f"🚀 [Customer] Onboarding queued: {customer.get_display_name()}")
    except ImportError:
        logger.info(f"🚀 [Customer] Would start onboarding (task runner not available): {customer.get_display_name()}")


def _activate_customer_services(customer: Customer) -> None:
    """Activate customer services when customer becomes active"""
    try:
        # Find all pending services for this customer and activate them
        from apps.provisioning.models import Service
        from apps.provisioning.services import ServiceActivationService

        pending_services = Service.objects.filter(customer=customer, status="pending")

        for service in pending_services:
            result = ServiceActivationService.activate_service(service=service, activation_reason="Customer activated")
            if result.is_ok():
                logger.info(f"⚡ [Customer] Service activated: {service.id}")

    except Exception as e:
        logger.exception(f"🔥 [Customer] Service activation failed: {e}")


def _suspend_customer_services(customer: Customer) -> None:
    """Suspend customer services when customer is suspended"""
    try:
        # Find all active services for this customer and suspend them
        from apps.provisioning.models import Service
        from apps.provisioning.services import ServiceManagementService

        active_services = Service.objects.filter(customer=customer, status="active")

        for service in active_services:
            service_management = ServiceManagementService()
            result = service_management.suspend_service(service, reason="Customer suspended", suspend_immediately=True)
            if result.is_ok():
                logger.info(f"⏸️ [Customer] Service suspended: {service.id}")

    except Exception as e:
        logger.exception(f"🔥 [Customer] Service suspension failed: {e}")
