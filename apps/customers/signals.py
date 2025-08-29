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

from .models import (
    Customer,
    CustomerAddress,
    CustomerBillingProfile,
    CustomerNote,
    CustomerPaymentMethod,
    CustomerTaxProfile,
)

logger = logging.getLogger(__name__)

# ===============================================================================
# BUSINESS CONSTANTS
# ===============================================================================

# Business thresholds for Romanian compliance
LARGE_CREDIT_LIMIT_THRESHOLD = 10000  # 10,000 RON threshold for credit limit alerts
EXTENDED_PAYMENT_TERMS_THRESHOLD = 60  # 60 days - Romanian law threshold

# ===============================================================================
# CUSTOMER CORE MODEL SIGNALS
# ===============================================================================

@receiver(post_save, sender=Customer)
def handle_customer_created_or_updated(sender: type[Customer], instance: Customer, created: bool, **kwargs: Any) -> None:
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
        old_values = getattr(instance, '_original_customer_values', {}) if not created else {}
        new_values = {
            'name': instance.name,
            'customer_type': instance.customer_type,
            'status': instance.status,
            'company_name': instance.company_name,
            'primary_email': instance.primary_email,
            'primary_phone': instance.primary_phone,
        }
        
        # Enhanced customer audit logging
        if not getattr(settings, 'DISABLE_AUDIT_SIGNALS', False):
            from apps.audit.services import CustomersAuditService  # noqa: PLC0415
            
            event_type = 'customer_created' if created else 'customer_updated'
            
            CustomersAuditService.log_customer_event(
                event_type=event_type,
                customer=instance,
                user=getattr(instance, '_audit_user', None),
                context=AuditContext(actor_type='system'),
                old_values=old_values,
                new_values=new_values,
                description=f"Customer {instance.get_display_name()} {'created' if created else 'updated'}"
            )
        
        if created:
            # New customer created
            _handle_new_customer_creation(instance)
            logger.info(f"👤 [Customer] Created {instance.get_display_name()} ({instance.customer_type})")
            
        else:
            # Customer updated - check for important changes
            old_status = old_values.get('status')
            if old_status and old_status != instance.status:
                _handle_customer_status_change(instance, old_status, instance.status)
                
            # Check for GDPR consent changes
            old_consent = old_values.get('data_processing_consent')
            if old_consent is not None and old_consent != instance.data_processing_consent:
                _handle_gdpr_consent_change(instance, old_consent, instance.data_processing_consent)
                
            # Check for marketing consent changes
            old_marketing = old_values.get('marketing_consent')
            if old_marketing is not None and old_marketing != instance.marketing_consent:
                _handle_marketing_consent_change(instance, old_marketing, instance.marketing_consent)
        
        # Romanian compliance verification for companies
        if instance.customer_type == 'company' and instance.company_name:
            _verify_romanian_company_compliance(instance)
            
    except Exception as e:
        logger.exception(f"🔥 [Customer Signal] Failed to handle customer save: {e}")


@receiver(pre_save, sender=Customer)
def store_original_customer_values(sender: type[Customer], instance: Customer, **kwargs: Any) -> None:
    """Store original customer values for audit trail"""
    try:
        if instance.pk:
            try:
                original = Customer.objects.get(pk=instance.pk)
                instance._original_customer_values = {
                    'status': original.status,
                    'customer_type': original.customer_type,
                    'company_name': original.company_name,
                    'primary_email': original.primary_email,
                    'primary_phone': original.primary_phone,
                    'data_processing_consent': original.data_processing_consent,
                    'marketing_consent': original.marketing_consent,
                    'industry': original.industry,
                    'assigned_account_manager': original.assigned_account_manager
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
                'customer_hard_deletion_attempted',
                {
                    'customer_id': str(instance.id),
                    'customer_name': instance.get_display_name(),
                    'customer_type': instance.customer_type,
                    'primary_email': instance.primary_email
                }
            )
        
        # Audit the deletion
        event_data = AuditEventData(
            event_type='customer_deleted',
            content_object=instance,
            description=f"Customer {'soft' if instance.is_deleted else 'hard'} deleted: {instance.get_display_name()}"
        )
        AuditService.log_event(event_data)
        
        logger.info(f"🗑️ [Customer] Customer deletion logged: {instance.get_display_name()}")
        
    except Exception as e:
        logger.exception(f"🔥 [Customer Signal] Failed to handle customer deletion: {e}")


# ===============================================================================
# CUSTOMER TAX PROFILE SIGNALS
# ===============================================================================

@receiver(post_save, sender=CustomerTaxProfile)
def handle_tax_profile_changes(sender: type[CustomerTaxProfile], instance: CustomerTaxProfile, created: bool, **kwargs: Any) -> None:
    """
    Handle tax profile creation/updates.
    
    Triggers:
    - Romanian compliance validation (CUI, VAT)
    - EU VAT validation for reverse charge
    - Compliance logging for tax authorities
    """
    try:
        event_type = 'customer_tax_profile_created' if created else 'customer_tax_profile_updated'
        
        old_values = getattr(instance, '_original_tax_values', {}) if not created else {}
        new_values = {
            'cui': instance.cui,
            'vat_number': instance.vat_number,
            'is_vat_payer': instance.is_vat_payer,
            'vat_rate': float(instance.vat_rate),
            'reverse_charge_eligible': instance.reverse_charge_eligible
        }
        
        # Enhanced tax profile audit logging
        if not getattr(settings, 'DISABLE_AUDIT_SIGNALS', False):
            from apps.audit.services import CustomersAuditService  # noqa: PLC0415
            
            CustomersAuditService.log_tax_profile_event(
                event_type=event_type,
                tax_profile=instance,
                user=getattr(instance, '_audit_user', None),
                context=AuditContext(actor_type='system'),
                old_values=old_values,
                new_values=new_values,
                description=f"Tax profile {'created' if created else 'updated'} for {instance.customer.get_display_name()}"
            )
        
        # Romanian compliance validation
        if instance.cui:
            _validate_romanian_cui(instance)
            
        # VAT number validation for EU customers
        if instance.vat_number and instance.vat_number.startswith(('RO', 'DE', 'FR', 'IT')):
            _trigger_vat_validation(instance)
            
        # Compliance logging for Romanian tax authorities
        if instance.cui and instance.cui.startswith('RO'):
            compliance_request = ComplianceEventRequest(
                compliance_type='romanian_tax_registration',
                reference_id=instance.cui,
                description=f"Romanian tax profile {'registered' if created else 'updated'}: {instance.cui}",
                status='success',
                evidence={
                    'cui': instance.cui,
                    'is_vat_payer': instance.is_vat_payer,
                    'vat_rate': float(instance.vat_rate),
                    'customer_id': str(instance.customer.id)
                }
            )
            AuditService.log_compliance_event(compliance_request)
            
        logger.info(f"🏛️ [Customer] Tax profile {'created' if created else 'updated'}: {instance.customer.get_display_name()}")
        
    except Exception as e:
        logger.exception(f"🔥 [Customer Signal] Failed to handle tax profile change: {e}")


@receiver(pre_save, sender=CustomerTaxProfile)
def store_original_tax_values(sender: type[CustomerTaxProfile], instance: CustomerTaxProfile, **kwargs: Any) -> None:
    """Store original tax profile values for comparison"""
    try:
        if instance.pk:
            try:
                original = CustomerTaxProfile.objects.get(pk=instance.pk)
                instance._original_tax_values = {
                    'cui': original.cui,
                    'vat_number': original.vat_number,
                    'is_vat_payer': original.is_vat_payer,
                    'vat_rate': float(original.vat_rate),
                    'reverse_charge_eligible': original.reverse_charge_eligible
                }
            except CustomerTaxProfile.DoesNotExist:
                instance._original_tax_values = {}
    except Exception as e:
        logger.exception(f"🔥 [Customer Signal] Failed to store original tax values: {e}")


# ===============================================================================
# CUSTOMER BILLING PROFILE SIGNALS
# ===============================================================================

@receiver(post_save, sender=CustomerBillingProfile)
def handle_billing_profile_changes(sender: type[CustomerBillingProfile], instance: CustomerBillingProfile, created: bool, **kwargs: Any) -> None:
    """
    Handle billing profile creation/updates.
    
    Triggers:
    - Credit limit monitoring and alerts
    - Payment terms changes for Romanian law compliance
    - Currency preference updates
    - Billing automation configuration
    """
    try:
        event_type = 'customer_billing_profile_created' if created else 'customer_billing_profile_updated'
        
        old_values = getattr(instance, '_original_billing_values', {}) if not created else {}
        new_values = {
            'payment_terms': instance.payment_terms,
            'credit_limit': float(instance.credit_limit),
            'preferred_currency': instance.preferred_currency,
            'invoice_delivery_method': instance.invoice_delivery_method,
            'auto_payment_enabled': instance.auto_payment_enabled
        }
        
        # Enhanced billing profile audit logging
        if not getattr(settings, 'DISABLE_AUDIT_SIGNALS', False):
            from apps.audit.services import CustomersAuditService  # noqa: PLC0415
            
            CustomersAuditService.log_billing_profile_event(
                event_type=event_type,
                billing_profile=instance,
                user=getattr(instance, '_audit_user', None),
                context=AuditContext(actor_type='system'),
                old_values=old_values,
                new_values=new_values,
                description=f"Billing profile {'created' if created else 'updated'} for {instance.customer.get_display_name()}"
            )
        
        if not created:
            # Check for credit limit changes
            old_credit_limit = old_values.get('credit_limit', 0)
            if old_credit_limit != float(instance.credit_limit):
                _handle_credit_limit_change(instance, old_credit_limit, float(instance.credit_limit))
                
            # Check for payment terms changes (Romanian compliance)
            old_payment_terms = old_values.get('payment_terms', 0)
            if old_payment_terms != instance.payment_terms:
                _handle_payment_terms_change(instance, old_payment_terms, instance.payment_terms)
                
        logger.info(f"💰 [Customer] Billing profile {'created' if created else 'updated'}: {instance.customer.get_display_name()}")
        
    except Exception as e:
        logger.exception(f"🔥 [Customer Signal] Failed to handle billing profile change: {e}")


@receiver(pre_save, sender=CustomerBillingProfile)
def store_original_billing_values(sender: type[CustomerBillingProfile], instance: CustomerBillingProfile, **kwargs: Any) -> None:
    """Store original billing profile values for comparison"""
    try:
        if instance.pk:
            try:
                original = CustomerBillingProfile.objects.get(pk=instance.pk)
                instance._original_billing_values = {
                    'payment_terms': original.payment_terms,
                    'credit_limit': float(original.credit_limit),
                    'preferred_currency': original.preferred_currency,
                    'invoice_delivery_method': original.invoice_delivery_method,
                    'auto_payment_enabled': original.auto_payment_enabled
                }
            except CustomerBillingProfile.DoesNotExist:
                instance._original_billing_values = {}
    except Exception as e:
        logger.exception(f"🔥 [Customer Signal] Failed to store original billing values: {e}")


# ===============================================================================
# CUSTOMER ADDRESS SIGNALS
# ===============================================================================

@receiver(post_save, sender=CustomerAddress)
def handle_address_changes(sender: type[CustomerAddress], instance: CustomerAddress, created: bool, **kwargs: Any) -> None:
    """
    Handle customer address creation/updates.
    
    Triggers:
    - Address validation and verification
    - Versioning management
    - Romanian postal system integration
    - Compliance logging for legal addresses
    """
    try:
        event_type = 'customer_address_created' if created else 'customer_address_updated'
        
        # Enhanced address audit logging
        if not getattr(settings, 'DISABLE_AUDIT_SIGNALS', False):
            from apps.audit.services import CustomersAuditService  # noqa: PLC0415
            
            old_values = getattr(instance, '_original_address_values', {}) if not created else {}
            new_values = {
                'address_type': instance.address_type,
                'address_line1': instance.address_line1,
                'city': instance.city,
                'county': instance.county,
                'postal_code': instance.postal_code,
                'country': instance.country,
                'is_current': instance.is_current,
                'is_validated': instance.is_validated
            }
            
            CustomersAuditService.log_address_event(
                event_type=event_type,
                address=instance,
                user=getattr(instance, '_audit_user', None),
                context=AuditContext(actor_type='system'),
                old_values=old_values,
                new_values=new_values,
                description=f"Address {instance.address_type} {'created' if created else 'updated'} for {instance.customer.get_display_name()}"
            )
        
        # Address validation for Romanian addresses
        if instance.country == 'România' and not instance.is_validated:
            _trigger_romanian_address_validation(instance)
            
        # Version management - ensure only one current address per type
        if instance.is_current:
            _ensure_single_current_address(instance)
            
        # Legal address compliance for Romanian companies
        if instance.address_type == 'legal' and instance.customer.customer_type == 'company':
            _verify_legal_address_compliance(instance)
            
        logger.info(f"🏠 [Customer] Address {instance.address_type} {'created' if created else 'updated'}: {instance.customer.get_display_name()}")
        
    except Exception as e:
        logger.exception(f"🔥 [Customer Signal] Failed to handle address change: {e}")


@receiver(pre_save, sender=CustomerAddress)
def store_original_address_values(sender: type[CustomerAddress], instance: CustomerAddress, **kwargs: Any) -> None:
    """Store original address values for comparison"""
    try:
        if instance.pk:
            try:
                original = CustomerAddress.objects.get(pk=instance.pk)
                instance._original_address_values = {
                    'address_type': original.address_type,
                    'address_line1': original.address_line1,
                    'city': original.city,
                    'county': original.county,
                    'postal_code': original.postal_code,
                    'country': original.country,
                    'is_current': original.is_current,
                    'is_validated': original.is_validated
                }
            except CustomerAddress.DoesNotExist:
                instance._original_address_values = {}
    except Exception as e:
        logger.exception(f"🔥 [Customer Signal] Failed to store original address values: {e}")


# ===============================================================================
# CUSTOMER PAYMENT METHOD SIGNALS
# ===============================================================================

@receiver(post_save, sender=CustomerPaymentMethod)
def handle_payment_method_changes(sender: type[CustomerPaymentMethod], instance: CustomerPaymentMethod, created: bool, **kwargs: Any) -> None:
    """
    Handle customer payment method creation/updates.
    
    Triggers:
    - Payment method validation
    - Stripe integration sync
    - Default payment method management
    - Security logging for payment changes
    """
    try:
        event_type = 'customer_payment_method_created' if created else 'customer_payment_method_updated'
        
        # Enhanced payment method audit logging
        if not getattr(settings, 'DISABLE_AUDIT_SIGNALS', False):
            from apps.audit.services import CustomersAuditService  # noqa: PLC0415
            
            old_values = getattr(instance, '_original_payment_values', {}) if not created else {}
            new_values = {
                'method_type': instance.method_type,
                'display_name': instance.display_name,
                'last_four': instance.last_four,
                'is_default': instance.is_default,
                'is_active': instance.is_active,
                # Don't log sensitive payment details
                'stripe_payment_method_id': '***' if instance.stripe_payment_method_id else None
            }
            
            CustomersAuditService.log_payment_method_event(
                event_type=event_type,
                payment_method=instance,
                user=getattr(instance, '_audit_user', None),
                context=AuditContext(actor_type='system'),
                old_values=old_values,
                new_values=new_values,
                description=f"Payment method {instance.method_type} {'created' if created else 'updated'} for {instance.customer.get_display_name()}"
            )
        
        # Security logging for payment method changes
        log_security_event(
            'customer_payment_method_changed',
            {
                'customer_id': str(instance.customer.id),
                'method_type': instance.method_type,
                'is_default': instance.is_default,
                'action': 'created' if created else 'updated'
            }
        )
        
        # Default payment method management
        if instance.is_default:
            _ensure_single_default_payment_method(instance)
            
        # Stripe integration validation
        if instance.method_type == 'stripe_card' and instance.stripe_payment_method_id:
            _validate_stripe_payment_method(instance)
            
        logger.info(f"💳 [Customer] Payment method {instance.method_type} {'created' if created else 'updated'}: {instance.customer.get_display_name()}")
        
    except Exception as e:
        logger.exception(f"🔥 [Customer Signal] Failed to handle payment method change: {e}")


@receiver(pre_save, sender=CustomerPaymentMethod)
def store_original_payment_values(sender: type[CustomerPaymentMethod], instance: CustomerPaymentMethod, **kwargs: Any) -> None:
    """Store original payment method values for comparison"""
    try:
        if instance.pk:
            try:
                original = CustomerPaymentMethod.objects.get(pk=instance.pk)
                instance._original_payment_values = {
                    'method_type': original.method_type,
                    'display_name': original.display_name,
                    'is_default': original.is_default,
                    'is_active': original.is_active
                }
            except CustomerPaymentMethod.DoesNotExist:
                instance._original_payment_values = {}
    except Exception as e:
        logger.exception(f"🔥 [Customer Signal] Failed to store original payment values: {e}")


@receiver(pre_delete, sender=CustomerPaymentMethod)
def handle_payment_method_deletion(sender: type[CustomerPaymentMethod], instance: CustomerPaymentMethod, **kwargs: Any) -> None:
    """Handle payment method deletion with security logging"""
    try:
        # Security logging for payment method deletion
        log_security_event(
            'customer_payment_method_deleted',
            {
                'customer_id': str(instance.customer.id),
                'method_type': instance.method_type,
                'display_name': instance.display_name,
                'was_default': instance.is_default
            }
        )
        
        # Audit the deletion
        event_data = AuditEventData(
            event_type='customer_payment_method_deleted',
            content_object=instance,
            description=f"Payment method deleted: {instance.display_name} for {instance.customer.get_display_name()}"
        )
        AuditService.log_event(event_data)
        
        logger.info(f"🗑️ [Customer] Payment method deleted: {instance.display_name}")
        
    except Exception as e:
        logger.exception(f"🔥 [Customer Signal] Failed to handle payment method deletion: {e}")


# ===============================================================================
# CUSTOMER NOTE SIGNALS
# ===============================================================================

@receiver(post_save, sender=CustomerNote)
def handle_customer_note_changes(sender: type[CustomerNote], instance: CustomerNote, created: bool, **kwargs: Any) -> None:
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
            if not getattr(settings, 'DISABLE_AUDIT_SIGNALS', False):
                from apps.audit.services import CustomersAuditService  # noqa: PLC0415
                
                CustomersAuditService.log_note_event(
                    event_type='customer_note_created',
                    note=instance,
                    user=instance.created_by,
                    context=AuditContext(actor_type='user' if instance.created_by else 'system'),
                    description=f"Note created: {instance.title} for {instance.customer.get_display_name()}"
                )
            
            # Handle important notes
            if instance.is_important:
                _handle_important_note(instance)
                
            # Handle complaints/compliments
            if instance.note_type in ['complaint', 'compliment']:
                _handle_feedback_note(instance)
                
            logger.info(f"📝 [Customer] Note created: {instance.title} ({instance.note_type})")
        
    except Exception as e:
        logger.exception(f"🔥 [Customer Signal] Failed to handle customer note: {e}")


# ===============================================================================
# BUSINESS LOGIC FUNCTIONS
# ===============================================================================

def _handle_new_customer_creation(customer: Customer) -> None:
    """Handle new customer creation tasks"""
    try:
        # Create default profiles if they don't exist
        if not hasattr(customer, 'tax_profile'):
            CustomerTaxProfile.objects.create(
                customer=customer,
                is_vat_payer=(customer.customer_type == 'company')
            )
            
        if not hasattr(customer, 'billing_profile'):
            CustomerBillingProfile.objects.create(
                customer=customer,
                payment_terms=30,  # Standard 30-day terms
                preferred_currency='RON'  # Romanian hosting platform
            )
        
        # Send welcome email
        _send_customer_welcome_email(customer)
        
        # Trigger customer onboarding workflow
        _trigger_customer_onboarding(customer)
        
    except Exception as e:
        logger.exception(f"🔥 [Customer Signal] New customer creation handling failed: {e}")


def _handle_customer_status_change(customer: Customer, old_status: str, new_status: str) -> None:
    """Handle customer status changes"""
    try:
        logger.info(f"🔄 [Customer] Status change {customer.get_display_name()}: {old_status} → {new_status}")
        
        # Security event for status changes
        log_security_event(
            'customer_status_changed',
            {
                'customer_id': str(customer.id),
                'customer_name': customer.get_display_name(),
                'old_status': old_status,
                'new_status': new_status
            }
        )
        
        # Handle specific status transitions
        if new_status == 'active' and old_status == 'prospect':
            _handle_customer_activation(customer)
        elif new_status == 'suspended':
            _handle_customer_suspension(customer, old_status)
        elif new_status == 'inactive' and old_status == 'active':
            _handle_customer_deactivation(customer)
            
    except Exception as e:
        logger.exception(f"🔥 [Customer Signal] Status change handling failed: {e}")


def _handle_gdpr_consent_change(customer: Customer, old_consent: bool, new_consent: bool) -> None:
    """Handle GDPR consent changes"""
    try:
        consent_action = 'granted' if new_consent else 'withdrawn'
        
        # Log compliance event
        compliance_request = ComplianceEventRequest(
            compliance_type='gdpr_consent',
            reference_id=f"customer_{customer.id}",
            description=f"GDPR data processing consent {consent_action}",
            status='success',
            evidence={
                'customer_id': str(customer.id),
                'old_consent': old_consent,
                'new_consent': new_consent,
                'consent_date': timezone.now().isoformat()
            }
        )
        AuditService.log_compliance_event(compliance_request)
        
        # Update consent timestamp
        if new_consent and not customer.gdpr_consent_date:
            Customer.objects.filter(pk=customer.pk).update(
                gdpr_consent_date=timezone.now()
            )
        
        logger.info(f"🛡️ [Customer] GDPR consent {consent_action}: {customer.get_display_name()}")
        
    except Exception as e:
        logger.exception(f"🔥 [Customer Signal] GDPR consent change failed: {e}")


def _handle_marketing_consent_change(customer: Customer, old_consent: bool, new_consent: bool) -> None:
    """Handle marketing consent changes"""
    try:
        consent_action = 'granted' if new_consent else 'withdrawn'
        
        # Log compliance event
        compliance_request = ComplianceEventRequest(
            compliance_type='marketing_consent',
            reference_id=f"customer_{customer.id}",
            description=f"Marketing consent {consent_action}",
            status='success',
            evidence={
                'customer_id': str(customer.id),
                'old_consent': old_consent,
                'new_consent': new_consent
            }
        )
        AuditService.log_compliance_event(compliance_request)
        
        logger.info(f"📧 [Customer] Marketing consent {consent_action}: {customer.get_display_name()}")
        
    except Exception as e:
        logger.exception(f"🔥 [Customer Signal] Marketing consent change failed: {e}")


def _verify_romanian_company_compliance(customer: Customer) -> None:
    """Verify Romanian company compliance requirements"""
    try:
        if customer.customer_type == 'company':
            # Check if tax profile exists and has CUI
            tax_profile = customer.get_tax_profile()
            if not tax_profile or not tax_profile.cui:
                logger.warning(f"⚠️ [Customer] Romanian company missing CUI: {customer.get_display_name()}")
                
                # Create compliance alert
                compliance_request = ComplianceEventRequest(
                    compliance_type='romanian_compliance_warning',
                    reference_id=f"customer_{customer.id}",
                    description="Romanian company missing required CUI",
                    status='warning',
                    evidence={'customer_type': customer.customer_type, 'missing': 'cui'}
                )
                AuditService.log_compliance_event(compliance_request)
                
    except Exception as e:
        logger.exception(f"🔥 [Customer Signal] Romanian compliance verification failed: {e}")


def _validate_romanian_cui(tax_profile: CustomerTaxProfile) -> None:
    """Validate Romanian CUI format and registration"""
    try:
        if tax_profile.cui and tax_profile.cui.startswith('RO'):
            # Validate CUI format
            if tax_profile.validate_cui():
                logger.info(f"✅ [Customer] Valid Romanian CUI: {tax_profile.cui}")
            else:
                logger.warning(f"❌ [Customer] Invalid Romanian CUI format: {tax_profile.cui}")
                
                # Log compliance violation
                compliance_request = ComplianceEventRequest(
                    compliance_type='cui_validation_failed',
                    reference_id=tax_profile.cui,
                    description=f"Invalid CUI format: {tax_profile.cui}",
                    status='validation_failed',
                    evidence={'cui': tax_profile.cui, 'customer_id': str(tax_profile.customer.id)}
                )
                AuditService.log_compliance_event(compliance_request)
                
    except Exception as e:
        logger.exception(f"🔥 [Customer Signal] CUI validation failed: {e}")


def _trigger_vat_validation(tax_profile: CustomerTaxProfile) -> None:
    """Trigger VAT number validation via VIES"""
    try:
        # Queue VAT validation task
        from apps.billing.tasks import validate_vat_number  # noqa: PLC0415
        validate_vat_number.delay(str(tax_profile.id))
        logger.info(f"🏛️ [Customer] VAT validation queued: {tax_profile.vat_number}")
    except ImportError:
        logger.info(f"🏛️ [Customer] Would validate VAT: {tax_profile.vat_number}")


def _handle_credit_limit_change(billing_profile: CustomerBillingProfile, old_limit: float, new_limit: float) -> None:
    """Handle customer credit limit changes"""
    try:
        change_type = 'increased' if new_limit > old_limit else 'decreased'
        change_amount = abs(new_limit - old_limit)
        
        logger.info(f"💰 [Customer] Credit limit {change_type} by {change_amount:.2f} RON: {billing_profile.customer.get_display_name()}")
        
        # Alert for significant credit limit increases
        if change_type == 'increased' and change_amount > LARGE_CREDIT_LIMIT_THRESHOLD:
            log_security_event(
                'large_credit_limit_increase',
                {
                    'customer_id': str(billing_profile.customer.id),
                    'old_limit': old_limit,
                    'new_limit': new_limit,
                    'increase_amount': change_amount
                }
            )
            
    except Exception as e:
        logger.exception(f"🔥 [Customer Signal] Credit limit change handling failed: {e}")


def _handle_payment_terms_change(billing_profile: CustomerBillingProfile, old_terms: int, new_terms: int) -> None:
    """Handle payment terms changes for Romanian compliance"""
    try:
        logger.info(f"📅 [Customer] Payment terms changed from {old_terms} to {new_terms} days: {billing_profile.customer.get_display_name()}")
        
        # Romanian law: payment terms > 60 days for companies require justification
        if new_terms > EXTENDED_PAYMENT_TERMS_THRESHOLD and billing_profile.customer.customer_type == 'company':
            compliance_request = ComplianceEventRequest(
                compliance_type='extended_payment_terms',
                reference_id=f"customer_{billing_profile.customer.id}",
                description=f"Extended payment terms: {new_terms} days",
                status='success',
                evidence={
                    'customer_id': str(billing_profile.customer.id),
                    'old_terms': old_terms,
                    'new_terms': new_terms,
                    'customer_type': billing_profile.customer.customer_type
                }
            )
            AuditService.log_compliance_event(compliance_request)
            
    except Exception as e:
        logger.exception(f"🔥 [Customer Signal] Payment terms change handling failed: {e}")


def _trigger_romanian_address_validation(address: CustomerAddress) -> None:
    """Trigger Romanian address validation"""
    try:
        # Queue Romanian postal validation
        logger.info(f"🏠 [Customer] Romanian address validation would be triggered for {address.city}, {address.county}")
        
        # Future: integrate with Romanian postal service API
        # For now, just log the intent
        
    except Exception as e:
        logger.exception(f"🔥 [Customer Signal] Romanian address validation failed: {e}")


def _ensure_single_current_address(address: CustomerAddress) -> None:
    """Ensure only one current address per type per customer"""
    try:
        # Set all other addresses of same type to not current
        CustomerAddress.objects.filter(
            customer=address.customer,
            address_type=address.address_type,
            is_current=True
        ).exclude(pk=address.pk).update(is_current=False)
        
    except Exception as e:
        logger.exception(f"🔥 [Customer Signal] Address versioning failed: {e}")


def _verify_legal_address_compliance(address: CustomerAddress) -> None:
    """Verify legal address compliance for Romanian companies"""
    try:
        if address.address_type == 'legal' and address.country == 'România':
            # Romanian companies must have legal address in Romania
            compliance_request = ComplianceEventRequest(
                compliance_type='legal_address_compliance',
                reference_id=f"customer_{address.customer.id}",
                description=f"Legal address registered: {address.city}, {address.county}",
                status='success',
                evidence={
                    'address_id': str(address.id),
                    'city': address.city,
                    'county': address.county,
                    'postal_code': address.postal_code
                }
            )
            AuditService.log_compliance_event(compliance_request)
            
    except Exception as e:
        logger.exception(f"🔥 [Customer Signal] Legal address compliance verification failed: {e}")


def _ensure_single_default_payment_method(payment_method: CustomerPaymentMethod) -> None:
    """Ensure only one default payment method per customer"""
    try:
        # Set all other payment methods to not default
        CustomerPaymentMethod.objects.filter(
            customer=payment_method.customer,
            is_default=True
        ).exclude(pk=payment_method.pk).update(is_default=False)
        
    except Exception as e:
        logger.exception(f"🔥 [Customer Signal] Default payment method management failed: {e}")


def _validate_stripe_payment_method(payment_method: CustomerPaymentMethod) -> None:
    """Validate Stripe payment method"""
    try:
        # Future: validate with Stripe API
        logger.info(f"💳 [Customer] Would validate Stripe payment method: {payment_method.display_name}")
        
    except Exception as e:
        logger.exception(f"🔥 [Customer Signal] Stripe payment method validation failed: {e}")


def _handle_important_note(note: CustomerNote) -> None:
    """Handle important customer notes"""
    try:
        # Send notification to account manager
        if note.customer.assigned_account_manager:
            _send_important_note_notification(note)
            
        logger.info(f"🚨 [Customer] Important note created: {note.title}")
        
    except Exception as e:
        logger.exception(f"🔥 [Customer Signal] Important note handling failed: {e}")


def _handle_feedback_note(note: CustomerNote) -> None:
    """Handle customer feedback notes (complaints/compliments)"""
    try:
        feedback_type = note.note_type
        
        # Queue feedback processing
        try:
            from apps.customers.tasks import (  # type: ignore[import-not-found]  # noqa: PLC0415
                process_customer_feedback,
            )
            process_customer_feedback.delay(str(note.id))
        except (ImportError, AttributeError):
            logger.info(f"📝 [Customer] Would process feedback for {note.customer.get_display_name()} (task not available)")
        
        logger.info(f"🗣️ [Customer] Customer {feedback_type} recorded: {note.title}")
        
    except ImportError:
        logger.info(f"🗣️ [Customer] Would process {note.note_type}: {note.title}")


def _handle_customer_activation(customer: Customer) -> None:
    """Handle customer activation from prospect to active"""
    try:
        logger.info(f"✅ [Customer] Customer activated: {customer.get_display_name()}")
        
        # Send activation welcome email
        _send_customer_activation_email(customer)
        
        # Enable services if any were pending
        _activate_customer_services(customer)
        
    except Exception as e:
        logger.exception(f"🔥 [Customer Signal] Customer activation failed: {e}")


def _handle_customer_suspension(customer: Customer, old_status: str) -> None:
    """Handle customer suspension"""
    try:
        logger.warning(f"⚠️ [Customer] Customer suspended: {customer.get_display_name()}")
        
        # Suspend related services
        _suspend_customer_services(customer)
        
        # Send suspension notification
        _send_customer_suspension_email(customer)
        
    except Exception as e:
        logger.exception(f"🔥 [Customer Signal] Customer suspension failed: {e}")


def _handle_customer_deactivation(customer: Customer) -> None:
    """Handle customer deactivation"""
    try:
        logger.info(f"💤 [Customer] Customer deactivated: {customer.get_display_name()}")
        
        # Send deactivation notification
        _send_customer_deactivation_email(customer)
        
    except Exception as e:
        logger.exception(f"🔥 [Customer Signal] Customer deactivation failed: {e}")


# ===============================================================================
# EMAIL NOTIFICATION FUNCTIONS
# ===============================================================================

def _send_customer_welcome_email(customer: Customer) -> None:
    """Send welcome email to new customers"""
    try:
        from apps.notifications.services import EmailService  # noqa: PLC0415
        
        EmailService.send_template_email(
            template_key='customer_welcome',
            recipient=customer.primary_email,
            context={'customer': customer},
            priority='normal'
        )
    except Exception as e:
        logger.exception(f"🔥 [Customer] Failed to send welcome email: {e}")


def _send_customer_activation_email(customer: Customer) -> None:
    """Send activation confirmation email"""
    try:
        from apps.notifications.services import EmailService  # noqa: PLC0415
        
        EmailService.send_template_email(
            template_key='customer_activated',
            recipient=customer.primary_email,
            context={'customer': customer},
            priority='high'
        )
    except Exception as e:
        logger.exception(f"🔥 [Customer] Failed to send activation email: {e}")


def _send_customer_suspension_email(customer: Customer) -> None:
    """Send suspension notification email"""
    try:
        from apps.notifications.services import EmailService  # noqa: PLC0415
        
        EmailService.send_template_email(
            template_key='customer_suspended',
            recipient=customer.primary_email,
            context={'customer': customer},
            priority='high'
        )
    except Exception as e:
        logger.exception(f"🔥 [Customer] Failed to send suspension email: {e}")


def _send_customer_deactivation_email(customer: Customer) -> None:
    """Send deactivation notification email"""
    try:
        from apps.notifications.services import EmailService  # noqa: PLC0415
        
        EmailService.send_template_email(
            template_key='customer_deactivated',
            recipient=customer.primary_email,
            context={'customer': customer}
        )
    except Exception as e:
        logger.exception(f"🔥 [Customer] Failed to send deactivation email: {e}")


def _send_important_note_notification(note: CustomerNote) -> None:
    """Send notification about important customer note"""
    try:
        from apps.notifications.services import EmailService  # noqa: PLC0415
        
        if note.customer.assigned_account_manager:
            EmailService.send_template_email(
                template_key='important_customer_note',
                recipient=note.customer.assigned_account_manager.email,
                context={
                    'note': note,
                    'customer': note.customer
                },
                priority='high'
            )
    except Exception as e:
        logger.exception(f"🔥 [Customer] Failed to send important note notification: {e}")


def _trigger_customer_onboarding(customer: Customer) -> None:
    """Trigger customer onboarding workflow"""
    try:
        # Queue onboarding tasks
        try:
            from apps.customers.tasks import start_customer_onboarding  # noqa: PLC0415
            start_customer_onboarding.delay(str(customer.id))
            logger.info(f"🚀 [Customer] Onboarding started: {customer.get_display_name()}")
        except (ImportError, AttributeError):
            logger.info(f"🚀 [Customer] Would start onboarding for {customer.get_display_name()} (task not available)")
    except Exception:
        logger.info(f"🚀 [Customer] Would start onboarding for: {customer.get_display_name()}")


def _activate_customer_services(customer: Customer) -> None:
    """Activate customer services when customer becomes active"""
    try:
        # Find all pending services for this customer and activate them
        from apps.provisioning.models import Service  # noqa: PLC0415
        from apps.provisioning.services import ServiceActivationService  # noqa: PLC0415
        pending_services = Service.objects.filter(
            customer=customer,
            status='pending'
        )
        
        for service in pending_services:
            result = ServiceActivationService.activate_service(
                service=service,
                activation_reason='Customer activated'
            )
            if result.is_ok():
                logger.info(f"⚡ [Customer] Service activated: {service.id}")
                
    except Exception as e:
        logger.exception(f"🔥 [Customer] Service activation failed: {e}")


def _suspend_customer_services(customer: Customer) -> None:
    """Suspend customer services when customer is suspended"""
    try:
        # Find all active services for this customer and suspend them
        from apps.provisioning.models import Service  # noqa: PLC0415
        from apps.provisioning.services import ServiceManagementService  # noqa: PLC0415
        active_services = Service.objects.filter(
            customer=customer,
            status='active'
        )
        
        for service in active_services:
            result = ServiceManagementService.suspend_service(
                service=service,
                reason='Customer suspended',
                suspend_immediately=True
            )
            if result.is_ok():
                logger.info(f"⏸️ [Customer] Service suspended: {service.id}")
                
    except Exception as e:
        logger.exception(f"🔥 [Customer] Service suspension failed: {e}")
