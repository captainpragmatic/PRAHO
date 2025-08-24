"""
SECURE User Registration Services - PRAHO Platform
Enhanced with comprehensive security measures addressing critical vulnerabilities.

This replaces the existing services.py with security-hardened implementations.
"""

from typing import Dict, Any, Tuple, Optional, TYPE_CHECKING, List
from django.db import transaction
from django.core.exceptions import ValidationError
from django.utils.translation import gettext_lazy as _
from django.contrib.auth import get_user_model
from django.core.mail import send_mail
from django.conf import settings
from django.contrib.auth.hashers import make_password, check_password
from django.core.cache import cache
from django.utils import timezone
import logging
import string
import random
import pyotp
import qrcode
import io
import base64
import hashlib
import time

from apps.common.types import Result, Ok, Err
from apps.common.security_decorators import (
    secure_user_registration, secure_customer_operation, secure_invitation_system,
    atomic_with_retry, prevent_race_conditions, audit_service_call, monitor_performance
)
from apps.common.validators import (
    SecureInputValidator, BusinessLogicValidator, SecureErrorHandler,
    log_security_event
)
from apps.customers.models import Customer, CustomerTaxProfile, CustomerBillingProfile, CustomerAddress
from .models import CustomerMembership

if TYPE_CHECKING:
    from .models import User
else:
    User = get_user_model()

logger = logging.getLogger(__name__)


# ===============================================================================
# SECURE USER REGISTRATION SERVICE
# ===============================================================================

class SecureUserRegistrationService:
    """
    🔒 Security-hardened user registration with comprehensive protection
    
    Addresses:
    - Race condition vulnerabilities
    - Email enumeration attacks  
    - Privilege escalation attempts
    - Input validation bypasses
    - Romanian compliance requirements
    """
    
    CUSTOMER_TYPES = [
        ('individual', _('Individual Person')),
        ('srl', _('SRL - Limited Liability Company')),  
        ('pfa', _('PFA - Authorized Physical Person')),
        ('sa', _('SA - Joint Stock Company')),
        ('ngo', _('NGO - Non-Governmental Organization')),
        ('other', _('Other Organization Type')),
    ]
    
    @classmethod
    @secure_user_registration(rate_limit=5)  # 5 registrations per hour per IP
    @atomic_with_retry(max_retries=3)
    @prevent_race_conditions(lambda cls, user_data, customer_data, **kwargs: 
                            f"{user_data.get('email', '')}:{customer_data.get('company_name', '')}")
    @audit_service_call("user_registration", lambda cls, user_data, customer_data, **kwargs: {
        'email': user_data.get('email', ''),
        'company_name': customer_data.get('company_name', ''),
        'customer_type': customer_data.get('customer_type', '')
    })
    @monitor_performance(max_duration_seconds=10.0, alert_threshold=3.0)
    def register_new_customer_owner(
        cls, 
        user_data: Dict[str, Any], 
        customer_data: Dict[str, Any],
        request_ip: str = None,
        user_agent: str = None,
        **kwargs
    ) -> Result[Tuple[User, Customer], str]:
        """
        🔒 Secure registration of new user as owner of NEW customer organization
        
        Security Enhancements:
        - Comprehensive input validation
        - Race condition prevention with distributed locking
        - Romanian business compliance validation
        - Audit logging with request tracking
        - Rate limiting per IP and email
        - Timing attack prevention
        """
        
        try:
            # Input validation is handled by @secure_user_registration decorator
            # At this point, user_data and customer_data are already validated
            
            # Step 1: Additional business logic validation
            # (Company uniqueness check is done in decorator with proper locking)
            
            # Step 2: Create the user account with security measures
            user = User.objects.create_user(
                email=user_data['email'],  # Validated email
                first_name=user_data['first_name'],  # XSS-safe
                last_name=user_data['last_name'],    # XSS-safe
                phone=user_data.get('phone', ''),   # Romanian format validated
                accepts_marketing=user_data.get('accepts_marketing', False),
                gdpr_consent_date=user_data.get('gdpr_consent_date'),
                # Security: No admin fields can be injected due to validation
            )
            
            # Step 3: Create customer organization with validated data
            customer = Customer.objects.create(
                company_name=customer_data['company_name'],  # Sanitized
                customer_type=customer_data.get('customer_type', 'other'),
                status='active',
                created_by=user
            )
            
            # Step 4: Create tax profile with Romanian compliance
            vat_number = customer_data.get('vat_number', '').strip()
            registration_number = customer_data.get('registration_number', '').strip()
            
            if vat_number or registration_number:
                tax_profile = CustomerTaxProfile.objects.create(
                    customer=customer,
                    vat_number=vat_number,  # RO prefix validated
                    registration_number=registration_number,  # CUI format validated
                    is_vat_payer=bool(vat_number),
                )
                
                # Log tax profile creation for Romanian compliance
                log_security_event('tax_profile_created', {
                    'customer_id': customer.id,
                    'has_vat': bool(vat_number),
                    'has_cui': bool(registration_number)
                }, request_ip)
            
            # Step 5: Create billing profile (secure defaults)
            CustomerBillingProfile.objects.create(
                customer=customer,
                payment_terms=30,  # Default 30 days
                preferred_currency='RON',  # Romanian Lei
                invoice_delivery_method='email',
            )
            
            # Step 6: Create billing address with validated data
            CustomerAddress.objects.create(
                customer=customer,
                address_type='billing',
                address_line1=customer_data.get('billing_address', ''),  # Sanitized
                city=customer_data.get('billing_city', ''),              # Sanitized  
                postal_code=customer_data.get('billing_postal_code', ''), # Sanitized
                county='',  # TODO: Auto-detect from city
                country='România',
                is_current=True,
            )
            
            # Step 7: Associate user as OWNER with security checks
            membership = CustomerMembership.objects.create(
                user=user,
                customer=customer,
                role='owner',  # Validated role
                is_primary=True,
            )
            
            # Step 8: Security audit logging
            log_security_event('customer_registration_success', {
                'user_id': user.id,
                'customer_id': customer.id,
                'email': user.email,
                'company_name': customer.company_name,
                'has_vat_number': bool(vat_number),
                'user_agent': user_agent
            }, request_ip)
            
            logger.info(f"✅ [Secure Registration] User {user.email} registered customer {customer.company_name}")
            return Ok((user, customer))
            
        except ValidationError as e:
            # Validation errors are handled by decorator
            raise
            
        except Exception as e:
            # Log unexpected errors without exposing details
            error_id = hashlib.sha256(f"{str(e)}{time.time()}".encode()).hexdigest()[:8]
            logger.error(f"🔥 [Secure Registration] Unexpected error {error_id}: {str(e)}")
            
            log_security_event('registration_system_error', {
                'error_id': error_id,
                'error_type': type(e).__name__
            }, request_ip)
            
            return Err(_("Registration could not be completed. Please contact support.") + f" (ID: {error_id})")
    
    @classmethod
    @secure_user_registration(rate_limit=3)  # Lower limit for join requests
    @atomic_with_retry(max_retries=3)
    @audit_service_call("join_request")
    @monitor_performance(max_duration_seconds=5.0)
    def request_join_existing_customer(
        cls,
        user_data: Dict[str, Any],
        company_identifier: str,
        identification_type: str,  # 'name', 'vat_number', 'registration_number'
        request_ip: str = None,
        **kwargs
    ) -> Result[Dict[str, Any], str]:
        """
        🔒 Secure request to join existing customer with enumeration prevention
        """
        
        try:
            # Input validation handled by decorator
            
            # Step 1: Secure company lookup (timing-safe)
            existing_customer = cls._find_customer_by_identifier_secure(
                company_identifier, 
                identification_type,
                request_ip
            )
            
            if not existing_customer:
                # Generic error message (no enumeration)
                log_security_event('join_request_invalid_company', {
                    'identifier_type': identification_type,
                    'identifier_hash': hashlib.sha256(company_identifier.encode()).hexdigest()[:16]
                }, request_ip)
                return Err(_("Company information could not be verified"))
            
            # Step 2: Create user in pending state
            user = User.objects.create_user(
                email=user_data['email'],
                first_name=user_data['first_name'],
                last_name=user_data['last_name'],
                phone=user_data.get('phone', ''),
                accepts_marketing=user_data.get('accepts_marketing', False),
                gdpr_consent_date=user_data.get('gdpr_consent_date'),
                is_active=False,  # 🚨 Pending approval
            )
            
            # Step 3: Create pending membership request
            membership = CustomerMembership.objects.create(
                user=user,
                customer=existing_customer,
                role='viewer',  # Default safe role
                is_primary=False,
            )
            
            # Step 4: Secure notification to owners
            cls._notify_owners_of_join_request_secure(existing_customer, user, request_ip)
            
            log_security_event('join_request_created', {
                'user_id': user.id,
                'customer_id': existing_customer.id,
                'pending_approval': True
            }, request_ip)
            
            return Ok({
                'user': user,
                'customer': existing_customer,
                'membership': membership,
                'status': 'pending_approval'
            })
            
        except Exception as e:
            return Err(SecureErrorHandler.safe_error_response(e, "join_request"))


# ===============================================================================
# SECURE CUSTOMER USER SERVICE
# ===============================================================================

class SecureCustomerUserService:
    """
    🔒 Security-hardened customer-user relationship management
    """
    
    @classmethod
    @secure_customer_operation(requires_owner=True)
    @atomic_with_retry(max_retries=3)
    @audit_service_call("user_creation")
    @monitor_performance(max_duration_seconds=8.0)
    def create_user_for_customer(
        cls, 
        customer, 
        first_name: str = "", 
        last_name: str = "", 
        send_welcome: bool = True,
        created_by=None,
        request_ip: str = None,
        **kwargs
    ) -> Result[Tuple[User, bool], str]:
        """
        🔒 Secure user creation for customer with comprehensive validation
        """
        try:
            # Input validation
            if first_name:
                first_name = SecureInputValidator.validate_name_secure(first_name, 'first_name')
            if last_name:
                last_name = SecureInputValidator.validate_name_secure(last_name, 'last_name')
            
            # Validate customer email
            if not hasattr(customer, 'primary_email') or not customer.primary_email:
                return Err(_("Customer does not have a valid email address"))
            
            validated_email = SecureInputValidator.validate_email_secure(
                customer.primary_email, 'user_creation'
            )
            
            # Check for existing user (race condition safe)
            with transaction.atomic():
                existing_user = User.objects.select_for_update().filter(
                    email=validated_email
                ).first()
                
                if existing_user:
                    return Err(_("User account already exists for this email"))
                
                # Extract names if not provided
                if not first_name and not last_name and hasattr(customer, 'name') and customer.name:
                    name_parts = customer.name.split()
                    first_name = name_parts[0] if name_parts else ''
                    last_name = ' '.join(name_parts[1:]) if len(name_parts) > 1 else ''
                
                # Create user with security measures
                user = User.objects.create_user(
                    email=validated_email,
                    first_name=first_name or '',
                    last_name=last_name or '',
                    phone=SecureInputValidator.validate_phone_romanian(
                        getattr(customer, 'primary_phone', '') or ''
                    ),
                    is_active=True,
                    created_by=created_by
                )
                user.set_unusable_password()  # Force password reset
                user.save()
                
                # Create secure membership
                CustomerMembership.objects.create(
                    user=user,
                    customer=customer,
                    role='owner',
                    is_primary=True,
                    created_by=created_by
                )
            
            # Send welcome email securely
            email_sent = False
            if send_welcome:
                email_sent = cls._send_welcome_email_secure(user, customer, request_ip)
            
            log_security_event('customer_user_created', {
                'user_id': user.id,
                'customer_id': customer.id,
                'email_sent': email_sent,
                'created_by_id': created_by.id if created_by else None
            }, request_ip)
            
            logger.info(f"✅ [Secure User Creation] Created user {user.email} for customer {customer.name}")
            return Ok((user, email_sent))
            
        except Exception as e:
            return Err(SecureErrorHandler.safe_error_response(e, "user_creation"))
    
    @classmethod
    @secure_customer_operation(requires_owner=False)
    @atomic_with_retry(max_retries=3)
    @audit_service_call("user_linking")
    def link_existing_user(
        cls, 
        user: User, 
        customer, 
        role: str = 'viewer',  # Secure default
        is_primary: bool = False,
        created_by=None,
        request_ip: str = None,
        **kwargs
    ) -> Result[Any, str]:
        """
        🔒 Secure linking of existing user to customer
        """
        try:
            # Validate role
            validated_role = SecureInputValidator.validate_customer_role(role)
            
            # Check for existing membership (race condition safe)
            with transaction.atomic():
                existing = CustomerMembership.objects.select_for_update().filter(
                    user=user, customer=customer
                ).first()
                
                if existing:
                    return Err(_("User is already associated with this organization"))
                
                # Create membership
                membership = CustomerMembership.objects.create(
                    user=user,
                    customer=customer,
                    role=validated_role,
                    is_primary=is_primary,
                    created_by=created_by
                )
            
            log_security_event('user_linked_to_customer', {
                'user_id': user.id,
                'customer_id': customer.id,
                'role': validated_role,
                'is_primary': is_primary
            }, request_ip)
            
            logger.info(f"✅ [Secure User Linking] Linked user {user.email} to customer {customer.name} as {validated_role}")
            return Ok(membership)
            
        except Exception as e:
            return Err(SecureErrorHandler.safe_error_response(e, "user_linking"))
    
    @classmethod
    @secure_invitation_system()
    @atomic_with_retry(max_retries=3)
    @audit_service_call("invitation_sent")
    @monitor_performance(max_duration_seconds=10.0)
    def invite_user_to_customer(
        cls,
        inviter,
        invitee_email: str,
        customer,
        role: str = 'viewer',
        request_ip: str = None,
        user_id: int = None,  # For rate limiting
        **kwargs
    ) -> Result[CustomerMembership, str]:
        """
        🔒 Secure user invitation with comprehensive protection
        
        Security Features:
        - TOCTOU-safe permission checking  
        - Rate limiting per user
        - Input validation and sanitization
        - Audit logging with request tracking
        """
        
        try:
            # Permission and input validation handled by @secure_invitation_system decorator
            
            # Check if user already exists and has membership
            with transaction.atomic():
                existing_user = User.objects.select_for_update().filter(
                    email=invitee_email
                ).first()
                
                if existing_user:
                    # Check for existing membership
                    existing_membership = CustomerMembership.objects.select_for_update().filter(
                        user=existing_user,
                        customer=customer
                    ).first()
                    
                    if existing_membership:
                        return Err(_("User already has access to this organization"))
                    
                    # Add to existing user
                    membership = CustomerMembership.objects.create(
                        user=existing_user,
                        customer=customer,
                        role=role,
                        is_primary=False,
                    )
                    user_created = False
                else:
                    # Create new user account (inactive until they accept)
                    new_user = User.objects.create_user(
                        email=invitee_email,
                        is_active=False,  # Will be activated when they accept invite
                    )
                    
                    membership = CustomerMembership.objects.create(
                        user=new_user,
                        customer=customer,
                        role=role,
                        is_primary=False,
                    )
                    user_created = True
            
            # Send secure invitation email
            cls._send_invitation_email_secure(membership, inviter, request_ip)
            
            log_security_event('invitation_sent', {
                'inviter_id': inviter.id,
                'invitee_email': invitee_email,
                'customer_id': customer.id,
                'role': role,
                'user_created': user_created
            }, request_ip)
            
            return Ok(membership)
            
        except Exception as e:
            return Err(SecureErrorHandler.safe_error_response(e, "invitation"))
    
    # ===============================================================================
    # SECURE HELPER METHODS
    # ===============================================================================
    
    @classmethod
    def _find_customer_by_identifier_secure(
        cls, 
        identifier: str, 
        identification_type: str,
        request_ip: str = None
    ) -> Optional[Customer]:
        """
        🔒 Timing-safe customer lookup preventing enumeration attacks
        """
        start_time = time.time()
        
        try:
            # Input validation
            if not identifier or len(identifier) > 200:
                return None
            
            SecureInputValidator._check_malicious_patterns(identifier)
            
            # Rate limit lookups
            cache_key = f"customer_lookup:{request_ip or 'unknown'}"
            lookups = cache.get(cache_key, 0)
            if lookups >= 20:  # 20 lookups per hour per IP
                return None
            cache.set(cache_key, lookups + 1, timeout=3600)
            
            # Perform lookup based on type
            customer = None
            if identification_type == 'name':
                customer = Customer.objects.filter(company_name__iexact=identifier).first()
            elif identification_type == 'vat_number':
                # Validate VAT format first
                try:
                    validated_vat = SecureInputValidator.validate_vat_number_romanian(identifier)
                    tax_profile = CustomerTaxProfile.objects.filter(vat_number=validated_vat).first()
                    customer = tax_profile.customer if tax_profile else None
                except ValidationError:
                    pass
            elif identification_type == 'registration_number':
                # Validate CUI format first
                try:
                    validated_cui = SecureInputValidator.validate_cui_romanian(identifier)
                    tax_profile = CustomerTaxProfile.objects.filter(registration_number=validated_cui).first()
                    customer = tax_profile.customer if tax_profile else None
                except ValidationError:
                    pass
            
            return customer
            
        finally:
            # Ensure consistent timing (prevent timing attacks)
            elapsed = time.time() - start_time
            if elapsed < 0.1:  # Minimum 100ms
                time.sleep(0.1 - elapsed)
    
    @classmethod
    def _send_welcome_email_secure(cls, user: User, customer, request_ip: str = None) -> bool:
        """
        🔒 Secure welcome email with proper token generation
        """
        try:
            from django.contrib.auth.tokens import default_token_generator
            from django.utils.encoding import force_bytes
            from django.utils.http import urlsafe_base64_encode
            from django.template.loader import render_to_string
            from django.core.mail import send_mail
            from django.conf import settings
            
            # Generate secure password reset token
            token = default_token_generator.make_token(user)
            uid = urlsafe_base64_encode(force_bytes(user.pk))
            
            # Prepare secure email context
            context = {
                'user': user,
                'customer': customer,
                'domain': getattr(settings, 'DOMAIN_NAME', 'localhost:8000'),
                'uid': uid,
                'token': token,
                'protocol': 'https' if getattr(settings, 'USE_HTTPS', False) else 'http',
                'support_email': getattr(settings, 'SUPPORT_EMAIL', 'support@praho.com')
            }
            
            # Render email templates (XSS-safe)
            subject = _('Welcome to PRAHO - Account Created for {customer_name}').format(
                customer_name=customer.name
            )
            text_message = render_to_string('customers/emails/welcome_email.txt', context)
            html_message = render_to_string('customers/emails/welcome_email.html', context)
            
            # Send email with error handling
            send_mail(
                subject=subject,
                message=text_message,
                from_email=settings.DEFAULT_FROM_EMAIL,
                recipient_list=[user.email],
                html_message=html_message,
                fail_silently=False
            )
            
            log_security_event('welcome_email_sent', {
                'user_id': user.id,
                'customer_id': customer.id
            }, request_ip)
            
            logger.info(f"📧 [Secure Email] Welcome email sent to {user.email}")
            return True
            
        except Exception as e:
            logger.error(f"📧 [Secure Email] Failed to send welcome email: {str(e)}")
            log_security_event('welcome_email_failed', {
                'user_id': user.id,
                'error': str(e)[:200]
            }, request_ip)
            return False
    
    @classmethod  
    def _notify_owners_of_join_request_secure(cls, customer, requesting_user, request_ip: str = None):
        """
        🔒 Secure notification to owners with rate limiting
        """
        try:
            # Rate limit notifications
            cache_key = f"join_notifications:{customer.id}"
            notifications = cache.get(cache_key, 0)
            if notifications >= 10:  # Max 10 notifications per hour per customer
                return
            cache.set(cache_key, notifications + 1, timeout=3600)
            
            # Get owners securely
            owners = User.objects.filter(
                customer_memberships__customer=customer,
                customer_memberships__role='owner',
                is_active=True
            ).distinct()
            
            for owner in owners:
                send_mail(
                    subject=_('[PRAHO] New Access Request for {company}').format(
                        company=customer.company_name
                    ),
                    message=_('A user has requested access to your organization. Please review in your dashboard.'),
                    from_email=settings.DEFAULT_FROM_EMAIL,
                    recipient_list=[owner.email],
                    fail_silently=True,  # Don't fail the whole process if email fails
                )
            
            log_security_event('join_request_notifications_sent', {
                'customer_id': customer.id,
                'requesting_user_id': requesting_user.id,
                'owners_notified': len(owners)
            }, request_ip)
            
        except Exception as e:
            logger.error(f"📧 [Secure Notification] Failed to notify owners: {str(e)}")
    
    @classmethod
    def _send_invitation_email_secure(cls, membership, inviter, request_ip: str = None):
        """
        🔒 Secure invitation email with proper tokens and expiration
        """
        try:
            user = membership.user
            customer = membership.customer
            
            # Generate secure invitation token (could be enhanced with JWT)
            invitation_token = hashlib.sha256(
                f"{user.id}:{customer.id}:{time.time()}".encode()
            ).hexdigest()
            
            # Store token temporarily
            cache.set(f"invitation_token:{invitation_token}", {
                'user_id': user.id,
                'customer_id': customer.id,
                'role': membership.role
            }, timeout=7*24*3600)  # 7 days expiration
            
            send_mail(
                subject=_('[PRAHO] Invitation to join {company}').format(
                    company=customer.company_name
                ),
                message=_('You have been invited to join an organization on PRAHO. Please check your dashboard to accept.'),
                from_email=settings.DEFAULT_FROM_EMAIL,
                recipient_list=[user.email],
                fail_silently=True,
            )
            
            log_security_event('invitation_email_sent', {
                'inviter_id': inviter.id,
                'invitee_id': user.id,
                'customer_id': customer.id
            }, request_ip)
            
        except Exception as e:
            logger.error(f"📧 [Secure Invitation] Failed to send invitation: {str(e)}")


# ===============================================================================
# EXPORT SECURE SERVICES (BACKWARD COMPATIBILITY)
# ===============================================================================

# For backward compatibility, export with original names
UserRegistrationService = SecureUserRegistrationService
CustomerUserService = SecureCustomerUserService