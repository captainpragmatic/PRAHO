"""
SECURE User Registration Services - PRAHO Platform
Enhanced with comprehensive security measures addressing critical vulnerabilities.

This replaces the existing services.py with security-hardened implementations.
"""

import hashlib
import logging
import time
from typing import TYPE_CHECKING, Any, Optional, TypedDict

from django.conf import settings
from django.contrib.auth import get_user_model
from django.core.cache import cache
from django.core.exceptions import ValidationError
from django.core.mail import send_mail
from django.db import transaction
from django.utils import timezone
from django.utils.translation import gettext_lazy as _

from apps.common.security_decorators import (
    atomic_with_retry,
    audit_service_call,
    monitor_performance,
    prevent_race_conditions,
    secure_customer_operation,
    secure_invitation_system,
    secure_user_registration,
)
from apps.common.types import (
    CUIString,
    EmailAddress,
    Err,
    Ok,
    PhoneNumber,
    Result,
    VATString,
)
from apps.common.validators import (
    SecureErrorHandler,
    SecureInputValidator,
    log_security_event,
)
from apps.customers.models import (
    Customer,
    CustomerAddress,
    CustomerBillingProfile,
    CustomerTaxProfile,
)

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

    class UserData(TypedDict):
        """Type definition for user registration data"""
        email: EmailAddress
        first_name: str
        last_name: str
        phone: Optional[PhoneNumber]
        accepts_marketing: Optional[bool]
        gdpr_consent_date: Optional[str]

    class CustomerData(TypedDict):
        """Type definition for customer registration data"""
        company_name: str
        customer_type: str
        vat_number: Optional[VATString]
        registration_number: Optional[CUIString]
        billing_address: Optional[str]
        billing_city: Optional[str]
        billing_postal_code: Optional[str]

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
        user_data: dict[str, Any],
        customer_data: dict[str, Any],
        request_ip: Optional[str] = None,
        user_agent: Optional[str] = None,
        **kwargs: Any
    ) -> Result[tuple[User, Customer], str]:
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
                CustomerTaxProfile.objects.create(
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
            CustomerMembership.objects.create(
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

        except ValidationError:
            # Validation errors are handled by decorator
            raise

        except Exception as e:
            # Log unexpected errors without exposing details
            error_id = hashlib.sha256(f"{e!s}{time.time()}".encode()).hexdigest()[:8]
            logger.error(f"🔥 [Secure Registration] Unexpected error {error_id}: {e!s}")

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
        user_data: dict[str, Any],
        company_identifier: str,
        identification_type: str,  # 'name', 'vat_number', 'registration_number'
        request_ip: str = None,
        **kwargs
    ) -> Result[dict[str, Any], str]:
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
    ) -> Result[tuple[User, bool], str]:
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
    ) -> Customer | None:
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
            from django.conf import settings
            from django.contrib.auth.tokens import default_token_generator
            from django.core.mail import send_mail
            from django.template.loader import render_to_string
            from django.utils.encoding import force_bytes
            from django.utils.http import urlsafe_base64_encode

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
            logger.error(f"📧 [Secure Email] Failed to send welcome email: {e!s}")
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
            logger.error(f"📧 [Secure Notification] Failed to notify owners: {e!s}")

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
            logger.error(f"📧 [Secure Invitation] Failed to send invitation: {e!s}")


# ===============================================================================
# SESSION SECURITY SERVICE
# ===============================================================================

class SessionSecurityService:
    """
    🔒 Secure session management for Romanian hosting security compliance
    
    Provides:
    - Session rotation on security events
    - 2FA secret cleanup during recovery
    - Activity tracking and suspicious behavior detection
    - Shared device mode with enhanced timeouts
    """

    # Session timeout policies (seconds)
    TIMEOUT_POLICIES = {
        'standard': 3600,        # 1 hour for regular users
        'sensitive': 1800,       # 30 min for admin/billing staff
        'shared_device': 900,    # 15 min for shared device mode
        'remember_me': 86400 * 7 # 7 days for remember me
    }

    @classmethod
    def rotate_session_on_password_change(cls, request, user=None):
        """🔒 Rotate session after password change and invalidate other sessions"""
        if not request.user.is_authenticated and not user:
            return

        target_user = user or request.user
        old_session_key = request.session.session_key

        # Cycle session key (Django's built-in security)
        request.session.cycle_key()
        new_session_key = request.session.session_key

        # Invalidate all other sessions for this user
        cls._invalidate_other_user_sessions(target_user.id, new_session_key)

        # Clear sensitive session data
        cls._clear_sensitive_session_data(request)

        # Log security event using existing pattern
        log_security_event('session_rotated_password_change', {
            'user_id': target_user.id,
            'old_session_key': old_session_key[:8] + '...',  # Truncated for security
            'new_session_key': new_session_key[:8] + '...'
        }, cls._get_client_ip(request))

        logger.warning(f"🔄 [SessionSecurity] Session rotated for {target_user.email} after password change")

    @classmethod
    def rotate_session_on_2fa_change(cls, request):
        """🔒 Rotate session when 2FA is enabled/disabled"""
        if not request.user.is_authenticated:
            return

        user = request.user
        old_session_key = request.session.session_key

        # Cycle session key
        request.session.cycle_key()
        new_session_key = request.session.session_key

        # For 2FA changes, invalidate other sessions as security measure
        cls._invalidate_other_user_sessions(user.id, new_session_key)

        # Log security event
        log_security_event('session_rotated_2fa_change', {
            'user_id': user.id,
            'old_session_key': old_session_key[:8] + '...',
            'new_session_key': new_session_key[:8] + '...'
        }, cls._get_client_ip(request))

        logger.warning(f"🔄 [SessionSecurity] Session rotated for {user.email} after 2FA change")

    @classmethod
    def cleanup_2fa_secrets_on_recovery(cls, user, request_ip=None):
        """🔒 Clean up 2FA secrets during account recovery"""
        if not user:
            return

        # Clear 2FA configuration
        user.two_factor_enabled = False
        user.two_factor_secret = ''  # This will encrypt empty string
        user.backup_tokens = []
        user.save(update_fields=['two_factor_enabled', '_two_factor_secret', 'backup_tokens'])

        # Invalidate all sessions for security
        cls._invalidate_all_user_sessions(user.id)

        # Log security event
        log_security_event('2fa_secrets_cleared_recovery', {
            'user_id': user.id,
            'email': user.email
        }, request_ip)

        logger.warning(f"🔐 [SessionSecurity] 2FA secrets cleared for {user.email} during recovery")

    @classmethod
    def update_session_timeout(cls, request):
        """🔒 Update session timeout based on user context"""
        if not hasattr(request, 'session') or not request.user.is_authenticated:
            return

        timeout_seconds = cls.get_appropriate_timeout(request)
        request.session.set_expiry(timeout_seconds)

        # Log timeout update
        log_security_event('session_timeout_updated', {
            'user_id': request.user.id,
            'timeout_seconds': timeout_seconds,
            'policy': cls._get_timeout_policy_name(timeout_seconds)
        }, cls._get_client_ip(request))

    @classmethod
    def get_appropriate_timeout(cls, request) -> int:
        """Get appropriate timeout based on user role and device context"""
        if not request.user.is_authenticated:
            return cls.TIMEOUT_POLICIES['standard']

        user = request.user

        # Shared device mode (shorter timeout)
        if request.session.get('shared_device_mode', False):
            return cls.TIMEOUT_POLICIES['shared_device']

        # Sensitive staff roles get shorter timeouts
        if hasattr(user, 'staff_role') and user.staff_role in ['admin', 'billing']:
            return cls.TIMEOUT_POLICIES['sensitive']

        # Remember me functionality
        if request.session.get('remember_me', False):
            return cls.TIMEOUT_POLICIES['remember_me']

        return cls.TIMEOUT_POLICIES['standard']

    @classmethod
    def enable_shared_device_mode(cls, request):
        """🔒 Enable shared device mode with enhanced security"""
        if not request.user.is_authenticated:
            return

        request.session['shared_device_mode'] = True
        request.session['shared_device_enabled_at'] = timezone.now().isoformat()

        # Set shorter timeout immediately
        timeout = cls.TIMEOUT_POLICIES['shared_device']
        request.session.set_expiry(timeout)

        # Clear any remember me settings
        request.session.pop('remember_me', None)

        log_security_event('shared_device_mode_enabled', {
            'user_id': request.user.id,
            'timeout_seconds': timeout
        }, cls._get_client_ip(request))

        logger.info(f"📱 [SessionSecurity] Shared device mode enabled for {request.user.email}")

    @classmethod
    def detect_suspicious_activity(cls, request) -> bool:
        """🔒 Detect suspicious session activity patterns"""
        if not request.user.is_authenticated:
            return False

        user_id = request.user.id
        current_ip = cls._get_client_ip(request)

        # Check for rapid IP changes (simplified detection)
        cache_key = f"recent_ips:{user_id}"
        recent_ips = cache.get(cache_key, [])

        # Add current IP
        recent_ips.append({
            'ip': current_ip,
            'timestamp': time.time()
        })

        # Keep only last hour of IPs
        one_hour_ago = time.time() - 3600
        recent_ips = [ip_data for ip_data in recent_ips if ip_data['timestamp'] > one_hour_ago]

        # Check for suspicious pattern (3+ different IPs in 1 hour)
        unique_ips = {ip_data['ip'] for ip_data in recent_ips}
        is_suspicious = len(unique_ips) >= 3

        if is_suspicious:
            log_security_event('suspicious_activity_detected', {
                'user_id': user_id,
                'ip_count': len(unique_ips),
                'current_ip': current_ip,
                'pattern': 'multiple_ips'
            }, current_ip)

            logger.warning(f"🚨 [SessionSecurity] Suspicious IP pattern for {request.user.email}: {unique_ips}")

        # Update cache
        cache.set(cache_key, recent_ips, timeout=3600)

        return is_suspicious

    @classmethod
    def log_session_activity(cls, request, activity_type: str, **extra_data):
        """🔒 Log session activity using existing security event system"""
        if not request.user.is_authenticated:
            return

        activity_data = {
            'user_id': request.user.id,
            'session_key': request.session.session_key[:8] + '...' if request.session.session_key else None,
            'activity_type': activity_type,
            'request_path': request.path,
            **extra_data
        }

        # Use existing security logging
        log_security_event(f'session_activity_{activity_type}', activity_data, cls._get_client_ip(request))

        # Log critical activities with warning level
        if activity_type in ['login', 'logout', 'password_changed', '2fa_disabled']:
            logger.warning(f"🔐 [SessionActivity] {activity_type.upper()}: {request.user.email}")

    # ===============================================================================
    # PRIVATE HELPER METHODS
    # ===============================================================================

    @classmethod
    def _invalidate_other_user_sessions(cls, user_id: int, keep_session_key: str):
        """Invalidate all sessions for a user except specified one"""
        try:
            from django.contrib.sessions.models import Session
            count = 0

            for session in Session.objects.all():
                try:
                    session_data = session.get_decoded()
                    session_user_id = session_data.get('_auth_user_id')

                    if session_user_id == str(user_id) and session.session_key != keep_session_key:
                        session.delete()
                        count += 1
                except:
                    # Skip invalid sessions
                    continue

            logger.info(f"🗑️ [SessionSecurity] Invalidated {count} other sessions for user {user_id}")
        except Exception as e:
            logger.error(f"🔥 [SessionSecurity] Error invalidating sessions for user {user_id}: {e}")

    @classmethod
    def _invalidate_all_user_sessions(cls, user_id: int):
        """Invalidate all sessions for a user"""
        try:
            from django.contrib.sessions.models import Session
            count = 0

            for session in Session.objects.all():
                try:
                    session_data = session.get_decoded()
                    session_user_id = session_data.get('_auth_user_id')

                    if session_user_id == str(user_id):
                        session.delete()
                        count += 1
                except:
                    # Skip invalid sessions
                    continue

            logger.warning(f"🗑️ [SessionSecurity] Invalidated {count} sessions for user {user_id}")
        except Exception as e:
            logger.error(f"🔥 [SessionSecurity] Error invalidating all sessions for user {user_id}: {e}")

    @classmethod
    def _clear_sensitive_session_data(cls, request):
        """Clear sensitive data from session"""
        sensitive_keys = [
            '2fa_secret', 'new_backup_codes', 'password_reset_token',
            'email_verification_token', 'temp_user_data'
        ]

        for key in sensitive_keys:
            if key in request.session:
                del request.session[key]

    @classmethod
    def _get_client_ip(cls, request) -> str:
        """Get real client IP address"""
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            return x_forwarded_for.split(',')[0].strip()
        return request.META.get('REMOTE_ADDR', '')

    @classmethod
    def _get_timeout_policy_name(cls, timeout_seconds: int) -> str:
        """Get policy name for timeout value"""
        for policy, seconds in cls.TIMEOUT_POLICIES.items():
            if seconds == timeout_seconds:
                return policy
        return 'custom'


# ===============================================================================
# EXPORT SECURE SERVICES (BACKWARD COMPATIBILITY)
# ===============================================================================

# For backward compatibility, export with original names
UserRegistrationService = SecureUserRegistrationService
CustomerUserService = SecureCustomerUserService
