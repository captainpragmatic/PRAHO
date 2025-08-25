"""
Enhanced Input Validation Framework - PRAHO Platform
Addresses critical security vulnerabilities and Romanian compliance requirements.
"""

import hashlib
import logging
import re
import time
from functools import wraps
from typing import Any

from django.core.cache import cache
from django.core.exceptions import ValidationError
from django.core.validators import validate_email
from django.db import transaction
from django.utils import timezone
from django.utils.translation import gettext_lazy as _

logger = logging.getLogger(__name__)

# ===============================================================================
# SECURITY CONSTANTS
# ===============================================================================

# Rate limiting thresholds
RATE_LIMIT_REGISTRATION_PER_IP = 5  # per hour
RATE_LIMIT_INVITATION_PER_USER = 10  # per hour
RATE_LIMIT_COMPANY_CHECK_PER_IP = 30  # per hour

# Input size limits (DoS prevention)
MAX_EMAIL_LENGTH = 254
MAX_NAME_LENGTH = 100
MAX_COMPANY_NAME_LENGTH = 200
MAX_PHONE_LENGTH = 20
MAX_VAT_NUMBER_LENGTH = 15
MAX_CUI_LENGTH = 10
MAX_DESCRIPTION_LENGTH = 1000

# Romanian specific patterns
ROMANIAN_VAT_PATTERN = r'^RO[0-9]{2,10}$'
ROMANIAN_CUI_PATTERN = r'^[0-9]{2,10}$'
ROMANIAN_PHONE_PATTERN = r'^(\+40|0)(7[0-9]{8}|2[0-9]{8}|3[0-9]{8})$'  # More restrictive Romanian mobile/landline

# Suspicious input patterns (injection attempts)
SUSPICIOUS_PATTERNS = [
    r'<script[^>]*>.*?</script>',  # XSS
    r'javascript:',  # XSS
    r'on\w+\s*=',  # Event handlers
    r'(union|select|insert|update|delete|drop|create|alter)\s+',  # SQL injection
    r'--\s*',  # SQL comments
    r'/\*.*?\*/',  # SQL comments
    r'eval\s*\(',  # Code execution
    r'exec\s*\(',  # Code execution
    r'[\r\n]',  # Newlines/control characters
]

# Allowed user roles for customer membership
ALLOWED_CUSTOMER_ROLES = ['owner', 'admin', 'manager', 'viewer']

# Admin-only fields that should never be in user input
RESTRICTED_USER_FIELDS = [
    'is_staff', 'is_superuser', 'is_active', 'user_permissions',
    'groups', 'last_login', 'date_joined', 'staff_role'
]


# ===============================================================================
# CORE VALIDATION DECORATORS
# ===============================================================================

def rate_limited(key_prefix: str, limit: int, window_minutes: int = 60):
    """
    Rate limiting decorator with Redis-like behavior using Django cache
    Prevents DoS and abuse attacks
    """
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            # Extract IP or user identifier
            request_ip = kwargs.get('request_ip') or 'unknown'
            user_id = kwargs.get('user_id', '')

            # Create rate limit key
            rate_key = f"{key_prefix}:{request_ip}:{user_id}"

            # Check current count
            current_count = cache.get(rate_key, 0)
            if current_count >= limit:
                logger.warning(f"🚨 [Security] Rate limit exceeded for {rate_key}")
                raise ValidationError(
                    _("Too many requests. Please try again later.")
                )

            # Execute function
            result = func(*args, **kwargs)

            # Increment counter (only on success)
            cache.set(rate_key, current_count + 1, timeout=window_minutes * 60)

            return result
        return wrapper
    return decorator


def timing_safe_validator(func):
    """
    Decorator to prevent timing attacks by ensuring consistent execution time
    """
    @wraps(func)
    def wrapper(*args, **kwargs):
        start_time = time.time()

        try:
            result = func(*args, **kwargs)
            success = True
        except Exception as e:
            result = e
            success = False

        # Ensure minimum execution time (prevents timing attacks)
        min_time = 0.1  # 100ms minimum
        elapsed = time.time() - start_time
        if elapsed < min_time:
            time.sleep(min_time - elapsed)

        if not success:
            raise result
        return result
    return wrapper


# ===============================================================================
# INPUT SANITIZATION & VALIDATION
# ===============================================================================

class SecureInputValidator:
    """Comprehensive input validation with security focus"""

    @staticmethod
    def validate_email_secure(email: str, context: str = "general") -> str:
        """
        Secure email validation preventing enumeration attacks
        """
        if not email or not isinstance(email, str):
            raise ValidationError(_("Invalid input format"))

        # Length check (DoS prevention)
        if len(email) > MAX_EMAIL_LENGTH:
            raise ValidationError(_("Input too long"))

        # XSS/injection check
        SecureInputValidator._check_malicious_patterns(email)

        # Normalize
        email = email.strip().lower()

        # Format validation
        try:
            validate_email(email)
        except ValidationError:
            # Generic error message (no enumeration)
            raise ValidationError(_("Invalid input format"))

        # Log suspicious attempts
        if '@' not in email or email.count('@') > 1:
            logger.warning(f"🚨 [Security] Suspicious email format: {email[:20]}...")

        return email

    @staticmethod
    def validate_name_secure(name: str, field_name: str = "name") -> str:
        """Secure name validation with XSS protection"""
        if not name or not isinstance(name, str):
            raise ValidationError(_("Invalid input format"))

        # Length check
        if len(name) > MAX_NAME_LENGTH:
            raise ValidationError(_("Input too long"))

        # XSS/injection check
        SecureInputValidator._check_malicious_patterns(name)

        # Character validation (letters, spaces, hyphens, apostrophes)
        if not re.match(r"^[a-zA-ZăâîșțĂÂÎȘȚ\s\-'\.]+$", name.strip()):
            raise ValidationError(_("Invalid characters detected"))

        # Normalize
        name = name.strip()

        # Length validation after normalization
        if len(name) < 1:
            raise ValidationError(_("Required field cannot be empty"))

        return name

    @staticmethod
    def validate_phone_romanian(phone: str) -> str:
        """Romanian phone number validation"""
        if not phone:
            return ""  # Phone is optional

        if not isinstance(phone, str):
            raise ValidationError(_("Invalid input format"))

        # Length check
        if len(phone) > MAX_PHONE_LENGTH:
            raise ValidationError(_("Input too long"))

        # XSS/injection check
        SecureInputValidator._check_malicious_patterns(phone)

        # Normalize
        phone = re.sub(r'[\s\-\(\)]', '', phone.strip())

        # Romanian format validation
        if not re.match(ROMANIAN_PHONE_PATTERN, phone):
            raise ValidationError(_("Invalid Romanian phone number format"))

        return phone

    @staticmethod
    def validate_vat_number_romanian(vat_number: str) -> str:
        """Romanian VAT number validation"""
        if not vat_number:
            return ""  # VAT is optional for some business types

        if not isinstance(vat_number, str):
            raise ValidationError(_("Invalid input format"))

        # Length check
        if len(vat_number) > MAX_VAT_NUMBER_LENGTH:
            raise ValidationError(_("Input too long"))

        # XSS/injection check
        SecureInputValidator._check_malicious_patterns(vat_number)

        # Normalize
        vat_number = vat_number.strip().upper()

        # Romanian VAT format validation
        if not re.match(ROMANIAN_VAT_PATTERN, vat_number):
            raise ValidationError(_("Invalid Romanian VAT number format"))

        return vat_number

    @staticmethod
    def validate_cui_romanian(cui: str) -> str:
        """Romanian CUI (Company Unique Identifier) validation"""
        if not cui:
            return ""  # CUI might be optional for some business types

        if not isinstance(cui, str):
            raise ValidationError(_("Invalid input format"))

        # Length check
        if len(cui) > MAX_CUI_LENGTH:
            raise ValidationError(_("Input too long"))

        # XSS/injection check
        SecureInputValidator._check_malicious_patterns(cui)

        # Normalize
        cui = cui.strip()

        # Romanian CUI format validation
        if not re.match(ROMANIAN_CUI_PATTERN, cui):
            raise ValidationError(_("Invalid Romanian CUI format"))

        # TODO: Add CUI checksum validation (Luhn algorithm variant)

        return cui

    @staticmethod
    def validate_company_name(company_name: str) -> str:
        """Company name validation with business logic"""
        if not company_name or not isinstance(company_name, str):
            raise ValidationError(_("Invalid input format"))

        # Length check
        if len(company_name) > MAX_COMPANY_NAME_LENGTH:
            raise ValidationError(_("Company name too long"))

        # XSS/injection check
        SecureInputValidator._check_malicious_patterns(company_name)

        # Business logic checks
        if len(company_name.strip()) < 2:
            raise ValidationError(_("Company name too short"))

        # Check for highly suspicious administrative patterns only
        admin_patterns = [r'\badmin\b', r'\broot\b', r'\bsystem\b', r'\bsuperuser\b']
        if any(re.search(pattern, company_name.lower()) for pattern in admin_patterns):
            raise ValidationError(_("Invalid company name"))

        return company_name.strip()

    @staticmethod
    def validate_customer_role(role: str) -> str:
        """Customer role validation"""
        if not role or not isinstance(role, str):
            raise ValidationError(_("Invalid input format"))

        role = role.strip().lower()

        if role not in ALLOWED_CUSTOMER_ROLES:
            logger.warning(f"🚨 [Security] Invalid role injection attempt: {role}")
            raise ValidationError(_("Invalid role specified"))

        return role

    @staticmethod
    def validate_user_data_dict(user_data: dict[str, Any]) -> dict[str, Any]:
        """
        Comprehensive user data validation preventing privilege escalation
        """
        if not isinstance(user_data, dict):
            raise ValidationError(_("Invalid input format"))

        # Check for restricted fields (privilege escalation prevention)
        for field in RESTRICTED_USER_FIELDS:
            if field in user_data:
                logger.warning(f"🚨 [Security] Privilege escalation attempt: {field}")
                raise ValidationError(_("Invalid input data"))

        # Validate required fields
        validated_data = {}

        # Email (required)
        if 'email' not in user_data:
            raise ValidationError(_("Required field missing"))
        validated_data['email'] = SecureInputValidator.validate_email_secure(
            user_data['email'], 'registration'
        )

        # Names (required)
        if 'first_name' not in user_data:
            raise ValidationError(_("Required field missing"))
        validated_data['first_name'] = SecureInputValidator.validate_name_secure(
            user_data['first_name'], 'first_name'
        )

        if 'last_name' not in user_data:
            raise ValidationError(_("Required field missing"))
        validated_data['last_name'] = SecureInputValidator.validate_name_secure(
            user_data['last_name'], 'last_name'
        )

        # Optional fields
        if 'phone' in user_data:
            validated_data['phone'] = SecureInputValidator.validate_phone_romanian(
                user_data['phone']
            )

        # Boolean fields with type safety
        if 'accepts_marketing' in user_data:
            if isinstance(user_data['accepts_marketing'], bool | str):
                validated_data['accepts_marketing'] = bool(user_data['accepts_marketing'])
            else:
                raise ValidationError(_("Invalid input format"))

        # GDPR consent validation
        if user_data.get('gdpr_consent_date'):
            validated_data['gdpr_consent_date'] = timezone.now()

        return validated_data

    @staticmethod
    def validate_customer_data_dict(customer_data: dict[str, Any]) -> dict[str, Any]:
        """
        Comprehensive customer data validation for Romanian businesses
        """
        if not isinstance(customer_data, dict):
            raise ValidationError(_("Invalid input format"))

        validated_data = {}

        # Company name (required)
        if 'company_name' not in customer_data:
            raise ValidationError(_("Required field missing"))
        validated_data['company_name'] = SecureInputValidator.validate_company_name(
            customer_data['company_name']
        )

        # Customer type validation
        if 'customer_type' in customer_data:
            allowed_types = ['individual', 'srl', 'pfa', 'sa', 'ngo', 'other']
            customer_type = customer_data['customer_type'].lower()
            if customer_type not in allowed_types:
                raise ValidationError(_("Invalid customer type"))
            validated_data['customer_type'] = customer_type

        # VAT number (optional but validated if provided)
        if 'vat_number' in customer_data:
            validated_data['vat_number'] = SecureInputValidator.validate_vat_number_romanian(
                customer_data['vat_number']
            )

        # Registration number/CUI (optional but validated if provided)
        if 'registration_number' in customer_data:
            validated_data['registration_number'] = SecureInputValidator.validate_cui_romanian(
                customer_data['registration_number']
            )

        # Address fields (optional)
        address_fields = ['billing_address', 'billing_city', 'billing_postal_code']
        for field in address_fields:
            if customer_data.get(field):
                value = customer_data[field].strip()
                SecureInputValidator._check_malicious_patterns(value)
                validated_data[field] = value

        return validated_data

    @staticmethod
    def _check_malicious_patterns(input_string: str) -> None:
        """
        Check for malicious patterns (XSS, SQL injection, etc.)
        """
        for pattern in SUSPICIOUS_PATTERNS:
            if re.search(pattern, input_string, re.IGNORECASE):
                logger.warning(f"🚨 [Security] Malicious pattern detected: {pattern}")
                raise ValidationError(_("Invalid input detected"))


# ===============================================================================
# BUSINESS LOGIC VALIDATORS
# ===============================================================================

class BusinessLogicValidator:
    """Business logic validation with race condition prevention"""

    @staticmethod
    @timing_safe_validator
    def check_company_uniqueness(company_data: dict[str, Any], request_ip: str = None) -> None:
        """
        Check company uniqueness with race condition prevention
        """
        from apps.customers.models import Customer, CustomerTaxProfile

        # Rate limiting for enumeration prevention
        cache_key = f"company_check:{request_ip or 'unknown'}"
        current_checks = cache.get(cache_key, 0)
        if current_checks >= RATE_LIMIT_COMPANY_CHECK_PER_IP:
            raise ValidationError(_("Service temporarily unavailable"))
        cache.set(cache_key, current_checks + 1, timeout=3600)

        company_name = company_data.get('company_name', '').strip()
        vat_number = company_data.get('vat_number', '').strip()
        registration_number = company_data.get('registration_number', '').strip()

        # Create deterministic hash for atomic checking
        check_hash = hashlib.sha256(
            f"{company_name}:{vat_number}:{registration_number}".encode()
        ).hexdigest()

        # Atomic check with database transaction
        with transaction.atomic():
            # Check with SELECT FOR UPDATE to prevent race conditions
            existing_company = None
            existing_vat = None
            existing_reg = None

            if company_name:
                existing_company = Customer.objects.select_for_update().filter(
                    company_name__iexact=company_name
                ).first()

            if vat_number:
                existing_vat = CustomerTaxProfile.objects.select_for_update().filter(
                    vat_number=vat_number
                ).first()

            if registration_number:
                existing_reg = CustomerTaxProfile.objects.select_for_update().filter(
                    registration_number=registration_number
                ).first()

            # Generic error message (no enumeration)
            if existing_company or existing_vat or existing_reg:
                logger.warning(f"🚨 [Security] Company registration conflict: {check_hash[:16]}")
                raise ValidationError(_("Registration validation failed"))

    @staticmethod
    def validate_user_permissions(user, customer, required_role: str = 'owner') -> None:
        """
        TOCTOU-safe permission validation
        """
        from apps.users.models import CustomerMembership

        # Check current membership atomically
        with transaction.atomic():
            membership = CustomerMembership.objects.select_for_update().filter(
                user=user,
                customer=customer,
                role__in=['owner', 'admin'] if required_role == 'owner' else [required_role]
            ).first()

            if not membership:
                logger.warning(f"🚨 [Security] Permission denied for user {user.id} on customer {customer.id}")
                raise ValidationError(_("Permission denied"))

            # Additional active user check
            if not user.is_active:
                logger.warning(f"🚨 [Security] Inactive user access attempt: {user.id}")
                raise ValidationError(_("Account not active"))

    @staticmethod
    @rate_limited("invitation", RATE_LIMIT_INVITATION_PER_USER, 60)
    def validate_invitation_request(inviter, invitee_email: str, customer, role: str, **kwargs) -> None:
        """
        Comprehensive invitation validation with rate limiting
        """
        from apps.users.models import CustomerMembership, User

        # Validate inviter permissions (TOCTOU-safe)
        BusinessLogicValidator.validate_user_permissions(inviter, customer, 'owner')

        # Validate role
        SecureInputValidator.validate_customer_role(role)

        # Validate invitee email
        validated_email = SecureInputValidator.validate_email_secure(invitee_email, 'invitation')

        # Check for existing membership (prevent duplicate invitations)
        existing_user = User.objects.filter(email=validated_email).first()
        if existing_user:
            existing_membership = CustomerMembership.objects.filter(
                user=existing_user,
                customer=customer
            ).first()
            if existing_membership:
                raise ValidationError(_("User already has access to this organization"))


# ===============================================================================
# SECURE ERROR HANDLING
# ===============================================================================

class SecureErrorHandler:
    """Security-conscious error handling preventing information disclosure"""

    @staticmethod
    def safe_error_response(error: Exception, context: str = "general") -> str:
        """
        Return safe error messages that don't leak sensitive information
        """
        # Log detailed error for administrators
        error_id = hashlib.sha256(f"{error!s}{time.time()}".encode()).hexdigest()[:8]
        logger.error(f"🔥 [Security] {context} error {error_id}: {error!s}")

        # Return generic error message to user
        generic_messages = {
            "registration": _("Registration could not be completed. Please contact support."),
            "user_registration": _("Registration could not be completed. Please contact support."),
            "invitation": _("Invitation could not be sent. Please try again later."),
            "validation": _("The provided information is invalid."),
            "permission": _("You don't have permission to perform this action."),
            "general": _("An error occurred. Please try again later.")
        }

        return generic_messages.get(context, generic_messages["general"]) + f" (ID: {error_id})"


# ===============================================================================
# AUDIT LOGGING INTEGRATION
# ===============================================================================

def log_security_event(event_type: str, details: dict[str, Any], request_ip: str = None):
    """
    Log security events for monitoring and forensics
    """
    try:

        # For now, just log to standard logger to avoid transaction issues
        logger.warning(f"🚨 [Security] {event_type}: {details} from IP: {request_ip}")

        # TODO: Integrate with audit service once transaction handling is fixed
        # audit_service.log_event(
        #     event_type=f"security_{event_type}",
        #     description=f"Security event: {event_type}",
        #     ip_address=request_ip,
        #     metadata={
        #         'event_category': 'security_validation',
        #         'timestamp': timezone.now().isoformat(),
        #         'details': details
        #     },
        #     actor_type='system'
        # )
    except Exception as e:
        logger.error(f"Failed to log security event: {e}")
