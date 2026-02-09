"""
Enhanced Input Validation Framework - PRAHO Platform
Addresses critical security vulnerabilities and Romanian compliance requirements.
"""

import hashlib
import ipaddress
import logging
import re
import socket
import time
from collections.abc import Callable
from datetime import datetime
from functools import wraps
from typing import Any, TypeVar, cast
from urllib.parse import urlparse

from django.core.cache import cache
from django.core.exceptions import ValidationError
from django.core.validators import validate_email
from django.db import transaction
from django.utils import timezone
from django.utils.translation import gettext_lazy as _

from apps.common.constants import COMPANY_NAME_MIN_LENGTH
from apps.common.types import (
    CUIString,
    EmailAddress,
    Err,
    VATString,
    validate_romanian_cui,
)
from apps.customers.customer_models import Customer
from apps.customers.profile_models import CustomerTaxProfile
from apps.users.models import CustomerMembership, User

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
MAX_URL_LENGTH = 2048  # Standard URL length limit
MAX_BANK_DETAIL_LENGTH = 100  # Bank detail field length limit

# Romanian specific patterns
ROMANIAN_VAT_PATTERN = r"^RO[0-9]{2,10}$"
ROMANIAN_CUI_PATTERN = r"^[0-9]{2,10}$"

# Suspicious input patterns (injection attempts)
SUSPICIOUS_PATTERNS = [
    r"<script[^>]*>.*?</script>",  # XSS
    r"javascript:",  # XSS
    r"on\w+\s*=",  # Event handlers
    r"(union|select|insert|update|delete|drop|create|alter)\s+",  # SQL injection
    r"--\s*",  # SQL comments
    r"/\*.*?\*/",  # SQL comments
    r"eval\s*\(",  # Code execution
    r"exec\s*\(",  # Code execution
    r"[\r\n]",  # Newlines/control characters
]

# Allowed user roles for customer membership
ALLOWED_CUSTOMER_ROLES = ["owner", "admin", "manager", "viewer"]

# Admin-only fields that should never be in user input
RESTRICTED_USER_FIELDS = [
    "is_staff",
    "is_superuser",
    "is_active",
    "user_permissions",
    "groups",
    "last_login",
    "date_joined",
    "staff_role",
]


# ===============================================================================
# CORE VALIDATION DECORATORS
# ===============================================================================

F = TypeVar("F", bound=Callable[..., Any])


def rate_limited(key_prefix: str, limit: int, window_minutes: int = 60) -> Callable[[F], F]:
    """
    Rate limiting decorator with Redis-like behavior using Django cache
    Prevents DoS and abuse attacks
    """

    def decorator(func: F) -> F:
        @wraps(func)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            # Extract IP or user identifier
            request_ip = kwargs.get("request_ip") or "unknown"
            user_id = kwargs.get("user_id", "")

            # Create rate limit key
            rate_key = f"{key_prefix}:{request_ip}:{user_id}"

            # Check current count
            current_count = cache.get(rate_key, 0)
            if current_count >= limit:
                logger.warning(f"🚨 [Security] Rate limit exceeded for {rate_key}")
                raise ValidationError(_("Too many requests. Please try again later."))

            # Execute function
            result = func(*args, **kwargs)

            # Increment counter (only on success)
            cache.set(rate_key, current_count + 1, timeout=window_minutes * 60)

            return result

        return cast(F, wrapper)

    return decorator


def timing_safe_validator(func: F) -> F:
    """
    Decorator to prevent timing attacks by ensuring consistent execution time
    """

    @wraps(func)
    def wrapper(*args: Any, **kwargs: Any) -> Any:
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

    return cast(F, wrapper)


# ===============================================================================
# INPUT SANITIZATION & VALIDATION
# ===============================================================================


class SecureInputValidator:
    """Comprehensive input validation with security focus"""

    @staticmethod
    @timing_safe_validator
    def validate_email_secure(email: str, context: str = "general") -> EmailAddress:
        """
        🔒 Secure email validation preventing enumeration attacks with consistent timing
        """
        # Security: Add consistent delay to prevent timing analysis
        start_time = time.time()

        if not email or not isinstance(email, str):
            # Security: Ensure consistent timing even for invalid inputs
            time.sleep(max(0, 0.1 - (time.time() - start_time)))
            raise ValidationError(_("Invalid input format"))

        # Length check (DoS prevention)
        if len(email) > MAX_EMAIL_LENGTH:
            time.sleep(max(0, 0.1 - (time.time() - start_time)))
            raise ValidationError(_("Input too long"))

        # XSS/injection check
        SecureInputValidator._check_malicious_patterns(email)

        # Normalize
        email = email.strip().lower()

        # Format validation
        try:
            validate_email(email)
        except ValidationError:
            # Security: Generic error message with consistent timing
            time.sleep(max(0, 0.1 - (time.time() - start_time)))
            raise ValidationError(_("Invalid input format")) from None

        # Log suspicious attempts (after timing normalization)
        if "@" not in email or email.count("@") > 1:
            logger.warning(f"🚨 [Security] Suspicious email format: {email[:20]}...")

        # Security: Ensure consistent timing for all successful validations
        time.sleep(max(0, 0.1 - (time.time() - start_time)))
        return EmailAddress(email)

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
    def validate_vat_number_romanian(vat_number: str) -> VATString:
        """Romanian VAT number validation"""
        if not vat_number:
            return VATString("")  # VAT is optional for some business types

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

        return VATString(vat_number)

    @staticmethod
    def validate_cui_romanian(cui: str) -> CUIString:
        """Romanian CUI (Company Unique Identifier) validation - delegating to types module"""
        if not cui:
            return CUIString("")  # CUI might be optional for some business types

        if not isinstance(cui, str):
            raise ValidationError(_("Invalid input format"))

        # Length check
        if len(cui) > MAX_CUI_LENGTH:
            raise ValidationError(_("Input too long"))

        # XSS/injection check
        SecureInputValidator._check_malicious_patterns(cui)

        # Use centralized validation from types module
        result = validate_romanian_cui(cui.strip())
        if result.is_err():
            error_result = cast(Err[str], result)
            raise ValidationError(_(error_result.error))

        return result.unwrap()

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
        if len(company_name.strip()) < COMPANY_NAME_MIN_LENGTH:
            raise ValidationError(_("Company name too short"))

        # Check for highly suspicious administrative patterns only
        admin_patterns = [r"\badmin\b", r"\broot\b", r"\bsystem\b", r"\bsuperuser\b"]
        if any(re.search(pattern, company_name.lower()) for pattern in admin_patterns):
            raise ValidationError(_("Invalid company name"))

        return company_name.strip()

    @staticmethod
    def validate_safe_url(url: str, return_pinned_ips: bool = False) -> str | tuple[str, list[str]]:
        """
        Validate URL destination to prevent SSRF attacks.
        A10 - Server-Side Request Forgery prevention

        Args:
            url: The URL to validate
            return_pinned_ips: If True, return (url, validated_ips) for DNS pinning

        Returns:
            Validated URL string, or tuple of (url, pinned_ips) if return_pinned_ips=True

        Note: When making HTTP requests, use the pinned IPs directly to prevent
        DNS rebinding attacks between validation and request time.
        """
        if not url or not isinstance(url, str):
            raise ValidationError(_("Invalid URL format"))

        # Length check (DoS prevention)
        if len(url) > MAX_URL_LENGTH:
            raise ValidationError(_("URL too long"))

        # XSS/injection check
        SecureInputValidator._check_malicious_patterns(url)

        url = url.strip()

        try:
            parsed = urlparse(url)
            SecureInputValidator._validate_url_scheme(parsed)
            validated_ips = SecureInputValidator._validate_url_hostname(parsed)
            SecureInputValidator._validate_url_port(parsed)

            logger.info(f"✅ [Security] Safe URL validated: {parsed.hostname} -> {validated_ips}")

            if return_pinned_ips:
                return url, validated_ips
            return url

        except ValidationError:
            # Re-raise our validation errors
            raise
        except Exception as e:
            logger.warning(f"⚠️ [Security] URL validation error: {e}")
            raise ValidationError(_("Invalid URL format")) from None

    @staticmethod
    def _validate_url_scheme(parsed: Any) -> None:
        """Validate URL scheme is safe"""
        allowed_schemes = ["http", "https"]
        if parsed.scheme.lower() not in allowed_schemes:
            raise ValidationError(_("Only HTTP and HTTPS URLs are allowed"))

    @staticmethod
    def _validate_url_hostname(parsed: Any) -> list[str]:
        """
        🔒 Enhanced hostname validation with DNS rebinding protection.

        Returns list of validated IP addresses for connection pinning.
        Callers should use these IPs directly to prevent DNS rebinding attacks.
        """
        if not parsed.hostname:
            raise ValidationError(_("Invalid URL format"))

        hostname = parsed.hostname.lower()

        # Block dangerous domains first (before DNS resolution)
        dangerous_domains = [
            "localhost",
            "127.0.0.1",
            "metadata.google.internal",
            "metadata.google.com",
            "metadata",
            "link-local",
            "instance-data",
            "::1",
            "10.",
            "172.",
            "192.168.",
            "169.254.",
        ]

        for dangerous in dangerous_domains:
            if dangerous in hostname:
                raise ValidationError(_("URL destination not allowed"))

        # Check for direct IP addresses and block private/internal ranges
        try:
            ip = ipaddress.ip_address(hostname)
            if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_reserved:
                raise ValidationError(_("URL destination not allowed"))
            # Direct IP provided, return it for pinning
            return [str(ip)]
        except ValueError:
            # Not an IP address, proceed with DNS resolution
            pass

        # Security: Resolve hostname and validate ALL resolved IPs
        # Return validated IPs for connection pinning to prevent DNS rebinding
        validated_ips: list[str] = []
        try:
            resolved_ips = socket.getaddrinfo(hostname, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
            for ip_info in resolved_ips:
                ip_str = ip_info[4][0]
                try:
                    ip = ipaddress.ip_address(ip_str)
                    # Security: Block any resolved IP that points to private/internal ranges
                    if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_reserved:
                        raise ValidationError(_("URL destination resolves to blocked IP range"))
                    validated_ips.append(str(ip))
                except ValueError:
                    continue

            if not validated_ips:
                raise ValidationError(_("No valid IP addresses resolved for URL"))

        except (TimeoutError, socket.gaierror):
            logger.warning(f"⚡ [Security] DNS resolution failed for hostname: {hostname}")
            raise ValidationError(_("Unable to verify URL destination")) from None

        return validated_ips

    @staticmethod
    def _validate_url_port(parsed: Any) -> None:
        """Validate URL port is not dangerous"""
        if parsed.port:
            dangerous_ports = [22, 23, 25, 53, 135, 445, 993, 995, 1433, 1521, 3306, 5432, 6379, 9200, 11211]
            if parsed.port in dangerous_ports:
                raise ValidationError(_("URL destination not allowed"))

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
    def validate_bank_details_schema(bank_details: dict[str, Any]) -> dict[str, Any]:
        """
        Validate bank details JSON schema to prevent data integrity issues
        A08 - Software and Data Integrity Failures prevention
        """
        if not bank_details or not isinstance(bank_details, dict):
            return {}

        # Define expected schema
        valid_keys = {
            "account_number",
            "bank_name",
            "routing_number",
            "iban",
            "swift_code",
            "account_holder",
            "bank_address",
            "currency",
        }

        validated_details: dict[str, Any] = {}

        for key, value in bank_details.items():
            # Only allow known keys
            if key not in valid_keys:
                logger.warning(f"🚨 [Security] Invalid bank details key: {key}")
                continue

            # Type validation
            if not isinstance(value, str | int | float):
                logger.warning(f"🚨 [Security] Invalid bank details value type for {key}: {type(value)}")
                continue

            # Convert to string and validate
            str_value = str(value).strip()

            # Length limits (prevent DoS)
            if len(str_value) > MAX_BANK_DETAIL_LENGTH:
                raise ValidationError(_("Bank detail field too long"))

            # XSS/injection check
            SecureInputValidator._check_malicious_patterns(str_value)

            # Specific field validation
            if key == "account_number" and str_value:
                # Allow only alphanumeric and common separators
                if not re.match(r"^[A-Za-z0-9\-\s]+$", str_value):
                    raise ValidationError(_("Invalid account number format"))
            elif key == "iban" and str_value:
                # Basic IBAN format check
                if not re.match(r"^[A-Za-z0-9]{15,34}$", str_value.replace(" ", "")):
                    raise ValidationError(_("Invalid IBAN format"))
            elif (
                key == "swift_code"
                and str_value
                and not re.match(r"^[A-Za-z]{4}[A-Za-z]{2}[A-Za-z0-9]{2}([A-Za-z0-9]{3})?$", str_value)
            ):
                # SWIFT code format check
                raise ValidationError(_("Invalid SWIFT code format"))

            validated_details[key] = str_value

        logger.info("✅ [Security] Bank details schema validated successfully")
        return validated_details

    @staticmethod
    def _validate_restricted_fields(user_data: dict[str, Any]) -> None:
        """Check for restricted fields to prevent privilege escalation."""
        for field in RESTRICTED_USER_FIELDS:
            if field in user_data:
                logger.warning(f"🚨 [Security] Privilege escalation attempt: {field}")
                raise ValidationError(_("Invalid input data"))

    @staticmethod
    def _validate_required_email(user_data: dict[str, Any]) -> str:
        """Validate required email field."""
        if "email" not in user_data:
            raise ValidationError(_("Required field missing"))
        return SecureInputValidator.validate_email_secure(user_data["email"], "registration")

    @staticmethod
    def _validate_required_names(user_data: dict[str, Any]) -> tuple[str, str]:
        """Validate required first_name and last_name fields."""
        if "first_name" not in user_data:
            raise ValidationError(_("Required field missing"))
        if "last_name" not in user_data:
            raise ValidationError(_("Required field missing"))

        first_name = SecureInputValidator.validate_name_secure(user_data["first_name"], "first_name")
        last_name = SecureInputValidator.validate_name_secure(user_data["last_name"], "last_name")
        return first_name, last_name

    @staticmethod
    def _validate_optional_phone(user_data: dict[str, Any]) -> str | None:
        """Validate optional phone field."""
        if "phone" not in user_data:
            return None

        phone = user_data["phone"]
        if not isinstance(phone, str):
            raise ValidationError(_("Invalid input format"))

        SecureInputValidator._check_malicious_patterns(phone)
        return phone.strip()

    @staticmethod
    def _validate_marketing_consent(user_data: dict[str, Any]) -> bool | None:
        """Validate marketing consent boolean field."""
        if "accepts_marketing" not in user_data:
            return None

        if not isinstance(user_data["accepts_marketing"], bool | str):
            raise ValidationError(_("Invalid input format"))

        return bool(user_data["accepts_marketing"])

    @staticmethod
    def _validate_gdpr_consent(user_data: dict[str, Any]) -> datetime | None:
        """Validate GDPR consent timestamp."""
        if not user_data.get("gdpr_consent_date"):
            return None
        return timezone.now()

    @staticmethod
    def validate_user_data_dict(user_data: dict[str, Any]) -> dict[str, Any]:
        """
        Comprehensive user data validation preventing privilege escalation
        """
        if not isinstance(user_data, dict):
            raise ValidationError(_("Invalid input format"))

        # Security validation first
        SecureInputValidator._validate_restricted_fields(user_data)

        # Build validated data from required and optional fields
        validated_data: dict[str, Any] = {}

        # Required fields
        validated_data["email"] = SecureInputValidator._validate_required_email(user_data)
        first_name, last_name = SecureInputValidator._validate_required_names(user_data)
        validated_data["first_name"] = first_name
        validated_data["last_name"] = last_name

        # Optional fields
        phone = SecureInputValidator._validate_optional_phone(user_data)
        if phone is not None:
            validated_data["phone"] = phone

        marketing_consent = SecureInputValidator._validate_marketing_consent(user_data)
        if marketing_consent is not None:
            validated_data["accepts_marketing"] = marketing_consent

        gdpr_consent = SecureInputValidator._validate_gdpr_consent(user_data)
        if gdpr_consent is not None:
            validated_data["gdpr_consent_date"] = gdpr_consent

        return validated_data

    @staticmethod
    def validate_customer_data_dict(customer_data: dict[str, Any]) -> dict[str, Any]:
        """
        Comprehensive customer data validation for Romanian businesses
        """
        if not isinstance(customer_data, dict):
            raise ValidationError(_("Invalid input format"))

        validated_data: dict[str, Any] = {}

        # Company name (required)
        if "company_name" not in customer_data:
            raise ValidationError(_("Required field missing"))
        validated_data["company_name"] = SecureInputValidator.validate_company_name(customer_data["company_name"])

        # Customer type validation
        if "customer_type" in customer_data:
            allowed_types = ["individual", "srl", "pfa", "sa", "ngo", "other"]
            customer_type = customer_data["customer_type"].lower()
            if customer_type not in allowed_types:
                raise ValidationError(_("Invalid customer type"))
            validated_data["customer_type"] = customer_type

        # VAT number (optional but validated if provided)
        if "vat_number" in customer_data:
            validated_data["vat_number"] = SecureInputValidator.validate_vat_number_romanian(
                customer_data["vat_number"]
            )

        # Registration number/CUI (optional but validated if provided)
        if "registration_number" in customer_data:
            validated_data["registration_number"] = SecureInputValidator.validate_cui_romanian(
                customer_data["registration_number"]
            )

        # Address fields (optional)
        address_fields = ["billing_address", "billing_city", "billing_postal_code"]
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
    def check_company_uniqueness(company_data: dict[str, Any], request_ip: str | None = None) -> None:
        """
        Check company uniqueness with race condition prevention
        """
        # Rate limiting for enumeration prevention
        cache_key = f"company_check:{request_ip or 'unknown'}"
        current_checks = cache.get(cache_key, 0)
        if current_checks >= RATE_LIMIT_COMPANY_CHECK_PER_IP:
            raise ValidationError(_("Service temporarily unavailable"))
        cache.set(cache_key, current_checks + 1, timeout=3600)

        company_name = company_data.get("company_name", "").strip()
        vat_number = company_data.get("vat_number", "").strip()
        registration_number = company_data.get("registration_number", "").strip()

        # Create deterministic hash for atomic checking
        check_hash = hashlib.sha256(f"{company_name}:{vat_number}:{registration_number}".encode()).hexdigest()

        # Atomic check with database transaction
        with transaction.atomic():
            # Check with SELECT FOR UPDATE to prevent race conditions
            existing_company: Customer | None = None
            existing_vat: CustomerTaxProfile | None = None
            existing_reg: CustomerTaxProfile | None = None

            if company_name:
                existing_company = (
                    Customer.objects.select_for_update().filter(company_name__iexact=company_name).first()
                )

            if vat_number:
                existing_vat = CustomerTaxProfile.objects.select_for_update().filter(vat_number=vat_number).first()  # type: ignore[misc,assignment] # django-stubs bug: fields exist but not recognized

            if registration_number:
                existing_reg = (
                    CustomerTaxProfile.objects.select_for_update()  # type: ignore[assignment] # django-stubs bug: fields exist but not recognized
                    .filter(registration_number=registration_number)  # type: ignore[misc] # django-stubs bug: fields exist but not recognized
                    .first()
                )

            # Generic error message (no enumeration)
            if existing_company or existing_vat or existing_reg:
                logger.warning(f"🚨 [Security] Company registration conflict: {check_hash[:16]}")
                raise ValidationError(_("Registration validation failed"))

    @staticmethod
    def validate_user_permissions(user: Any, customer: Any, required_role: str = "owner") -> None:
        """
        TOCTOU-safe permission validation
        """
        # Check current membership atomically
        with transaction.atomic():
            membership = (
                CustomerMembership.objects.select_for_update()
                .filter(
                    user=user,
                    customer=customer,
                    role__in=["owner", "admin"] if required_role == "owner" else [required_role],
                )
                .first()
            )

            if not membership:
                logger.warning(f"🚨 [Security] Permission denied for user {user.id} on customer {customer.id}")
                raise ValidationError(_("Permission denied"))

            # Additional active user check
            if not user.is_active:
                logger.warning(f"🚨 [Security] Inactive user access attempt: {user.id}")
                raise ValidationError(_("Account not active"))

    @staticmethod
    @rate_limited("invitation", RATE_LIMIT_INVITATION_PER_USER, 60)
    def validate_invitation_request(inviter: Any, invitee_email: str, customer: Any, role: str, **kwargs: Any) -> None:
        """
        Comprehensive invitation validation with rate limiting
        """
        # Validate inviter permissions (TOCTOU-safe)
        BusinessLogicValidator.validate_user_permissions(inviter, customer, "owner")

        # Validate role
        SecureInputValidator.validate_customer_role(role)

        # Validate invitee email
        validated_email = SecureInputValidator.validate_email_secure(invitee_email, "invitation")

        # Check for existing membership (prevent duplicate invitations)
        existing_user = User.objects.filter(email=validated_email).first()
        if existing_user:
            existing_membership = CustomerMembership.objects.filter(user=existing_user, customer=customer).first()
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
            "general": _("An error occurred. Please try again later."),
        }

        return generic_messages.get(context, generic_messages["general"]) + f" (ID: {error_id})"


# ===============================================================================
# AUDIT LOGGING INTEGRATION
# ===============================================================================


def log_security_event(event_type: str, details: dict[str, Any], request_ip: str | None = None) -> None:
    """
    Log security events for monitoring and forensics
    """
    try:
        # For now, just log to standard logger to avoid transaction issues
        logger.warning(f"🚨 [Security] {event_type}: {details} from IP: {request_ip}")

        # TODO: Integrate with audit service once transaction handling is fixed
    except Exception as e:
        logger.error(f"Failed to log security event: {e}")
