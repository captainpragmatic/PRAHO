"""
Comprehensive type system for PRAHO Platform
Rust-inspired Result pattern and Django-specific type aliases for clean architecture.
"""

from collections.abc import Callable
from dataclasses import dataclass
from __future__ import annotations
from typing import TYPE_CHECKING, Any, Generic, TypeVar

from django.contrib.admin import ModelAdmin
from django.db import models
from django.db.models import QuerySet
from django.http import HttpRequest, HttpResponse
from django.http import JsonResponse as DjangoJsonResponse

if TYPE_CHECKING:
    pass

# Type variables for generic Result
T = TypeVar('T')  # Success type
E = TypeVar('E')  # Error type

# ===============================================================================
# RESULT TYPES
# ===============================================================================

@dataclass(frozen=True)
class Ok(Generic[T]):
    """Success result containing a value"""
    value: T

    def is_ok(self) -> bool:
        return True

    def is_err(self) -> bool:
        return False

    def unwrap(self) -> T:
        """Get the success value"""
        return self.value

    def unwrap_or(self, default: T) -> T:
        """Get the success value (ignores default)"""
        return self.value

    def map(self, func: Callable[[T], Any]) -> 'Result[Any, Any]':
        """Transform the success value"""
        try:
            return Ok(func(self.value))
        except Exception as e:
            return Err(str(e))


@dataclass(frozen=True)
class Err(Generic[E]):
    """Error result containing an error value"""
    error: E

    def is_ok(self) -> bool:
        return False

    def is_err(self) -> bool:
        return True

    def unwrap(self) -> Any:
        """Raises an exception - use unwrap_or() for safe access"""
        raise ValueError(f"Called unwrap on Err: {self.error}")

    def unwrap_or(self, default: T) -> T:
        """Get the default value since this is an error"""
        return default

    def map(self, func: Callable[[Any], Any]) -> 'Result[Any, E]':
        """No-op for error results"""
        return self


# Result type alias
Result = Ok[T] | Err[E]

# ===============================================================================
# TYPE VARIABLES
# ===============================================================================

M = TypeVar('M', bound=models.Model)  # Model type for Django models
AdminModel = TypeVar('AdminModel', bound=models.Model)  # Model type for admin

# ===============================================================================
# REQUEST HANDLING TYPES
# ===============================================================================

RequestHandler = Callable[[HttpRequest], HttpResponse]
AjaxHandler = Callable[[HttpRequest], DjangoJsonResponse]
HTMXHandler = Callable[[HttpRequest], HttpResponse]

# ===============================================================================
# DJANGO MODEL TYPES
# ===============================================================================

QuerySetGeneric = QuerySet[M]
if TYPE_CHECKING:
    from typing import TypeVar
    _AdminModel = TypeVar("_AdminModel", bound=models.Model)
    ModelAdminGeneric = ModelAdmin[_AdminModel]
else:
    ModelAdminGeneric = ModelAdmin

# ===============================================================================
# BUSINESS TYPES
# ===============================================================================

CUIString = str  # Romanian CUI format: "RO12345678"
VATString = str  # Romanian VAT format: "RO12345678"
EmailAddress = str  # Validated email address
InvoiceNumber = str  # Sequential invoice number: "2024-0001"
OrderNumber = str  # Order reference: "ORD-2024-0001"
ProformaNumber = str  # Proforma invoice number: "PRO-2024-0001"
PaymentReference = str  # Payment reference for transactions
DomainName = str  # Valid domain name: "example.com"
PhoneNumber = str  # International phone format: "+40721123456"

# ===============================================================================
# ADMIN PATTERN TYPES
# ===============================================================================

AdminDisplayMethod = Callable[[ModelAdminGeneric], str]
AdminPermissionMethod = Callable[[ModelAdminGeneric, HttpRequest], bool]
AdminActionMethod = Callable[[ModelAdminGeneric, HttpRequest, QuerySetGeneric], None]

# ===============================================================================
# FORM AND VALIDATION TYPES
# ===============================================================================

FormData = dict[str, Any]
ValidationErrors = dict[str, list[str]]
FieldValidator = Callable[[Any], Result[str, str]]

# ===============================================================================
# RESPONSE TYPES
# ===============================================================================

JSONResponse = DjangoJsonResponse
CSVResponse = HttpResponse  # Response with CSV content
ExcelResponse = HttpResponse  # Response with Excel content
PDFResponse = HttpResponse  # Response with PDF content

# ===============================================================================
# SERVICE LAYER TYPES
# ===============================================================================

ServiceMethod = Callable[..., Result[Any, str]]
RepositoryMethod = Callable[..., Result[Any, str]]
GatewayMethod = Callable[..., Result[Any, str]]

# ===============================================================================
# WEBHOOK TYPES
# ===============================================================================

WebhookPayload = dict[str, Any]
WebhookSignature = str  # HMAC signature for webhook verification
WebhookEvent = str  # Event type: "invoice.paid", "customer.created", etc.

# ===============================================================================
# CACHE TYPES
# ===============================================================================

CacheKey = str
CacheValue = Any
CacheTTL = int  # Time to live in seconds

# ===============================================================================
# ROMANIAN BUSINESS CONSTANTS
# ===============================================================================

ROMANIAN_VAT_RATE = 0.19  # 19% standard VAT rate
ROMANIAN_VAT_RATE_PERCENT = 19  # For display purposes

# ===============================================================================
# ROMANIAN BUSINESS SPECIFIC TYPES
# ===============================================================================

@dataclass(frozen=True)
class RomanianVATNumber:
    """Romanian VAT number validation"""
    value: VATString

    def __post_init__(self) -> None:
        if not self.is_valid():
            raise ValueError(f"Invalid Romanian VAT number: {self.value}")

    def is_valid(self) -> bool:
        """Validate Romanian VAT number format"""
        if not self.value.startswith('RO'):
            return False

        digits = self.value[2:]
        if not digits.isdigit():
            return False

        return len(digits) >= 2 and len(digits) <= 10


@dataclass(frozen=True)
class Money:
    """Money type with currency support"""
    amount: int  # Store in cents/bani for precision
    currency: str = 'RON'

    def __post_init__(self) -> None:
        if self.currency not in ['RON', 'EUR', 'USD']:
            raise ValueError(f"Unsupported currency: {self.currency}")

    @classmethod
    def from_decimal(cls, amount: float, currency: str = 'RON') -> 'Money':
        """Create Money from decimal amount"""
        return cls(int(amount * 100), currency)

    def to_decimal(self) -> float:
        """Get decimal amount"""
        return self.amount / 100

    def __str__(self) -> str:
        if self.currency == 'RON':
            return f"{self.to_decimal():.2f} lei"
        else:
            return f"{self.currency} {self.to_decimal():.2f}"


# ===============================================================================
# BUSINESS ENTITY TYPES
# ===============================================================================

@dataclass(frozen=True)
class CUI:
    """Romanian CUI (Company Unique Identifier)"""
    value: CUIString

    def __post_init__(self) -> None:
        if not self.is_valid():
            raise ValueError(f"Invalid Romanian CUI: {self.value}")

    def is_valid(self) -> bool:
        """Validate Romanian CUI format"""
        if not self.value.startswith('RO'):
            return False

        digits = self.value[2:]
        if not digits.isdigit():
            return False

        return len(digits) >= 2 and len(digits) <= 10

    def __str__(self) -> str:
        return self.value


# ===============================================================================
# VALIDATION HELPERS
# ===============================================================================

def validate_romanian_cui(cui: str) -> Result[CUIString, str]:
    """Validate Romanian CUI (company ID) - accepts both RO12345678 and 12345678 formats"""
    # Remove RO prefix if present for validation
    digits = cui
    if cui.startswith('RO'):
        digits = cui[2:]
    
    if not digits.isdigit():
        return Err("CUI must contain only digits")

    if len(digits) < 2 or len(digits) > 10:
        return Err("CUI must have 2-10 digits")

    # Return the normalized format without RO prefix
    return Ok(CUIString(digits))


def validate_email(email: str) -> Result[EmailAddress, str]:
    """Basic email validation"""
    if '@' not in email:
        return Err("Invalid email format")

    parts = email.split('@')
    if len(parts) != 2:
        return Err("Invalid email format")

    local, domain = parts
    if not local or not domain:
        return Err("Invalid email format")

    return Ok(EmailAddress(email))


def validate_romanian_phone(phone: str) -> Result[PhoneNumber, str]:
    """Validate Romanian phone number with comprehensive support for Romanian formats"""
    import re

    # Store original format for return
    original = phone
    
    # Remove all non-digit characters for validation
    digits = re.sub(r'\D', '', phone)

    if not digits:
        return Err("Phone number is required")

    # Handle +40 prefix (Romanian country code)
    if digits.startswith('40'):
        # Remove the 40 prefix and validate the remaining number
        local_digits = digits[2:]
        if len(local_digits) >= 9 and len(local_digits) <= 10:
            # Check if it's a valid Romanian number (starts with 7 for mobile or 2/3 for landline)
            if local_digits.startswith(('7', '2', '3')):
                # Return cleaned version of original format
                return Ok(PhoneNumber(original.replace(' ', '').replace('-', '')))

    # Handle national format (starts with 0)
    elif digits.startswith('0'):
        local_digits = digits[1:]  # Remove leading 0
        if len(local_digits) >= 9 and len(local_digits) <= 10:
            # Check if it's a valid Romanian number
            if local_digits.startswith(('7', '2', '3')):
                # Return cleaned version of original format
                return Ok(PhoneNumber(original.replace(' ', '').replace('-', '')))

    # Handle direct format (without country code or leading 0)
    elif len(digits) >= 9 and len(digits) <= 10:
        # Check if it's a valid Romanian number
        if digits.startswith(('7', '2', '3')):
            # Return cleaned version of original format
            return Ok(PhoneNumber(original.replace(' ', '').replace('-', '')))

    return Err("Invalid Romanian phone number format. Expected: +40 721 123 456, 0721 123 456, or 721 123 456")


def calculate_romanian_vat(amount_cents: int, include_vat: bool = True) -> dict[str, float]:
    """Calculate Romanian VAT (19%) for the given amount"""
    
    if include_vat:
        # Amount includes VAT, extract base amount
        base_amount = int(amount_cents / (1 + ROMANIAN_VAT_RATE))
        vat_amount = amount_cents - base_amount
    else:
        # Amount excludes VAT, calculate VAT
        base_amount = amount_cents
        vat_amount = int(amount_cents * ROMANIAN_VAT_RATE)

    return {
        'base_amount': base_amount,
        'vat_amount': vat_amount,
        'total_amount': base_amount + vat_amount,
        'vat_rate': ROMANIAN_VAT_RATE
    }


def validate_domain_name(domain: str) -> Result[DomainName, str]:
    """Validate domain name format"""
    import re
    
    if not domain:
        return Err("Domain name is required")
    
    # Basic domain validation regex
    pattern = r'^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$'
    
    if not re.match(pattern, domain, re.IGNORECASE):
        return Err("Invalid domain name format")
    
    if len(domain) > 253:  # RFC 1035 max length
        return Err("Domain name too long")
    
    return Ok(DomainName(domain.lower()))


# ===============================================================================
# COMMON EXCEPTIONS
# ===============================================================================

class BusinessError(Exception):
    """Base exception for business logic errors"""


class ValidationError(BusinessError):
    """Validation error with field information"""
    def __init__(self, field: str, message: str):
        self.field = field
        self.message = message
        super().__init__(f"{field}: {message}")


class AuthorizationError(BusinessError):
    """User not authorized for this operation"""


class RomanianComplianceError(BusinessError):
    """Romanian compliance violation"""


class DomainValidationError(ValidationError):
    """Domain-specific validation error"""


class InvoiceValidationError(ValidationError):
    """Invoice-specific validation error"""


class PaymentValidationError(ValidationError):
    """Payment-specific validation error"""
