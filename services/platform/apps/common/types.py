"""
Comprehensive type system for PRAHO Platform
Rust-inspired Result pattern and Django-specific type aliases for clean architecture.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass
from decimal import Decimal
from typing import TYPE_CHECKING, Any, Generic, Protocol, TypeVar

# ModelAdmin import removed - Django admin disabled
from django.contrib.auth.models import AbstractUser
from django.db import models
from django.db.models import QuerySet
from django.forms import Form
from django.http import HttpRequest, HttpResponse
from django.http import JsonResponse as DjangoJsonResponse

from apps.common.constants import (
    CUI_MAX_LENGTH,
    CUI_MIN_LENGTH,
    DOMAIN_NAME_MAX_LENGTH,
    EMAIL_PARTS_COUNT,
)

if TYPE_CHECKING:
    pass

# Type variables for generic Result
T = TypeVar("T")  # Success type
E = TypeVar("E")  # Error type

# Additional type variables for Django patterns
UserT = TypeVar("UserT", bound=AbstractUser)
FormT = TypeVar("FormT", bound=Form)
# AdminT type variable removed - Django admin disabled

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

    def map(self, func: Callable[[T], Any]) -> Result[Any, Any]:
        """Transform the success value"""
        try:
            return Ok(func(self.value))
        except Exception as e:
            return Err(str(e))

    def and_then(self, func: Callable[[T], Result[Any, Any]]) -> Result[Any, Any]:
        """Chain operations that can fail"""
        try:
            return func(self.value)
        except Exception as e:
            return Err(str(e))

    def unwrap_err(self) -> Any:
        """Raises an exception since this is success, not error - provides consistent API"""
        raise ValueError(f"Called unwrap_err on Ok: {self.value}")


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

    def map(self, func: Callable[[Any], Any]) -> Result[Any, E]:
        """No-op for error results"""
        return self

    def and_then(self, func: Callable[[Any], Result[Any, Any]]) -> Result[Any, E]:
        """No-op for error results - return self"""
        return self

    def unwrap_err(self) -> E:
        """Get the error value"""
        return self.error


# Result type alias
Result = Ok[T] | Err[E]

# ===============================================================================
# TYPE VARIABLES
# ===============================================================================

M = TypeVar("M", bound=models.Model)  # Model type for Django models

# ===============================================================================
# REQUEST HANDLING TYPES
# ===============================================================================

RequestHandler = Callable[[HttpRequest], HttpResponse]
AjaxHandler = Callable[[HttpRequest], DjangoJsonResponse]
HTMXHandler = Callable[[HttpRequest], HttpResponse]

# ===============================================================================
# DJANGO MODEL TYPES
# ===============================================================================

# ModelAdminGeneric types removed - Django admin disabled

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
# ADMIN PATTERN TYPES - REMOVED
# ===============================================================================

# All admin pattern types removed - Django admin disabled
# Staff operations now use custom views with role-based access control

# ===============================================================================
# FORM AND VALIDATION TYPES
# ===============================================================================

FormData = dict[str, Any]
ValidationErrors = dict[str, list[str]]
FieldValidator = Callable[[Any], Result[str, str]]
FormCleanMethod = Callable[..., Any]
FormSaveMethod = Callable[..., M]
ChoiceTuple = tuple[str | int, str]
ChoicesList = list[ChoiceTuple]
FormFieldType = Any  # Django form fields have complex inheritance

# ===============================================================================
# RESPONSE TYPES
# ===============================================================================

JSONResponse = DjangoJsonResponse
CSVResponse = HttpResponse  # Response with CSV content
ExcelResponse = HttpResponse  # Response with Excel content
PDFResponse = HttpResponse  # Response with PDF content
TemplateResponse = HttpResponse  # Django TemplateResponse
RedirectResponse = HttpResponse  # Django redirect response
ErrorResponse = HttpResponse  # Error response with status code

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

ROMANIAN_VAT_RATE = 0.21  # 21% standard VAT rate
ROMANIAN_VAT_RATE_PERCENT = 21  # For display purposes

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
        if not self.value.startswith("RO"):
            return False

        digits = self.value[2:]
        if not digits.isdigit():
            return False

        return len(digits) >= CUI_MIN_LENGTH and len(digits) <= CUI_MAX_LENGTH


@dataclass(frozen=True)
class Money:
    """Money type with currency support"""

    amount: int  # Store in cents/bani for precision
    currency: str = "RON"

    def __post_init__(self) -> None:
        if self.currency not in ["RON", "EUR", "USD"]:
            raise ValueError(f"Unsupported currency: {self.currency}")

    @classmethod
    def from_decimal(cls, amount: float, currency: str = "RON") -> Money:
        """Create Money from decimal amount"""
        return cls(int(amount * 100), currency)

    def to_decimal(self) -> float:
        """Get decimal amount"""
        return self.amount / 100

    def __str__(self) -> str:
        if self.currency == "RON":
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
        if not self.value.startswith("RO"):
            return False

        digits = self.value[2:]
        if not digits.isdigit():
            return False

        return len(digits) >= CUI_MIN_LENGTH and len(digits) <= CUI_MAX_LENGTH

    def __str__(self) -> str:
        return self.value


# ===============================================================================
# VALIDATION HELPERS
# ===============================================================================


def validate_romanian_cui(cui: str) -> Result[CUIString, str]:
    """Validate Romanian CUI (company ID) - accepts only numeric format (no RO prefix)"""
    # CUI should not have RO prefix (that's for VAT numbers)
    if cui.startswith("RO"):
        return Err("CUI should not have RO prefix")

    if not cui.isdigit():
        return Err("CUI must contain only digits")

    if len(cui) < CUI_MIN_LENGTH or len(cui) > CUI_MAX_LENGTH:
        return Err("CUI must have 2-10 digits")

    # Return the normalized format
    return Ok(CUIString(cui))


def validate_email(email: str) -> Result[EmailAddress, str]:
    """Basic email validation"""
    if "@" not in email:
        return Err("Invalid email format")

    parts = email.split("@")
    if len(parts) != EMAIL_PARTS_COUNT:
        return Err("Invalid email format")

    local, domain = parts
    if not local or not domain:
        return Err("Invalid email format")

    return Ok(EmailAddress(email))


def calculate_romanian_vat(amount_cents: int, include_vat: bool = True) -> dict[str, float]:
    """Calculate Romanian VAT (21%) for the given amount"""

    if include_vat:
        # Amount includes VAT, extract base amount
        base_amount = int(amount_cents / (1 + ROMANIAN_VAT_RATE))
        vat_amount = amount_cents - base_amount
    else:
        # Amount excludes VAT, calculate VAT
        base_amount = amount_cents
        vat_amount = int(amount_cents * ROMANIAN_VAT_RATE)

    return {
        "base_amount": base_amount,
        "vat_amount": vat_amount,
        "total_amount": base_amount + vat_amount,
        "vat_rate": ROMANIAN_VAT_RATE,
    }


def validate_domain_name(domain: str) -> Result[DomainName, str]:
    """Validate domain name format"""
    if not domain:
        return Err("Domain name is required")

    # Basic domain validation regex
    pattern = r"^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$"

    if not re.match(pattern, domain, re.IGNORECASE):
        return Err("Invalid domain name format")

    if len(domain) > DOMAIN_NAME_MAX_LENGTH:  # RFC 1035 max length
        return Err("Domain name too long")

    return Ok(DomainName(domain.lower()))


# ===============================================================================
# DJANGO MODEL METHOD TYPES
# ===============================================================================

ModelSaveMethod = Callable[[M], None]
ModelCleanMethod = Callable[[M], None]
ModelStrMethod = Callable[[M], str]
ModelGetAbsoluteUrlMethod = Callable[[M], str]
ModelDeleteMethod = Callable[[M], tuple[int, dict[str, int]]]
ModelProperty = property

# ===============================================================================
# AUTHENTICATION AND AUTHORIZATION TYPES
# ===============================================================================

PermissionString = str  # Django permission string: "app.permission_model"
RoleIdentifier = str  # Role identifier for RBAC
AuthToken = str  # Authentication token
SessionKey = str  # Django session key
TwoFactorSecret = str  # TOTP/HOTP secret
TwoFactorCode = str  # Six-digit 2FA code
PasswordResetToken = str  # Password reset token

# ===============================================================================
# HTMX AND FRONTEND TYPES
# ===============================================================================

HTMXTrigger = str  # HTMX trigger event: "click", "keyup", etc.
HTMXSwap = str  # HTMX swap strategy: "innerHTML", "outerHTML", etc.
HTMXTarget = str  # CSS selector for HTMX target
CSSSelector = str  # CSS selector string
CSSClass = str  # CSS class name
CSSClasses = list[str]  # List of CSS class names
AlpineData = dict[str, Any]  # Alpine.js reactive data

# ===============================================================================
# TEMPLATE AND CONTEXT TYPES
# ===============================================================================

TemplateName = str  # Django template name: "app/template.html"
TemplateContext = dict[str, Any]  # Template context data
HTMLContent = str  # Raw HTML content
URLPattern = str  # URL pattern string
URLName = str  # Django URL name

# ===============================================================================
# PAGINATION AND FILTERING TYPES
# ===============================================================================

PageNumber = int  # Pagination page number (1-based)
PageSize = int  # Number of items per page
SearchQuery = str  # Search query string
FilterDict = dict[str, Any]  # Filter parameters
SortField = str  # Field name for sorting
SortDirection = str  # "asc" or "desc"
OrderingTuple = tuple[str, ...]  # Django ordering tuple

# ===============================================================================
# FILE AND MEDIA TYPES
# ===============================================================================

FilePath = str  # File system path
FileName = str  # File name with extension
FileSize = int  # File size in bytes
MimeType = str  # MIME type: "image/png", "application/pdf"
FileUrl = str  # URL to file resource
ImageDimensions = tuple[int, int]  # (width, height) in pixels

# ===============================================================================
# LOGGING AND MONITORING TYPES
# ===============================================================================

LogLevel = str  # Log level: "DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"
LogMessage = str  # Log message content
LogContext = dict[str, Any]  # Additional log context
MetricName = str  # Metric identifier
MetricValue = float | int  # Metric value
TimestampMs = int  # Unix timestamp in milliseconds

# ===============================================================================
# INTEGRATION AND API TYPES
# ===============================================================================

APIKey = str  # External API key
APISecret = str  # External API secret
APIEndpoint = str  # API endpoint URL
APIVersion = str  # API version string
APIHeaders = dict[str, str]  # HTTP headers for API requests
APIQueryParams = dict[str, str | int | bool]  # Query parameters
APIResponseStatus = int  # HTTP status code
APIResponseHeaders = dict[str, str]  # Response headers

# ===============================================================================
# BILLING AND FINANCIAL TYPES
# ===============================================================================

TaxRate = float  # Tax rate as decimal: 0.19 for 19%
DiscountRate = float  # Discount rate as decimal: 0.10 for 10%
Amount = int  # Amount in cents/smallest currency unit
AmountDecimal = float  # Amount as decimal value
Currency = str  # Currency code: "RON", "EUR", "USD"
BankAccount = str  # Bank account number
BankIBAN = str  # International Bank Account Number
BankBIC = str  # Bank Identifier Code

# ===============================================================================
# SERVICE AND PROVISIONING TYPES
# ===============================================================================

ServiceType = str  # Service type: "hosting", "domain", "ssl"
ServicePlan = str  # Service plan identifier
ServiceStatus = str  # Service status: "active", "suspended", "cancelled"
ServerHostname = str  # Server hostname
ServerIP = str  # Server IP address (IPv4 or IPv6)
ServerPort = int  # Server port number
ServiceConfig = dict[str, Any]  # Service configuration parameters
ProvisioningStatus = str  # Provisioning status

# ===============================================================================
# NOTIFICATION AND COMMUNICATION TYPES
# ===============================================================================

NotificationType = str  # Notification type: "email", "sms", "webhook"
NotificationTemplate = str  # Template identifier
NotificationSubject = str  # Email/notification subject
NotificationBody = str  # Notification content
RecipientList = list[EmailAddress]  # List of notification recipients
NotificationChannel = str  # Delivery channel

# ===============================================================================
# DOMAIN AND DNS TYPES
# ===============================================================================

DomainTLD = str  # Top-level domain: ".com", ".ro"
DomainRegistrar = str  # Domain registrar name
DomainStatus = str  # Domain status: "active", "expired", "pending"
DNSRecordType = str  # DNS record type: "A", "CNAME", "MX", "TXT"
DNSRecordValue = str  # DNS record value
DNSRecordTTL = int  # DNS record time-to-live in seconds
NameserverList = list[str]  # List of nameservers

# ===============================================================================
# AUDIT AND COMPLIANCE TYPES
# ===============================================================================

AuditAction = str  # Action type: "create", "update", "delete"
AuditEntity = str  # Entity type being audited
AuditChanges = dict[str, Any]  # Changed fields and values
AuditTrailId = str  # Unique audit trail identifier
ComplianceRule = str  # Compliance rule identifier
GDPRProcessingBasis = str  # GDPR legal basis for processing

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


class ServiceProvisioningError(BusinessError):
    """Service provisioning error"""


class IntegrationError(BusinessError):
    """External integration error"""


class APIRateLimitError(BusinessError):
    """API rate limit exceeded"""


# ===============================================================================
# PROTOCOL DEFINITIONS 📜
# ===============================================================================


class Serializable(Protocol):
    """Protocol for objects that can be serialized to JSON"""

    def serialize(self) -> dict[str, Any]: ...


class Auditable(Protocol):
    """Protocol for objects that support audit logging"""

    def get_audit_data(self) -> AuditChanges: ...
    def get_audit_entity(self) -> AuditEntity: ...


class Billable(Protocol):
    """Protocol for objects that can generate billing entries"""

    def get_billing_amount(self) -> Amount: ...
    def get_billing_description(self) -> str: ...
    def get_billing_currency(self) -> Currency: ...


class Provisionable(Protocol):
    """Protocol for services that can be provisioned"""

    def provision(self) -> Result[ServiceConfig, str]: ...
    def deprovision(self) -> Result[bool, str]: ...
    def get_status(self) -> ServiceStatus: ...


class Cacheable(Protocol):
    """Protocol for objects that can be cached"""

    def get_cache_key(self) -> CacheKey: ...
    def get_cache_ttl(self) -> CacheTTL: ...


class Notifiable(Protocol):
    """Protocol for objects that can receive notifications"""

    def get_notification_preferences(self) -> dict[NotificationType, bool]: ...
    def get_notification_address(self, channel: NotificationChannel) -> str: ...


# ===============================================================================
# COMPLEX TYPE COMBINATIONS 🔄
# ===============================================================================

# API data types
APIResponseData = dict[str, Any] | list[dict[str, Any]]  # API response data

# Common combinations used throughout the platform
# AdminMethodReturnType removed - Django admin disabled
ValidationResult = Result[Any, ValidationErrors]
ServiceResult = Result[Any, str]
APIResult = Result[APIResponseData, str]
FormResult = Result[FormT, ValidationErrors]

# Repository layer types
RepoCreateResult = Result[M, str]
RepoUpdateResult = Result[M, str]
RepoDeleteResult = Result[bool, str]
RepoFindResult = Result[M | None, str]
RepoListResult = Result[list[M], str]

# Service layer combinations
BusinessResult = Result[Any, BusinessError]
AuthenticationResult = Result[UserT, str]
AuthorizationResult = Result[bool, str]

# Integration layer types
WebhookProcessingResult = Result[dict[str, Any], str]
PaymentProcessingResult = Result[dict[str, Any], str]
ProvisioningResult = Result[ServiceConfig, str]

# Template context helpers
PaginationContext = dict[str, Any]  # Contains page info, has_next, etc.
FormContext = dict[str, Any]  # Contains form, errors, success messages
BreadcrumbContext = list[dict[str, str]]  # List of breadcrumb items

# HTMX response helpers
HTMXTemplateResponse = tuple[TemplateName, TemplateContext]
HTMXJsonResponse = dict[str, Any]
HTMXRedirectResponse = str  # URL to redirect to

# Common Django patterns
ModelFieldValue = str | int | float | bool | Decimal | None
ModelFieldChoices = list[tuple[ModelFieldValue, str]]
ModelMetaOptions = dict[str, Any]

# Async variants for future use (when Django adds full async support)
AsyncRequestHandler = Callable[[HttpRequest], Any]  # Will be Awaitable[HttpResponse]
AsyncServiceMethod = Callable[..., Any]  # Will be Awaitable[ServiceResult]
AsyncRepoMethod = Callable[..., Any]  # Will be Awaitable[RepoCreateResult]

# ===============================================================================
# DJANGO CHOICE FIELD STUB
# ===============================================================================

# Import ChoiceField from django_choices module

# ===============================================================================
# LEGACY COMPATIBILITY ALIASES 🔄
# ===============================================================================

# Aliases for common Django types to ease migration from untyped code
DjangoUser = AbstractUser
DjangoModel = models.Model
DjangoForm = Form
# DjangoAdmin removed - Django admin disabled
DjangoRequest = HttpRequest
DjangoResponse = HttpResponse
DjangoQuerySet = QuerySet

# Backward compatibility for older naming conventions
UserModel = AbstractUser
BaseModel = models.Model
BaseForm = Form
# BaseAdmin removed - Django admin disabled
