"""
Result types for error handling in PRAHO Platform
Rust-inspired Result pattern for cleaner error handling.
"""

from typing import Generic, TypeVar, Union, Callable, Any
from dataclasses import dataclass

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
Result = Union[Ok[T], Err[E]]

# ===============================================================================
# ROMANIAN BUSINESS SPECIFIC TYPES
# ===============================================================================

@dataclass(frozen=True)
class RomanianVATNumber:
    """Romanian VAT number validation"""
    value: str
    
    def __post_init__(self):
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
    
    def __post_init__(self):
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
# VALIDATION HELPERS
# ===============================================================================

def validate_romanian_cui(cui: str) -> Result[str, str]:
    """Validate Romanian CUI (company ID)"""
    if not cui.startswith('RO'):
        return Err("CUI must start with 'RO'")
    
    digits = cui[2:]
    if not digits.isdigit():
        return Err("CUI must contain only digits after 'RO'")
    
    if len(digits) < 2 or len(digits) > 10:
        return Err("CUI must have 2-10 digits")
    
    return Ok(cui)


def validate_email(email: str) -> Result[str, str]:
    """Basic email validation"""
    if '@' not in email:
        return Err("Invalid email format")
    
    parts = email.split('@')
    if len(parts) != 2:
        return Err("Invalid email format")
    
    local, domain = parts
    if not local or not domain:
        return Err("Invalid email format")
    
    return Ok(email)


def validate_romanian_phone(phone: str) -> Result[str, str]:
    """Validate Romanian phone number with comprehensive support for Romanian formats"""
    import re
    
    # Remove all non-digit characters
    digits = re.sub(r'\D', '', phone)
    
    if not digits:
        return Err("Phone number is required")
    
    # Handle +40 prefix (Romanian country code)
    if digits.startswith('40'):
        # Remove the 40 prefix and validate the remaining number
        local_digits = digits[2:]
        if len(local_digits) >= 9 and len(local_digits) <= 10:
            # Check if it's a valid Romanian number (starts with 7 for mobile or 2/3 for landline)
            if local_digits.startswith('7') or local_digits.startswith('2') or local_digits.startswith('3'):
                return Ok(f"+40{local_digits}")
    
    # Handle national format (starts with 0)
    elif digits.startswith('0'):
        local_digits = digits[1:]  # Remove leading 0
        if len(local_digits) >= 9 and len(local_digits) <= 10:
            # Check if it's a valid Romanian number
            if local_digits.startswith('7') or local_digits.startswith('2') or local_digits.startswith('3'):
                return Ok(f"+40{local_digits}")
    
    # Handle direct format (without country code or leading 0)
    elif len(digits) >= 9 and len(digits) <= 10:
        # Check if it's a valid Romanian number
        if digits.startswith('7') or digits.startswith('2') or digits.startswith('3'):
            return Ok(f"+40{digits}")
    
    return Err("Invalid Romanian phone number format. Expected: +40 721 123 456, 0721 123 456, or 721 123 456")


def calculate_romanian_vat(amount_cents: int, include_vat: bool = True) -> dict:
    """Calculate Romanian VAT (19%) for the given amount"""
    VAT_RATE = 0.19
    
    if include_vat:
        # Amount includes VAT, extract base amount
        base_amount = int(amount_cents / (1 + VAT_RATE))
        vat_amount = amount_cents - base_amount
    else:
        # Amount excludes VAT, calculate VAT
        base_amount = amount_cents
        vat_amount = int(amount_cents * VAT_RATE)
    
    return {
        'base_amount': base_amount,
        'vat_amount': vat_amount,
        'total_amount': base_amount + vat_amount,
        'vat_rate': VAT_RATE
    }


# ===============================================================================
# COMMON EXCEPTIONS
# ===============================================================================

class BusinessError(Exception):
    """Base exception for business logic errors"""
    pass


class ValidationError(BusinessError):
    """Validation error with field information"""
    def __init__(self, field: str, message: str):
        self.field = field
        self.message = message
        super().__init__(f"{field}: {message}")


class AuthorizationError(BusinessError):
    """User not authorized for this operation"""
    pass


class RomanianComplianceError(BusinessError):
    """Romanian compliance violation"""
    pass
