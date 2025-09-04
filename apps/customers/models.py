"""
Customer models re-export hub for PRAHO Platform.
Maintains backward compatibility after ADR-0012 feature-based reorganization.
"""

# Core customer models
# Contact models
from .contact_models import (
    CustomerAddress,
    CustomerNote,
    CustomerPaymentMethod,
)
from .customer_models import (
    Customer,
    SoftDeleteManager,
    SoftDeleteModel,
    security_logger,
    validate_bank_details,
)

# Profile models
from .profile_models import (
    CustomerBillingProfile,
    CustomerTaxProfile,
)

# Backward compatibility: Re-export all models
__all__ = [
    # Core models
    "Customer",
    # Contact models
    "CustomerAddress",
    # Profile models
    "CustomerBillingProfile",
    "CustomerNote",
    "CustomerPaymentMethod",
    "CustomerTaxProfile",
    "SoftDeleteManager",
    "SoftDeleteModel",
    "security_logger",
    "validate_bank_details",
]
