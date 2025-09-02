"""
Customer views re-export hub for PRAHO Platform.
Maintains backward compatibility after ADR-0012 feature-based reorganization.
"""

# Core customer views
# Contact management views
from .contact_views import (
    customer_address_add,
    customer_note_add,
)
from .customer_views import (
    _handle_secure_error,
    customer_assign_user,
    customer_create,
    customer_delete,
    customer_detail,
    customer_edit,
    customer_list,
    customer_search_api,
    customer_services_api,
    security_logger,
)

# Profile management views
from .profile_views import (
    customer_billing_profile,
    customer_tax_profile,
)

# Backward compatibility: Re-export all views
__all__ = [
    # Core customer views
    "_handle_secure_error",
    # Contact views
    "customer_address_add",
    "customer_assign_user",
    # Profile views
    "customer_billing_profile",
    "customer_create",
    "customer_delete",
    "customer_detail",
    "customer_edit",
    "customer_list",
    "customer_note_add",
    "customer_search_api",
    "customer_services_api",
    "customer_tax_profile",
    "security_logger",
]
