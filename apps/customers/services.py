"""
Customer services re-export hub for PRAHO Platform.
Maintains backward compatibility after ADR-0012 feature-based reorganization.
"""

# Core customer service
# Contact service
from .contact_service import ContactService
from .customer_service import CustomerService

# Profile service
from .profile_service import ProfileService

# Backward compatibility: Re-export all services
__all__ = [
    "ContactService",
    "CustomerService",
    "ProfileService",
]
