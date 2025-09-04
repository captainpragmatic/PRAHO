"""
Customer services re-export hub for PRAHO Platform.
Maintains backward compatibility after ADR-0012 feature-based reorganization.
"""

from typing import Any

# Core customer service
# Contact service
from .contact_service import ContactService

# Credit service
from .credit_service import CustomerCreditService
from .customer_service import CustomerService

# Profile service
from .profile_service import ProfileService


# Missing services placeholders
class CustomerAnalyticsService:
    """Placeholder for customer analytics"""
    @staticmethod
    def get_customer_metrics(customer_id: str) -> dict[str, Any]:
        # TODO: Implement analytics
        return {}

class CustomerStatsService:
    """Placeholder for customer statistics"""  
    @staticmethod
    def update_stats(customer_id: str) -> None:
        # TODO: Implement stats update
        pass

# Backward compatibility: Re-export all services
__all__ = [
    "ContactService",
    "CustomerAnalyticsService",
    "CustomerCreditService",
    "CustomerService",
    "CustomerStatsService",
    "ProfileService",
]
