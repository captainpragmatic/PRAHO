"""
Provisioning services backward compatibility layer.
Re-exports all service classes for existing imports.
"""

import logging

from .provisioning_service import ProvisioningService

# Logger for backward compatibility with tests
logger = logging.getLogger(__name__)

# Backward compatibility alias
ServiceActivationService = ProvisioningService


# Missing services placeholders
class ServiceManagementService:
    """Placeholder for service management functionality"""

    @staticmethod
    def manage_service(service_id: str, action: str) -> bool:
        # TODO: Implement service management
        return True

    @staticmethod
    def mark_service_for_review(service_id: str, reason: str = "") -> bool:
        # TODO: Implement service review marking
        return True


class ServiceGroupService:
    """Placeholder for service group management"""

    @staticmethod
    def manage_group(group_id: str, action: str) -> bool:
        # TODO: Implement group management
        return True


# Re-export for backward compatibility
__all__ = [
    "ProvisioningService",
    "ServiceActivationService",  # Legacy name
    "ServiceGroupService",
    "ServiceManagementService",
    "logger",  # For test mocking compatibility
]
