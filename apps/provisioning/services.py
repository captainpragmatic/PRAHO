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

# Re-export for backward compatibility
__all__ = [
    'ProvisioningService',
    'ServiceActivationService',  # Legacy name
    'logger',  # For test mocking compatibility
]
