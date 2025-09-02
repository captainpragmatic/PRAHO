"""
Provisioning models aggregator for Django compatibility.
Imports all feature models for migrations and admin.
"""

# Import all models from feature files
from .service_models import ServicePlan, Server, Service, ProvisioningTask
from .relationship_models import ServiceRelationship, ServiceDomain, ServiceGroup, ServiceGroupMember

# Re-export for external imports
__all__ = [
    # Core service models
    'ServicePlan', 'Server', 'Service', 'ProvisioningTask',
    # Relationship models  
    'ServiceRelationship', 'ServiceDomain', 'ServiceGroup', 'ServiceGroupMember',
]