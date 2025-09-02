"""
Provisioning models aggregator for Django compatibility.
Imports all feature models for migrations and admin.
"""

# Import all models from feature files
from .relationship_models import ServiceDomain, ServiceGroup, ServiceGroupMember, ServiceRelationship
from .service_models import ProvisioningTask, Server, Service, ServicePlan
from .virtualmin_models import (
    VirtualminAccount,
    VirtualminDriftRecord,
    VirtualminProvisioningJob,
    VirtualminServer,
)

# Re-export for external imports
__all__ = [
    'ProvisioningTask',
    'Server',
    'Service',
    'ServiceDomain',
    'ServiceGroup',
    'ServiceGroupMember',
    'ServicePlan',
    'ServiceRelationship',
    # Virtualmin models
    'VirtualminAccount',
    'VirtualminDriftRecord',
    'VirtualminProvisioningJob',
    'VirtualminServer',
]
