"""
Provisioning models aggregator for Django compatibility.
Imports all feature models for migrations and admin.
"""

# Import all models from feature files
from .account_hostname_models import (
    AccountHostname,
    AccountNameCertificate,
    AccountNameCertificateBudget,
    AccountNameCertificateInstall,
)
from .hosted_domain_dns_models import HostedDomainDnsStatus
from .relationship_models import ServiceDomain, ServiceGroup, ServiceGroupMember, ServiceRelationship
from .service_models import ProvisioningTask, Server, Service, ServicePlan, ServicePlanPrice
from .service_request_models import ServiceRequest
from .virtualmin_migration_models import MigrationBridge, NodeDrain, VirtualminMigration
from .virtualmin_models import (
    VirtualminAccount,
    VirtualminDriftRecord,
    VirtualminProvisioningJob,
    VirtualminServer,
)
from .virtualmin_usage_models import AccountUsageState, NodeUsageSyncState, UsageInterval, UsageReading

# Re-export for external imports
__all__ = [
    "AccountHostname",
    "AccountNameCertificate",
    "AccountNameCertificateBudget",
    "AccountNameCertificateInstall",
    "AccountUsageState",
    "HostedDomainDnsStatus",
    "MigrationBridge",
    "NodeDrain",
    "NodeUsageSyncState",
    "ProvisioningTask",
    "Server",
    "Service",
    "ServiceDomain",
    "ServiceGroup",
    "ServiceGroupMember",
    "ServicePlan",
    "ServicePlanPrice",
    "ServiceRelationship",
    "ServiceRequest",
    "UsageInterval",
    "UsageReading",
    # Virtualmin models
    "VirtualminAccount",
    "VirtualminDriftRecord",
    "VirtualminMigration",
    "VirtualminProvisioningJob",
    "VirtualminServer",
]
