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
from .component_migration_models import (
    ComponentMigrationApproval,
    ComponentMigrationReview,
    SourceServiceObligation,
    SourceServiceRelease,
)
from .hosted_domain_dns_models import HostedDomainDnsStatus
from .hosting_limit_execution_models import HostingLimitExecution
from .hosting_limit_models import HostingLimitApplication, ServiceHostingLimits
from .hosting_node_policy_models import NodeHostingExecution, NodeHostingPolicy, NodeHostingReview
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
from .virtualmin_security_models import NodeSecurityDecision, NodeSecurityExecution, NodeSecurityReview
from .virtualmin_usage_models import AccountUsageState, NodeUsageSyncState, UsageInterval, UsageReading

# Re-export for external imports
__all__ = [
    "AccountHostname",
    "AccountNameCertificate",
    "AccountNameCertificateBudget",
    "AccountNameCertificateInstall",
    "AccountUsageState",
    "ComponentMigrationApproval",
    "ComponentMigrationReview",
    "HostedDomainDnsStatus",
    "HostingLimitApplication",
    "HostingLimitExecution",
    "MigrationBridge",
    "NodeDrain",
    "NodeHostingExecution",
    "NodeHostingPolicy",
    "NodeHostingReview",
    "NodeSecurityDecision",
    "NodeSecurityExecution",
    "NodeSecurityReview",
    "NodeUsageSyncState",
    "ProvisioningTask",
    "Server",
    "Service",
    "ServiceDomain",
    "ServiceGroup",
    "ServiceGroupMember",
    "ServiceHostingLimits",
    "ServicePlan",
    "ServicePlanPrice",
    "ServiceRelationship",
    "ServiceRequest",
    "SourceServiceObligation",
    "SourceServiceRelease",
    "UsageInterval",
    "UsageReading",
    # Virtualmin models
    "VirtualminAccount",
    "VirtualminDriftRecord",
    "VirtualminMigration",
    "VirtualminProvisioningJob",
    "VirtualminServer",
]
