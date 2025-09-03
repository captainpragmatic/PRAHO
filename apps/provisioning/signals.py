"""
Provisioning signals for PRAHO Platform
General service lifecycle management for Romanian hosting compliance.

Includes:
- Service plan creation, updates, and pricing changes
- Service lifecycle events (creation, activation, suspension, termination)
- Server provisioning and resource management
- Service relationships and dependency tracking
- Service group management and coordination
- Service domain binding and DNS management
- Provisioning task automation and monitoring
- Romanian hosting compliance logging

Note: Virtualmin-specific signals are in virtualmin_signals.py
"""

import logging
from typing import Any

from django.conf import settings
from django.db.models.signals import post_save
from django.dispatch import receiver

from apps.audit.services import (
    AuditContext,
    AuditEventData,
    AuditService,
)
from apps.common.validators import log_security_event

from .models import (
    Server,
    Service,
    ServiceDomain,
    ServicePlan,
)

logger = logging.getLogger(__name__)

# ===============================================================================
# BUSINESS CONSTANTS
# ===============================================================================

# Service plan thresholds for Romanian hosting
HIGH_VALUE_PLAN_THRESHOLD = 500  # 500 RON threshold for high-value plans
ENTERPRISE_DISK_THRESHOLD = 100  # 100 GB threshold for enterprise plans
RESOURCE_USAGE_ALERT_THRESHOLD = 85  # 85% resource usage alert threshold

# Server capacity thresholds
SERVER_OVERLOAD_THRESHOLD = 90  # 90% resource usage threshold
MAX_SERVICES_WARNING_THRESHOLD = 0.8  # 80% of max services capacity

# Service lifecycle thresholds
LONG_PROVISIONING_THRESHOLD = 30  # 30 minutes for provisioning timeout

# Pricing and billing thresholds
PRICE_CHANGE_DETECTION_THRESHOLD = 0.01  # Minimum price change detection (1 cent)
SIGNIFICANT_PRICE_CHANGE_PERCENTAGE = 25  # 25% price change threshold for security alerts
CRITICAL_SERVICE_DOWNTIME_THRESHOLD = 5  # 5 minutes critical service downtime

# ===============================================================================
# SERVICE PLAN SIGNALS
# ===============================================================================


@receiver(post_save, sender=ServicePlan)
def handle_service_plan_created_or_updated(
    sender: type[ServicePlan], instance: ServicePlan, created: bool, **kwargs: Any
) -> None:
    """
    Handle service plan creation and updates.

    Triggers:
    - Audit logging for plan changes
    - Price change notifications for significant modifications
    - Compliance logging for high-value plans
    - Security alerts for suspicious price changes
    """
    # Check if audit signals are disabled (for testing)
    if getattr(settings, "DISABLE_AUDIT_SIGNALS", False):
        return

    try:
        if created:
            # Use helper function for modularity and testability
            _handle_new_service_plan_creation(instance)

        else:
            # Handle plan updates
            update_fields = kwargs.get("update_fields")
            
            if update_fields:
                # Check for price changes
                if any(field in update_fields for field in ["price_monthly", "price_quarterly", "price_annual", "setup_fee"]):
                    logger.info(f"💰 [ServicePlan] Price change detected for {instance.name}")

                # Check for status changes
                if "is_active" in update_fields:
                    AuditService.log_event(
                        AuditEventData(
                            event_type="service_plan_status_changed",
                            content_object=instance,
                            new_values={"is_active": instance.is_active},
                            description=f"Service plan '{instance.name}' status changed to {'active' if instance.is_active else 'inactive'}",
                        ),
                        context=AuditContext(
                            actor_type="system",
                            metadata={
                                "source_app": "provisioning",
                                "compliance_event": True,
                                "status_change": True,
                            }
                        ),
                    )

    except Exception as e:
        logger.exception(f"🔥 [ServicePlan] Failed to process plan signals: {e}")


# ===============================================================================
# SERVICE LIFECYCLE SIGNALS
# ===============================================================================


@receiver(post_save, sender=Service)
def audit_service_lifecycle_events(
    sender: type[Service], instance: Service, created: bool, **kwargs: Any
) -> None:
    """
    Audit service lifecycle events for Romanian compliance and operational tracking.
    
    Logs:
    - Service creation, activation, suspension, and termination
    - Plan changes and pricing updates
    - Status changes and administrative actions
    - Customer relationship changes
    """
    # Check if audit signals are disabled (for testing)
    if getattr(settings, "DISABLE_AUDIT_SIGNALS", False):
        return

    try:
        if created:
            # Use helper function for modularity and testability
            _handle_new_service_creation(instance)
            
        else:
            # Handle service updates
            update_fields = kwargs.get("update_fields")
            
            if update_fields and "status" in update_fields:
                    AuditService.log_event(
                        AuditEventData(
                            event_type="service_status_changed",
                            content_object=instance,
                            new_values={"status": instance.status},
                            description=f"Service '{instance.service_name}' status changed to {instance.status}",
                        ),
                        context=AuditContext(
                            actor_type="system",
                            metadata={
                                "source_app": "provisioning",
                                "compliance_event": True,
                                "service_lifecycle": True,
                                "status_change": True,
                                "customer_id": str(instance.customer.id),
                                "requires_billing_update": instance.status in ["suspended", "terminated"],
                            }
                        ),
                    )

    except Exception as e:
        logger.exception(f"🔥 [Service] Failed to audit service lifecycle: {e}")


# ===============================================================================
# SERVER MANAGEMENT SIGNALS
# ===============================================================================


@receiver(post_save, sender=Server)
def audit_server_management_events(
    sender: type[Server], instance: Server, created: bool, **kwargs: Any
) -> None:
    """
    Audit server management events for infrastructure tracking and compliance.
    
    Logs server creation, configuration changes, and capacity monitoring.
    """
    # Check if audit signals are disabled (for testing)
    if getattr(settings, "DISABLE_AUDIT_SIGNALS", False):
        return

    try:
        if created:
            # Use helper function for modularity and testability
            _handle_new_server_creation(instance)

        else:
            # Handle server updates
            update_fields = kwargs.get("update_fields")
            
            # When save() is called without update_fields, we need to detect changes differently
            # For now, let's log any server update that's not creation
            if update_fields is None or (update_fields and "status" in update_fields):
                # Always log status changes since we can't easily detect field changes in signals
                AuditService.log_event(
                    AuditEventData(
                        event_type="server_status_changed",
                        content_object=instance,
                        new_values={"status": instance.status},
                        description=f"Server '{instance.name}' status changed to {instance.status}",
                    ),
                    context=AuditContext(
                        actor_type="system",
                        metadata={
                            "source_app": "provisioning",
                            "infrastructure_event": True,
                            "server_management": True,
                            "status_change": True,
                            "server_hostname": instance.hostname,
                            "requires_monitoring_update": True,
                        }
                    ),
                )
                
                logger.info(f"🖥️ [Server] Status changed: {instance.name} -> {instance.status}")

    except Exception as e:
        logger.exception(f"🔥 [Server] Failed to audit server management: {e}")


# ===============================================================================
# SERVICE DOMAIN SIGNALS
# ===============================================================================


@receiver(post_save, sender=ServiceDomain)
def handle_service_domain_changes(
    sender: type[ServiceDomain], instance: ServiceDomain, created: bool, **kwargs: Any
) -> None:
    """
    Handle service domain binding and DNS management events.
    
    Triggers provisioning tasks for DNS configuration and SSL certificate management.
    """
    # Check if audit signals are disabled (for testing)
    if getattr(settings, "DISABLE_AUDIT_SIGNALS", False):
        return

    try:
        if created:
            # Log domain binding
            AuditService.log_event(
                AuditEventData(
                    event_type="service_domain_bound",
                    content_object=instance,
                    new_values={
                        "domain": instance.full_domain_name,
                        "service_id": str(instance.service.id),
                        "domain_type": instance.domain_type,
                        "ssl_enabled": instance.ssl_enabled,
                        "dns_management": instance.dns_management,
                    },
                    description=f"Domain '{instance.full_domain_name}' bound to service {instance.service.service_name}",
                ),
                context=AuditContext(
                    actor_type="system",
                    metadata={
                        "source_app": "provisioning",
                        "service_domain": True,
                        "dns_management": True,
                        "domain_binding": True,
                        "requires_dns_configuration": instance.dns_management,
                        "requires_ssl_provisioning": instance.ssl_enabled,
                    }
                ),
            )

            logger.info(f"🌐 [ServiceDomain] Bound: {instance.full_domain_name} to {instance.service.service_name}")

    except Exception as e:
        logger.exception(f"🔥 [ServiceDomain] Failed to handle domain changes: {e}")


# ===============================================================================
# PROVISIONING TASK SIGNALS
# ===============================================================================


# Provisioning task signals would go here if needed
# Currently handled by the task system itself


# ===============================================================================
# HELPER FUNCTIONS FOR TESTING AND MODULARITY
# ===============================================================================


def _handle_new_service_plan_creation(instance: ServicePlan) -> None:
    """
    Internal helper function for handling new service plan creation.
    Separated for testability and modularity.
    """
    # Log plan creation
    AuditService.log_event(
        AuditEventData(
            event_type="service_plan_created",
            content_object=instance,
            new_values={
                "name": instance.name,
                "plan_type": instance.plan_type,
                "price_monthly": float(instance.price_monthly),
                "price_quarterly": float(instance.price_quarterly) if instance.price_quarterly else None,
                "price_annual": float(instance.price_annual) if instance.price_annual else None,
                "setup_fee": float(instance.setup_fee) if instance.setup_fee else None,
                "is_active": instance.is_active,
                "is_public": instance.is_public,
            },
            description=f"Service plan '{instance.name}' created with monthly price {instance.price_monthly} RON",
        ),
        context=AuditContext(
            actor_type="system",
            metadata={
                "source_app": "provisioning",
                "compliance_event": True,
                "pricing_event": True,
                "high_value_plan": float(instance.price_monthly) >= HIGH_VALUE_PLAN_THRESHOLD,
                "enterprise_plan": (
                    instance.disk_space_gb and instance.disk_space_gb >= ENTERPRISE_DISK_THRESHOLD
                ),
            }
        ),
    )

    logger.info(f"✅ [ServicePlan] Created plan: {instance.name} at {instance.price_monthly} RON/month")


def _handle_new_server_creation(instance: Server) -> None:
    """
    Internal helper function for handling new server creation.
    Separated for testability and modularity.
    """
    # Log server registration
    AuditService.log_event(
        AuditEventData(
            event_type="server_registered",
            content_object=instance,
            new_values={
                "name": instance.name,
                "hostname": instance.hostname,
                "server_type": instance.server_type,
                "location": instance.location,
                "capacity": instance.max_services,
                "status": instance.status,
            },
            description=f"Server '{instance.name}' registered at {instance.hostname}",
        ),
        context=AuditContext(
            actor_type="system",
            metadata={
                "source_app": "provisioning",
                "infrastructure_event": True,
                "server_management": True,
                "server_hostname": instance.hostname,
                "server_type": instance.server_type,
            }
        ),
    )

    logger.info(f"🖥️ [Server] Registered: {instance.name} ({instance.hostname}) - {instance.server_type}")


def _handle_new_service_creation(instance: Service) -> None:
    """
    Internal helper function for handling new service creation.
    Separated for testability and modularity.
    """
    # Log service creation
    AuditService.log_event(
        AuditEventData(
            event_type="service_created",
            content_object=instance,
            new_values={
                "service_name": instance.service_name,
                "domain": instance.domain,
                "customer_id": str(instance.customer.id),
                "service_plan_id": str(instance.service_plan.id) if instance.service_plan else None,
                "billing_cycle": instance.billing_cycle,
                "price": float(instance.price),
                "status": instance.status,
            },
            description=f"Service '{instance.service_name}' created for customer {instance.customer.company_name}",
        ),
        context=AuditContext(
            actor_type="system",
            metadata={
                "source_app": "provisioning",
                "compliance_event": True,
                "service_lifecycle": True,
                "customer_id": str(instance.customer.id),
                "billing_cycle": instance.billing_cycle,
                "high_value_service": float(instance.price) >= HIGH_VALUE_PLAN_THRESHOLD,
            }
        ),
    )

    logger.info(f"✅ [Service] Created: {instance.service_name} for {instance.customer.company_name}")


def log_virtualmin_security_event(event_type: str, details: dict, ip_address: str) -> None:
    """
    Log security events related to Virtualmin operations.
    
    Args:
        event_type: Type of security event (e.g., 'virtualmin_auth_failure', 'access_violation')
        details: Dictionary containing event details
        ip_address: IP address of the source of the event
    """
    try:
        # Enhance details with Virtualmin-specific metadata
        enhanced_details = details.copy()
        enhanced_details.update({
            "source_app": "provisioning",
            "virtualmin_integration": True,
        })
        
        # Call the log_security_event function with expected parameters
        log_security_event(event_type, enhanced_details, ip_address)
        
        logger.info(f"🔒 [Security] Virtualmin {event_type}: {details}")
        
    except Exception as e:
        logger.error(f"🔥 [Security] Failed to log Virtualmin security event: {e}")


def notify_provisioning_completion(account: Any, success: bool = True, details: dict | None = None) -> None:
    """
    Send provisioning completion notifications.
    
    Args:
        account: VirtualminAccount object that was provisioned
        success: Whether the provisioning was successful
        details: Optional details about the provisioning process
    """
    try:
        details = details or {}
        status = "success" if success else "failed"
        
        # Log provisioning completion
        AuditService.log_event(
            AuditEventData(
                event_type="virtualmin_provisioning_completed",
                content_object=account,
                new_values={
                    "success": success,
                    "status": status,
                    "domain": account.domain,
                    "server_hostname": account.server.hostname if account.server else None,
                    "details": details,
                },
                description=f"Virtualmin provisioning {'completed' if success else 'failed'} for domain '{account.domain}'",
            ),
            context=AuditContext(
                actor_type="system",
                metadata={
                    "source_app": "provisioning",
                    "provisioning_event": True,
                    "provisioning_completion": True,
                    "cross_app_notification": True,
                    "virtualmin_provisioning": True,
                    "completion_status": status,
                    "domain": account.domain,
                    "server_hostname": account.server.hostname if account.server else None,
                }
            ),
        )
        
        logger.info(f"📋 [Provisioning] Virtualmin {'completed' if success else 'failed'} for domain {account.domain}: {details}")
        
        # Here you could add email notifications, webhook calls, etc.
        # For now, we just log the completion
        
    except Exception as e:
        logger.error(f"🔥 [Provisioning] Failed to notify completion for domain {getattr(account, 'domain', 'unknown')}: {e}")
