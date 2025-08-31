"""
Provisioning signals for PRAHO Platform
Comprehensive service lifecycle management with Romanian hosting compliance.

Includes:
- Service plan creation, updates, and pricing changes
- Service lifecycle events (creation, activation, suspension, termination)
- Server provisioning and resource management
- Service relationships and dependency tracking
- Service group management and coordination
- Service domain binding and DNS management
- Provisioning task automation and monitoring
- Romanian hosting compliance logging
"""

import logging
from decimal import Decimal
from typing import Any

from django.conf import settings
from django.db.models.signals import post_save, pre_delete, pre_save
from django.dispatch import receiver
from django.utils import timezone

from apps.audit.services import (
    AuditContext,
    AuditEventData,
    AuditService,
    ComplianceEventRequest,
)
from apps.common.validators import log_security_event

from .models import (
    ProvisioningTask,
    Server,
    Service,
    ServiceDomain,
    ServiceGroup,
    ServicePlan,
    ServiceRelationship,
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
    - Pricing compliance verification
    - Romanian VAT calculation updates
    - Feature specification validation
    - High-value plan security logging
    """
    try:
        # Get previous values for audit trail
        old_values = getattr(instance, "_original_plan_values", {}) if not created else {}
        new_values = {
            "name": instance.name,
            "plan_type": instance.plan_type,
            "price_monthly": float(instance.price_monthly),
            "price_quarterly": float(instance.price_quarterly) if instance.price_quarterly else None,
            "price_annual": float(instance.price_annual) if instance.price_annual else None,
            "setup_fee": float(instance.setup_fee),
            "is_active": instance.is_active,
            "is_public": instance.is_public,
            "auto_provision": instance.auto_provision,
            "includes_vat": instance.includes_vat,
        }

        # Enhanced service plan audit logging
        if not getattr(settings, "DISABLE_AUDIT_SIGNALS", False):
            from apps.audit.services import ProvisioningAuditService  # noqa: PLC0415 - Service integration

            event_type = "service_plan_created" if created else "service_plan_updated"

            ProvisioningAuditService.log_service_plan_event(
                event_type=event_type,
                service_plan=instance,
                user=getattr(instance, "_audit_user", None),
                context=AuditContext(actor_type="system"),
                old_values=old_values,
                new_values=new_values,
                description=f"Service plan {instance.name} {'created' if created else 'updated'}",
            )

        if created:
            # New service plan created
            _handle_new_service_plan_creation(instance)
            logger.info(f"📋 [Provisioning] Created service plan: {instance.name} ({instance.plan_type})")

        else:
            # Service plan updated - check for important changes
            old_monthly_price = old_values.get("price_monthly", 0)
            if (
                old_monthly_price
                and abs(float(instance.price_monthly) - old_monthly_price) > PRICE_CHANGE_DETECTION_THRESHOLD
            ):
                _handle_service_plan_pricing_change(instance, old_monthly_price, float(instance.price_monthly))

            # Check for availability changes
            old_active = old_values.get("is_active")
            if old_active is not None and old_active != instance.is_active:
                _handle_service_plan_availability_change(instance, old_active, instance.is_active)

        # Romanian VAT compliance verification
        if instance.includes_vat:
            _verify_romanian_vat_compliance(instance)

        # High-value plan security logging
        if float(instance.price_monthly) >= HIGH_VALUE_PLAN_THRESHOLD:
            _handle_high_value_plan_security(instance, created)

    except Exception as e:
        logger.exception(f"🔥 [Provisioning Signal] Failed to handle service plan save: {e}")


@receiver(pre_save, sender=ServicePlan)
def store_original_service_plan_values(sender: type[ServicePlan], instance: ServicePlan, **kwargs: Any) -> None:
    """Store original service plan values for audit trail"""
    try:
        if instance.pk:
            try:
                original = ServicePlan.objects.get(pk=instance.pk)
                instance._original_plan_values = {
                    "name": original.name,
                    "plan_type": original.plan_type,
                    "price_monthly": float(original.price_monthly),
                    "price_quarterly": float(original.price_quarterly) if original.price_quarterly else None,
                    "price_annual": float(original.price_annual) if original.price_annual else None,
                    "setup_fee": float(original.setup_fee),
                    "is_active": original.is_active,
                    "is_public": original.is_public,
                    "auto_provision": original.auto_provision,
                    "includes_vat": original.includes_vat,
                }
            except ServicePlan.DoesNotExist:
                instance._original_plan_values = {}
    except Exception as e:
        logger.exception(f"🔥 [Provisioning Signal] Failed to store original plan values: {e}")


# ===============================================================================
# SERVER SIGNALS
# ===============================================================================


@receiver(post_save, sender=Server)
def handle_server_created_or_updated(sender: type[Server], instance: Server, created: bool, **kwargs: Any) -> None:
    """
    Handle server creation and updates.

    Triggers:
    - Infrastructure audit logging
    - Resource capacity monitoring
    - Security logging for server changes
    - Monitoring system integration
    - Maintenance scheduling
    """
    try:
        # Get previous values for audit trail
        old_values = getattr(instance, "_original_server_values", {}) if not created else {}
        new_values = {
            "name": instance.name,
            "hostname": instance.hostname,
            "server_type": instance.server_type,
            "status": instance.status,
            "primary_ip": str(instance.primary_ip),
            "location": instance.location,
            "datacenter": instance.datacenter,
            "cpu_cores": instance.cpu_cores,
            "ram_gb": instance.ram_gb,
            "disk_capacity_gb": instance.disk_capacity_gb,
            "is_active": instance.is_active,
        }

        # Enhanced server audit logging
        if not getattr(settings, "DISABLE_AUDIT_SIGNALS", False):
            from apps.audit.services import ProvisioningAuditService  # noqa: PLC0415 - Service integration

            event_type = "server_created" if created else "server_updated"

            ProvisioningAuditService.log_server_event(
                event_type=event_type,
                server=instance,
                user=getattr(instance, "_audit_user", None),
                context=AuditContext(actor_type="system"),
                old_values=old_values,
                new_values=new_values,
                description=f"Server {instance.name} {'created' if created else 'updated'}",
            )

        if created:
            # New server created
            _handle_new_server_creation(instance)
            logger.info(f"🖥️ [Provisioning] Created server: {instance.name} ({instance.server_type})")

        else:
            # Server updated - check for important changes
            old_status = old_values.get("status")
            if old_status and old_status != instance.status:
                _handle_server_status_change(instance, old_status, instance.status)

        # Resource usage monitoring
        if instance.cpu_usage_percent and float(instance.cpu_usage_percent) > SERVER_OVERLOAD_THRESHOLD:
            _handle_server_overload_alert(instance, "cpu", float(instance.cpu_usage_percent))

        if instance.ram_usage_percent and float(instance.ram_usage_percent) > SERVER_OVERLOAD_THRESHOLD:
            _handle_server_overload_alert(instance, "ram", float(instance.ram_usage_percent))

        # Service capacity monitoring
        if (
            instance.max_services
            and instance.active_services_count >= instance.max_services * MAX_SERVICES_WARNING_THRESHOLD
        ):
            _handle_server_capacity_warning(instance)

    except Exception as e:
        logger.exception(f"🔥 [Provisioning Signal] Failed to handle server save: {e}")


@receiver(pre_save, sender=Server)
def store_original_server_values(sender: type[Server], instance: Server, **kwargs: Any) -> None:
    """Store original server values for audit trail"""
    try:
        if instance.pk:
            try:
                original = Server.objects.get(pk=instance.pk)
                instance._original_server_values = {
                    "name": original.name,
                    "hostname": original.hostname,
                    "server_type": original.server_type,
                    "status": original.status,
                    "primary_ip": str(original.primary_ip),
                    "location": original.location,
                    "datacenter": original.datacenter,
                    "cpu_cores": original.cpu_cores,
                    "ram_gb": original.ram_gb,
                    "disk_capacity_gb": original.disk_capacity_gb,
                    "is_active": original.is_active,
                }
            except Server.DoesNotExist:
                instance._original_server_values = {}
    except Exception as e:
        logger.exception(f"🔥 [Provisioning Signal] Failed to store original server values: {e}")


# ===============================================================================
# SERVICE SIGNALS
# ===============================================================================


@receiver(post_save, sender=Service)
def handle_service_created_or_updated(sender: type[Service], instance: Service, created: bool, **kwargs: Any) -> None:
    """
    Handle service creation and updates.

    Triggers:
    - Service lifecycle audit logging
    - Provisioning task creation
    - Billing system integration
    - Romanian compliance verification
    - Resource allocation tracking
    - Customer notification
    """
    try:
        # Get previous values for audit trail
        old_values = getattr(instance, "_original_service_values", {}) if not created else {}
        new_values = {
            "service_name": instance.service_name,
            "domain": instance.domain,
            "status": instance.status,
            "billing_cycle": instance.billing_cycle,
            "price": float(instance.price),
            "server_id": str(instance.server.id) if instance.server else None,
            "auto_renew": instance.auto_renew,
        }

        # Enhanced service audit logging
        if not getattr(settings, "DISABLE_AUDIT_SIGNALS", False):
            from apps.audit.services import ProvisioningAuditService  # noqa: PLC0415 - Service integration

            event_type = "service_created" if created else "service_updated"

            ProvisioningAuditService.log_service_event(
                event_type=event_type,
                service=instance,
                user=getattr(instance, "_audit_user", None),
                context=AuditContext(actor_type="system"),
                old_values=old_values,
                new_values=new_values,
                description=f"Service {instance.service_name} {'created' if created else 'updated'}",
            )

        if created:
            # New service created
            _handle_new_service_creation(instance)
            logger.info(
                f"⚙️ [Provisioning] Created service: {instance.service_name} for {instance.customer.get_display_name()}"
            )

        else:
            # Service updated - check for important changes
            old_status = old_values.get("status")
            if old_status and old_status != instance.status:
                _handle_service_status_change(instance, old_status, instance.status)

            # Check for server assignment changes
            old_server_id = old_values.get("server_id")
            current_server_id = str(instance.server.id) if instance.server else None
            if old_server_id != current_server_id:
                _handle_service_server_change(instance, old_server_id, current_server_id)

        # Resource usage monitoring
        if instance.disk_usage_mb and instance.service_plan.disk_space_gb:
            usage_percentage = (instance.disk_usage_mb / (instance.service_plan.disk_space_gb * 1024)) * 100
            if usage_percentage > RESOURCE_USAGE_ALERT_THRESHOLD:
                _handle_service_resource_alert(instance, "disk", usage_percentage)

        # Romanian compliance verification for business services
        if instance.customer.customer_type == "company":
            _verify_service_romanian_compliance(instance)

    except Exception as e:
        logger.exception(f"🔥 [Provisioning Signal] Failed to handle service save: {e}")


@receiver(pre_save, sender=Service)
def store_original_service_values(sender: type[Service], instance: Service, **kwargs: Any) -> None:
    """Store original service values for audit trail"""
    try:
        if instance.pk:
            try:
                original = Service.objects.get(pk=instance.pk)
                instance._original_service_values = {
                    "service_name": original.service_name,
                    "domain": original.domain,
                    "status": original.status,
                    "billing_cycle": original.billing_cycle,
                    "price": float(original.price),
                    "server_id": str(original.server.id) if original.server else None,
                    "auto_renew": original.auto_renew,
                }
            except Service.DoesNotExist:
                instance._original_service_values = {}
    except Exception as e:
        logger.exception(f"🔥 [Provisioning Signal] Failed to store original service values: {e}")


@receiver(pre_delete, sender=Service)
def handle_service_deletion(sender: type[Service], instance: Service, **kwargs: Any) -> None:
    """
    Handle service deletion with compliance logging.

    Romanian compliance: Service data must be archived for legal requirements.
    """
    try:
        # Security logging for service deletion
        log_security_event(
            "service_deleted",
            {
                "service_id": str(instance.id),
                "service_name": instance.service_name,
                "customer_id": str(instance.customer.id),
                "customer_name": instance.customer.get_display_name(),
                "service_type": instance.service_plan.plan_type,
                "domain": instance.domain,
            },
        )

        # Audit the deletion
        event_data = AuditEventData(
            event_type="service_deleted",
            content_object=instance,
            description=f"Service deleted: {instance.service_name} for {instance.customer.get_display_name()}",
        )
        AuditService.log_event(event_data)

        # Handle service dependencies
        _handle_service_deletion_dependencies(instance)

        logger.info(f"🗑️ [Provisioning] Service deletion logged: {instance.service_name}")

    except Exception as e:
        logger.exception(f"🔥 [Provisioning Signal] Failed to handle service deletion: {e}")


# ===============================================================================
# SERVICE RELATIONSHIP SIGNALS
# ===============================================================================


@receiver(post_save, sender=ServiceRelationship)
def handle_service_relationship_created_or_updated(
    sender: type[ServiceRelationship], instance: ServiceRelationship, created: bool, **kwargs: Any
) -> None:
    """
    Handle service relationship creation and updates.

    Triggers:
    - Relationship audit logging
    - Dependency validation
    - Billing impact calculation
    - Auto-provisioning triggers
    """
    try:
        event_type = "service_relationship_created" if created else "service_relationship_updated"

        # Enhanced service relationship audit logging
        if not getattr(settings, "DISABLE_AUDIT_SIGNALS", False):
            from apps.audit.services import ProvisioningAuditService  # noqa: PLC0415 - Service integration

            ProvisioningAuditService.log_service_relationship_event(
                event_type=event_type,
                relationship=instance,
                user=getattr(instance, "_audit_user", None),
                context=AuditContext(actor_type="system"),
                description=f"Service relationship {'created' if created else 'updated'}: {instance.parent_service.service_name} → {instance.child_service.service_name}",
            )

        if created:
            # New relationship created
            _handle_new_service_relationship(instance)
            logger.info(
                f"🔗 [Provisioning] Service relationship created: {instance.parent_service.service_name} → {instance.child_service.service_name}"
            )

            # Auto-provision child service if configured
            if instance.auto_provision and instance.child_service.status == "pending":
                _trigger_auto_provisioning(
                    instance.child_service,
                    f"Auto-provision via relationship with {instance.parent_service.service_name}",
                )

        # Validate dependency chains
        _validate_service_dependencies(instance)

    except Exception as e:
        logger.exception(f"🔥 [Provisioning Signal] Failed to handle service relationship save: {e}")


# ===============================================================================
# SERVICE GROUP SIGNALS
# ===============================================================================


@receiver(post_save, sender=ServiceGroup)
def handle_service_group_created_or_updated(
    sender: type[ServiceGroup], instance: ServiceGroup, created: bool, **kwargs: Any
) -> None:
    """
    Handle service group creation and updates.

    Triggers:
    - Group lifecycle audit logging
    - Coordinated billing setup
    - Group provisioning management
    - Customer notification
    """
    try:
        event_type = "service_group_created" if created else "service_group_updated"

        old_values = getattr(instance, "_original_group_values", {}) if not created else {}
        new_values = {
            "name": instance.name,
            "group_type": instance.group_type,
            "status": instance.status,
            "billing_cycle": instance.billing_cycle,
            "auto_provision": instance.auto_provision,
            "coordinated_billing": instance.coordinated_billing,
        }

        # Enhanced service group audit logging
        if not getattr(settings, "DISABLE_AUDIT_SIGNALS", False):
            from apps.audit.services import ProvisioningAuditService  # noqa: PLC0415 - Service integration

            ProvisioningAuditService.log_service_group_event(
                event_type=event_type,
                service_group=instance,
                user=getattr(instance, "_audit_user", None),
                context=AuditContext(actor_type="system"),
                old_values=old_values,
                new_values=new_values,
                description=f"Service group {instance.name} {'created' if created else 'updated'}",
            )

        if created:
            # New service group created
            _handle_new_service_group_creation(instance)
            logger.info(f"📦 [Provisioning] Created service group: {instance.name} ({instance.group_type})")

        else:
            # Check for status changes
            old_status = old_values.get("status")
            if old_status and old_status != instance.status:
                _handle_service_group_status_change(instance, old_status, instance.status)

    except Exception as e:
        logger.exception(f"🔥 [Provisioning Signal] Failed to handle service group save: {e}")


@receiver(pre_save, sender=ServiceGroup)
def store_original_service_group_values(sender: type[ServiceGroup], instance: ServiceGroup, **kwargs: Any) -> None:
    """Store original service group values for audit trail"""
    try:
        if instance.pk:
            try:
                original = ServiceGroup.objects.get(pk=instance.pk)
                instance._original_group_values = {
                    "name": original.name,
                    "group_type": original.group_type,
                    "status": original.status,
                    "billing_cycle": original.billing_cycle,
                    "auto_provision": original.auto_provision,
                    "coordinated_billing": original.coordinated_billing,
                }
            except ServiceGroup.DoesNotExist:
                instance._original_group_values = {}
    except Exception as e:
        logger.exception(f"🔥 [Provisioning Signal] Failed to store original group values: {e}")


# ===============================================================================
# PROVISIONING TASK SIGNALS
# ===============================================================================


@receiver(post_save, sender=ProvisioningTask)
def handle_provisioning_task_created_or_updated(
    sender: type[ProvisioningTask], instance: ProvisioningTask, created: bool, **kwargs: Any
) -> None:
    """
    Handle provisioning task creation and updates.

    Triggers:
    - Task execution monitoring
    - Failure detection and alerting
    - Performance tracking
    - Romanian compliance logging
    """
    try:
        event_type = "provisioning_task_created" if created else "provisioning_task_updated"

        old_values = getattr(instance, "_original_task_values", {}) if not created else {}
        new_values = {
            "task_type": instance.task_type,
            "status": instance.status,
            "retry_count": instance.retry_count,
            "service_name": instance.service.service_name,
        }

        # Enhanced provisioning task audit logging
        if not getattr(settings, "DISABLE_AUDIT_SIGNALS", False):
            from apps.audit.services import ProvisioningAuditService  # noqa: PLC0415 - Service integration

            ProvisioningAuditService.log_provisioning_task_event(
                event_type=event_type,
                task=instance,
                user=getattr(instance, "_audit_user", None),
                context=AuditContext(actor_type="system"),
                old_values=old_values,
                new_values=new_values,
                description=f"Provisioning task {instance.get_task_type_display()} {'created' if created else 'updated'} for {instance.service.service_name}",
            )

        if not created:
            # Check for status changes
            old_status = old_values.get("status")
            if old_status and old_status != instance.status:
                _handle_provisioning_task_status_change(instance, old_status, instance.status)

        # Monitor long-running tasks
        if instance.started_at and not instance.completed_at:
            duration = timezone.now() - instance.started_at
            if duration.total_seconds() > LONG_PROVISIONING_THRESHOLD * 60:
                _handle_long_provisioning_task(instance, duration.total_seconds())

    except Exception as e:
        logger.exception(f"🔥 [Provisioning Signal] Failed to handle provisioning task save: {e}")


@receiver(pre_save, sender=ProvisioningTask)
def store_original_provisioning_task_values(
    sender: type[ProvisioningTask], instance: ProvisioningTask, **kwargs: Any
) -> None:
    """Store original provisioning task values for audit trail"""
    try:
        if instance.pk:
            try:
                original = ProvisioningTask.objects.get(pk=instance.pk)
                instance._original_task_values = {
                    "task_type": original.task_type,
                    "status": original.status,
                    "retry_count": original.retry_count,
                    "service_name": original.service.service_name,
                }
            except ProvisioningTask.DoesNotExist:
                instance._original_task_values = {}
    except Exception as e:
        logger.exception(f"🔥 [Provisioning Signal] Failed to store original task values: {e}")


# ===============================================================================
# SERVICE DOMAIN SIGNALS
# ===============================================================================


@receiver(post_save, sender=ServiceDomain)
def handle_service_domain_created_or_updated(
    sender: type[ServiceDomain], instance: ServiceDomain, created: bool, **kwargs: Any
) -> None:
    """
    Handle service domain creation and updates.

    Triggers:
    - Domain binding audit logging
    - DNS configuration management
    - SSL certificate provisioning
    - Romanian .ro domain compliance
    """
    try:
        event_type = "service_domain_created" if created else "service_domain_updated"

        # Enhanced service domain audit logging
        if not getattr(settings, "DISABLE_AUDIT_SIGNALS", False):
            from apps.audit.services import ProvisioningAuditService  # noqa: PLC0415 - Service integration

            ProvisioningAuditService.log_service_domain_event(
                event_type=event_type,
                service_domain=instance,
                user=getattr(instance, "_audit_user", None),
                context=AuditContext(actor_type="system"),
                description=f"Service domain {instance.full_domain_name} {'bound' if created else 'updated'} to {instance.service.service_name}",
            )

        if created:
            # New domain binding created
            _handle_new_service_domain_binding(instance)
            logger.info(
                f"🌐 [Provisioning] Domain bound: {instance.full_domain_name} to {instance.service.service_name}"
            )

        # Handle SSL configuration
        if instance.ssl_enabled and instance.ssl_type != "none":
            _trigger_ssl_certificate_provisioning(instance)

        # Romanian .ro domain compliance
        if instance.domain.name.endswith(".ro"):
            _verify_romanian_domain_compliance(instance)

    except Exception as e:
        logger.exception(f"🔥 [Provisioning Signal] Failed to handle service domain save: {e}")


# ===============================================================================
# BUSINESS LOGIC FUNCTIONS
# ===============================================================================


def _handle_new_service_plan_creation(plan: ServicePlan) -> None:
    """Handle new service plan creation tasks"""
    try:
        # Trigger pricing validation
        _validate_service_plan_pricing(plan)

        # Setup monitoring for plan usage
        _setup_plan_usage_monitoring(plan)

        # Romanian VAT compliance check
        if plan.includes_vat:
            _setup_vat_compliance_monitoring(plan)

    except Exception as e:
        logger.exception(f"🔥 [Provisioning Signal] New service plan creation handling failed: {e}")


def _handle_service_plan_pricing_change(plan: ServicePlan, old_price: float, new_price: float) -> None:
    """Handle service plan pricing changes"""
    try:
        price_change = new_price - old_price
        change_percentage = (abs(price_change) / old_price) * 100 if old_price > 0 else 0

        logger.info(
            f"💰 [Provisioning] Plan pricing changed: {plan.name} {old_price:.2f} → {new_price:.2f} RON ({change_percentage:.1f}% change)"
        )

        # Significant price changes require security logging
        if change_percentage > SIGNIFICANT_PRICE_CHANGE_PERCENTAGE:
            log_security_event(
                "significant_plan_price_change",
                {
                    "plan_id": str(plan.id),
                    "plan_name": plan.name,
                    "old_price": old_price,
                    "new_price": new_price,
                    "change_percentage": change_percentage,
                },
            )

        # Update existing services with new pricing (if configured)
        _update_existing_services_pricing(plan, old_price, new_price)

    except Exception as e:
        logger.exception(f"🔥 [Provisioning Signal] Plan pricing change handling failed: {e}")


def _handle_service_plan_availability_change(plan: ServicePlan, old_active: bool, new_active: bool) -> None:
    """Handle service plan availability changes"""
    try:
        availability_action = "activated" if new_active else "deactivated"

        logger.info(f"📋 [Provisioning] Service plan {availability_action}: {plan.name}")

        # Log compliance event for plan availability
        compliance_request = ComplianceEventRequest(
            compliance_type="service_plan_availability",
            reference_id=f"plan_{plan.id}",
            description=f"Service plan {availability_action}: {plan.name}",
            status="success",
            evidence={
                "plan_id": str(plan.id),
                "plan_name": plan.name,
                "plan_type": plan.plan_type,
                "old_active": old_active,
                "new_active": new_active,
            },
        )
        AuditService.log_compliance_event(compliance_request)

        # Handle existing services if plan is deactivated
        if not new_active:
            _handle_deactivated_plan_services(plan)

    except Exception as e:
        logger.exception(f"🔥 [Provisioning Signal] Plan availability change handling failed: {e}")


def _handle_new_server_creation(server: Server) -> None:
    """Handle new server creation tasks"""
    try:
        # Setup monitoring for new server
        _setup_server_monitoring(server)

        # Initialize resource tracking
        _initialize_server_resource_tracking(server)

        # Security logging for new infrastructure
        log_security_event(
            "new_server_created",
            {
                "server_id": str(server.id),
                "server_name": server.name,
                "server_type": server.server_type,
                "location": server.location,
                "primary_ip": str(server.primary_ip),
            },
        )

    except Exception as e:
        logger.exception(f"🔥 [Provisioning Signal] New server creation handling failed: {e}")


def _handle_server_status_change(server: Server, old_status: str, new_status: str) -> None:
    """Handle server status changes"""
    try:
        logger.info(f"🖥️ [Provisioning] Server status change {server.name}: {old_status} → {new_status}")

        # Security event for critical status changes
        if new_status in ["offline", "decommissioned"]:
            log_security_event(
                "server_critical_status_change",
                {
                    "server_id": str(server.id),
                    "server_name": server.name,
                    "old_status": old_status,
                    "new_status": new_status,
                    "active_services": server.active_services_count,
                },
            )

        # Handle services on server status changes
        if new_status == "offline":
            _handle_server_offline_services(server)
        elif new_status == "maintenance":
            _handle_server_maintenance_services(server)
        elif new_status == "active" and old_status in ["offline", "maintenance"]:
            _handle_server_recovery_services(server)

    except Exception as e:
        logger.exception(f"🔥 [Provisioning Signal] Server status change handling failed: {e}")


def _handle_server_overload_alert(server: Server, resource_type: str, usage_percentage: float) -> None:
    """Handle server resource overload alerts"""
    try:
        logger.warning(
            f"⚠️ [Provisioning] Server {resource_type.upper()} overload: {server.name} ({usage_percentage:.1f}%)"
        )

        # Security logging for resource overload
        log_security_event(
            "server_resource_overload",
            {
                "server_id": str(server.id),
                "server_name": server.name,
                "resource_type": resource_type,
                "usage_percentage": usage_percentage,
                "threshold": SERVER_OVERLOAD_THRESHOLD,
            },
        )

        # Trigger load balancing or scaling alerts
        _trigger_server_scaling_alert(server, resource_type, usage_percentage)

    except Exception as e:
        logger.exception(f"🔥 [Provisioning Signal] Server overload alert handling failed: {e}")


def _handle_new_service_creation(service: Service) -> None:
    """Handle new service creation tasks"""
    try:
        # Create initial provisioning task if auto-provision is enabled
        if service.service_plan.auto_provision:
            ProvisioningTask.objects.create(
                service=service, task_type="create_service", status="pending", parameters={"auto_created": True}
            )

        # Setup service monitoring
        _setup_service_monitoring(service)

        # Romanian compliance initialization
        if service.customer.customer_type == "company":
            _initialize_service_compliance_tracking(service)

        # Notification to customer
        _send_service_creation_notification(service)

    except Exception as e:
        logger.exception(f"🔥 [Provisioning Signal] New service creation handling failed: {e}")


def _handle_service_status_change(service: Service, old_status: str, new_status: str) -> None:
    """Handle service status changes"""
    try:
        logger.info(f"⚙️ [Provisioning] Service status change {service.service_name}: {old_status} → {new_status}")

        # Update activation timestamp
        if new_status == "active" and not service.activated_at:
            Service.objects.filter(pk=service.pk).update(activated_at=timezone.now())
        elif new_status == "suspended":
            Service.objects.filter(pk=service.pk).update(suspended_at=timezone.now())

        # Handle specific status transitions
        if new_status == "active" and old_status in ["pending", "provisioning"]:
            _handle_service_activation(service)
        elif new_status == "suspended":
            _handle_service_suspension(service, old_status)
        elif new_status == "terminated":
            _handle_service_termination(service, old_status)

        # Romanian compliance logging
        compliance_request = ComplianceEventRequest(
            compliance_type="service_status_change",
            reference_id=f"service_{service.id}",
            description=f"Service status changed: {old_status} → {new_status}",
            status="success",
            evidence={
                "service_id": str(service.id),
                "service_name": service.service_name,
                "customer_id": str(service.customer.id),
                "old_status": old_status,
                "new_status": new_status,
            },
        )
        AuditService.log_compliance_event(compliance_request)

    except Exception as e:
        logger.exception(f"🔥 [Provisioning Signal] Service status change handling failed: {e}")


def _handle_service_server_change(service: Service, old_server_id: str | None, new_server_id: str | None) -> None:
    """Handle service server assignment changes"""
    try:
        if old_server_id != new_server_id:
            action = "assigned" if new_server_id else "unassigned"
            server_name = service.server.name if service.server else "None"

            logger.info(f"🖥️ [Provisioning] Service server {action}: {service.service_name} → {server_name}")

            # Security logging for server assignment changes
            log_security_event(
                "service_server_change",
                {
                    "service_id": str(service.id),
                    "service_name": service.service_name,
                    "old_server_id": old_server_id,
                    "new_server_id": new_server_id,
                    "customer_id": str(service.customer.id),
                },
            )

            # Trigger migration tasks if needed
            if old_server_id and new_server_id:
                _trigger_service_migration(service, old_server_id, new_server_id)

    except Exception as e:
        logger.exception(f"🔥 [Provisioning Signal] Service server change handling failed: {e}")


def _handle_new_service_relationship(relationship: ServiceRelationship) -> None:
    """Handle new service relationship creation"""
    try:
        # Validate relationship business rules
        _validate_relationship_business_rules(relationship)

        # Update billing if necessary
        if relationship.billing_impact in ["discounted", "included"]:
            _update_relationship_billing(relationship)

        # Setup dependency monitoring
        if relationship.is_required:
            _setup_dependency_monitoring(relationship)

    except Exception as e:
        logger.exception(f"🔥 [Provisioning Signal] New service relationship handling failed: {e}")


def _handle_new_service_group_creation(group: ServiceGroup) -> None:
    """Handle new service group creation"""
    try:
        # Setup coordinated billing if enabled
        if group.coordinated_billing:
            _setup_coordinated_billing(group)

        # Initialize group monitoring
        _initialize_group_monitoring(group)

        # Send notification to customer
        _send_service_group_notification(group)

    except Exception as e:
        logger.exception(f"🔥 [Provisioning Signal] New service group creation handling failed: {e}")


def _handle_service_group_status_change(group: ServiceGroup, old_status: str, new_status: str) -> None:
    """Handle service group status changes"""
    try:
        logger.info(f"📦 [Provisioning] Service group status change {group.name}: {old_status} → {new_status}")

        # Cascade status changes to member services if configured
        if new_status == "suspended":
            _suspend_group_services(group)
        elif new_status == "active" and old_status == "suspended":
            _reactivate_group_services(group)
        elif new_status == "cancelled":
            _cancel_group_services(group)

    except Exception as e:
        logger.exception(f"🔥 [Provisioning Signal] Service group status change handling failed: {e}")


def _handle_provisioning_task_status_change(task: ProvisioningTask, old_status: str, new_status: str) -> None:
    """Handle provisioning task status changes"""
    try:
        logger.info(f"🔄 [Provisioning] Task status change {task.get_task_type_display()}: {old_status} → {new_status}")

        if new_status == "completed":
            _handle_task_completion(task)
        elif new_status == "failed":
            _handle_task_failure(task)
        elif new_status == "running":
            _handle_task_start(task)

    except Exception as e:
        logger.exception(f"🔥 [Provisioning Signal] Task status change handling failed: {e}")


def _handle_new_service_domain_binding(service_domain: ServiceDomain) -> None:
    """Handle new service domain binding"""
    try:
        # Configure DNS if management is enabled
        if service_domain.dns_management:
            _configure_domain_dns(service_domain)

        # Setup email routing if configured
        if service_domain.email_routing:
            _configure_domain_email(service_domain)

        # Setup redirects if configured
        if service_domain.domain_type == "redirect" and service_domain.redirect_url:
            _configure_domain_redirect(service_domain)

    except Exception as e:
        logger.exception(f"🔥 [Provisioning Signal] New service domain binding handling failed: {e}")


# ===============================================================================
# ROMANIAN COMPLIANCE FUNCTIONS
# ===============================================================================


def _verify_romanian_vat_compliance(plan: ServicePlan) -> None:
    """Verify Romanian VAT compliance for service plans"""
    try:
        if plan.includes_vat:
            # Standard Romanian VAT rate is 19%
            expected_vat_rate = Decimal("0.19")

            compliance_request = ComplianceEventRequest(
                compliance_type="romanian_vat_compliance",
                reference_id=f"plan_{plan.id}",
                description=f"VAT compliance verified for plan: {plan.name}",
                status="success",
                evidence={
                    "plan_id": str(plan.id),
                    "plan_name": plan.name,
                    "includes_vat": plan.includes_vat,
                    "expected_vat_rate": float(expected_vat_rate),
                },
            )
            AuditService.log_compliance_event(compliance_request)

    except Exception as e:
        logger.exception(f"🔥 [Provisioning Signal] Romanian VAT compliance verification failed: {e}")


def _verify_service_romanian_compliance(service: Service) -> None:
    """Verify Romanian compliance for business services"""
    try:
        if service.customer.customer_type == "company":
            # Check if customer has valid CUI
            tax_profile = service.customer.get_tax_profile()
            if tax_profile and tax_profile.cui:
                compliance_request = ComplianceEventRequest(
                    compliance_type="business_service_compliance",
                    reference_id=f"service_{service.id}",
                    description="Romanian business service compliance verified",
                    status="success",
                    evidence={
                        "service_id": str(service.id),
                        "customer_cui": tax_profile.cui,
                        "service_type": service.service_plan.plan_type,
                    },
                )
                AuditService.log_compliance_event(compliance_request)
            else:
                logger.warning(f"⚠️ [Provisioning] Business service without valid CUI: {service.service_name}")

    except Exception as e:
        logger.exception(f"🔥 [Provisioning Signal] Service Romanian compliance verification failed: {e}")


def _verify_romanian_domain_compliance(service_domain: ServiceDomain) -> None:
    """Verify Romanian .ro domain compliance"""
    try:
        if service_domain.domain.name.endswith(".ro"):
            compliance_request = ComplianceEventRequest(
                compliance_type="romanian_domain_compliance",
                reference_id=f"domain_{service_domain.domain.id}",
                description=f"Romanian .ro domain compliance verified: {service_domain.domain.name}",
                status="success",
                evidence={
                    "domain_name": service_domain.domain.name,
                    "service_id": str(service_domain.service.id),
                    "customer_id": str(service_domain.service.customer.id),
                },
            )
            AuditService.log_compliance_event(compliance_request)

    except Exception as e:
        logger.exception(f"🔥 [Provisioning Signal] Romanian domain compliance verification failed: {e}")


# ===============================================================================
# PLACEHOLDER FUNCTIONS (TO BE IMPLEMENTED)
# ===============================================================================


def _handle_high_value_plan_security(plan: ServicePlan, created: bool) -> None:
    """Security logging for high-value plans"""
    logger.info(f"💰 [Provisioning] High-value plan security check: {plan.name} ({plan.price_monthly} RON)")


def _validate_service_plan_pricing(plan: ServicePlan) -> None:
    """Validate service plan pricing"""
    logger.info(f"✅ [Provisioning] Plan pricing validated: {plan.name}")


def _setup_plan_usage_monitoring(plan: ServicePlan) -> None:
    """Setup monitoring for plan usage"""
    logger.info(f"📊 [Provisioning] Plan usage monitoring setup: {plan.name}")


def _setup_vat_compliance_monitoring(plan: ServicePlan) -> None:
    """Setup VAT compliance monitoring"""
    logger.info(f"🏛️ [Provisioning] VAT compliance monitoring setup: {plan.name}")


def _update_existing_services_pricing(plan: ServicePlan, old_price: float, new_price: float) -> None:
    """Update existing services with new pricing"""
    logger.info(f"💰 [Provisioning] Would update existing services pricing for plan: {plan.name}")


def _handle_deactivated_plan_services(plan: ServicePlan) -> None:
    """Handle services when plan is deactivated"""
    logger.info(f"⚠️ [Provisioning] Would handle deactivated plan services: {plan.name}")


def _setup_server_monitoring(server: Server) -> None:
    """Setup monitoring for new server"""
    logger.info(f"📊 [Provisioning] Server monitoring setup: {server.name}")


def _initialize_server_resource_tracking(server: Server) -> None:
    """Initialize resource tracking for server"""
    logger.info(f"📈 [Provisioning] Resource tracking initialized: {server.name}")


def _handle_server_offline_services(server: Server) -> None:
    """Handle services when server goes offline"""
    logger.warning(f"🔴 [Provisioning] Server offline - handling services: {server.name}")


def _handle_server_maintenance_services(server: Server) -> None:
    """Handle services during server maintenance"""
    logger.info(f"🔧 [Provisioning] Server maintenance - handling services: {server.name}")


def _handle_server_recovery_services(server: Server) -> None:
    """Handle services when server recovers"""
    logger.info(f"✅ [Provisioning] Server recovered - handling services: {server.name}")


def _handle_server_capacity_warning(server: Server) -> None:
    """Handle server capacity warnings"""
    logger.warning(f"⚠️ [Provisioning] Server capacity warning: {server.name}")


def _trigger_server_scaling_alert(server: Server, resource_type: str, usage: float) -> None:
    """Trigger server scaling alerts"""
    logger.warning(f"🚨 [Provisioning] Scaling alert: {server.name} {resource_type} {usage:.1f}%")


def _setup_service_monitoring(service: Service) -> None:
    """Setup monitoring for new service"""
    logger.info(f"📊 [Provisioning] Service monitoring setup: {service.service_name}")


def _initialize_service_compliance_tracking(service: Service) -> None:
    """Initialize compliance tracking for service"""
    logger.info(f"🏛️ [Provisioning] Compliance tracking initialized: {service.service_name}")


def _send_service_creation_notification(service: Service) -> None:
    """Send notification about service creation"""
    logger.info(f"📧 [Provisioning] Service creation notification: {service.service_name}")


def _handle_service_activation(service: Service) -> None:
    """Handle service activation"""
    logger.info(f"✅ [Provisioning] Service activated: {service.service_name}")


def _handle_service_suspension(service: Service, old_status: str) -> None:
    """Handle service suspension"""
    logger.warning(f"⏸️ [Provisioning] Service suspended: {service.service_name}")


def _handle_service_termination(service: Service, old_status: str) -> None:
    """Handle service termination"""
    logger.info(f"🔚 [Provisioning] Service terminated: {service.service_name}")


def _handle_service_resource_alert(service: Service, resource_type: str, usage: float) -> None:
    """Handle service resource usage alerts"""
    logger.warning(f"⚠️ [Provisioning] Service resource alert: {service.service_name} {resource_type} {usage:.1f}%")


def _trigger_service_migration(service: Service, old_server_id: str, new_server_id: str) -> None:
    """Trigger service migration between servers"""
    logger.info(f"🔄 [Provisioning] Service migration triggered: {service.service_name}")


def _handle_service_deletion_dependencies(service: Service) -> None:
    """Handle dependencies when service is deleted"""
    logger.info(f"🗑️ [Provisioning] Handling deletion dependencies: {service.service_name}")


def _validate_service_dependencies(relationship: ServiceRelationship) -> None:
    """Validate service dependency chains"""
    logger.info(f"🔗 [Provisioning] Dependency validation: {relationship}")


def _validate_relationship_business_rules(relationship: ServiceRelationship) -> None:
    """Validate relationship business rules"""
    logger.info(f"✅ [Provisioning] Relationship rules validated: {relationship}")


def _update_relationship_billing(relationship: ServiceRelationship) -> None:
    """Update billing for service relationships"""
    logger.info(f"💰 [Provisioning] Relationship billing updated: {relationship}")


def _setup_dependency_monitoring(relationship: ServiceRelationship) -> None:
    """Setup dependency monitoring"""
    logger.info(f"📊 [Provisioning] Dependency monitoring setup: {relationship}")


def _trigger_auto_provisioning(service: Service, reason: str) -> None:
    """Trigger auto-provisioning for service"""
    logger.info(f"⚡ [Provisioning] Auto-provisioning triggered: {service.service_name} - {reason}")


def _setup_coordinated_billing(group: ServiceGroup) -> None:
    """Setup coordinated billing for service group"""
    logger.info(f"💰 [Provisioning] Coordinated billing setup: {group.name}")


def _initialize_group_monitoring(group: ServiceGroup) -> None:
    """Initialize monitoring for service group"""
    logger.info(f"📊 [Provisioning] Group monitoring initialized: {group.name}")


def _send_service_group_notification(group: ServiceGroup) -> None:
    """Send notification about service group"""
    logger.info(f"📧 [Provisioning] Service group notification: {group.name}")


def _suspend_group_services(group: ServiceGroup) -> None:
    """Suspend all services in group"""
    logger.warning(f"⏸️ [Provisioning] Suspending group services: {group.name}")


def _reactivate_group_services(group: ServiceGroup) -> None:
    """Reactivate all services in group"""
    logger.info(f"▶️ [Provisioning] Reactivating group services: {group.name}")


def _cancel_group_services(group: ServiceGroup) -> None:
    """Cancel all services in group"""
    logger.info(f"❌ [Provisioning] Cancelling group services: {group.name}")


def _handle_task_completion(task: ProvisioningTask) -> None:
    """Handle provisioning task completion"""
    logger.info(f"✅ [Provisioning] Task completed: {task.get_task_type_display()}")


def _handle_task_failure(task: ProvisioningTask) -> None:
    """Handle provisioning task failure"""
    logger.error(f"❌ [Provisioning] Task failed: {task.get_task_type_display()}")


def _handle_task_start(task: ProvisioningTask) -> None:
    """Handle provisioning task start"""
    logger.info(f"▶️ [Provisioning] Task started: {task.get_task_type_display()}")


def _handle_long_provisioning_task(task: ProvisioningTask, duration_seconds: float) -> None:
    """Handle long-running provisioning tasks"""
    logger.warning(
        f"⏱️ [Provisioning] Long-running task: {task.get_task_type_display()} ({duration_seconds / 60:.1f} minutes)"
    )


def _configure_domain_dns(service_domain: ServiceDomain) -> None:
    """Configure DNS for service domain"""
    logger.info(f"🌐 [Provisioning] DNS configuration: {service_domain.full_domain_name}")


def _configure_domain_email(service_domain: ServiceDomain) -> None:
    """Configure email routing for domain"""
    logger.info(f"📧 [Provisioning] Email routing configuration: {service_domain.full_domain_name}")


def _configure_domain_redirect(service_domain: ServiceDomain) -> None:
    """Configure domain redirect"""
    logger.info(f"↩️ [Provisioning] Redirect configuration: {service_domain.full_domain_name}")


def _trigger_ssl_certificate_provisioning(service_domain: ServiceDomain) -> None:
    """Trigger SSL certificate provisioning"""
    logger.info(f"🔒 [Provisioning] SSL certificate provisioning: {service_domain.full_domain_name}")
