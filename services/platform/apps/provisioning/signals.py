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
from django.db import transaction
from django.db.models.signals import post_save, pre_delete
from django.dispatch import receiver
from django.utils import timezone

from apps.audit.services import (
    AuditContext,
    AuditEventData,
    AuditService,
)
from apps.common.validators import log_security_event
from apps.settings.services import SettingsService

from .models import (
    ProvisioningTask,
    Server,
    Service,
    ServiceDomain,
    ServiceGroup,
    ServicePlan,
)
from .security_utils import (
    IdempotencyManager,
    ProvisioningErrorClassifier,
    ProvisioningParametersValidator,
    SecureTaskParameters,
    log_security_event_safe,
    sanitize_log_parameters,
)
from .virtualmin_tasks import VirtualminProvisioningParams, provision_virtualmin_account_async

logger = logging.getLogger(__name__)

# Constants for magic values used in signal handlers
DEFAULT_TEMPLATE_NAME = "Default"

# ===============================================================================
# BUSINESS CONSTANTS
# ===============================================================================

# Module-level defaults for SettingsService fallbacks
_DEFAULT_HIGH_VALUE_PLAN_THRESHOLD_CENTS = 50000  # 500 RON in cents
_DEFAULT_RESOURCE_USAGE_ALERT_THRESHOLD = 85  # 85% resource usage alert threshold
_DEFAULT_SERVER_OVERLOAD_THRESHOLD = 90  # 90% resource usage threshold
_DEFAULT_LONG_PROVISIONING_THRESHOLD_MINUTES = 30  # 30 minutes for provisioning timeout


def get_resource_usage_alert_threshold() -> int:
    """Get resource usage alert threshold from SettingsService (runtime)."""
    return SettingsService.get_integer_setting(
        "provisioning.resource_usage_alert_threshold", _DEFAULT_RESOURCE_USAGE_ALERT_THRESHOLD
    )


def get_server_overload_threshold() -> int:
    """Get server overload threshold from SettingsService (runtime)."""
    return SettingsService.get_integer_setting(
        "provisioning.server_overload_threshold", _DEFAULT_SERVER_OVERLOAD_THRESHOLD
    )


def get_long_provisioning_threshold_minutes() -> int:
    """Get long provisioning threshold from SettingsService (runtime)."""
    return SettingsService.get_integer_setting(
        "provisioning.long_provisioning_threshold_minutes", _DEFAULT_LONG_PROVISIONING_THRESHOLD_MINUTES
    )


# Structural constants (not configurable via SettingsService)
ENTERPRISE_DISK_THRESHOLD = 100  # 100 GB threshold for enterprise plans
MAX_SERVICES_WARNING_THRESHOLD = 0.8  # 80% of max services capacity
PRICE_CHANGE_DETECTION_THRESHOLD = 0.01  # Minimum price change detection (1 cent)
SIGNIFICANT_PRICE_CHANGE_PERCENTAGE = 25  # 25% price change threshold for security alerts
CRITICAL_SERVICE_DOWNTIME_THRESHOLD = 5  # 5 minutes critical service downtime

# ===============================================================================
# MODEL LIFECYCLE COVERAGE SIGNALS
# ===============================================================================


def _log_provisioning_model_event(  # noqa: PLR0913
    *,
    event_type: str,
    instance: Any,
    description: str,
    new_values: dict[str, Any] | None = None,
    old_values: dict[str, Any] | None = None,
    metadata: dict[str, Any] | None = None,
) -> None:
    """Log lightweight provisioning model lifecycle events."""
    if getattr(settings, "DISABLE_AUDIT_SIGNALS", False):
        return

    try:
        event_metadata = {
            "source_app": "provisioning",
            "model_lifecycle": True,
        }
        if metadata:
            event_metadata.update(metadata)

        AuditService.log_event(
            AuditEventData(
                event_type=event_type,
                content_object=instance,
                old_values=old_values or {},
                new_values=new_values or {},
                description=description,
            ),
            context=AuditContext(actor_type="system", metadata=event_metadata),
        )
    except Exception as e:
        logger.exception(f"🔥 [Provisioning Lifecycle] Failed to log {event_type}: {e}")


@receiver(post_save, sender=ProvisioningTask)
def audit_provisioning_task_lifecycle(
    sender: type[ProvisioningTask], instance: ProvisioningTask, created: bool, **kwargs: Any
) -> None:
    """Audit lifecycle events for ProvisioningTask model."""
    event_type = "provisioning_task_created" if created else "provisioning_task_updated"
    _log_provisioning_model_event(
        event_type=event_type,
        instance=instance,
        description=f"Provisioning task {instance.id} {'created' if created else 'updated'}",
        new_values={
            "task_id": str(instance.id),
            "service_id": str(instance.service_id),
            "task_type": instance.task_type,
            "status": instance.status,
            "retry_count": instance.retry_count,
        },
        metadata={"model": "ProvisioningTask"},
    )


@receiver(pre_delete, sender=ProvisioningTask)
def audit_provisioning_task_deleted(sender: type[ProvisioningTask], instance: ProvisioningTask, **kwargs: Any) -> None:
    """Audit deletion events for ProvisioningTask model."""
    _log_provisioning_model_event(
        event_type="provisioning_task_deleted",
        instance=instance,
        description=f"Provisioning task {instance.id} deleted",
        old_values={
            "task_id": str(instance.id),
            "service_id": str(instance.service_id),
            "task_type": instance.task_type,
            "status": instance.status,
            "retry_count": instance.retry_count,
        },
        metadata={"model": "ProvisioningTask"},
    )


@receiver(post_save, sender=ServiceGroup)
def audit_service_group_lifecycle(
    sender: type[ServiceGroup], instance: ServiceGroup, created: bool, **kwargs: Any
) -> None:
    """Audit lifecycle events for ServiceGroup model."""
    event_type = "service_group_created" if created else "service_group_updated"
    _log_provisioning_model_event(
        event_type=event_type,
        instance=instance,
        description=f"Service group '{instance.name}' {'created' if created else 'updated'}",
        new_values={
            "group_id": str(instance.id),
            "customer_id": str(instance.customer_id),
            "name": instance.name,
            "group_type": instance.group_type,
            "status": instance.status,
        },
        metadata={"model": "ServiceGroup"},
    )


@receiver(pre_delete, sender=ServiceGroup)
def audit_service_group_deleted(sender: type[ServiceGroup], instance: ServiceGroup, **kwargs: Any) -> None:
    """Audit deletion events for ServiceGroup model."""
    _log_provisioning_model_event(
        event_type="service_group_deleted",
        instance=instance,
        description=f"Service group '{instance.name}' deleted",
        old_values={
            "group_id": str(instance.id),
            "customer_id": str(instance.customer_id),
            "name": instance.name,
            "group_type": instance.group_type,
            "status": instance.status,
        },
        metadata={"model": "ServiceGroup"},
    )


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
                if any(
                    field in update_fields
                    for field in ["price_monthly", "price_quarterly", "price_annual", "setup_fee"]
                ):
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
                            },
                        ),
                    )

    except Exception as e:
        logger.exception(f"🔥 [ServicePlan] Failed to process plan signals: {e}")


# ===============================================================================
# SERVICE LIFECYCLE SIGNALS
# ===============================================================================


@receiver(post_save, sender=Service)
def audit_service_lifecycle_events(sender: type[Service], instance: Service, created: bool, **kwargs: Any) -> None:
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
                # Log status change
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
                        },
                    ),
                )

                # Trigger automatic provisioning if service becomes active
                if instance.status == "active":
                    _trigger_automatic_virtualmin_provisioning(instance)

    except Exception as e:
        logger.exception(f"🔥 [Service] Failed to audit service lifecycle: {e}")


# ===============================================================================
# SERVER MANAGEMENT SIGNALS
# ===============================================================================


@receiver(post_save, sender=Server)
def audit_server_management_events(sender: type[Server], instance: Server, created: bool, **kwargs: Any) -> None:
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
                        },
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
                    },
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
                "high_value_plan": float(instance.price_monthly)
                >= SettingsService.get_integer_setting(
                    "provisioning.high_value_plan_threshold_cents", _DEFAULT_HIGH_VALUE_PLAN_THRESHOLD_CENTS
                )
                / 100,
                "enterprise_plan": (instance.disk_space_gb and instance.disk_space_gb >= ENTERPRISE_DISK_THRESHOLD),
            },
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
            },
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
                "high_value_service": float(instance.price)
                >= SettingsService.get_integer_setting(
                    "provisioning.high_value_plan_threshold_cents", _DEFAULT_HIGH_VALUE_PLAN_THRESHOLD_CENTS
                )
                / 100,
            },
        ),
    )

    logger.info(f"✅ [Service] Created: {instance.service_name} for {instance.customer.company_name}")


def log_virtualmin_security_event(event_type: str, details: dict[str, Any], ip_address: str) -> None:
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
        enhanced_details.update(
            {
                "source_app": "provisioning",
                "virtualmin_integration": True,
            }
        )

        # Call the log_security_event function with expected parameters
        log_security_event(event_type, enhanced_details, ip_address)

        logger.info(f"🔒 [Security] Virtualmin {event_type}: {details}")

    except Exception as e:
        logger.error(f"🔥 [Security] Failed to log Virtualmin security event: {e}")


def notify_provisioning_completion(account: Any, success: bool = True, details: dict[str, Any] | None = None) -> None:
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
                },
            ),
        )

        logger.info(
            f"📋 [Provisioning] Virtualmin {'completed' if success else 'failed'} for domain {account.domain}: {details}"
        )

        # Here you could add email notifications, webhook calls, etc.
        # For now, we just log the completion

    except Exception as e:
        logger.error(
            f"🔥 [Provisioning] Failed to notify completion for domain {getattr(account, 'domain', 'unknown')}: {e}"
        )


def _validate_service_for_provisioning(service: Service) -> bool:
    """Check if service requires and is ready for provisioning."""
    if not service.requires_hosting_account():
        logger.info(f"⏭️ [AutoProvisioning] Service {service.service_name} doesn't require hosting account")
        return False
    return True


def _check_existing_virtualmin_account(service: Service) -> bool:
    """Check if service already has a VirtualMin account."""
    if hasattr(service, "virtualmin_account") and service.virtualmin_account:
        logger.info(f"⏭️ [AutoProvisioning] VirtualMin account already exists for {service.service_name}")
        return True
    return False


def _get_and_validate_primary_domain(service: Service) -> str | None:
    """Get and validate primary domain for the service."""
    primary_domain = service.get_primary_domain()
    if not primary_domain:
        logger.warning(f"⚠️ [AutoProvisioning] No primary domain found for service {service.service_name}")
        return None
    return primary_domain


def _validate_provisioning_parameters(service_id_str: str, primary_domain: str) -> tuple[bool, dict[str, str]]:
    """Validate all provisioning parameters."""
    try:
        validated_service_id = ProvisioningParametersValidator.validate_service_id(service_id_str)
        validated_domain = ProvisioningParametersValidator.validate_domain(primary_domain)
        validated_template = ProvisioningParametersValidator.validate_template(DEFAULT_TEMPLATE_NAME)

        return True, {"service_id": validated_service_id, "domain": validated_domain, "template": validated_template}
    except Exception as validation_error:
        logger.error(f"❌ [AutoProvisioning] Parameter validation failed: {validation_error}")
        log_security_event_safe(
            "virtualmin_parameter_validation_failed",
            {"error": str(validation_error), "original_domain": primary_domain},
            service_id_str,
            primary_domain,
        )
        return False, {}


def _handle_idempotency_check(service_id: str, operation_params: dict[str, Any]) -> tuple[bool, str | None]:
    """Handle idempotency check for the operation."""
    idempotency_key = IdempotencyManager.generate_key(service_id, "auto_provision", operation_params)

    is_new, _existing_result = IdempotencyManager.check_and_set(
        idempotency_key, {"status": "in_progress", "started_at": timezone.now().isoformat()}
    )

    if not is_new:
        logger.info(f"⏭️ [AutoProvisioning] Operation already in progress (key: {idempotency_key[:16]}...)")
        return False, idempotency_key

    return True, idempotency_key


def _prepare_secure_parameters(validated_params: dict[str, str]) -> tuple[bool, SecureTaskParameters | None]:
    """Prepare and encrypt secure parameters for the task."""
    raw_params: VirtualminProvisioningParams = {
        "service_id": validated_params["service_id"],
        "domain": validated_params["domain"],
        "username": None,  # Will be generated automatically
        "password": None,  # Will be generated automatically
        "template": validated_params["template"],
        "server_id": None,  # Will be selected automatically by load balancer
    }

    try:
        secure_params = SecureTaskParameters.create(dict(raw_params))
        return True, secure_params
    except Exception as encryption_error:
        logger.error(f"🔥 [AutoProvisioning] Parameter encryption failed: {encryption_error}")
        log_security_event_safe(
            "virtualmin_parameter_encryption_failed",
            {"error": str(encryption_error)},
            validated_params["service_id"],
            validated_params["domain"],
        )
        return False, None


def _schedule_provisioning_task(
    secure_params: SecureTaskParameters, validated_params: dict[str, str]
) -> tuple[bool, str | None]:
    """Schedule the async provisioning task."""
    try:
        task_id = provision_virtualmin_account_async(secure_params)
        return True, task_id
    except Exception as task_error:
        logger.error(f"🔥 [AutoProvisioning] Task scheduling failed: {task_error}")
        log_security_event_safe(
            "virtualmin_task_scheduling_failed",
            {"error": str(task_error)},
            validated_params["service_id"],
            validated_params["domain"],
        )
        return False, None


def _log_audit_event(service: Service, audit_data: dict[str, Any]) -> None:
    """Log audit event for the provisioning operation."""
    try:
        AuditService.log_event(
            AuditEventData(
                event_type="virtualmin_auto_provisioning_scheduled",
                content_object=service,
                new_values={
                    "domain": audit_data["domain"],
                    "task_id": audit_data["task_id"],
                    "service_id": audit_data["service_id"],
                    "customer_id": str(service.customer.id),
                    "idempotency_key": audit_data["idempotency_key"][:16] + "...",  # Truncated for security
                    "parameter_hash": audit_data["parameter_hash"][:16] + "...",
                },
                description=f"Automatic VirtualMin provisioning scheduled for domain '{audit_data['domain']}'",
            ),
            context=AuditContext(
                actor_type="system",
                metadata={
                    "source_app": "provisioning",
                    "provisioning_event": True,
                    "automatic_provisioning": True,
                    "service_lifecycle": True,
                    "domain": audit_data["domain"],
                    "task_id": audit_data["task_id"],
                    "customer_id": str(service.customer.id),
                    "security_enhanced": True,
                    "correlation_id": audit_data["correlation_id"],
                },
            ),
        )
    except Exception as audit_error:
        logger.warning(f"⚠️ [AutoProvisioning] Audit logging failed (non-critical): {audit_error}")


def _trigger_automatic_virtualmin_provisioning(service: Service) -> None:
    """
    Trigger automatic VirtualMin account creation when service becomes active.

    SECURITY FIXES APPLIED:
    1. Race condition protection with atomic database operations
    2. Input validation and sanitization for all parameters
    3. Secure parameter handling with encryption
    4. Proper error classification and state management
    5. Idempotency key management to prevent duplicate operations

    Args:
        service: The Service instance that became active
    """
    service_id_str = str(service.id)
    correlation_id = f"auto_provision_{service_id_str}"

    # Initialize secure logging context
    safe_log_ctx = {
        "service_id": service_id_str,
        "service_name": service.service_name,
        "customer_id": str(service.customer.id),
        "correlation_id": correlation_id,
    }

    try:
        # Step 1-3: Validate service requirements and setup
        if not _validate_service_for_provisioning(service):
            return

        # Step 2: RACE CONDITION FIX - Use atomic transaction with select_for_update
        with transaction.atomic():
            # Lock the service row to prevent concurrent provisioning attempts
            locked_service = Service.objects.select_for_update().select_related("customer").get(id=service.id)

            # Perform all validation checks within transaction
            if _check_existing_virtualmin_account(locked_service):
                return

            primary_domain = _get_and_validate_primary_domain(locked_service)
            is_valid, validated_params = (
                _validate_provisioning_parameters(service_id_str, primary_domain) if primary_domain else (False, {})
            )

            # Early exit for any validation failures
            if not primary_domain or not is_valid:
                return

            safe_log_ctx["domain"] = validated_params["domain"]

            # Step 4-5: Idempotency check and parameter preparation
            operation_params = {**validated_params, "operation": "auto_provision"}
            is_new_operation, idempotency_key = _handle_idempotency_check(
                validated_params["service_id"], operation_params
            )

            if not is_new_operation:
                return

            params_prepared, secure_params = _prepare_secure_parameters(validated_params)
            if not params_prepared or secure_params is None:
                if idempotency_key:
                    IdempotencyManager.clear(idempotency_key)
                return

            safe_log_ctx["parameter_hash"] = secure_params.parameter_hash[:16]

        # Step 6: Schedule async provisioning task (outside transaction to avoid deadlock)
        task_scheduled, task_id = _schedule_provisioning_task(secure_params, validated_params)
        if not task_scheduled or task_id is None:
            if idempotency_key:
                IdempotencyManager.clear(idempotency_key)
            return

        safe_log_ctx["task_id"] = task_id

        # Step 7: Update idempotency with task ID
        if idempotency_key:
            IdempotencyManager.complete(
                idempotency_key, {"status": "scheduled", "task_id": task_id, "scheduled_at": timezone.now().isoformat()}
            )

        # Step 8: Secure audit logging
        assert secure_params is not None  # We checked earlier and returned if None
        audit_data = {
            "domain": validated_params["domain"],
            "task_id": task_id,
            "service_id": validated_params["service_id"],
            "idempotency_key": idempotency_key,
            "parameter_hash": secure_params.parameter_hash,
            "correlation_id": correlation_id,
        }
        _log_audit_event(service, audit_data)

        # Success logging
        logger.info(
            f"🚀 [AutoProvisioning] Scheduled secure VirtualMin provisioning: {sanitize_log_parameters(safe_log_ctx)}"
        )

    except Exception as e:
        error_type = ProvisioningErrorClassifier.classify_error(str(e))

        logger.error(f"🔥 [AutoProvisioning] Critical error in secure provisioning: {e}")

        # Log security event for critical errors
        log_security_event_safe(
            "virtualmin_auto_provisioning_critical_error",
            {
                "error": str(e),
                "error_type": error_type.value,
                "context": safe_log_ctx,
            },
            service_id_str,
        )

        # Clear any partial idempotency state
        if "idempotency_key" in locals() and idempotency_key:
            IdempotencyManager.clear(idempotency_key)
