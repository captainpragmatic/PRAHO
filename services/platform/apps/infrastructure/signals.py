"""
Infrastructure Signals

Django signals for automatic audit logging and event handling.
"""

from __future__ import annotations

import logging
from typing import Any

from django.db.models.signals import post_save, pre_save
from django.dispatch import receiver

from .audit_service import InfrastructureAuditContext, InfrastructureAuditService
from .models import CloudProvider, NodeDeployment, NodeRegion, NodeSize

logger = logging.getLogger(__name__)


# ===============================================================================
# NODE DEPLOYMENT SIGNALS
# ===============================================================================


@receiver(post_save, sender=NodeDeployment)
def node_deployment_post_save(
    sender: type[NodeDeployment],
    instance: NodeDeployment,
    created: bool,
    **kwargs: Any,
) -> None:
    """
    Handle NodeDeployment save events for audit logging.

    Logs deployment creation and status changes.
    """
    # Skip if signal disabled (for bulk operations)
    if getattr(instance, "_skip_signals", False):
        return

    if created:
        # Log new deployment creation
        InfrastructureAuditService.log_deployment_created(
            deployment=instance,
            context=InfrastructureAuditContext(
                user=instance.initiated_by,
                metadata={"signal": "post_save", "created": True},
            ),
        )
        logger.info(f"[Signal] NodeDeployment created: {instance.hostname}")


@receiver(pre_save, sender=NodeDeployment)
def node_deployment_pre_save(
    sender: type[NodeDeployment],
    instance: NodeDeployment,
    **kwargs: Any,
) -> None:
    """
    Track status changes before save for audit trail.

    Stores the previous status for comparison in post_save.
    """
    if instance.pk:
        try:
            old_instance = NodeDeployment.objects.get(pk=instance.pk)
            instance._previous_status = old_instance.status
        except NodeDeployment.DoesNotExist:
            instance._previous_status = None
    else:
        instance._previous_status = None


# ===============================================================================
# CLOUD PROVIDER SIGNALS
# ===============================================================================


@receiver(post_save, sender=CloudProvider)
def cloud_provider_post_save(
    sender: type[CloudProvider],
    instance: CloudProvider,
    created: bool,
    **kwargs: Any,
) -> None:
    """
    Handle CloudProvider save events for audit logging.
    """
    if getattr(instance, "_skip_signals", False):
        return

    if created:
        InfrastructureAuditService.log_provider_created(
            provider=instance,
            context=InfrastructureAuditContext(
                metadata={"signal": "post_save", "created": True},
            ),
        )
        logger.info(f"[Signal] CloudProvider created: {instance.name}")
    elif hasattr(instance, "_old_values"):
        InfrastructureAuditService.log_provider_updated(
            provider=instance,
            old_values=instance._old_values,
            context=InfrastructureAuditContext(
                metadata={"signal": "post_save"},
            ),
        )
        logger.info(f"[Signal] CloudProvider updated: {instance.name}")


@receiver(pre_save, sender=CloudProvider)
def cloud_provider_pre_save(
    sender: type[CloudProvider],
    instance: CloudProvider,
    **kwargs: Any,
) -> None:
    """
    Store old values before save for audit comparison.
    """
    if instance.pk:
        try:
            old_instance = CloudProvider.objects.get(pk=instance.pk)
            instance._old_values = {
                "name": old_instance.name,
                "code": old_instance.code,
                "provider_type": old_instance.provider_type,
                "is_active": old_instance.is_active,
            }
        except CloudProvider.DoesNotExist:
            pass


# ===============================================================================
# NODE SIZE SIGNALS
# ===============================================================================


@receiver(post_save, sender=NodeSize)
def node_size_post_save(
    sender: type[NodeSize],
    instance: NodeSize,
    created: bool,
    **kwargs: Any,
) -> None:
    """
    Handle NodeSize save events for audit logging.
    """
    if getattr(instance, "_skip_signals", False):
        return

    if created:
        InfrastructureAuditService.log_size_created(
            size=instance,
            context=InfrastructureAuditContext(
                metadata={"signal": "post_save", "created": True},
            ),
        )
        logger.info(f"[Signal] NodeSize created: {instance.name}")
    elif hasattr(instance, "_old_values"):
        InfrastructureAuditService.log_size_updated(
            size=instance,
            old_values=instance._old_values,
            context=InfrastructureAuditContext(
                metadata={"signal": "post_save"},
            ),
        )
        logger.info(f"[Signal] NodeSize updated: {instance.name}")


@receiver(pre_save, sender=NodeSize)
def node_size_pre_save(
    sender: type[NodeSize],
    instance: NodeSize,
    **kwargs: Any,
) -> None:
    """
    Store old values before save for audit comparison.
    """
    if instance.pk:
        try:
            old_instance = NodeSize.objects.get(pk=instance.pk)
            instance._old_values = {
                "name": old_instance.name,
                "vcpus": old_instance.vcpus,
                "memory_gb": old_instance.memory_gb,
                "disk_gb": old_instance.disk_gb,
                "monthly_cost_eur": str(old_instance.monthly_cost_eur),
                "is_active": old_instance.is_active,
            }
        except NodeSize.DoesNotExist:
            pass


# ===============================================================================
# NODE REGION SIGNALS
# ===============================================================================


@receiver(post_save, sender=NodeRegion)
def node_region_post_save(
    sender: type[NodeRegion],
    instance: NodeRegion,
    created: bool,
    **kwargs: Any,
) -> None:
    """
    Handle NodeRegion save events for audit logging.

    Only logs when is_active status changes.
    """
    if getattr(instance, "_skip_signals", False):
        return

    # Log region toggle if is_active changed
    if hasattr(instance, "_previous_is_active") and instance._previous_is_active != instance.is_active:
        InfrastructureAuditService.log_region_toggled(
            region=instance,
            context=InfrastructureAuditContext(
                metadata={"signal": "post_save"},
            ),
        )
        action = "enabled" if instance.is_active else "disabled"
        logger.info(f"[Signal] NodeRegion {action}: {instance.name}")


@receiver(pre_save, sender=NodeRegion)
def node_region_pre_save(
    sender: type[NodeRegion],
    instance: NodeRegion,
    **kwargs: Any,
) -> None:
    """
    Store previous is_active state for toggle detection.
    """
    if instance.pk:
        try:
            old_instance = NodeRegion.objects.get(pk=instance.pk)
            instance._previous_is_active = old_instance.is_active
        except NodeRegion.DoesNotExist:
            pass
