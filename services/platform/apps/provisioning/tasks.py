"""
Provisioning background tasks using Django-Q2
Handles service provisioning, monitoring, and maintenance tasks
"""

from __future__ import annotations

import logging
from typing import Any

from django.utils import timezone
from django_q.tasks import async_task

from .models import Service
from .provisioning_service import ProvisioningService

logger = logging.getLogger(__name__)


def provision_service_task(service_id: int, **kwargs: Any) -> dict[str, Any]:
    """
    Background task to provision a service.
    This runs asynchronously in Django-Q2 queue.
    """
    try:
        logger.info(f"🚀 [Provisioning Task] Starting provisioning for service {service_id}")

        # Get the service
        try:
            service = Service.objects.get(id=service_id)
        except Service.DoesNotExist:
            error_msg = f"Service {service_id} not found"
            logger.error(f"❌ [Provisioning Task] {error_msg}")
            return {"status": "error", "error": error_msg}

        # Call the provisioning service
        result = ProvisioningService.provision_service(service)

        logger.info(f"✅ [Provisioning Task] Completed for service {service_id}: {result.get('status')}")
        return result

    except Exception as e:
        error_msg = f"Task failed for service {service_id}: {e}"
        logger.error(f"🔥 [Provisioning Task] {error_msg}")

        # Try to update service status to failed if we can access it
        try:
            service = Service.objects.get(id=service_id)
            service.status = "failed"
            service.last_provisioning_attempt = timezone.now()
            service.provisioning_errors = error_msg
            service.save(update_fields=["status", "last_provisioning_attempt", "provisioning_errors"])
        except Exception as save_error:
            logger.error(f"🔥 [Provisioning Task] Could not update service status: {save_error}")

        return {"status": "error", "error": error_msg}


def queue_service_provisioning(service: Service, delay_seconds: int = 0) -> str:
    """
    Queue a service for provisioning.
    Returns the task ID.
    """
    logger.info(f"📋 [Queue] Queueing provisioning for service {service.id} ({service.service_name})")

    # Set service status to pending if not already set
    if service.status not in ["provisioning", "active", "failed"]:
        service.status = "pending"
        service.save(update_fields=["status"])

    # Queue the task
    task_id = async_task(
        "apps.provisioning.tasks.provision_service_task",
        service.id,
        hook="apps.provisioning.tasks.provisioning_complete_hook",
        timeout=300,  # 5 minutes timeout
        retry=2,  # Retry up to 2 times
        sync=False,  # Always async
    )

    # Store task ID for tracking
    service.provisioning_task_id = task_id
    service.save(update_fields=["provisioning_task_id"])

    logger.info(f"📋 [Queue] Service {service.id} queued with task ID: {task_id}")
    return str(task_id)


def provisioning_complete_hook(task: object) -> None:
    """
    Hook called when provisioning task completes (success or failure).
    """
    try:
        service_id = task.args[0] if task.args else None
        if not service_id:
            logger.warning("🔔 [Hook] Provisioning complete hook called without service ID")
            return

        if task.success:
            logger.info(f"🎉 [Hook] Provisioning completed successfully for service {service_id}")
        else:
            logger.error(f"💥 [Hook] Provisioning failed for service {service_id}: {task.result}")

    except Exception as e:
        logger.error(f"🔥 [Hook] Error in provisioning complete hook: {e}")


def retry_failed_provisioning(service_id: int) -> str:
    """
    Retry provisioning for a failed service.
    """
    try:
        service = Service.objects.get(id=service_id)

        if service.status != "failed":
            raise ValueError(f"Service {service_id} is not in failed status (current: {service.status})")

        logger.info(f"🔄 [Retry] Retrying provisioning for service {service_id}")

        # Clear previous errors and reset status
        service.provisioning_errors = ""
        service.status = "pending"
        service.save(update_fields=["provisioning_errors", "status"])

        # Queue for provisioning
        return queue_service_provisioning(service)

    except Service.DoesNotExist:
        error_msg = f"Service {service_id} not found"
        logger.error(f"❌ [Retry] {error_msg}")
        raise
