"""
Provisioning services backward compatibility layer.
Re-exports all service classes for existing imports.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any

from apps.common.types import Err, Ok, Result

from .provisioning_service import ProvisioningService

if TYPE_CHECKING:
    from .models import Service

# Logger for backward compatibility with tests
logger = logging.getLogger(__name__)

# Backward compatibility alias
ServiceActivationService = ProvisioningService


class ServiceManagementService:
    """Service management functionality for controlling service state and reviews."""

    VALID_ACTIONS = ("start", "stop", "restart", "suspend", "resume", "check_status")

    @staticmethod
    def manage_service(service_id: str, action: str) -> Result[dict[str, Any], str]:
        """
        Manage a service with the specified action.

        Args:
            service_id: UUID of the service to manage
            action: One of 'start', 'stop', 'restart', 'suspend', 'resume', 'check_status'

        Returns:
            Result with operation details or error message
        """
        from apps.provisioning.models import Service  # noqa: PLC0415

        if action not in ServiceManagementService.VALID_ACTIONS:
            return Err(f"Invalid action '{action}'. Valid actions: {ServiceManagementService.VALID_ACTIONS}")

        try:
            service = Service.objects.get(id=service_id)
        except Service.DoesNotExist:
            return Err(f"Service {service_id} not found")

        try:
            previous_status = service.status

            if action == "start":
                service.status = "active"
                service.save(update_fields=["status", "updated_at"])
                logger.info(f"⚙️ [ServiceMgmt] Started service {service_id}")

            elif action == "stop":
                service.status = "stopped"
                service.save(update_fields=["status", "updated_at"])
                logger.info(f"⚙️ [ServiceMgmt] Stopped service {service_id}")

            elif action == "restart":
                service.status = "restarting"
                service.save(update_fields=["status", "updated_at"])
                service.status = "active"
                service.save(update_fields=["status", "updated_at"])
                logger.info(f"⚙️ [ServiceMgmt] Restarted service {service_id}")

            elif action == "suspend":
                service.status = "suspended"
                service.save(update_fields=["status", "updated_at"])
                logger.info(f"⚙️ [ServiceMgmt] Suspended service {service_id}")

            elif action == "resume":
                if service.status != "suspended":
                    return Err(f"Service {service_id} is not suspended")
                service.status = "active"
                service.save(update_fields=["status", "updated_at"])
                logger.info(f"⚙️ [ServiceMgmt] Resumed service {service_id}")

            elif action == "check_status":
                logger.info(f"⚙️ [ServiceMgmt] Status check for service {service_id}: {service.status}")

            return Ok({
                "service_id": str(service.id),
                "action": action,
                "previous_status": previous_status,
                "current_status": service.status,
                "success": True,
            })

        except Exception as e:
            logger.error(f"🔥 [ServiceMgmt] Failed to {action} service {service_id}: {e}")
            return Err(f"Failed to {action} service: {e}")

    @staticmethod
    def mark_service_for_review(service_id: str, reason: str = "") -> Result[dict[str, Any], str]:
        """
        Mark a service for manual review.

        Args:
            service_id: UUID of the service
            reason: Reason for review (e.g., 'unusual_activity', 'customer_request', 'billing_issue')

        Returns:
            Result with review details or error message
        """
        from django.utils import timezone  # noqa: PLC0415

        from apps.audit.services import AuditService  # noqa: PLC0415
        from apps.provisioning.models import Service  # noqa: PLC0415

        try:
            service = Service.objects.get(id=service_id)
        except Service.DoesNotExist:
            return Err(f"Service {service_id} not found")

        try:
            service.status = "pending_review"
            service.save(update_fields=["status", "updated_at"])

            AuditService.log_simple_event(
                event_type="service_marked_for_review",
                user=None,
                content_object=service,
                description=f"Service {service_id} marked for review: {reason or 'No reason specified'}",
                actor_type="system",
                metadata={
                    "service_id": str(service.id),
                    "reason": reason,
                    "marked_at": timezone.now().isoformat(),
                    "source_app": "provisioning",
                },
            )

            logger.info(f"⚠️ [ServiceMgmt] Marked service {service_id} for review: {reason}")
            return Ok({
                "service_id": str(service.id),
                "status": "pending_review",
                "reason": reason,
                "success": True,
            })

        except Exception as e:
            logger.error(f"🔥 [ServiceMgmt] Failed to mark service {service_id} for review: {e}")
            return Err(f"Failed to mark service for review: {e}")


class ServiceGroupService:
    """Service group management for batch operations on related services."""

    VALID_GROUP_ACTIONS = ("suspend_all", "resume_all", "check_all", "sync_status")

    @staticmethod
    def manage_group(group_id: str, action: str) -> Result[dict[str, Any], str]:
        """
        Manage a group of services with the specified action.

        Args:
            group_id: Customer ID or service group identifier
            action: One of 'suspend_all', 'resume_all', 'check_all', 'sync_status'

        Returns:
            Result with batch operation results or error message
        """
        from apps.provisioning.models import Service  # noqa: PLC0415

        if action not in ServiceGroupService.VALID_GROUP_ACTIONS:
            return Err(f"Invalid group action '{action}'. Valid: {ServiceGroupService.VALID_GROUP_ACTIONS}")

        try:
            services = Service.objects.filter(customer_id=group_id)
            if not services.exists():
                return Err(f"No services found for group {group_id}")

            results = {"total": services.count(), "processed": 0, "errors": []}

            for service in services:
                try:
                    if action == "suspend_all":
                        service.status = "suspended"
                        service.save(update_fields=["status", "updated_at"])
                    elif action == "resume_all":
                        if service.status == "suspended":
                            service.status = "active"
                            service.save(update_fields=["status", "updated_at"])
                    elif action in ("check_all", "sync_status"):
                        pass  # Just checking status

                    results["processed"] += 1

                except Exception as e:
                    results["errors"].append({"service_id": str(service.id), "error": str(e)})

            logger.info(
                f"⚙️ [ServiceGroup] {action} completed for group {group_id}: "
                f"{results['processed']}/{results['total']} services"
            )

            return Ok({
                "group_id": group_id,
                "action": action,
                "results": results,
                "success": len(results["errors"]) == 0,
            })

        except Exception as e:
            logger.error(f"🔥 [ServiceGroup] Failed to {action} group {group_id}: {e}")
            return Err(f"Failed to {action} group: {e}")


# Re-export for backward compatibility
__all__ = [
    "ProvisioningService",
    "ServiceActivationService",  # Legacy name
    "ServiceGroupService",
    "ServiceManagementService",
    "logger",  # For test mocking compatibility
]
