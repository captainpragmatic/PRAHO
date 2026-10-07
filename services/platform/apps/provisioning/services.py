"""
Provisioning services backward compatibility layer.
Re-exports all service classes for existing imports.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any

from django.db import transaction as db_transaction
from django.utils import timezone

from apps.common.types import Err, Ok, Result

from .provisioning_service import ProvisioningService

if TYPE_CHECKING:
    pass

# Logger for backward compatibility with tests
logger = logging.getLogger(__name__)

# Backward compatibility alias
ServiceActivationService = ProvisioningService


class ServiceManagementService:
    """Service management functionality for controlling service state and reviews."""

    VALID_ACTIONS = ("start", "stop", "restart", "suspend", "resume", "check_status")

    @staticmethod
    def manage_service(service_id: str, action: str, reason: str = "") -> Result[dict[str, Any], str]:
        """
        Manage a service with the specified action.

        Args:
            service_id: UUID of the service to manage
            action: One of 'start', 'stop', 'restart', 'suspend', 'resume', 'check_status'
            reason: Recorded on the service when the action is 'suspend'; ignored otherwise

        Returns:
            Result with operation details or error message
        """
        from apps.provisioning.models import (  # noqa: PLC0415  # Deferred: avoids circular import
            Service,  # Circular: same-app  # Deferred: avoids circular import
        )

        if action not in ServiceManagementService.VALID_ACTIONS:
            return Err(f"Invalid action '{action}'. Valid actions: {ServiceManagementService.VALID_ACTIONS}")

        try:
            service = Service.objects.get(id=service_id)
        except Service.DoesNotExist:
            return Err(f"Service {service_id} not found")

        try:
            previous_status = service.status

            if action == "start":
                service.activate()
                service.save(
                    update_fields=["status", "activated_at", "suspended_at", "suspension_reason", "updated_at"]
                )
                logger.info(f"⚙️ [ServiceMgmt] Started service {service_id}")

            elif action == "stop":
                # "stop" maps to suspend — there is no terminal "stopped" state
                service.suspend(reason="manual_stop")
                service.save(update_fields=["status", "suspended_at", "suspension_reason", "updated_at"])
                logger.info(f"⚙️ [ServiceMgmt] Stopped (suspended) service {service_id}")

            elif action == "restart":
                # suspend then re-activate — atomic so partial failure doesn't leave service suspended
                with db_transaction.atomic():
                    service.suspend(reason="restart")
                    service.save(update_fields=["status", "suspended_at", "suspension_reason", "updated_at"])
                    service.activate()
                    service.save(
                        update_fields=["status", "activated_at", "suspended_at", "suspension_reason", "updated_at"]
                    )
                logger.info(f"⚙️ [ServiceMgmt] Restarted service {service_id}")

            elif action == "suspend":
                service.suspend(reason=reason)
                service.save(update_fields=["status", "suspended_at", "suspension_reason", "updated_at"])
                logger.info(f"⚙️ [ServiceMgmt] Suspended service {service_id}: {reason or 'no reason given'}")

            elif action == "resume":
                if service.status != "suspended":
                    return Err(f"Service {service_id} is not suspended")
                service.activate()
                service.save(
                    update_fields=["status", "activated_at", "suspended_at", "suspension_reason", "updated_at"]
                )
                logger.info(f"⚙️ [ServiceMgmt] Resumed service {service_id}")

            elif action == "check_status":
                logger.info(f"⚙️ [ServiceMgmt] Status check for service {service_id}: {service.status}")

            return Ok(
                {
                    "service_id": str(service.id),
                    "action": action,
                    "previous_status": previous_status,
                    "current_status": service.status,
                    "success": True,
                }
            )

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
        from apps.audit.services import (  # noqa: PLC0415  # Deferred: avoids circular import
            AuditService,  # Circular: cross-app  # Deferred: avoids circular import
        )
        from apps.provisioning.models import (  # noqa: PLC0415  # Deferred: avoids circular import
            Service,  # Circular: same-app  # Deferred: avoids circular import
        )

        try:
            service = Service.objects.get(id=service_id)
        except Service.DoesNotExist:
            return Err(f"Service {service_id} not found")

        try:
            # "pending_review" is not a formal FSM status; record the review request
            # in admin_notes and log an audit event without changing the FSM state.
            review_note = f"[REVIEW REQUESTED] {reason or 'No reason specified'}"
            service.admin_notes = f"{review_note}\n{service.admin_notes}".strip()
            service.save(update_fields=["admin_notes", "updated_at"])

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
            return Ok(
                {
                    "service_id": str(service.id),
                    "status": service.status,
                    "review_requested": True,
                    "reason": reason,
                    "success": True,
                }
            )

        except Exception as e:
            logger.error(f"🔥 [ServiceMgmt] Failed to mark service {service_id} for review: {e}")
            return Err(f"Failed to mark service for review: {e}")


# Re-export for backward compatibility
__all__ = [
    "ProvisioningService",
    "ServiceActivationService",  # Legacy name
    "ServiceManagementService",
    "logger",  # For test mocking compatibility
]
