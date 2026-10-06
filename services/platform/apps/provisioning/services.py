"""
Provisioning services backward compatibility layer.
Re-exports all service classes for existing imports.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any, Final

from django.db import transaction as db_transaction
from django.utils import timezone
from django.utils.translation import gettext as _

from apps.common.types import Err, Ok, Result

from .provisioning_service import ProvisioningService

if TYPE_CHECKING:
    from apps.customers.models import Customer

    from .service_models import Service
    from .virtualmin_models import VirtualminAccount

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
        from apps.provisioning.models import (  # noqa: PLC0415  # Deferred: avoids circular import
            Service,  # Circular: same-app  # Deferred: avoids circular import
        )

        if action not in ServiceGroupService.VALID_GROUP_ACTIONS:
            return Err(f"Invalid group action '{action}'. Valid: {ServiceGroupService.VALID_GROUP_ACTIONS}")

        try:
            services = Service.objects.filter(customer_id=group_id)
            if not services.exists():
                return Err(f"No services found for group {group_id}")

            results: dict[str, Any] = {"total": services.count(), "processed": 0, "errors": []}

            for service in services:
                try:
                    if action == "suspend_all":
                        service.suspend()
                        service.save(update_fields=["status", "suspended_at", "suspension_reason", "updated_at"])
                    elif action == "resume_all":
                        if service.status == "suspended":
                            service.activate()
                            service.save(
                                update_fields=[
                                    "status",
                                    "activated_at",
                                    "suspended_at",
                                    "suspension_reason",
                                    "updated_at",
                                ]
                            )
                    elif action in ("check_all", "sync_status"):
                        pass  # Just checking status

                    results["processed"] += 1

                except Exception as e:
                    results["errors"].append({"service_id": str(service.id), "error": str(e)})

            logger.info(
                f"⚙️ [ServiceGroup] {action} completed for group {group_id}: "
                f"{results['processed']}/{results['total']} services"
            )

            return Ok(
                {
                    "group_id": group_id,
                    "action": action,
                    "results": results,
                    "success": len(results["errors"]) == 0,
                }
            )

        except Exception as e:
            logger.error(f"🔥 [ServiceGroup] Failed to {action} group {group_id}: {e}")
            return Err(f"Failed to {action} group: {e}")


# The suspension_reason a staff Suspend writes, and the only one a staff Activate lifts.
# A machine token, matched like "payment_overdue" and "customer_suspended".
STAFF_ACCOUNT_SUSPENSION_REASON: Final = "staff_account_suspend"
# The provisioning pipeline owns these; an account only turns on when it completes.
_PIPELINE_OWNED_STATUSES: Final = frozenset({"pending", "provisioning", "failed"})
_INELIGIBLE_CUSTOMER_STATUSES: Final = frozenset({"suspended", "inactive"})


def _queue_reconcile_on_commit(service_id: Any) -> None:
    from apps.provisioning.virtualmin_tasks import (  # noqa: PLC0415  # Deferred: avoids circular import
        reconcile_virtualmin_service_state_async,  # Circular: same-app
    )

    sid = str(service_id)
    # robust: a lost enqueue must not fail the staff action; the divergence sweep re-finds it.
    db_transaction.on_commit(lambda: reconcile_virtualmin_service_state_async(sid), robust=True)


def _eligibility_refusal(service: Service, customer: Customer | None) -> str | None:
    """Why staff may not turn this service's hosting on, or None.

    Shared by every Activate path, including the one that only queues a reconcile for an
    already-active service. ``customer`` is the row the caller locked, read through
    ``all_objects``: the default manager hides soft-deleted customers, and a hidden row must
    not read as "no status" and pass. An unpaid subscription blocks it too, the same guard
    as the customer cascade's resume.
    """
    from apps.billing.subscription_models import Subscription  # noqa: PLC0415  # ADR-0007: cross-app
    from apps.customers.signals import (  # noqa: PLC0415  # ADR-0007: importing it registers receivers
        DELINQUENT_SUBSCRIPTION_STATES,
    )

    if customer is None or customer.deleted_at is not None:
        return str(_("The customer has been deleted; hosting stays off."))
    if customer.status in _INELIGIBLE_CUSTOMER_STATUSES:
        return str(_("The customer is {status}; reactivate the customer first.").format(status=customer.status))
    if Subscription.objects.filter(service_id=service.pk, status__in=DELINQUENT_SUBSCRIPTION_STATES).exists():
        return str(_("The service's subscription is not paid up; settle it in billing first."))
    return None


def _staff_resume_refusal(service: Service, customer: Customer | None) -> str | None:
    """Why staff may not resume this suspended Service from the account page, or None.

    Only a suspension staff made there can be lifted there; then the customer must be eligible.
    """
    if service.status != "suspended" or service.suspension_reason != STAFF_ACCOUNT_SUSPENSION_REASON:
        return str(
            _(
                "Service {name} is {status} by another process ({reason}); lift it from the "
                "service page, billing or the customer."
            ).format(name=service.service_name, status=service.status, reason=service.suspension_reason or "-")
        )
    return _eligibility_refusal(service, customer)


class HostingAccountStaffActions:
    """Staff Suspend and Activate for a hosting account, applied to its Service (#566, ADR-0051).

    The reconciler is the single writer of an account's enabled state, so these never call
    Virtualmin. Each one re-reads the Service under a row lock, checks every guard on that
    row, and either transitions it or queues a reconcile, in one short transaction.

    Activate also locks the customer row, before the Service: billing's customer → Service
    order, so there is no inversion. A customer suspension that has not committed waits for
    it; one that has is what the locked read sees. Without that lock the suspension could
    commit between the check and the resume, and its cascade, which selects only active
    services, would skip this one. The subscription stays a plain read: if billing marks it
    past due after the read, billing then waits on the Service lock, finds it active and
    suspends it.

    Returns ``Ok("queued")`` or ``Ok("resumed")``, or ``Err`` with a message for staff.
    """

    @staticmethod
    def suspend(account: VirtualminAccount) -> Result[str, str]:
        from apps.provisioning.models import Service  # noqa: PLC0415  # Circular: same-app

        with db_transaction.atomic():
            service = Service.objects.select_for_update(of=("self",)).filter(pk=account.service_id).first()
            if service is None:
                return Err(_("This account has no service."))
            if service.status in _PIPELINE_OWNED_STATUSES:
                return Err(
                    _("Service {name} is {status}; manage it from the service page.").format(
                        name=service.service_name, status=service.status
                    )
                )
            if service.status == "active":
                service.suspend(reason=STAFF_ACCOUNT_SUSPENSION_REASON)
                # The Service post_save receiver queues the reconcile that disables hosting.
                service.save(update_fields=["status", "suspended_at", "suspension_reason", "updated_at"])
                return Ok("queued")
            # Suspended, terminated or expired: hosting is already meant to be off. Converge.
            _queue_reconcile_on_commit(service.pk)
            return Ok("queued")

    @staticmethod
    def activate(account: VirtualminAccount) -> Result[str, str]:
        from apps.customers.models import Customer  # noqa: PLC0415  # ADR-0007: cross-app
        from apps.provisioning.domain_veto import domain_disables_hosting  # noqa: PLC0415  # Circular: same-app
        from apps.provisioning.models import Service  # noqa: PLC0415  # Circular: same-app

        # A service never changes customer, so reading the id before locking is safe.
        customer_id = Service.objects.filter(pk=account.service_id).values_list("customer_id", flat=True).first()
        with db_transaction.atomic():
            # Customer first, then Service (see the class docstring for why).
            customer = (
                Customer.all_objects.select_for_update().filter(pk=customer_id).first()
                if customer_id is not None
                else None
            )
            service = Service.objects.select_for_update(of=("self",)).filter(pk=account.service_id).first()
            if service is None:
                return Err(_("This account has no service."))

            if service.status == "active":
                if domain_disables_hosting(account):
                    return Err(
                        _(
                            "A domain bound to service {name} is expired, suspended or cancelled, "
                            "so its hosting stays off."
                        ).format(name=service.service_name)
                    )
                refusal = _eligibility_refusal(service, customer)
                if refusal is not None:
                    return Err(refusal)
                # Hosting should already be on; let the reconciler repair whatever is off.
                _queue_reconcile_on_commit(service.pk)
                return Ok("queued")

            refusal = _staff_resume_refusal(service, customer)
            if refusal is not None:
                return Err(refusal)

            service.activate()
            # The Service post_save receiver queues the reconcile that enables hosting.
            service.save(update_fields=["status", "activated_at", "suspended_at", "suspension_reason", "updated_at"])
            return Ok("resumed")


# Re-export for backward compatibility
__all__ = [
    "STAFF_ACCOUNT_SUSPENSION_REASON",
    "HostingAccountStaffActions",
    "ProvisioningService",
    "ServiceActivationService",  # Legacy name
    "ServiceGroupService",
    "ServiceManagementService",
    "logger",  # For test mocking compatibility
]
