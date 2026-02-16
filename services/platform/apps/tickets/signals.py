"""
Ticket lifecycle signals for PRAHO Platform
Focus on status transitions and audit logging without SLA complexity.
"""

import logging
from typing import Any

from django.db import models
from django.db.models.signals import post_save, pre_save
from django.dispatch import receiver

from apps.audit.services import AuditService, TicketsAuditService

from .models import Ticket

logger = logging.getLogger(__name__)


@receiver(pre_save, sender=Ticket)
def capture_ticket_status_change(sender: type[Ticket], instance: Ticket, **kwargs: Any) -> None:
    """
    Capture ticket status changes for audit logging.

    This pre_save signal captures the old status so we can compare it in post_save.
    """
    try:
        if instance.pk:
            # Get the old instance from database to compare status
            old_instance = Ticket.objects.get(pk=instance.pk)
            instance._old_status = old_instance.status
        else:
            # New ticket - no old status
            instance._old_status = None
    except Ticket.DoesNotExist:
        # Edge case: instance has PK but doesn't exist in DB
        instance._old_status = None
    except Exception as e:
        logger.error(f"🔥 [Tickets Signal] Failed to capture old status for ticket {instance.pk}: {e}")
        instance._old_status = None


@receiver(post_save, sender=Ticket)
def log_ticket_lifecycle_events(sender: type[Ticket], instance: Ticket, created: bool, **kwargs: Any) -> None:
    """
    Log ticket lifecycle events focusing on status transitions.

    Events tracked:
    - Ticket creation
    - Status changes
    - Customer service quality metrics
    """
    try:
        # Handle new ticket creation
        if created:
            _log_ticket_opened(instance)
            return

        # Handle status changes for existing tickets
        old_status = getattr(instance, "_old_status", None)
        if old_status and old_status != instance.status:
            _handle_status_change(instance, old_status, instance.status)

    except Exception as e:
        # Never let audit logging break ticket operations
        logger.error(f"🔥 [Tickets Signal] Failed to log ticket event for {instance.ticket_number}: {e}")


def _log_ticket_opened(ticket: Ticket) -> None:
    """Log ticket creation event"""
    try:
        TicketsAuditService.log_ticket_opened(
            ticket=ticket,
            sla_metadata={},  # Empty SLA metadata since we removed SLA system
            should_escalate=False,  # Default escalation
            romanian_business_context={
                "customer_cui": getattr(ticket.customer, "cui", None),
                "service_category": ticket.category.name if ticket.category else "General",
                "contact_language": "ro",  # Default to Romanian for local customers
            },
        )

        logger.info(f"✅ [Tickets] Opened ticket {ticket.ticket_number} for {ticket.customer}")

    except Exception as e:
        logger.error(f"🔥 [Tickets] Failed to log ticket opened: {e}")


def _handle_status_change(ticket: Ticket, old_status: str, new_status: str) -> None:
    """Handle status change events"""

    # Define open and closed status groups
    open_statuses = {"open", "in_progress", "waiting_on_customer"}
    closed_statuses = {"closed"}

    was_open = old_status in open_statuses
    is_closed = new_status in closed_statuses

    # Log ticket closure event
    if was_open and is_closed:
        _log_ticket_closed(ticket, old_status, new_status)

    # Log significant status changes
    elif old_status != new_status:
        _log_status_change(ticket, old_status, new_status)


def _log_ticket_closed(ticket: Ticket, old_status: str, new_status: str) -> None:
    """Log ticket closure with service metrics"""
    try:
        # Calculate customer service metrics
        service_metrics = _calculate_service_metrics(ticket)

        TicketsAuditService.log_ticket_closed(
            ticket=ticket,
            old_status=old_status,
            new_status=new_status,
            service_metrics=service_metrics,
            sla_performance={},  # Empty SLA performance since we removed SLA system
            romanian_compliance={
                "gdpr_compliant": True,  # All ticket handling is GDPR compliant
                "data_retention_applied": True,
                "customer_rights_respected": True,
            },
        )

        logger.info(f"✅ [Tickets] Closed ticket {ticket.ticket_number} with resolution: {ticket.resolution_code}")

    except Exception as e:
        logger.error(f"🔥 [Tickets] Failed to log ticket closure: {e}")


def _log_status_change(ticket: Ticket, old_status: str, new_status: str) -> None:
    """Log significant status changes to audit trail"""
    try:
        # Log meaningful status transitions
        significant_changes = {
            ("open", "in_progress"): "agent_started_work",
            ("in_progress", "waiting_on_customer"): "awaiting_customer_response",
            ("waiting_on_customer", "in_progress"): "customer_responded",
            ("waiting_on_customer", "open"): "customer_responded_unassigned",
        }

        change_key = (old_status, new_status)
        if change_key in significant_changes:
            event_type = significant_changes[change_key]
            logger.info(
                f"📝 [Tickets] Status change for {ticket.ticket_number}: {old_status} -> {new_status} ({event_type})"
            )

            AuditService.log_simple_event(
                event_type=f"ticket_status_{event_type}",
                user=ticket.assigned_to,
                content_object=ticket,
                description=f"Ticket {ticket.ticket_number} status: {old_status} -> {new_status}",
                old_values={"status": old_status},
                new_values={"status": new_status},
                metadata={
                    "ticket_number": ticket.ticket_number,
                    "customer_id": str(ticket.customer_id),
                    "transition_type": event_type,
                },
                actor_type="support_system",
            )

    except Exception as e:
        logger.error(f"🔥 [Tickets] Failed to log status change: {e}")


def _calculate_service_metrics(ticket: Ticket) -> dict[str, Any]:
    """Calculate customer service quality metrics"""

    # Count interactions (comments from support)
    support_comments = ticket.comments.filter(comment_type="support").count()
    customer_comments = ticket.comments.filter(comment_type="customer").count()

    # Calculate time tracking metrics
    total_time_spent = ticket.worklogs.aggregate(total=models.Sum("time_spent"))["total"] or 0

    # Service quality indicators
    service_metrics = {
        "support_interactions": support_comments,
        "customer_interactions": customer_comments,
        "interaction_ratio": support_comments / max(customer_comments, 1),
        "total_hours_worked": float(total_time_spent),
        "satisfaction_rating": ticket.satisfaction_rating,
        "was_escalated": ticket.is_escalated,
        "agent_assigned": ticket.assigned_to.get_full_name() if ticket.assigned_to else None,
        "attachments_count": ticket.attachments.count(),
        "resolution_code": ticket.resolution_code,
        "customer_replied_during_process": ticket.has_customer_replied,
    }

    return service_metrics
