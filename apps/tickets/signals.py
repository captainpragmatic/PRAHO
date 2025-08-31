"""
Streamlined ticket signals for PRAHO Platform
Focus ONLY on open/close events for SLA tracking and customer service compliance.
"""

import logging
from typing import Any

from django.db import models
from django.db.models.signals import post_save, pre_save
from django.dispatch import receiver
from django.utils import timezone

from apps.audit.services import TicketsAuditService

from .models import Ticket

logger = logging.getLogger(__name__)

# Business constants for Romanian customer service standards
SLA_COMPLIANCE_THRESHOLDS: dict[str, Any] = {
    "response_warning_hours": 20,  # Alert when 20/24 hours passed without response
    "resolution_warning_hours": 60,  # Alert when 60/72 hours passed without resolution
    "escalation_priority_levels": ["high", "urgent", "critical"],  # Auto-escalate these priorities
    "weekend_sla_adjustment_factor": 1.5,  # 50% longer SLA on weekends
}

# Romanian business hours constants
BUSINESS_HOURS: dict[str, int] = {
    "max_weekday": 5,  # Monday=0, Sunday=6 (so < 5 means weekday)
    "start_hour": 9,  # 9:00 AM
    "end_hour": 17,  # 5:00 PM (17:00)
}


@receiver(pre_save, sender=Ticket)
def capture_ticket_status_change(sender: type[Ticket], instance: Ticket, **kwargs: Any) -> None:
    """
    Capture ticket status changes to determine if this is an open/close event.

    This pre_save signal captures the old status so we can compare it in post_save.
    We only care about transitions that affect SLA tracking.
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
    Log ticket lifecycle events focusing on SLA-critical transitions.

    Events tracked:
    - Ticket creation (opened)
    - Status changes from open -> closed states
    - SLA breach warnings
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
    """Log ticket creation event with SLA setup"""
    try:
        # Calculate SLA compliance metadata
        sla_metadata = _calculate_sla_metadata(ticket)

        # Determine if auto-escalation should be applied
        escalation_priorities = SLA_COMPLIANCE_THRESHOLDS.get("escalation_priority_levels", [])
        should_escalate = ticket.priority in escalation_priorities

        TicketsAuditService.log_ticket_opened(
            ticket=ticket,
            sla_metadata=sla_metadata,
            should_escalate=should_escalate,
            romanian_business_context={
                "customer_cui": getattr(ticket.customer, "cui", None),
                "service_category": ticket.category.name if ticket.category else "General",
                "contact_language": "ro",  # Default to Romanian for local customers
                "business_hours": _is_business_hours(),
            },
        )

        logger.info(f"✅ [Tickets] Opened ticket {ticket.ticket_number} for {ticket.customer}")

    except Exception as e:
        logger.error(f"🔥 [Tickets] Failed to log ticket opened: {e}")


def _handle_status_change(ticket: Ticket, old_status: str, new_status: str) -> None:
    """Handle status change events with focus on SLA-critical transitions"""

    # Define open and closed status groups
    open_statuses = {"new", "open", "pending"}
    closed_statuses = {"resolved", "closed"}

    was_open = old_status in open_statuses
    is_closed = new_status in closed_statuses

    # Log ticket closure event
    if was_open and is_closed:
        _log_ticket_closed(ticket, old_status, new_status)

    # Log status changes that affect SLA (but don't close the ticket)
    elif old_status != new_status:
        _log_status_change(ticket, old_status, new_status)


def _log_ticket_closed(ticket: Ticket, old_status: str, new_status: str) -> None:
    """Log ticket closure with comprehensive SLA analysis"""
    try:
        # Set resolved_at if not already set
        if not ticket.resolved_at:
            ticket.resolved_at = timezone.now()
            ticket.save(update_fields=["resolved_at"])

        # Calculate SLA performance
        sla_performance = _calculate_sla_performance(ticket)

        # Calculate customer service metrics
        service_metrics = _calculate_service_metrics(ticket)

        TicketsAuditService.log_ticket_closed(
            ticket=ticket,
            old_status=old_status,
            new_status=new_status,
            sla_performance=sla_performance,
            service_metrics=service_metrics,
            romanian_compliance={
                "gdpr_compliant": True,  # All ticket handling is GDPR compliant
                "data_retention_applied": True,
                "customer_rights_respected": True,
            },
        )

        logger.info(f"✅ [Tickets] Closed ticket {ticket.ticket_number} - SLA: {sla_performance['overall_compliance']}")

    except Exception as e:
        logger.error(f"🔥 [Tickets] Failed to log ticket closure: {e}")


def _log_status_change(ticket: Ticket, old_status: str, new_status: str) -> None:
    """Log non-closure status changes that might affect SLA"""
    try:
        # Only log significant status changes that affect customer experience
        significant_changes = {
            ("new", "open"): "agent_assigned",
            ("open", "pending"): "waiting_customer_response",
            ("pending", "open"): "customer_responded",
        }

        change_key = (old_status, new_status)
        if change_key in significant_changes:
            logger.info(f"📝 [Tickets] Status change for {ticket.ticket_number}: {old_status} -> {new_status}")

    except Exception as e:
        logger.error(f"🔥 [Tickets] Failed to log status change: {e}")


def _calculate_sla_metadata(ticket: Ticket) -> dict[str, Any]:
    """Calculate SLA metadata for new ticket"""

    # Get SLA thresholds from category or use defaults
    response_hours = ticket.category.sla_response_hours if ticket.category else 24
    resolution_hours = ticket.category.sla_resolution_hours if ticket.category else 72

    # Adjust for weekends if needed
    if not _is_business_hours():
        adjustment_factor = SLA_COMPLIANCE_THRESHOLDS.get("weekend_sla_adjustment_factor", 1.5)
        response_hours = int(response_hours * adjustment_factor)
        resolution_hours = int(resolution_hours * adjustment_factor)

    return {
        "sla_response_deadline": ticket.sla_response_due.isoformat() if ticket.sla_response_due else None,
        "sla_resolution_deadline": ticket.sla_resolution_due.isoformat() if ticket.sla_resolution_due else None,
        "response_hours_allocated": response_hours,
        "resolution_hours_allocated": resolution_hours,
        "priority_level": ticket.priority,
        "category": ticket.category.name if ticket.category else None,
        "weekend_adjustment_applied": not _is_business_hours(),
        "escalation_eligible": ticket.priority in SLA_COMPLIANCE_THRESHOLDS.get("escalation_priority_levels", []),
    }


def _calculate_sla_performance(ticket: Ticket) -> dict[str, Any]:
    """Calculate comprehensive SLA performance metrics"""
    now = timezone.now()

    # Response SLA calculation
    response_compliant = True
    response_time_minutes = None
    if ticket.first_response_at and ticket.sla_response_due:
        response_time_minutes = int((ticket.first_response_at - ticket.created_at).total_seconds() / 60)
        response_compliant = ticket.first_response_at <= ticket.sla_response_due
    elif ticket.sla_response_due and not ticket.first_response_at:
        # No response yet, check if overdue
        response_compliant = now <= ticket.sla_response_due

    # Resolution SLA calculation
    resolution_compliant = True
    resolution_time_hours = None
    if ticket.resolved_at and ticket.sla_resolution_due:
        resolution_time_hours = (ticket.resolved_at - ticket.created_at).total_seconds() / 3600
        resolution_compliant = ticket.resolved_at <= ticket.sla_resolution_due
    elif ticket.sla_resolution_due and not ticket.resolved_at:
        # Just closed but no resolved_at set, check current time
        resolution_compliant = now <= ticket.sla_resolution_due
        if ticket.resolved_at:
            resolution_time_hours = (ticket.resolved_at - ticket.created_at).total_seconds() / 3600

    # Overall compliance
    overall_compliance = response_compliant and resolution_compliant

    return {
        "response_sla_met": response_compliant,
        "resolution_sla_met": resolution_compliant,
        "overall_compliance": overall_compliance,
        "response_time_minutes": response_time_minutes,
        "resolution_time_hours": resolution_time_hours,
        "sla_grade": "EXCELLENT" if overall_compliance else "BREACH",
        "customer_impact": "low" if overall_compliance else "medium",
    }


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
        "required_customer_response": ticket.requires_customer_response,
        "agent_assigned": ticket.assigned_to.get_full_name() if ticket.assigned_to else None,
        "attachments_count": ticket.attachments.count(),
    }

    return service_metrics


def _is_business_hours() -> bool:
    """Check if current time is within Romanian business hours"""
    now = timezone.now()

    # Convert to Bucharest time
    bucharest_tz = timezone.get_default_timezone()
    local_time = now.astimezone(bucharest_tz)

    # Romanian business hours: Monday-Friday, 9:00-17:00
    is_weekday = local_time.weekday() < BUSINESS_HOURS["max_weekday"]
    is_business_hour = BUSINESS_HOURS["start_hour"] <= local_time.hour < BUSINESS_HOURS["end_hour"]

    return is_weekday and is_business_hour
