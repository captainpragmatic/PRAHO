"""
Ticket Status Service for PRAHO Platform
Centralized state management for the 4-status ticket system.
"""

import logging
from typing import Any, ClassVar

from django.db.models import QuerySet
from django.utils import timezone

from apps.users.models import User

from .models import Ticket

logger = logging.getLogger(__name__)

# FSM transition dispatch map: new_status -> method_name on Ticket
_TICKET_TRANSITION_MAP: dict[str, str] = {
    "in_progress": "start_work",
    "waiting_on_customer": "wait_on_customer",
    "closed": "close",
    "open": "reopen",
}


class TicketStatusService:
    """
    Centralized service for managing ticket status transitions.

    Enforces business rules for the 4-status system:
    - open: Needs triage/first response
    - in_progress: Agent actively working/owning it
    - waiting_on_customer: Paused; waiting for customer input
    - closed: Final state with resolution code

    Status transitions are enforced by the FSMField on Ticket; this service
    adds business rules on top (auto-assignment, resolution code requirement, etc.).
    """

    # Status transition rules
    AUTO_ASSIGN_ACTIONS: ClassVar[list[str]] = ["reply", "reply_and_wait"]
    CUSTOMER_WAITING_ACTIONS: ClassVar[list[str]] = ["reply_and_wait"]
    CLOSING_ACTIONS: ClassVar[list[str]] = ["close_with_resolution"]

    @classmethod
    def create_ticket(cls, **ticket_data: Any) -> Ticket:
        """
        Create a new ticket with initial status.

        New tickets always start as 'open' and unassigned.
        """
        ticket_data["status"] = "open"
        ticket_data["assigned_to"] = None
        ticket_data["has_customer_replied"] = False

        ticket = Ticket.objects.create(**ticket_data)

        logger.info(f"✅ [TicketStatus] Created ticket {ticket.ticket_number} with status: open")
        return ticket

    @classmethod
    def handle_first_agent_reply(
        cls, ticket: Ticket, agent: User, reply_action: str, resolution_code: str | None = None
    ) -> Ticket:
        """
        Handle first agent reply with automatic assignment.

        Default behavior: Move to 'in_progress' and assign to replying agent.
        Agent can override with explicit actions.
        """
        if ticket.assigned_to is not None:
            logger.warning(
                f"⚠️ [TicketStatus] Ticket {ticket.ticket_number} already assigned, treating as subsequent reply"
            )
            return cls.handle_agent_reply(ticket, agent, reply_action, resolution_code)

        # Assign ticket to replying agent
        ticket.assigned_to = agent
        ticket.assigned_at = timezone.now()

        # Apply status transition based on reply action
        new_status = cls._determine_new_status_from_action(
            current_status=ticket.status, reply_action=reply_action, default="in_progress"
        )

        # Handle closing with resolution
        if reply_action in cls.CLOSING_ACTIONS:
            if not resolution_code:
                raise ValueError("Resolution code required when closing ticket")
            ticket.resolution_code = resolution_code
            # closed_at is set by the FSM close() transition side effect

        # Reset customer replied indicators when agent responds (except for internal notes)
        if reply_action != "internal_note":
            ticket.has_customer_replied = False
            ticket.customer_replied_at = None

        # Apply FSM transition (close() sets closed_at as side effect)
        if new_status != ticket.status:
            cls._apply_fsm_transition(ticket, new_status)
        ticket.save()

        logger.info(
            f"✅ [TicketStatus] First agent reply on {ticket.ticket_number}: {reply_action} -> {new_status}, assigned to {agent}"
        )
        return ticket

    @classmethod
    def handle_agent_reply(
        cls, ticket: Ticket, agent: User, reply_action: str, resolution_code: str | None = None
    ) -> Ticket:
        """
        Handle subsequent agent replies with explicit action selection.
        """
        current_status = ticket.status

        # Determine new status based on reply action
        if reply_action == "reply":
            # Continue working - keep in_progress (or move from waiting_on_customer)
            new_status = "in_progress" if current_status == "waiting_on_customer" else current_status

        elif reply_action == "reply_and_wait":
            # Explicit request for customer response
            new_status = "waiting_on_customer"

        elif reply_action == "internal_note":
            # No status change for internal notes
            new_status = current_status

        elif reply_action == "close_with_resolution":
            # Close ticket with resolution code
            if not resolution_code:
                raise ValueError("Resolution code required when closing ticket")
            new_status = "closed"
            ticket.resolution_code = resolution_code
            # closed_at is set by the FSM close() transition side effect

        else:
            raise ValueError(f"Invalid reply action: {reply_action}")

        # Apply FSM transition (close() sets closed_at as side effect)
        if new_status != current_status:
            cls._apply_fsm_transition(ticket, new_status)

        # Ensure ticket is assigned if agent is replying (but not for internal notes)
        if reply_action != "internal_note" and not ticket.assigned_to:
            ticket.assigned_to = agent
            ticket.assigned_at = timezone.now()

        # Reset customer replied indicators when agent responds (except for internal notes)
        if reply_action != "internal_note":
            ticket.has_customer_replied = False
            ticket.customer_replied_at = None

        ticket.save()

        logger.info(f"✅ [TicketStatus] Agent reply on {ticket.ticket_number}: {reply_action} -> {new_status}")
        return ticket

    @classmethod
    def handle_customer_reply(cls, ticket: Ticket) -> Ticket:
        """
        Handle customer reply with auto-transition logic.

        Rules:
        - If waiting_on_customer + assigned -> in_progress
        - If waiting_on_customer + unassigned -> open
        - Otherwise keep current status
        """
        current_status = ticket.status

        # Set customer reply flags
        ticket.has_customer_replied = True
        ticket.customer_replied_at = timezone.now()

        # Auto-transition logic
        if current_status == "waiting_on_customer":
            if ticket.assigned_to:
                ticket.start_work()
                logger.info(
                    f"📝 [TicketStatus] Customer replied to {ticket.ticket_number}: resuming work (assigned agent)"
                )
            else:
                ticket.back_to_queue()
                logger.info(f"📝 [TicketStatus] Customer replied to {ticket.ticket_number}: back to queue (unassigned)")

        else:
            # For other statuses, just log the customer reply
            logger.info(
                f"📝 [TicketStatus] Customer replied to {ticket.ticket_number}: status remains {current_status}"
            )

        ticket.save()
        return ticket

    @classmethod
    def close_ticket(cls, ticket: Ticket, resolution_code: str) -> Ticket:
        """
        Close ticket with resolution code.
        """
        if not resolution_code:
            raise ValueError("Resolution code is required when closing ticket")

        # close() FSM transition sets closed_at as a side effect
        ticket.close()
        ticket.resolution_code = resolution_code
        ticket.save()

        logger.info(f"✅ [TicketStatus] Closed ticket {ticket.ticket_number} with resolution: {resolution_code}")
        return ticket

    @classmethod
    def reopen_ticket(cls, ticket: Ticket) -> Ticket:
        """
        Reopen a closed ticket (customer reply within allowed timeframe).
        """
        if ticket.status != "closed":
            raise ValueError("Only closed tickets can be reopened")

        # reopen() FSM transition sets closed_at = None and goes to "open"
        ticket.reopen()
        ticket.resolution_code = ""
        ticket.has_customer_replied = False
        ticket.customer_replied_at = None

        # If assigned, immediately move to in_progress
        if ticket.assigned_to:
            ticket.start_work()

        ticket.save()

        logger.info(f"🔄 [TicketStatus] Reopened ticket {ticket.ticket_number} as {ticket.status}")
        return ticket

    @classmethod
    def _determine_new_status_from_action(cls, current_status: str, reply_action: str, default: str) -> str:
        """Determine new status based on reply action with fallback default."""
        if reply_action in cls.CUSTOMER_WAITING_ACTIONS:
            return "waiting_on_customer"
        elif reply_action in cls.CLOSING_ACTIONS:
            return "closed"
        elif reply_action == "internal_note":
            return current_status
        else:
            return default

    @staticmethod
    def _apply_fsm_transition(ticket: Ticket, new_status: str) -> None:
        """
        Apply the FSM transition for the given target status.

        django-fsm enforces valid transitions at the model level;
        invalid transitions raise TransitionNotAllowed.
        """
        transition_method_name = _TICKET_TRANSITION_MAP.get(new_status)
        if transition_method_name is None:
            raise ValueError(f"No FSM transition mapped for target status: {new_status}")
        getattr(ticket, transition_method_name)()

    @classmethod
    def get_allowed_transitions(cls, current_status: str) -> list[str]:
        """Get list of allowed status transitions for current status.

        Returns all mapped target statuses that differ from the current status.
        The FSMField on Ticket enforces actual validity at transition time.
        """
        return [target for target in _TICKET_TRANSITION_MAP if target != current_status]

    @classmethod
    def get_queue_tickets(cls, queue_type: str, assigned_to: User | None = None) -> QuerySet[Ticket]:
        """
        Get tickets for specific queues.

        Queue types:
        - inbox: Open + Unassigned
        - my_tickets: Assigned to specific user, any status except closed
        - waiting: Waiting on customer
        - closed: Recently closed tickets
        """
        base_query = Ticket.objects.select_related("customer", "assigned_to", "category")

        if queue_type == "inbox":
            return base_query.filter(status="open", assigned_to__isnull=True)

        elif queue_type == "my_tickets" and assigned_to:
            return base_query.filter(assigned_to=assigned_to).exclude(status="closed")

        elif queue_type == "waiting":
            return base_query.filter(status="waiting_on_customer")

        elif queue_type == "closed":
            return base_query.filter(status="closed").order_by("-closed_at")

        else:
            raise ValueError(f"Invalid queue type: {queue_type}")
