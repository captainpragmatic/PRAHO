"""Persist submissions and staff decisions without applying hosting or billing changes."""

from __future__ import annotations

from typing import TYPE_CHECKING, TypedDict
from uuid import UUID

from django.db import IntegrityError, transaction
from django.utils import timezone
from django.utils.translation import gettext as _
from django_fsm import TransitionNotAllowed

from .service_models import Service
from .service_request_models import SERVICE_REQUEST_NOTE_LIMIT, ServiceRequest

if TYPE_CHECKING:
    from apps.customers.models import Customer
    from apps.tickets.models import Ticket
    from apps.users.models import User


class ServiceRequestError(ValueError):
    def __init__(self, message: str, status_code: int = 400) -> None:
        super().__init__(message)
        self.status_code = status_code


class ServiceRequestReceipt(TypedDict):
    request_id: str
    ticket_id: int
    ticket_number: str


def _receipt(item: ServiceRequest) -> ServiceRequestReceipt:
    # This receipt is also returned on retries after private staff review.
    return {"request_id": str(item.pk), "ticket_id": item.ticket_id, "ticket_number": item.ticket.ticket_number}


def _check_duplicate(item: ServiceRequest, service_id: int, action: str, reason: str) -> ServiceRequestReceipt:
    if (item.service_id, item.action, item.reason) != (service_id, action, reason):
        raise ServiceRequestError(_("This submission was already used for a different request."), 409)
    return _receipt(item)


@transaction.atomic
def submit_service_request(  # noqa: PLR0913 -- immutable submission identity
    *,
    customer: Customer,
    user: User,
    service_id: int,
    action: str,
    reason: str,
    submission_id: UUID,
) -> tuple[ServiceRequestReceipt, bool]:
    from apps.audit.services import AuditService  # noqa: PLC0415 -- cross-app service
    from apps.tickets.models import SupportCategory  # noqa: PLC0415 -- cross-app model
    from apps.tickets.services import TicketStatusService  # noqa: PLC0415 -- cross-app service
    from apps.users.models import CustomerMembership  # noqa: PLC0415 -- cross-app model

    allowed_roles = (
        ["owner", "billing"]
        if action in [ServiceRequest.Action.SUSPEND, ServiceRequest.Action.CANCEL]
        else ["owner", "billing", "tech"]
    )
    if not CustomerMembership.objects.filter(
        customer=customer, user=user, is_active=True, role__in=allowed_roles, user__is_active=True
    ).exists():
        raise ServiceRequestError(_("Access denied."), 403)
    try:
        service = Service.objects.select_for_update(of=("self",)).get(pk=service_id, customer=customer)
    except Service.DoesNotExist as exc:
        raise ServiceRequestError(_("Service not found or access denied."), 404) from exc
    scope = {"customer": customer, "requested_by": user, "submission_id": submission_id}
    existing = ServiceRequest.objects.select_related("ticket").filter(**scope).first()
    if existing:
        return _check_duplicate(existing, service_id, action, reason), False
    if service.status not in ["active", "suspended"]:
        raise ServiceRequestError(_("Requests are available for active or suspended services."))
    if action not in ServiceRequest.Action.values or len(reason) > SERVICE_REQUEST_NOTE_LIMIT:
        raise ServiceRequestError(_("Invalid service request."))
    if action in [ServiceRequest.Action.SUSPEND, ServiceRequest.Action.CANCEL] and not reason.strip():
        raise ServiceRequestError(_("A reason is required for this request."))
    try:
        # Roll back both rows if another service submission races for this UUID.
        with transaction.atomic():
            label = ServiceRequest.Action(action).label
            category, _created = SupportCategory.objects.get_or_create(
                name="Service Requests",
                defaults={
                    "name_en": "Service Requests",
                    "description": "Customer requests to upgrade, downgrade, suspend or cancel a service",
                    "icon": "server",
                    "color": "#6366F1",
                },
            )
            ticket = TicketStatusService.create_ticket(
                customer=customer,
                related_service=service,
                created_by=user,
                source="api",
                category=category,
                priority="high" if action == ServiceRequest.Action.CANCEL else "normal",
                title=f"{label}: {service.service_name}"[:200],
                description=reason or label,
                contact_email=customer.primary_email,
                contact_person=customer.name[:100],
            )
            item = ServiceRequest.objects.create(ticket=ticket, service=service, action=action, reason=reason, **scope)
            AuditService.log_simple_event(
                "support_ticket_created",
                user=user,
                content_object=item,
                description="Customer service request submitted",
                metadata={"service_request_id": str(item.pk), "service_id": service.pk, "ticket_id": ticket.pk},
            )
    except IntegrityError:
        existing = ServiceRequest.objects.select_related("ticket").filter(**scope).first()
        if existing is None:
            raise
        return _check_duplicate(existing, service_id, action, reason), False
    return _receipt(item), True


@transaction.atomic
def review_service_request(
    *,
    ticket_id: int,
    staff: User,
    decision: str,
    expected_status: str,
    note: str = "",
) -> ServiceRequest:
    from apps.audit.services import AuditService  # noqa: PLC0415 -- cross-app service
    from apps.tickets.models import Ticket, TicketComment  # noqa: PLC0415 -- cross-app models

    if not staff.is_active or not staff.is_staff_user:
        raise ServiceRequestError(_("Staff privileges required."), 403)
    targets = {"approve": "approved", "reject": "rejected", "complete": "completed"}
    note = note.strip()
    if (
        decision not in targets
        or len(note) > SERVICE_REQUEST_NOTE_LIMIT
        or (decision in ["reject", "complete"] and not note)
    ):
        raise ServiceRequestError(_("Provide a valid decision and a note for rejection or completion."))
    # Keep this ordering consistent with ticket replies and inactivity closure.
    ticket = Ticket.objects.select_for_update(of=("self",)).get(pk=ticket_id)
    try:
        item = ServiceRequest.objects.select_for_update(of=("self",)).get(ticket=ticket)
    except ServiceRequest.DoesNotExist as exc:
        raise ServiceRequestError(_("Service request not found."), 404) from exc
    if item.status == targets[decision]:
        actor_id = item.completed_by_id if decision == "complete" else item.reviewed_by_id
        if (actor_id, item.last_decision_note, item.last_decision_from_status) == (staff.pk, note, expected_status):
            return item
        raise ServiceRequestError(_("A different staff decision was already recorded. Reload the ticket."), 409)
    if item.status != expected_status:
        raise ServiceRequestError(_("This request has already changed. Reload the ticket before reviewing it."), 409)
    previous = item.status
    try:
        getattr(item, decision)()
    except TransitionNotAllowed as exc:
        raise ServiceRequestError(
            _("This request has already changed. Reload the ticket before reviewing it."), 409
        ) from exc
    if decision == "complete":
        item.completed_by = staff
        item.completed_at = timezone.now()
    else:
        item.reviewed_by = staff
        item.reviewed_at = timezone.now()
    item.last_decision_note = note
    item.last_decision_from_status = previous
    item.save()
    TicketComment.objects.create(
        ticket=ticket,
        author=staff,
        content=f"{item.get_status_display()}\n{note}".strip(),
        comment_type="internal",
        is_public=False,
        reply_action="internal_note",
    )
    _update_ticket_after_review(ticket, staff, decision)
    AuditService.log_simple_event(
        "support_ticket_updated",
        user=staff,
        content_object=item,
        description="Staff reviewed a service request",
        old_values={"status": previous},
        new_values={"status": item.status},
        metadata={"ticket_id": ticket.pk, "service_id": item.service_id},
    )
    return item


def _update_ticket_after_review(ticket: Ticket, staff: User, decision: str) -> None:
    from apps.tickets.services import TicketStatusService  # noqa: PLC0415 -- cross-app service

    if decision == "approve":
        if ticket.status == "closed":
            TicketStatusService.reopen_ticket(ticket)
        if ticket.status != "in_progress":
            ticket.start_work()
        if ticket.assigned_to_id is None:
            ticket.assigned_to = staff
            ticket.assigned_at = timezone.now()
        ticket.save()
    elif ticket.status != "closed":
        TicketStatusService.close_ticket(ticket, "fixed" if decision == "complete" else "cancelled")
