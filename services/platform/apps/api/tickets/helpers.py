"""Shared creation path for customer API tickets."""

from __future__ import annotations

from typing import TYPE_CHECKING

from apps.tickets.models import Ticket

if TYPE_CHECKING:
    from apps.customers.models import Customer
    from apps.provisioning.service_models import Service
    from apps.tickets.models import SupportCategory
    from apps.users.models import User


def create_customer_ticket(  # noqa: PLR0913 -- explicit ticket fields shared by both customer endpoints
    *,
    customer: Customer,
    created_by: User | None,
    title: str,
    description: str,
    priority: str = "normal",
    category: SupportCategory | None = None,
    related_service: Service | None = None,
    contact_email: str = "",
    contact_person: str = "",
    contact_phone: str = "",
) -> Ticket:
    """Create an API ticket with customer contact defaults and lifecycle auditing."""
    return Ticket.objects.create(
        customer=customer,
        source="api",
        created_by=created_by,
        title=title,
        description=description,
        priority=priority,
        category=category,
        related_service=related_service,
        contact_email=contact_email or customer.primary_email,
        contact_person=contact_person or customer.name,
        contact_phone=contact_phone,
    )
