"""
Customer management service layer.
Core customer CRUD operations and business logic.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any

from django.db import models

if TYPE_CHECKING:
    from django.db.models import QuerySet

    from apps.users.models import User

    from .customer_models import Customer

logger = logging.getLogger(__name__)


class CustomerService:
    """Service class for customer management operations."""

    @staticmethod
    def get_accessible_customers(user: User) -> QuerySet[Customer]:
        """Get customers accessible to the user based on their permissions."""
        # Late import to avoid circular dependencies
        from .customer_models import Customer  # noqa: PLC0415

        if user.is_staff:
            return Customer.objects.all()

        # Regular users can only access customers they are members of
        return Customer.objects.filter(memberships__user=user, memberships__is_active=True).distinct()

    @staticmethod
    def create_customer(
        user: User,
        name: str,
        customer_type: str = "individual",
        **kwargs: Any,
    ) -> Customer:
        """Create a new customer with proper validation."""
        # Late import to avoid circular dependencies
        from .customer_models import Customer  # noqa: PLC0415

        # Basic validation
        if not name.strip():
            raise ValueError("Customer name is required")

        # Create customer
        customer = Customer.objects.create(name=name.strip(), customer_type=customer_type, created_by=user, **kwargs)

        logger.info(
            f"✅ [Customer] Created customer: {customer.name} (ID: {customer.id})",
            extra={"customer_id": customer.id, "user_id": user.id, "operation": "customer_create"},
        )

        return customer

    @staticmethod
    def update_customer(customer: Customer, user: User, **updates: Any) -> Customer:
        """Update customer with audit logging."""
        # Log the update operation
        logger.info(
            f"📝 [Customer] Updating customer: {customer.name} (ID: {customer.id})",
            extra={
                "customer_id": customer.id,
                "user_id": user.id,
                "operation": "customer_update",
                "fields_updated": list(updates.keys()),
            },
        )

        for field, value in updates.items():
            if hasattr(customer, field):
                setattr(customer, field, value)

        customer.save()
        return customer

    @staticmethod
    def search_customers(query: str, user: User) -> QuerySet[Customer]:
        """Search customers accessible to the user."""
        accessible_customers = CustomerService.get_accessible_customers(user)

        if not query.strip():
            return accessible_customers

        # Simple search across name, company_name, and email
        return accessible_customers.filter(
            models.Q(name__icontains=query)
            | models.Q(company_name__icontains=query)
            | models.Q(primary_email__icontains=query)
        )

    @staticmethod
    def get_customer_summary(customer: Customer) -> dict[str, Any]:
        """Get customer summary information."""
        return {
            "id": customer.id,
            "name": customer.get_display_name(),
            "type": customer.customer_type,
            "status": customer.status,
            "email": customer.primary_email,
            "phone": customer.primary_phone,
            "created_at": customer.created_at,
            "has_tax_profile": customer.get_tax_profile() is not None,
            "has_billing_profile": customer.get_billing_profile() is not None,
            "address_count": customer.addresses.count(),
            "note_count": customer.notes.count(),
        }
