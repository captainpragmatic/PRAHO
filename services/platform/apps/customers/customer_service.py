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
        from .customer_models import Customer  # noqa: PLC0415  # Deferred: avoids circular import

        if user.is_staff_user:
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
        from .customer_models import Customer  # noqa: PLC0415  # Deferred: avoids circular import

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

    # Explicit allowlist of fields that can be updated via update_customer()
    UPDATABLE_FIELDS = frozenset(
        {
            "name",
            "company_name",
            "customer_type",
            "primary_email",
            "primary_phone",
            "industry",
            "website",
            "status",
            "assigned_account_manager",
            "data_processing_consent",
            "marketing_consent",
        }
    )

    @staticmethod
    def update_customer(customer: Customer, user: User, **updates: Any) -> Customer:
        """Update customer with audit logging. Only allows safe fields via UPDATABLE_FIELDS."""
        # Filter to allowed fields only
        safe_updates = {k: v for k, v in updates.items() if k in CustomerService.UPDATABLE_FIELDS}
        rejected = set(updates.keys()) - CustomerService.UPDATABLE_FIELDS
        if rejected:
            logger.warning(
                f"⚠️ [Customer] Rejected non-updatable fields: {rejected}",
                extra={"customer_id": customer.id, "user_id": user.id, "rejected_fields": list(rejected)},
            )

        logger.info(
            f"📝 [Customer] Updating customer: {customer.name} (ID: {customer.id})",
            extra={
                "customer_id": customer.id,
                "user_id": user.id,
                "operation": "customer_update",
                "fields_updated": list(safe_updates.keys()),
            },
        )

        changed_fields = []
        for field, value in safe_updates.items():
            setattr(customer, field, value)
            changed_fields.append(field)

        if changed_fields:
            customer.save(update_fields=[*changed_fields, "updated_at"])
        return customer

    @staticmethod
    def search_customers(query: str, user: User) -> QuerySet[Customer]:
        """Search customers accessible to the user."""
        accessible_customers = CustomerService.get_accessible_customers(user)

        if not query.strip():
            return accessible_customers

        from apps.common.cui_validator import CUIValidator  # noqa: PLC0415

        # Search across name, company_name, email, and Romanian tax identifier (CUI). CUIs are
        # stored as digits, so "RO14399840" is searched as "14399840".
        return accessible_customers.filter(
            models.Q(name__icontains=query)
            | models.Q(company_name__icontains=query)
            | models.Q(primary_email__icontains=query)
            | models.Q(tax_profile__cui__icontains=CUIValidator.normalize(query.strip()))
        ).distinct()

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


def activate_customer_after_payment(customer_id: int, invoice_id: int) -> None:
    """Move a prospect to active, or an inactive customer back to active, after a paid invoice (ADR-0066).

    Runs after the payment commits, in its own transaction, and never raises: a failure here must not
    touch the payment, and only costs the label and its email, which staff can set from the customer
    page. A suspended or already active customer is left as it is. Running twice changes nothing.
    """
    from django.db import transaction  # noqa: PLC0415

    from .customer_models import Customer  # noqa: PLC0415

    try:
        with transaction.atomic():
            customer = Customer.objects.select_for_update(of=("self",)).filter(pk=customer_id).first()
            if customer is None or customer.status not in ("prospect", "inactive"):
                return
            old_status = customer.status
            if old_status == "prospect":
                customer.activate()
            else:
                customer.reactivate()
            customer.save(update_fields=["status", "updated_at"])
        logger.info(f"✅ [Customer] {customer_id} {old_status} → active after invoice {invoice_id} was paid")
    except Exception:
        logger.exception(f"🔥 [Customer] Could not activate customer {customer_id} after invoice {invoice_id}")
