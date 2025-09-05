"""
Customer profile service layer.
Tax and billing profile management business logic.
"""

from __future__ import annotations

import logging
from decimal import Decimal
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from apps.users.models import User

    from .customer_models import Customer
    from .profile_models import CustomerBillingProfile, CustomerTaxProfile

logger = logging.getLogger(__name__)


class ProfileService:
    """Service class for customer profile management."""

    @staticmethod
    def create_tax_profile(
        customer: Customer,
        user: User,
        cui: str = "",
        **kwargs: Any,
    ) -> CustomerTaxProfile:
        """Create tax profile for customer."""

        from .profile_models import CustomerTaxProfile  # noqa: PLC0415

        tax_profile = CustomerTaxProfile.objects.create(customer=customer, cui=cui, **kwargs)  # type: ignore[misc]

        logger.info(
            f"✅ [Profile] Created tax profile for customer: {customer.name}",
            extra={"customer_id": customer.id, "user_id": user.id, "operation": "tax_profile_create"},
        )

        return tax_profile  # type: ignore[return-value]

    @staticmethod
    def create_billing_profile(
        customer: Customer,
        user: User,
        **kwargs: Any,
    ) -> CustomerBillingProfile:
        """Create billing profile for customer."""

        from .profile_models import CustomerBillingProfile  # noqa: PLC0415

        billing_profile = CustomerBillingProfile.objects.create(customer=customer, **kwargs)  # type: ignore[misc]

        logger.info(
            f"✅ [Profile] Created billing profile for customer: {customer.name}",
            extra={"customer_id": customer.id, "user_id": user.id, "operation": "billing_profile_create"},
        )

        return billing_profile  # type: ignore[return-value]

    @staticmethod
    def update_tax_profile(
        tax_profile: CustomerTaxProfile,
        user: User,
        **updates: Any,
    ) -> CustomerTaxProfile:
        """Update tax profile with validation."""
        # Validate CUI if provided
        if updates.get("cui") and not tax_profile.validate_cui():
            raise ValueError("Invalid CUI format")

        for field, value in updates.items():
            if hasattr(tax_profile, field):
                setattr(tax_profile, field, value)

        tax_profile.save()

        logger.info(
            f"📝 [Profile] Updated tax profile for customer: {tax_profile.customer.name}",
            extra={"customer_id": tax_profile.customer.id, "user_id": user.id, "operation": "tax_profile_update"},
        )

        return tax_profile

    @staticmethod
    def update_billing_profile(
        billing_profile: CustomerBillingProfile,
        user: User,
        **updates: Any,
    ) -> CustomerBillingProfile:
        """Update billing profile."""
        for field, value in updates.items():
            if hasattr(billing_profile, field):
                setattr(billing_profile, field, value)

        billing_profile.save()

        logger.info(
            f"📝 [Profile] Updated billing profile for customer: {billing_profile.customer.name}",
            extra={
                "customer_id": billing_profile.customer.id,
                "user_id": user.id,
                "operation": "billing_profile_update",
            },
        )

        return billing_profile

    @staticmethod
    def get_customer_account_balance(customer: Customer) -> Decimal:
        """Get customer's current account balance."""
        billing_profile = customer.get_billing_profile()
        if billing_profile:
            return billing_profile.get_account_balance()
        return Decimal("0.00")

    @staticmethod
    def validate_tax_compliance(customer: Customer) -> dict[str, Any]:
        """Validate customer tax compliance status."""
        tax_profile = customer.get_tax_profile()

        compliance_status = {
            "has_tax_profile": tax_profile is not None,
            "cui_valid": False,
            "vat_configured": False,
            "compliance_score": 0,
        }

        if tax_profile:
            compliance_status["cui_valid"] = tax_profile.validate_cui()
            compliance_status["vat_configured"] = bool(tax_profile.vat_number)

            # Calculate compliance score
            score = 0
            if compliance_status["cui_valid"]:
                score += 40
            if compliance_status["vat_configured"]:
                score += 30
            if tax_profile.registration_number:
                score += 30

            compliance_status["compliance_score"] = score

        return compliance_status
