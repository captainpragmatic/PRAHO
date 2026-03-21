"""
Customer profile service layer.
Tax and billing profile management business logic.
"""

from __future__ import annotations

import logging
from decimal import Decimal
from typing import TYPE_CHECKING

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
        **kwargs: object,
    ) -> CustomerTaxProfile:
        """Create tax profile for customer."""

        from .profile_models import CustomerTaxProfile

        tax_profile, _ = CustomerTaxProfile.objects.update_or_create(
            customer=customer,
            defaults={"cui": cui, **kwargs},
        )

        logger.info(
            f"✅ [Profile] Created tax profile for customer: {customer.name}",
            extra={"customer_id": customer.id, "user_id": user.id, "operation": "tax_profile_create"},
        )

        return tax_profile

    @staticmethod
    def create_billing_profile(
        customer: Customer,
        user: User,
        **kwargs: object,
    ) -> CustomerBillingProfile:
        """Create billing profile for customer."""

        from .profile_models import CustomerBillingProfile

        billing_profile, _ = CustomerBillingProfile.objects.update_or_create(
            customer=customer,
            defaults=kwargs,
        )

        logger.info(
            f"✅ [Profile] Created billing profile for customer: {customer.name}",
            extra={"customer_id": customer.id, "user_id": user.id, "operation": "billing_profile_create"},
        )

        return billing_profile

    TAX_PROFILE_UPDATABLE_FIELDS = frozenset(
        {
            "cui",
            "cnp",
            "registration_number",
            "is_vat_payer",
            "vat_number",
            "vat_rate",
            "reverse_charge_eligible",
        }
    )

    BILLING_PROFILE_UPDATABLE_FIELDS = frozenset(
        {
            "payment_terms",
            "credit_limit",
            "preferred_currency",
            "auto_payment_enabled",
        }
    )

    @staticmethod
    def update_tax_profile(
        tax_profile: CustomerTaxProfile,
        user: User,
        **updates: object,
    ) -> CustomerTaxProfile:
        """Update tax profile with validation. Only allows safe fields."""
        safe_updates = {k: v for k, v in updates.items() if k in ProfileService.TAX_PROFILE_UPDATABLE_FIELDS}

        changed_fields: list[str] = []

        if "cui" in safe_updates:
            new_cui = safe_updates.pop("cui")
            if not isinstance(new_cui, str):
                raise ValueError("CUI must be a string")
            from apps.common.cui_validator import CUIValidator

            result = CUIValidator.validate_strict(new_cui)
            if not result.is_valid:
                raise ValueError(f"Invalid CUI format: {result.error_message}")
            tax_profile.cui = new_cui
            changed_fields.append("cui")

        for field, value in safe_updates.items():
            setattr(tax_profile, field, value)
            changed_fields.append(field)

        if changed_fields:
            tax_profile.save(update_fields=[*changed_fields, "updated_at"])

        logger.info(
            f"📝 [Profile] Updated tax profile for customer: {tax_profile.customer.name}",
            extra={"customer_id": tax_profile.customer.id, "user_id": user.id, "operation": "tax_profile_update"},
        )

        return tax_profile

    @staticmethod
    def update_billing_profile(
        billing_profile: CustomerBillingProfile,
        user: User,
        **updates: object,
    ) -> CustomerBillingProfile:
        """Update billing profile. Only allows safe fields."""
        safe_updates = {k: v for k, v in updates.items() if k in ProfileService.BILLING_PROFILE_UPDATABLE_FIELDS}

        changed_fields = []
        for field, value in safe_updates.items():
            setattr(billing_profile, field, value)
            changed_fields.append(field)

        if changed_fields:
            billing_profile.save(update_fields=[*changed_fields, "updated_at"])

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
    def validate_tax_compliance(customer: Customer) -> dict[str, object]:
        """Validate customer tax compliance status."""
        tax_profile = customer.get_tax_profile()

        compliance_status: dict[str, object] = {
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
