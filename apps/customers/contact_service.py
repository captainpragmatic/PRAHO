"""
Customer contact service layer.
Address, payment methods, and notes management business logic.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from django.db import models

if TYPE_CHECKING:
    from django.db.models import QuerySet

    from apps.users.models import User

    from .contact_models import CustomerAddress, CustomerNote, CustomerPaymentMethod
    from .customer_models import Customer

# Import at top level to fix PLC0415
from .contact_models import CustomerAddress, CustomerNote, CustomerPaymentMethod

logger = logging.getLogger(__name__)


@dataclass
class AddressData:
    """Data container for address creation."""
    address_type: str
    address_line1: str
    city: str
    county: str
    postal_code: str


class ContactService:
    """Service class for customer contact management."""

    @staticmethod
    def create_address(
        customer: Customer,
        user: User,
        address_data: AddressData,
        **kwargs: Any
    ) -> CustomerAddress:
        """Create customer address with versioning support."""
        # If creating a new current address of this type, mark existing ones as non-current
        if kwargs.get("is_current", True):
            CustomerAddress.objects.filter(
                customer=customer,
                address_type=address_data.address_type,
                is_current=True
            ).update(is_current=False)
            
            # Get the next version number
            last_version = CustomerAddress.objects.filter(
                customer=customer,
                address_type=address_data.address_type
            ).aggregate(models.Max("version"))["version__max"] or 0
            
            kwargs["version"] = last_version + 1
        
        address = CustomerAddress.objects.create(
            customer=customer,
            address_type=address_data.address_type,
            address_line1=address_data.address_line1,
            city=address_data.city,
            county=address_data.county,
            postal_code=address_data.postal_code,
            **kwargs
        )
        
        logger.info(
            f"✅ [Contact] Created address for customer: {customer.name}",
            extra={
                "customer_id": customer.id,
                "user_id": user.id,
                "address_type": address_data.address_type,
                "operation": "address_create"
            }
        )
        
        return address

    @staticmethod
    def create_payment_method(
        customer: Customer,
        user: User,
        method_type: str,
        display_name: str,
        **kwargs: Any
    ) -> CustomerPaymentMethod:
        """Create customer payment method."""
        
        payment_method = CustomerPaymentMethod.objects.create(
            customer=customer,
            method_type=method_type,
            display_name=display_name,
            **kwargs
        )
        
        logger.info(
            f"✅ [Contact] Created payment method for customer: {customer.name}",
            extra={
                "customer_id": customer.id,
                "user_id": user.id,
                "method_type": method_type,
                "operation": "payment_method_create"
            }
        )
        
        return payment_method

    @staticmethod
    def create_note(
        customer: Customer,
        user: User,
        title: str,
        content: str,
        note_type: str = "general",
        **kwargs: Any
    ) -> CustomerNote:
        """Create customer note."""
        
        note = CustomerNote.objects.create(
            customer=customer,
            created_by=user,
            title=title,
            content=content,
            note_type=note_type,
            **kwargs
        )
        
        logger.info(
            f"✅ [Contact] Created note for customer: {customer.name}",
            extra={
                "customer_id": customer.id,
                "user_id": user.id,
                "note_type": note_type,
                "operation": "note_create"
            }
        )
        
        return note

    @staticmethod
    def get_current_addresses(customer: Customer) -> QuerySet[CustomerAddress]:
        """Get all current addresses for customer."""
        return CustomerAddress.objects.filter(customer=customer, is_current=True)

    @staticmethod
    def get_active_payment_methods(customer: Customer) -> QuerySet[CustomerPaymentMethod]:
        """Get active payment methods for customer."""
        return CustomerPaymentMethod.objects.filter(customer=customer, is_active=True)

    @staticmethod
    def get_recent_notes(customer: Customer, limit: int = 10) -> QuerySet[CustomerNote]:
        """Get recent notes for customer."""
        return CustomerNote.objects.filter(customer=customer)[:limit]

    @staticmethod
    def set_default_payment_method(
        customer: Customer,
        payment_method: CustomerPaymentMethod,
        user: User
    ) -> CustomerPaymentMethod:
        """Set a payment method as default for customer."""
        # Remove default from other methods
        CustomerPaymentMethod.objects.filter(
            customer=customer,
            is_default=True
        ).update(is_default=False)
        
        # Set this method as default
        payment_method.is_default = True
        payment_method.save()
        
        logger.info(
            f"✅ [Contact] Set default payment method for customer: {customer.name}",
            extra={
                "customer_id": customer.id,
                "user_id": user.id,
                "payment_method_id": payment_method.id,
                "operation": "set_default_payment_method"
            }
        )
        
        return payment_method

    @staticmethod
    def validate_address_completeness(address: CustomerAddress) -> dict:
        """Validate address completeness and format."""
        validation_result = {
            "is_complete": True,
            "missing_fields": [],
            "warnings": []
        }
        
        required_fields = ["address_line1", "city", "county", "postal_code"]
        for field in required_fields:
            if not getattr(address, field, "").strip():
                validation_result["is_complete"] = False
                validation_result["missing_fields"].append(field)
        
        # Validate postal code format for Romania
        if address.country == "România" and address.postal_code and (not address.postal_code.isdigit() or len(address.postal_code) != 6):
            validation_result["warnings"].append("Romanian postal codes should be 6 digits")
        
        return validation_result
