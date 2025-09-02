"""
Customer contact models for PRAHO Platform  
Address, payment methods, and notes models for customer contact management.
"""

from __future__ import annotations

from typing import Any, ClassVar

from django.db import models
from django.utils.translation import gettext_lazy as _

from .customer_models import SoftDeleteModel, validate_bank_details


class CustomerAddress(SoftDeleteModel):
    """
    Customer addresses with versioning support.

    🚨 CASCADE: ON DELETE CASCADE from Customer
    """

    ADDRESS_TYPE_CHOICES: ClassVar[tuple[tuple[str, str], ...]] = (
        ("primary", "Adresa principală"),
        ("billing", "Adresa facturare"),
        ("delivery", "Adresa livrare"),
        ("legal", "Sediul social"),
    )

    customer = models.ForeignKey(
        "customers.Customer",
        on_delete=models.CASCADE,  # Delete addresses when customer deleted
        related_name="addresses",
    )

    address_type = models.CharField(max_length=20, choices=ADDRESS_TYPE_CHOICES, verbose_name="Tip adresă")

    # Address Fields
    address_line1 = models.CharField(max_length=200, verbose_name="Adresa 1")
    address_line2 = models.CharField(max_length=200, blank=True, verbose_name="Adresa 2")
    city = models.CharField(max_length=100, verbose_name="Oraș")
    county = models.CharField(max_length=100, verbose_name="Județ")
    postal_code = models.CharField(max_length=10, verbose_name="Cod poștal")
    country = models.CharField(max_length=100, default="România", verbose_name="Țara")

    # Versioning
    is_current = models.BooleanField(default=True, verbose_name="Adresa curentă")
    version = models.PositiveIntegerField(default=1, verbose_name="Versiune")

    # Validation
    is_validated = models.BooleanField(default=False, verbose_name="Validată")
    validated_at = models.DateTimeField(null=True, blank=True)

    # Audit
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = "customer_addresses"
        verbose_name = _("Customer Address")
        verbose_name_plural = _("Customer Addresses")
        unique_together: ClassVar[tuple[tuple[str, ...], ...]] = (("customer", "address_type", "is_current"),)
        indexes: ClassVar[tuple[models.Index, ...]] = (
            models.Index(fields=["customer", "address_type"]),
            models.Index(fields=["customer", "is_current"]),
            models.Index(fields=["postal_code"]),
        )

    def __str__(self) -> str:
        return f"{self.customer.get_display_name()} - {dict(self.ADDRESS_TYPE_CHOICES)[self.address_type]}"

    def get_full_address(self) -> str:
        """Get formatted address"""
        parts = [self.address_line1, self.address_line2, f"{self.city}, {self.county}", self.postal_code, self.country]
        return ", ".join(part for part in parts if part)


class CustomerPaymentMethod(SoftDeleteModel):
    """
    Customer payment methods (Stripe, bank transfer, etc.)

    🚨 CASCADE: ON DELETE CASCADE from Customer
    """

    METHOD_TYPE_CHOICES: ClassVar[tuple[tuple[str, str], ...]] = (
        ("stripe_card", "Card Stripe"),
        ("bank_transfer", "Transfer bancar"),
        ("cash", "Numerar"),
        ("other", "Altele"),
    )

    customer = models.ForeignKey(
        "customers.Customer",
        on_delete=models.CASCADE,  # Delete payment methods when customer deleted
        related_name="payment_methods",
    )

    method_type = models.CharField(max_length=20, choices=METHOD_TYPE_CHOICES, verbose_name="Tip metodă")

    # Stripe Integration
    stripe_customer_id = models.CharField(max_length=100, blank=True)
    stripe_payment_method_id = models.CharField(max_length=100, blank=True)

    # Display Information
    display_name = models.CharField(max_length=100, verbose_name="Nume afișaj")
    last_four = models.CharField(max_length=4, blank=True, verbose_name="Ultimele 4 cifre")

    # Status
    is_default = models.BooleanField(default=False, verbose_name="Implicit")
    is_active = models.BooleanField(default=True, verbose_name="Activ")

    # Bank Transfer Details (encrypted)
    bank_details = models.JSONField(blank=True, null=True, verbose_name="Detalii bancare")

    # Audit
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = "customer_payment_methods"
        verbose_name = _("Customer Payment Method")
        verbose_name_plural = _("Customer Payment Methods")
        indexes: ClassVar[tuple[models.Index, ...]] = (
            models.Index(fields=["customer", "is_default"]),
            models.Index(fields=["stripe_customer_id"]),
        )

    def __str__(self) -> str:
        return f"{self.customer.get_display_name()} - {self.display_name}"

    def save(self, *args: Any, **kwargs: Any) -> None:
        """Save with bank details validation and default method logic"""
        self.full_clean()
        
        # Handle default payment method logic
        if self.is_default:
            # Set all other payment methods for this customer to non-default
            CustomerPaymentMethod.objects.filter(
                customer=self.customer,
                is_default=True
            ).exclude(pk=self.pk).update(is_default=False)
        
        super().save(*args, **kwargs)

    def clean(self) -> None:
        """🔒 Enhanced bank details validation for security and compliance"""
        super().clean()
        if self.bank_details:
            # Security: Enhanced validation with our new secure function
            validate_bank_details(self.bank_details)

            # Additional validation with existing secure input validator
            from apps.common.validators import SecureInputValidator  # Avoid circular import  # noqa: PLC0415

            self.bank_details = SecureInputValidator.validate_bank_details_schema(self.bank_details)


class CustomerNote(SoftDeleteModel):
    """Customer interaction notes with soft delete"""

    NOTE_TYPE_CHOICES: ClassVar[tuple[tuple[str, str], ...]] = (
        ("general", "Generală"),
        ("call", "Apel telefonic"),
        ("email", "Email"),
        ("meeting", "Întâlnire"),
        ("complaint", "Reclamație"),
        ("compliment", "Compliment"),
    )

    customer = models.ForeignKey(
        "customers.Customer",
        on_delete=models.CASCADE,  # Delete notes when customer deleted
        related_name="notes",
    )

    note_type = models.CharField(max_length=20, choices=NOTE_TYPE_CHOICES, default="general", verbose_name="Tip notă")

    title = models.CharField(max_length=200, verbose_name="Titlu")
    content = models.TextField(verbose_name="Conținut")

    is_important = models.BooleanField(default=False, verbose_name="Important")
    is_private = models.BooleanField(default=False, verbose_name="Privat")

    created_at = models.DateTimeField(auto_now_add=True)
    created_by = models.ForeignKey(
        "users.User",
        on_delete=models.SET_NULL,  # Keep note when user deleted
        null=True,
        verbose_name="Creat de",
    )

    class Meta:
        db_table = "customer_notes"
        verbose_name = _("Customer Note")
        verbose_name_plural = _("Customer Notes")
        ordering: ClassVar[tuple[str, ...]] = ("-created_at",)
        indexes: ClassVar[tuple[models.Index, ...]] = (
            models.Index(fields=["customer", "-created_at"]),
            models.Index(fields=["is_important"]),
        )

    def __str__(self) -> str:
        return f"{self.title} - {self.customer.get_display_name()}"
