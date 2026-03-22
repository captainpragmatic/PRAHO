"""
Customer contact models for PRAHO Platform
Address, payment methods, and notes models for customer contact management.
"""

from __future__ import annotations

from typing import Any, ClassVar

from django.db import models
from django.db import transaction as db_transaction
from django.db.models import Q, UniqueConstraint
from django.utils.translation import gettext_lazy as _

from apps.common.fields import EncryptedJSONField

from .customer_models import SoftDeleteModel, validate_bank_details


class CustomerAddress(SoftDeleteModel):
    """
    Customer addresses with versioning support.

    Each address can independently be flagged as the primary address and/or
    the billing address. The save() method enforces uniqueness automatically:
    setting is_primary=True clears the flag on all other active addresses,
    and likewise for is_billing=True.

    🚨 CASCADE: ON DELETE CASCADE from Customer
    """

    customer = models.ForeignKey(
        "customers.Customer",
        on_delete=models.CASCADE,  # Delete addresses when customer deleted
        related_name="addresses",
    )

    # Role flags — replaces the old address_type CharField
    is_primary = models.BooleanField(default=False, verbose_name=_("Adresa principală"))
    is_billing = models.BooleanField(default=False, verbose_name=_("Adresa facturare"))

    # Optional free-text label chosen by the customer
    label = models.CharField(max_length=50, blank=True, verbose_name=_("Etichetă"))

    # Address Fields
    address_line1 = models.CharField(max_length=200, verbose_name=_("Adresa 1"))
    address_line2 = models.CharField(max_length=200, blank=True, verbose_name=_("Adresa 2"))
    city = models.CharField(max_length=100, verbose_name=_("Oraș"))
    county = models.CharField(max_length=100, verbose_name=_("Județ"))
    postal_code = models.CharField(max_length=10, verbose_name=_("Cod poștal"))
    country = models.CharField(max_length=100, default="România", verbose_name=_("Țara"))

    # Versioning
    is_current = models.BooleanField(default=True, verbose_name=_("Adresa curentă"))
    version = models.PositiveIntegerField(default=1, verbose_name=_("Versiune"))

    # Validation
    is_validated = models.BooleanField(default=False, verbose_name=_("Validată"))
    validated_at = models.DateTimeField(null=True, blank=True)

    # Audit
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = "customer_addresses"
        verbose_name = _("Customer Address")
        verbose_name_plural = _("Customer Addresses")
        indexes: ClassVar[tuple[models.Index, ...]] = (
            models.Index(fields=["customer", "is_primary"], name="addr_cust_is_primary_idx"),
            models.Index(fields=["customer", "is_billing"], name="addr_cust_is_billing_idx"),
            models.Index(fields=["customer", "is_current"]),
            models.Index(fields=["postal_code"]),
            # Partial indexes: SoftDeleteManager always filters deleted_at__isnull=True
            models.Index(
                fields=["customer", "is_primary"],
                condition=Q(deleted_at__isnull=True),
                name="addr_cust_primary_active_idx",
            ),
            models.Index(
                fields=["customer", "is_billing"],
                condition=Q(deleted_at__isnull=True),
                name="addr_cust_billing_active_idx",
            ),
        )

    def __str__(self) -> str:
        roles = []
        if self.is_primary:
            roles.append(str(_("Adresa principală")))
        if self.is_billing:
            roles.append(str(_("Adresa facturare")))
        role_label = ", ".join(roles) if roles else str(_("Adresă"))
        return f"{self.customer.get_display_name()} - {role_label}"

    def save(self, *args: Any, **kwargs: Any) -> None:
        """Save with exclusive primary/billing flag enforcement (atomic)."""
        with db_transaction.atomic():
            if self.is_primary:
                CustomerAddress.objects.filter(
                    customer=self.customer,
                    is_primary=True,
                    deleted_at__isnull=True,
                ).exclude(pk=self.pk).update(is_primary=False)
            if self.is_billing:
                CustomerAddress.objects.filter(
                    customer=self.customer,
                    is_billing=True,
                    deleted_at__isnull=True,
                ).exclude(pk=self.pk).update(is_billing=False)
            super().save(*args, **kwargs)

    def get_full_address(self) -> str:
        """Get formatted address"""
        parts = [self.address_line1, self.address_line2, f"{self.city}, {self.county}", self.postal_code, self.country]
        return ", ".join(part for part in parts if part)


class CustomerPaymentMethod(SoftDeleteModel):
    """
    Customer payment methods (Stripe, bank transfer, etc.)

    🚨 CASCADE: ON DELETE CASCADE from Customer
    """

    METHOD_TYPE_CHOICES: ClassVar[tuple[tuple[str, Any], ...]] = (
        ("stripe_card", _("Card Stripe")),
        ("bank_transfer", _("Transfer bancar")),
        ("cash", _("Numerar")),
        ("other", _("Altele")),
    )

    customer = models.ForeignKey(
        "customers.Customer",
        on_delete=models.CASCADE,  # Delete payment methods when customer deleted
        related_name="payment_methods",
    )

    method_type = models.CharField(max_length=20, choices=METHOD_TYPE_CHOICES, verbose_name=_("Tip metodă"))

    # Stripe Integration
    stripe_customer_id = models.CharField(max_length=100, blank=True)
    stripe_payment_method_id = models.CharField(max_length=100, blank=True)

    # Display Information
    display_name = models.CharField(max_length=100, verbose_name=_("Nume afișaj"))
    last_four = models.CharField(max_length=4, blank=True, verbose_name=_("Ultimele 4 cifre"))

    # Status
    is_default = models.BooleanField(default=False, verbose_name=_("Implicit"))
    is_active = models.BooleanField(default=True, verbose_name=_("Activ"))

    # Bank Transfer Details (AES-256-GCM encrypted at rest)
    bank_details = EncryptedJSONField(blank=True, null=True, verbose_name=_("Detalii bancare"))

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
        constraints: ClassVar[list[UniqueConstraint]] = [
            UniqueConstraint(
                fields=["customer"],
                condition=Q(is_default=True, deleted_at__isnull=True),
                name="unique_default_payment_per_cust",
                violation_error_message=_("Only one default payment method per customer is allowed."),
            ),
        ]

    def __str__(self) -> str:
        return f"{self.customer.get_display_name()} - {self.display_name}"

    def save(self, *args: Any, **kwargs: Any) -> None:
        """Save with default payment method logic (atomic)."""
        with db_transaction.atomic():
            if self.is_default:
                CustomerPaymentMethod.objects.filter(customer=self.customer, is_default=True).exclude(
                    pk=self.pk
                ).update(is_default=False)
            # WORKAROUND: Django's save() does not call full_clean() by default.
            # For bank_details (financial data), we enforce validation here as
            # defense-in-depth.
            # See: https://docs.djangoproject.com/en/5.2/ref/models/instances/#validating-objects
            self.full_clean()
            super().save(*args, **kwargs)

    def clean(self) -> None:
        """🔒 Enhanced bank details validation for security and compliance"""
        super().clean()
        if self.bank_details:
            # Security: Enhanced validation with our new secure function
            validate_bank_details(self.bank_details)

            # Additional validation with existing secure input validator
            from apps.common.validators import (  # noqa: PLC0415  # Deferred: avoids circular import
                SecureInputValidator,  # Avoid circular import  # Circular: cross-app
            )

            self.bank_details = SecureInputValidator.validate_bank_details_schema(self.bank_details)


class CustomerNote(SoftDeleteModel):
    """Customer interaction notes with soft delete"""

    NOTE_TYPE_CHOICES: ClassVar[tuple[tuple[str, Any], ...]] = (
        ("general", _("Generală")),
        ("call", _("Apel telefonic")),
        ("email", _("Email")),
        ("meeting", _("Întâlnire")),
        ("complaint", _("Reclamație")),
        ("compliment", _("Compliment")),
    )

    customer = models.ForeignKey(
        "customers.Customer",
        on_delete=models.CASCADE,  # Delete notes when customer deleted
        related_name="notes",
    )

    note_type = models.CharField(
        max_length=20, choices=NOTE_TYPE_CHOICES, default="general", verbose_name=_("Tip notă")
    )

    title = models.CharField(max_length=200, verbose_name=_("Titlu"))
    content = models.TextField(verbose_name=_("Conținut"))

    is_important = models.BooleanField(default=False, verbose_name=_("Important"))
    is_private = models.BooleanField(default=False, verbose_name=_("Privat"))

    created_at = models.DateTimeField(auto_now_add=True)
    created_by = models.ForeignKey(
        "users.User",
        on_delete=models.SET_NULL,  # Keep note when user deleted
        null=True,
        verbose_name=_("Creat de"),
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
