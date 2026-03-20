"""
Order Management models for PRAHO Platform
Handles the complete order lifecycle from cart to provisioning.
Romanian hosting provider specific order processing and configuration.
"""

import logging
import uuid
from collections.abc import Iterable
from decimal import Decimal
from typing import TYPE_CHECKING, Any, ClassVar, Optional, cast

from django.core.validators import MinValueValidator
from django.db import DatabaseError, IntegrityError, NotSupportedError, connection, models, transaction
from django.utils import timezone
from django.utils.translation import gettext_lazy as _
from django_fsm import ConcurrentTransitionMixin, FSMField, transition

from apps.common.financial_arithmetic import calculate_document_totals, calculate_line_totals

if TYPE_CHECKING:
    from apps.provisioning.models import Service

# ===============================================================================
# ORDER MANAGEMENT MODELS
# ===============================================================================

logger = logging.getLogger(__name__)


def _order_has_items(instance: models.Model) -> bool:
    """FSM condition: order must have at least one item before submitting."""
    order = cast("Order", instance)
    return bool(order.items.exists())


class Order(ConcurrentTransitionMixin, models.Model):
    """
    Customer order for products/services.
    Tracks the entire lifecycle from cart to provisioning.
    Romanian compliance and VAT handling included.
    """

    # Use UUID for better security and external references
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)

    # Order identification
    order_number = models.CharField(max_length=50, unique=True, help_text=_("Human-readable order number"))

    # Customer relationship
    customer = models.ForeignKey("customers.Customer", on_delete=models.PROTECT, related_name="orders")

    # Order status workflow
    STATUS_CHOICES: ClassVar[tuple[tuple[str, Any], ...]] = (
        ("draft", _("Draft")),  # Cart/Quote stage - can be modified
        ("pending", _("Pending")),  # Awaiting payment
        ("confirmed", _("Confirmed")),  # Payment confirmed, ready for processing
        ("processing", _("Processing")),  # Payment received, provisioning in progress
        ("completed", _("Completed")),  # Fully provisioned and delivered
        ("cancelled", _("Cancelled")),  # Cancelled by customer or admin
        ("failed", _("Failed")),  # Payment or provisioning failed
        ("refunded", _("Refunded")),  # Order was refunded
        ("partially_refunded", _("Partially Refunded")),  # Partial refund processed
    )
    status = FSMField(
        max_length=20,
        choices=STATUS_CHOICES,
        default="draft",
        protected=True,
        help_text=_("Current order status"),
    )

    # Editable fields by status for hybrid editing approach
    EDITABLE_FIELDS_BY_STATUS: ClassVar[dict[str, list[str]]] = {
        "draft": ["*"],  # Everything editable
        "pending": ["*"],  # Everything editable (payment not processed yet)
        "confirmed": [
            "notes",
            "delivery_date",
            "shipping_address_line1",
            "shipping_address_line2",
            "shipping_city",
            "shipping_county",
            "shipping_postal_code",
            "shipping_country",
        ],  # Limited to delivery and notes
        "processing": [
            "notes",
            "delivery_date",
            "shipping_address_line1",
            "shipping_address_line2",
            "shipping_city",
            "shipping_county",
            "shipping_postal_code",
            "shipping_country",
        ],  # Limited to delivery and notes
        "completed": ["notes"],  # Only administrative notes
        "failed": ["*"],  # Full edit to retry/fix issues
        "cancelled": ["notes"],  # Only notes for record keeping
        "refunded": ["notes"],  # Only notes
        "partially_refunded": ["notes", "refund_reason"],  # Notes and refund details
    }

    # Financial information
    currency = models.ForeignKey("billing.Currency", on_delete=models.PROTECT, help_text=_("Order currency"))
    exchange_to_ron = models.DecimalField(
        max_digits=18, decimal_places=6, null=True, blank=True, help_text=_("Exchange rate to RON at time of order")
    )

    # Amounts in cents for precision
    subtotal_cents = models.BigIntegerField(default=0, help_text=_("Subtotal before tax in cents"))
    tax_cents = models.BigIntegerField(default=0, help_text=_("Total tax amount in cents"))
    discount_cents = models.BigIntegerField(default=0, help_text=_("Total discount amount in cents"))
    total_cents = models.BigIntegerField(default=0, help_text=_("Final total amount in cents"))

    # Customer information snapshot (for billing)
    customer_email = models.EmailField(help_text=_("Customer email at time of order"))
    customer_name = models.CharField(max_length=255, help_text=_("Customer name at time of order"))
    customer_company = models.CharField(max_length=255, blank=True, help_text=_("Company name if business customer"))
    customer_vat_id = models.CharField(max_length=50, blank=True, help_text=_("VAT ID for Romanian compliance"))

    # Billing address snapshot
    billing_address = models.JSONField(default=dict, help_text=_("Billing address snapshot"))

    # Payment processing
    payment_method = models.CharField(
        max_length=50,
        blank=True,
        choices=[
            ("card", _("Credit/Debit Card")),
            ("bank_transfer", _("Bank Transfer")),
            ("paypal", _("PayPal")),
            ("crypto", _("Cryptocurrency")),
            ("wallet", _("Account Credit")),
            ("manual", _("Manual Payment")),
        ],
        help_text=_("Payment method used"),
    )
    transaction_id = models.CharField(max_length=255, blank=True, help_text=_("Payment gateway transaction ID"))
    payment_intent_id = models.CharField(max_length=255, blank=True, help_text=_("Stripe payment intent ID"))
    gateway_response = models.JSONField(default=dict, blank=True, help_text=_("Payment gateway response data"))

    # Source tracking
    source_ip = models.GenericIPAddressField(null=True, blank=True, help_text=_("Customer IP address"))
    user_agent = models.TextField(blank=True, help_text=_("Customer browser user agent"))
    referrer = models.URLField(blank=True, help_text=_("Referrer URL"))
    utm_source = models.CharField(max_length=100, blank=True)
    utm_medium = models.CharField(max_length=100, blank=True)
    utm_campaign = models.CharField(max_length=100, blank=True)

    # Administrative
    notes = models.TextField(blank=True, help_text=_("Internal order notes"))
    customer_notes = models.TextField(blank=True, help_text=_("Notes from customer"))

    # Invoice relationship
    invoice = models.ForeignKey(
        "billing.Invoice",
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="orders",
        help_text=_("Generated invoice for this order"),
    )

    # Idempotency key for preventing duplicate orders
    idempotency_key = models.CharField(
        max_length=64,
        blank=True,
        default="",
        help_text=_("Client-provided idempotency key to prevent duplicate orders"),
    )

    # Metadata
    meta = models.JSONField(default=dict, blank=True, help_text=_("Additional order metadata"))

    # Timestamps
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    completed_at = models.DateTimeField(null=True, blank=True, help_text=_("When order was completed"))
    expires_at = models.DateTimeField(null=True, blank=True, help_text=_("When draft order expires"))

    class Meta:
        db_table = "orders"
        verbose_name = _("Order")
        verbose_name_plural = _("Orders")
        ordering: ClassVar[tuple[str, ...]] = ("-created_at",)
        indexes: ClassVar[tuple[models.Index, ...]] = (
            models.Index(fields=["customer", "-created_at"]),
            models.Index(fields=["status", "-created_at"]),
            models.Index(fields=["order_number"]),
            models.Index(fields=["customer_email"]),
            models.Index(fields=["-created_at"]),
            # 🚀 Performance: Payment status filtering for admin dashboard
            models.Index(fields=["status", "payment_method", "-created_at"]),
            # 🚀 Performance: Customer order history with status
            models.Index(fields=["customer", "status"]),
        )
        # DB-level guards against negative financial values (#71)
        constraints: ClassVar[tuple[models.BaseConstraint, ...]] = (
            models.CheckConstraint(
                condition=models.Q(subtotal_cents__gte=0),
                name="order_subtotal_non_negative",
            ),
            models.CheckConstraint(
                condition=models.Q(tax_cents__gte=0),
                name="order_tax_non_negative",
            ),
            models.CheckConstraint(
                condition=models.Q(discount_cents__gte=0),
                name="order_discount_non_negative",
            ),
            models.CheckConstraint(
                condition=models.Q(total_cents__gte=0),
                name="order_total_non_negative",
            ),
            models.UniqueConstraint(
                fields=["customer", "idempotency_key"],
                condition=models.Q(idempotency_key__gt=""),
                name="unique_customer_idempotency_key",
            ),
            models.CheckConstraint(
                condition=models.Q(
                    status__in=[
                        "draft",
                        "pending",
                        "confirmed",
                        "processing",
                        "completed",
                        "cancelled",
                        "failed",
                        "refunded",
                        "partially_refunded",
                    ]
                ),
                name="order_status_valid_values",
            ),
        )

    def __str__(self) -> str:
        return f"Order {self.order_number} - {self.customer_email}"

    # Markers to identify order_number uniqueness violations in IntegrityError messages.
    # PostgreSQL uses the constraint name; SQLite uses "column_name".
    _ORDER_NUMBER_COLLISION_MARKERS = ("orders_order_number_key", "orders.order_number")
    # Markers for non-retryable IntegrityErrors (e.g., idempotency key constraint).
    # If these appear in the exception string, re-raise immediately instead of retrying.
    _NON_RETRYABLE_CONSTRAINT_MARKERS = ("unique_customer_idempotency_key",)

    def save(self, *args: Any, **kwargs: Any) -> None:
        """Auto-generate order number before saving, with retry on collision.

        The retry loop (with savepoints via transaction.atomic) is only engaged
        during initial creation (_state.adding=True).  Plain updates bypass it
        entirely to avoid unnecessary savepoint overhead and to avoid accidentally
        swallowing non-retryable constraint errors on existing rows.

        Each creation retry is wrapped in a savepoint because PostgreSQL aborts
        the entire transaction on IntegrityError — without a savepoint, subsequent
        save() calls would fail with InFailedSqlTransaction.
        """
        if not self.order_number:
            self.generate_order_number()

        # Only retry on creation (order_number collision is only possible on INSERT)
        if self._state.adding:
            max_retries = 3
            for attempt in range(max_retries):
                try:
                    # Savepoint: PostgreSQL aborts the transaction on IntegrityError,
                    # so each attempt needs its own savepoint to allow retry.
                    with transaction.atomic():
                        super().save(*args, **kwargs)
                    return
                except IntegrityError as exc:
                    exc_str = str(exc)
                    # Never retry non-order-number constraints (e.g., idempotency key)
                    if any(m in exc_str for m in self._NON_RETRYABLE_CONSTRAINT_MARKERS):
                        raise
                    is_order_number_collision = any(m in exc_str for m in self._ORDER_NUMBER_COLLISION_MARKERS)
                    if not is_order_number_collision or attempt >= max_retries - 1:
                        raise
                    # Regenerate sequence only, preserving the original prefix format.
                    # This prevents split-brain between model format (ORD-{date}-{seq})
                    # and service format (ORD-{year}-{customer}-{seq}).
                    logger.warning(
                        "⚠️ [Order] order_number collision on attempt %d, regenerating sequence",
                        attempt + 1,
                    )
                    self._regenerate_order_number_sequence()
        else:
            super().save(*args, **kwargs)

    def refresh_from_db(
        self,
        using: str | None = None,
        fields: Iterable[str] | None = None,
        from_queryset: "models.QuerySet[Order] | None" = None,
    ) -> None:
        """Override to allow refresh_from_db to work with FSMField(protected=True).

        django-fsm protected fields block setattr via the descriptor. Django's
        refresh_from_db uses setattr internally, which would raise AttributeError
        if the field is already in __dict__. Temporarily removing the protected
        field from __dict__ lets Django's setattr path bypass the descriptor
        guard and populate the field from the database.
        """
        fsm_fields = ["status"]
        if fields is not None:
            fields_set = set(fields)
            fsm_fields = [f for f in fsm_fields if f in fields_set]
        saved = {f: self.__dict__.pop(f) for f in fsm_fields if f in self.__dict__}
        try:
            super().refresh_from_db(using=using, fields=fields, from_queryset=from_queryset)
        except Exception:
            self.__dict__.update(saved)
            raise

    @property
    def subtotal(self) -> Decimal:
        """Return subtotal in currency units"""
        return Decimal(self.subtotal_cents) / 100

    @property
    def tax_amount(self) -> Decimal:
        """Return tax amount in currency units"""
        return Decimal(self.tax_cents) / 100

    @property
    def discount_amount(self) -> Decimal:
        """Return discount amount in currency units"""
        return Decimal(self.discount_cents) / 100

    @property
    def total(self) -> Decimal:
        """Return total in currency units"""
        return Decimal(self.total_cents) / 100

    @property
    def is_draft(self) -> bool:
        """Check if order is still in draft state"""
        return bool(self.status == "draft")

    @property
    def is_paid(self) -> bool:
        """Check if order has been paid"""
        return bool(self.status in ["confirmed", "processing", "completed"])

    @property
    def can_be_cancelled(self) -> bool:
        """Check if order can be cancelled"""
        return self.status in ["draft", "pending", "confirmed"]

    def can_edit_field(self, field_name: str) -> bool:
        """Check if a specific field can be edited based on current status"""
        editable_fields = self.EDITABLE_FIELDS_BY_STATUS.get(self.status, [])
        return "*" in editable_fields or field_name in editable_fields

    def get_editable_fields(self) -> list[str]:
        """Get list of fields that can be edited in current status"""
        return self.EDITABLE_FIELDS_BY_STATUS.get(self.status, [])

    @staticmethod
    def _locked_latest_order_number(qs: models.QuerySet["Order"]) -> str | None:
        """Attempt select_for_update inside its own savepoint; fall back on unsupported backends.

        Wrapping in transaction.atomic() ensures the lock works even when the
        caller is in autocommit mode (PostgreSQL raises TransactionManagementError
        for select_for_update outside a transaction, not NotSupportedError).
        """
        try:
            with transaction.atomic():
                return qs.select_for_update(of=("self",)).values_list("order_number", flat=True).first()
        except (NotSupportedError, DatabaseError):
            if connection.vendor != "sqlite":
                logger.error(
                    "⚠️ [Order] select_for_update failed on %s — TOCTOU race possible",
                    connection.vendor,
                )
            return qs.values_list("order_number", flat=True).first()

    def generate_order_number(self) -> None:
        """Generate a unique order number via OrderNumberingService.

        Delegates to OrderNumberingService for per-customer sequential numbering
        (ORD-{YYYY}-{customer_id[:8]}-{seq:04d}), ensuring a single canonical
        format across both model and service code paths.

        Falls back to date-based global numbering only if customer is None
        (shouldn't happen in normal flow — orders always have a customer).
        """
        if not self.order_number:
            if self.customer:
                from .services import OrderNumberingService

                self.order_number = OrderNumberingService.generate_order_number(self.customer)
            else:
                # Fallback: no customer (shouldn't happen in production)
                date_part = timezone.now().strftime("%Y%m%d")
                prefix = f"ORD-{date_part}-"
                qs = Order.objects.filter(order_number__startswith=prefix).order_by("-order_number")
                latest = self._locked_latest_order_number(qs)
                if latest:
                    try:
                        last_seq = int(latest.split("-")[-1])
                        next_seq = last_seq + 1
                    except (ValueError, IndexError):
                        next_seq = 1
                else:
                    next_seq = 1
                self.order_number = f"{prefix}{next_seq:06d}"

    def _regenerate_order_number_sequence(self) -> None:
        """Regenerate just the sequence part of an existing order number.

        Preserves the prefix format (whether from model or service generator)
        to prevent format split-brain on collision retry.
        """
        if not self.order_number:
            self.generate_order_number()
            return
        # Split on last dash to extract prefix and sequence
        parts = self.order_number.rsplit("-", 1)
        expected_parts = 2  # prefix + sequence
        if len(parts) != expected_parts:
            # Can't determine format — fall back to full regeneration
            self.order_number = ""
            self.generate_order_number()
            return
        prefix = parts[0] + "-"
        seq_width = len(parts[1])  # Preserve zero-padding width (4 or 6)
        qs = Order.objects.filter(order_number__startswith=prefix).order_by("-order_number")
        latest = self._locked_latest_order_number(qs)
        if latest:
            try:
                last_seq = int(latest.rsplit("-", 1)[-1])
                next_seq = last_seq + 1
            except (ValueError, IndexError):
                next_seq = 1
        else:
            next_seq = 1
        self.order_number = f"{prefix}{next_seq:0{seq_width}d}"

    def calculate_totals(self) -> None:
        """
        Recalculate order totals from line items.
        Should be called after adding/removing/updating items.
        """
        totals = calculate_document_totals(list(self.items.all()), self.discount_cents)
        self.subtotal_cents = totals.subtotal_cents
        self.tax_cents = totals.tax_cents
        self.total_cents = totals.total_cents
        self.save(update_fields=["subtotal_cents", "tax_cents", "total_cents"])

    # =========================================================================
    # FSM TRANSITIONS
    # =========================================================================

    @transition(field=status, source="draft", target="pending", conditions=[_order_has_items])
    def submit(self) -> None:
        """Submit draft order for payment."""

    @transition(field=status, source="pending", target="confirmed")
    def confirm(self) -> None:
        """Confirm order after payment verification."""

    @transition(field=status, source="confirmed", target="processing")
    def start_processing(self) -> None:
        """Start provisioning the order."""

    @transition(field=status, source="processing", target="completed")
    def complete(self) -> None:
        """Mark order as completed."""
        self.completed_at = timezone.now()

    @transition(field=status, source=["draft", "pending", "confirmed", "processing", "failed"], target="cancelled")
    def cancel(self) -> None:
        """Cancel the order."""

    @transition(field=status, source=["pending", "processing"], target="failed")
    def fail(self) -> None:
        """Mark order as failed."""

    @transition(field=status, source="failed", target="pending")
    def retry(self) -> None:
        """Retry a failed order."""

    @transition(field=status, source="completed", target="refunded")
    def refund_order(self) -> None:
        """Fully refund a completed order."""

    @transition(field=status, source="completed", target="partially_refunded")
    def partial_refund(self) -> None:
        """Partially refund a completed order."""

    @transition(field=status, source="partially_refunded", target="refunded")
    def complete_refund(self) -> None:
        """Complete remaining refund on partially refunded order."""


class OrderItem(models.Model):
    """
    Individual line item in an order.
    Links to product and stores pricing/configuration snapshot.
    """

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)

    # Order relationship
    order = models.ForeignKey(Order, on_delete=models.CASCADE, related_name="items")

    # Product relationship
    product = models.ForeignKey("products.Product", on_delete=models.PROTECT, help_text=_("Product being ordered"))

    # Product information snapshot (in case product changes)
    product_name = models.CharField(max_length=200, help_text=_("Product name at time of order"))
    product_type = models.CharField(max_length=30, help_text=_("Product type at time of order"))

    # Quantity and pricing
    quantity = models.PositiveIntegerField(
        default=1, validators=[MinValueValidator(1)], help_text=_("Quantity ordered")
    )
    unit_price_cents = models.BigIntegerField(
        validators=[MinValueValidator(0)], help_text=_("Unit price in cents (snapshot)")
    )
    setup_cents = models.BigIntegerField(
        default=0, validators=[MinValueValidator(0)], help_text=_("Setup fee in cents")
    )

    # Tax calculation
    tax_rate = models.DecimalField(
        max_digits=5,
        decimal_places=4,
        default=Decimal("0.0000"),
        help_text=_("Tax rate applied (e.g., 0.2100 for 21%)"),
    )
    tax_cents = models.BigIntegerField(default=0, help_text=_("Tax amount in cents"))

    # Line total
    line_total_cents = models.BigIntegerField(default=0, help_text=_("Total for this line including tax"))

    # Product configuration for provisioning
    config = models.JSONField(
        default=dict, blank=True, help_text=_("Product configuration (domain, username, specs, etc.)")
    )

    # Domain association (if applicable)
    domain_name = models.CharField(max_length=255, blank=True, help_text=_("Associated domain name"))

    # Service relationship (after provisioning)
    service = models.ForeignKey(
        "provisioning.Service",
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="order_items",
        help_text=_("Provisioned service for this order item"),
    )

    # Provisioning status
    PROVISIONING_STATUS: ClassVar[tuple[tuple[str, Any], ...]] = (
        ("pending", _("Pending")),
        ("in_progress", _("In Progress")),
        ("completed", _("Completed")),
        ("failed", _("Failed")),
        ("cancelled", _("Cancelled")),
    )
    provisioning_status = FSMField(
        max_length=20,
        choices=PROVISIONING_STATUS,
        default="pending",
        protected=True,
        help_text=_("Provisioning status for this item"),
    )
    provisioning_notes = models.TextField(blank=True, help_text=_("Provisioning notes and error messages"))

    # Timestamps
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    provisioned_at = models.DateTimeField(
        null=True, blank=True, help_text=_("When this item was successfully provisioned")
    )

    class Meta:
        db_table = "order_items"
        verbose_name = _("Order Item")
        verbose_name_plural = _("Order Items")
        ordering: ClassVar[tuple[str, ...]] = ("created_at",)
        indexes: ClassVar[tuple[models.Index, ...]] = (
            models.Index(fields=["order", "created_at"]),
            models.Index(fields=["product"]),
            models.Index(fields=["provisioning_status"]),
            # 🚀 Performance: Provisioning queue optimization
            models.Index(fields=["provisioning_status", "-created_at"]),
            # 🚀 Performance: Product and order tracking
            models.Index(fields=["product", "provisioning_status"]),
        )
        # DB-level guards against negative financial values (#71)
        constraints: ClassVar[tuple[models.BaseConstraint, ...]] = (
            models.CheckConstraint(
                condition=models.Q(unit_price_cents__gte=0),
                name="orderitem_unit_price_non_negative",
            ),
            models.CheckConstraint(
                condition=models.Q(setup_cents__gte=0),
                name="orderitem_setup_non_negative",
            ),
            models.CheckConstraint(
                condition=models.Q(tax_cents__gte=0),
                name="orderitem_tax_non_negative",
            ),
            models.CheckConstraint(
                condition=models.Q(line_total_cents__gte=0),
                name="orderitem_line_total_non_negative",
            ),
            models.CheckConstraint(
                condition=models.Q(
                    provisioning_status__in=["pending", "in_progress", "completed", "failed", "cancelled"]
                ),
                name="orderitem_provisioning_status_valid_values",
            ),
        )

    def __str__(self) -> str:
        return f"{self.product_name} x{self.quantity} ({self.order.order_number})"

    def save(self, *args: Any, **kwargs: Any) -> None:
        """Auto-calculate totals before saving"""
        # Store product details snapshot
        if self.product and not self.product_name:
            self.product_name = self.product.name
            self.product_type = self.product.product_type

        # Skip VAT recalculation for non-financial field updates (#130/M5)
        update_fields = kwargs.get("update_fields")
        _financial_fields = {"unit_price_cents", "tax_rate", "tax_cents", "quantity", "setup_cents", "line_total_cents"}
        if update_fields and not (set(update_fields) & _financial_fields):
            super().save(*args, **kwargs)
            return

        # Apply default VAT when tax_rate was not explicitly set.
        # This keeps direct model creation aligned with the authoritative VAT rules.
        if self.tax_rate == Decimal("0.0000") and self.order_id:
            try:
                from .vat_rules import CustomerVATInfo, OrderVATCalculator

                customer = self.order.customer
                if not hasattr(customer, "tax_profile"):
                    raise LookupError("No tax profile available for automatic VAT inference")

                tax_profile = customer.tax_profile
                vat_number = getattr(tax_profile, "vat_number", "")
                customer_vat_info: CustomerVATInfo = {
                    "country": getattr(customer, "country", "RO") or "RO",
                    "is_business": bool(getattr(customer, "company_name", "")),
                    "vat_number": vat_number,
                    "customer_id": str(customer.id),
                    "order_id": str(self.order.id),
                }

                customer_vat_info["is_vat_payer"] = tax_profile.is_vat_payer
                customer_vat_info["reverse_charge_eligible"] = tax_profile.reverse_charge_eligible
                if tax_profile.vat_rate is not None:
                    customer_vat_info["custom_vat_rate"] = tax_profile.vat_rate

                vat_result = OrderVATCalculator.calculate_vat(
                    subtotal_cents=self.subtotal_cents,
                    customer_info=customer_vat_info,
                )
                self.tax_rate = (vat_result.vat_rate / Decimal("100")).quantize(Decimal("0.0001"))
            except Exception as exc:
                # Fallback to explicit tax_rate provided by caller (or 0.0000 default).
                logger.debug("Skipping automatic VAT inference for order item %s: %s", self.id, exc)

        # Calculate totals
        self.calculate_totals()

        super().save(*args, **kwargs)

    def refresh_from_db(
        self,
        using: str | None = None,
        fields: Iterable[str] | None = None,
        from_queryset: "models.QuerySet[OrderItem] | None" = None,
    ) -> None:
        """Override to allow refresh_from_db to work with FSMField(protected=True).

        See Order.refresh_from_db for the full explanation.
        """
        fsm_fields = ["provisioning_status"]
        if fields is not None:
            fields_set = set(fields)
            fsm_fields = [f for f in fsm_fields if f in fields_set]
        saved = {f: self.__dict__.pop(f) for f in fsm_fields if f in self.__dict__}
        try:
            super().refresh_from_db(using=using, fields=fields, from_queryset=from_queryset)
        except Exception:
            self.__dict__.update(saved)
            raise

    @property
    def unit_price(self) -> Decimal:
        """Return unit price in currency units"""
        return Decimal(self.unit_price_cents) / 100

    @unit_price.setter
    def unit_price(self, value: Decimal) -> None:
        """Set unit price from currency units"""
        self.unit_price_cents = int(value * 100)

    @property
    def setup_fee(self) -> Decimal:
        """Return setup fee in currency units"""
        return Decimal(self.setup_cents) / 100

    @property
    def tax_amount(self) -> Decimal:
        """Return tax amount in currency units"""
        return Decimal(self.tax_cents) / 100

    @property
    def subtotal_cents(self) -> int:
        """Calculate subtotal before tax"""
        return (self.unit_price_cents * self.quantity) + self.setup_cents

    @property
    def line_total(self) -> Decimal:
        """Return line total in currency units"""
        return Decimal(self.line_total_cents) / 100

    # =========================================================================
    # BILLING PERIOD - Stored in config JSON for flexibility
    # =========================================================================

    BILLING_PERIOD_CHOICES: ClassVar[dict[str, str]] = {
        "once": "One Time",
        "monthly": "Monthly",
        "quarterly": "Quarterly",
        "semiannual": "Semi-Annual",
        "annual": "Annual",
        "biennial": "Biennial",
        "triennial": "Triennial",
    }

    @property
    def billing_period(self) -> str:
        """Get billing period from config (default: monthly)"""
        return str(self.config.get("billing_period", "monthly"))

    @billing_period.setter
    def billing_period(self, value: str) -> None:
        """Store billing period in config JSON"""
        if not isinstance(self.config, dict):
            self.config = {}
        self.config["billing_period"] = value

    def get_billing_period_display(self) -> str:
        """Human-readable billing period for templates"""
        return self.BILLING_PERIOD_CHOICES.get(self.billing_period, "Monthly")

    def subtotal(self) -> Decimal:
        """Return subtotal in currency units"""
        return Decimal(self.subtotal_cents) / 100

    def calculate_totals(self) -> int:
        """Calculate tax and line total with proper banker's rounding for Romanian VAT compliance."""
        totals = calculate_line_totals(self.subtotal_cents, self.tax_rate)
        self.tax_cents = totals.tax_cents
        self.line_total_cents = totals.line_total_cents
        return self.line_total_cents

    # =========================================================================
    # FSM TRANSITIONS
    # =========================================================================

    @transition(field=provisioning_status, source="pending", target="in_progress")
    def start_provisioning(self) -> None:
        """Start provisioning this item."""

    @transition(field=provisioning_status, source="in_progress", target="completed")
    def complete_provisioning(self) -> None:
        """Mark provisioning as completed."""
        self.provisioned_at = timezone.now()

    @transition(field=provisioning_status, source="in_progress", target="failed")
    def fail_provisioning(self) -> None:
        """Mark provisioning as failed."""

    @transition(field=provisioning_status, source=["pending", "in_progress"], target="cancelled")
    def cancel_provisioning(self) -> None:
        """Cancel provisioning."""

    @transition(field=provisioning_status, source="failed", target="pending")
    def retry_provisioning(self) -> None:
        """Retry failed provisioning."""

    def mark_as_provisioned(self, service: Optional["Service"] = None) -> None:
        """Mark this item as successfully provisioned and activate the service.

        The item's ``provisioning_status`` must be ``"in_progress"`` before
        calling this method (``complete_provisioning()`` requires that source).
        Callers are responsible for calling ``start_provisioning()`` first when
        the item is still in ``"pending"`` state.
        """
        self.complete_provisioning()  # FSM transition sets provisioned_at
        if service:
            self.service = service

        # Update the linked service status to active when provisioning completes
        if self.service and self.service.status == "provisioning":
            self.service.complete_provisioning()
            self.service.save(update_fields=["status", "activated_at"])

        self.save(update_fields=["provisioning_status", "provisioned_at", "service", "updated_at"])


class OrderStatusHistory(models.Model):
    """
    Track order status changes for audit trail and customer notifications.
    """

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)

    # Order relationship
    order = models.ForeignKey(Order, on_delete=models.CASCADE, related_name="status_history")

    # Status change details
    old_status = models.CharField(max_length=20, blank=True, help_text=_("Previous status"))
    new_status = models.CharField(max_length=20, help_text=_("New status"))

    # Change context
    changed_by = models.ForeignKey(
        "users.User", on_delete=models.SET_NULL, null=True, blank=True, help_text=_("User who made the change")
    )
    reason = models.CharField(max_length=255, blank=True, help_text=_("Reason for status change"))
    notes = models.TextField(blank=True, help_text=_("Additional notes about the change"))

    # Automatic vs manual change
    is_automatic = models.BooleanField(default=False, help_text=_("Whether this was an automatic system change"))

    # Timestamp
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = "order_status_history"
        verbose_name = _("Order Status History")
        verbose_name_plural = _("Order Status Histories")
        ordering: ClassVar[tuple[str, ...]] = ("-created_at",)
        indexes: ClassVar[tuple[models.Index, ...]] = (models.Index(fields=["order", "-created_at"]),)

    def __str__(self) -> str:
        return f"{self.order.order_number}: {self.old_status} → {self.new_status}"
