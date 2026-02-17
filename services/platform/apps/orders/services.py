from __future__ import annotations

import logging
import uuid
from dataclasses import dataclass, field
from decimal import Decimal
from typing import TYPE_CHECKING, Any, TypedDict

from django.contrib.auth import get_user_model
from django.core.exceptions import ObjectDoesNotExist
from django.db import models, transaction
from django.utils import timezone

from apps.billing.models import Currency
from apps.common.types import EmailAddress, Err, Ok, Result
from apps.common.validators import log_security_event
from apps.products.models import Product
from apps.provisioning.service_models import Service, ServicePlan

if TYPE_CHECKING:
    from apps.customers.models import Customer
    from apps.users.models import User

    from .models import Order

"""
Order Management Services for PRAHO Platform
Handles order lifecycle, Romanian VAT compliance, and integration with billing/provisioning.
"""

UserModel = get_user_model()
logger = logging.getLogger(__name__)

# ===============================================================================
# ORDER SERVICE PARAMETER OBJECTS
# ===============================================================================


class OrderFilters(TypedDict, total=False):
    """Type definition for order filtering parameters"""

    status: str
    customer_id: uuid.UUID
    order_number: str
    date_from: str
    date_to: str
    min_total: Decimal
    max_total: Decimal
    search: str


class OrderItemData(TypedDict, total=False):
    """Type definition for order item data"""

    product_id: uuid.UUID | None
    service_id: uuid.UUID | None
    quantity: int
    unit_price_cents: int
    setup_cents: int
    description: str
    meta: dict[str, Any]


class BillingAddressData(TypedDict):
    """Type definition for Romanian billing address with compliance fields"""

    company_name: str
    contact_name: str
    email: EmailAddress
    phone: str
    address_line1: str
    address_line2: str
    city: str
    county: str
    postal_code: str
    country: str
    fiscal_code: str  # CUI in Romania
    registration_number: str
    vat_number: str


@dataclass
class OrderCreateData:
    """Parameter object for order creation"""

    customer: Customer
    items: list[OrderItemData]
    billing_address: BillingAddressData
    currency: str = "RON"
    notes: str = ""
    meta: dict[str, Any] = field(default_factory=dict)


@dataclass
class OrderUpdateData:
    """Parameter object for order updates"""

    billing_address: BillingAddressData | None = None
    notes: str | None = None
    meta: dict[str, Any] | None = None


@dataclass
class StatusChangeData:
    """Parameter object for order status changes"""

    new_status: str
    notes: str = ""
    changed_by: User | None = None


# ===============================================================================
# ORDER CALCULATION SERVICES
# ===============================================================================


class OrderCalculationService:
    """
    Service for order financial calculations with Romanian VAT compliance.

    IMPORTANT: All VAT calculations delegated to OrderVATCalculator for consistency.
    This ensures all financial calculations use the same rounding and tax rules.
    """

    @staticmethod
    def calculate_order_totals(
        items: list[OrderItemData], customer: Customer = None, billing_address: dict | None = None
    ) -> dict[str, int]:
        """
        Calculate order subtotal, VAT, and total in cents using authoritative VAT calculator.

        Args:
            items: Order items with pricing
            customer: Customer for VAT determination (optional, defaults to Romanian business)
            billing_address: Billing address for VAT calculation (optional)

        Returns:
            Dict with subtotal_cents, tax_cents, total_cents
        """
        # Calculate subtotal from items
        subtotal_cents = 0
        for item in items:
            unit = int(item["unit_price_cents"]) if item.get("unit_price_cents") is not None else 0
            qty = int(item["quantity"]) if item.get("quantity") is not None else 0
            setup = int(item.get("setup_cents", 0))
            subtotal_cents += (qty * unit) + setup

        # Use authoritative VAT calculator for consistency
        from .vat_rules import CustomerVATInfo, OrderVATCalculator  # noqa: PLC0415

        # Determine customer context for VAT calculation
        if billing_address:
            country = billing_address.get("country") or "RO"
            vat_number = billing_address.get("vat_number") or billing_address.get("vat_id")
            is_business = bool(billing_address.get("company_name")) or bool(vat_number)
        elif customer:
            country = getattr(customer, "country", "RO") or "RO"
            is_business = bool(getattr(customer, "company_name", ""))
            vat_number = getattr(customer.tax_profile, "vat_number", "") if hasattr(customer, "tax_profile") else ""
        else:
            # Default to Romanian business for consistency
            country = "RO"
            is_business = True
            vat_number = ""

        # Calculate VAT using authoritative calculator
        customer_vat_info: CustomerVATInfo = {
            "country": country,
            "is_business": is_business,
            "vat_number": vat_number,
            "customer_id": str(customer.id) if customer else "unknown",
            "order_id": "calculation",
        }

        # Inject per-customer overrides from CustomerTaxProfile (if available)
        if customer and hasattr(customer, "tax_profile"):
            try:
                tax_profile = customer.tax_profile
                customer_vat_info["is_vat_payer"] = tax_profile.is_vat_payer
                customer_vat_info["reverse_charge_eligible"] = tax_profile.reverse_charge_eligible
                # Pass custom rate if explicitly set (None means "use country default")
                if tax_profile.vat_rate is not None:
                    customer_vat_info["custom_vat_rate"] = tax_profile.vat_rate
            except (ObjectDoesNotExist, AttributeError):
                pass  # Profile doesn't exist yet — use defaults
        vat_result = OrderVATCalculator.calculate_vat(subtotal_cents=subtotal_cents, customer_info=customer_vat_info)

        return {
            "subtotal_cents": subtotal_cents,
            "tax_cents": int(vat_result.vat_cents),
            "total_cents": int(vat_result.total_cents),
        }


# ===============================================================================
# ORDER NUMBERING SERVICE
# ===============================================================================


class OrderNumberingService:
    """Service for generating sequential order numbers per Romanian compliance"""

    @staticmethod
    @transaction.atomic
    def generate_order_number(customer: Customer) -> str:
        """Generate sequential order number for customer compliance"""
        from .models import Order  # noqa: PLC0415

        current_year = timezone.now().year
        # Use first 8 characters of UUID hex (no hyphens) as customer identifier
        customer_id = str(customer.pk).replace("-", "")[:8].upper()
        prefix = f"ORD-{current_year}-{customer_id}"

        # Get the highest existing order number for this customer and year
        latest_order = (
            Order.objects.filter(customer=customer, order_number__startswith=prefix, created_at__year=current_year)
            .order_by("-order_number")
            .first()
        )

        if latest_order and latest_order.order_number.startswith(prefix):
            # Extract sequence number and increment
            try:
                sequence_part = latest_order.order_number.split("-")[-1]
                next_sequence = int(sequence_part) + 1
            except (ValueError, IndexError):
                next_sequence = 1
        else:
            next_sequence = 1

        return f"{prefix}-{next_sequence:04d}"


# ===============================================================================
# MAIN ORDER SERVICE
# ===============================================================================


class OrderService:
    """Main service for order management operations"""

    @staticmethod
    def build_billing_address_from_customer(customer: Customer) -> BillingAddressData:
        """
        Build billing address data from customer profile (database lookup).
        This ensures we always use the most current customer data.
        """
        from apps.customers.models import CustomerAddress  # noqa: PLC0415

        # Get current address from CustomerAddress model - try multiple strategies
        address = None

        # First, try to get billing address marked as current
        address = CustomerAddress.objects.filter(customer=customer, address_type="billing", is_current=True).first()

        # If no billing address, try primary address marked as current
        if not address:
            address = CustomerAddress.objects.filter(customer=customer, address_type="primary", is_current=True).first()

        # If still no address, get any current address
        if not address:
            address = CustomerAddress.objects.filter(customer=customer, is_current=True).first()

        # Last resort: get the most recent address for this customer
        if not address:
            address = CustomerAddress.objects.filter(customer=customer).order_by("-created_at").first()

        return BillingAddressData(
            company_name=customer.company_name or "",
            contact_name=customer.name,
            email=customer.primary_email,
            phone=customer.primary_phone if customer.primary_phone != "+40712345678" else "",  # Skip default phone
            address_line1=address.address_line1 if address else "",
            address_line2=address.address_line2 if address else "",
            city=address.city if address else "",
            county=address.county if address else "",
            postal_code=address.postal_code if address else "",
            country="RO"
            if (address and address.country in ["România", "Romania"]) or not address
            else (address.country if address else "RO"),
            fiscal_code=getattr(customer.tax_profile, "cui", "") if hasattr(customer, "tax_profile") else "",
            registration_number=getattr(customer, "registration_number", ""),
            vat_number=getattr(customer.tax_profile, "vat_number", "") if hasattr(customer, "tax_profile") else "",
        )

    @staticmethod
    @transaction.atomic
    def create_order(data: OrderCreateData, created_by: User | None = None) -> Result[Order, str]:
        """Create new order with validation and audit trail"""
        logger.warning(f"🧮 [OrderService] Starting order creation for customer {data.customer.id}")
        try:
            from .models import Order, OrderItem  # noqa: PLC0415

            # Generate order number
            order_number = OrderNumberingService.generate_order_number(data.customer)

            # Calculate financial totals using consistent VAT calculator
            totals = OrderCalculationService.calculate_order_totals(
                items=data.items, customer=data.customer, billing_address=dict(data.billing_address)
            )

            logger.warning(
                f"🧮 [OrderService] Calculated totals for order creation: subtotal={totals['subtotal_cents']}¢, tax={totals['tax_cents']}¢, total={totals['total_cents']}¢"
            )

            # Get currency instance (Currency already imported at top)
            currency_instance = Currency.objects.get(code=data.currency)

            # Create order
            order = Order.objects.create(
                order_number=order_number,
                customer=data.customer,
                currency=currency_instance,
                notes=data.notes,
                meta=data.meta,
                # Customer snapshot fields
                customer_email=data.customer.primary_email,
                customer_name=data.customer.name,
                customer_company=data.customer.company_name or "",
                customer_vat_id=getattr(data.customer.tax_profile, "vat_number", "")
                if hasattr(data.customer, "tax_profile")
                else "",
                # Billing address as JSON
                billing_address=dict(data.billing_address),
                # Financial totals
                **totals,
            )

            # Create order items
            for item_data in data.items:
                # Calculate line totals (include setup fee if provided) with VAT rules
                subtotal_cents = item_data["quantity"] * item_data["unit_price_cents"] + int(
                    item_data.get("setup_cents", 0)
                )

                # Determine VAT using comprehensive VAT rules (per customer country/business)
                try:
                    from .vat_rules import CustomerVATInfo, OrderVATCalculator  # noqa: PLC0415

                    # Extract customer VAT context from billing address snapshot
                    customer_country = (data.billing_address.get("country") or "RO").upper()
                    vat_number = data.billing_address.get("vat_number") or data.billing_address.get("vat_id") or ""
                    is_business = bool(data.billing_address.get("company_name")) or bool(vat_number)

                    customer_vat_info: CustomerVATInfo = {
                        "country": customer_country,
                        "is_business": is_business,
                        "vat_number": vat_number,
                        "customer_id": str(data.customer.id),
                        "order_id": None,
                    }

                    # Inject per-customer overrides (must match calculate_order_totals)
                    if hasattr(data.customer, "tax_profile"):
                        try:
                            tax_profile = data.customer.tax_profile
                            customer_vat_info["is_vat_payer"] = tax_profile.is_vat_payer
                            customer_vat_info["reverse_charge_eligible"] = tax_profile.reverse_charge_eligible
                            if tax_profile.vat_rate is not None:
                                customer_vat_info["custom_vat_rate"] = tax_profile.vat_rate
                        except (ObjectDoesNotExist, AttributeError):
                            pass  # No tax profile yet — use defaults

                    vat_result = OrderVATCalculator.calculate_vat(
                        subtotal_cents=subtotal_cents, customer_info=customer_vat_info
                    )
                    # Convert percent to decimal rate with 4 places for storage
                    tax_rate_decimal = (vat_result.vat_rate / Decimal("100")).quantize(Decimal("0.0001"))
                    tax_cents = int(vat_result.vat_cents)
                except Exception as e:
                    # Fallback to centralized VAT service if VAT rules fail
                    logger.warning(f"🔥 [OrderService] VAT calculation failed, using fallback: {e}")
                    from apps.common.tax_service import TaxService  # noqa: PLC0415

                    fallback_vat_result = TaxService.calculate_vat(
                        amount_cents=subtotal_cents,
                        country_code="RO",  # Conservative Romanian default
                    )
                    tax_rate_decimal = (fallback_vat_result["vat_rate_percent"] / Decimal("100")).quantize(
                        Decimal("0.0001")
                    )
                    tax_cents = fallback_vat_result["vat_cents"]

                line_total_cents = subtotal_cents + tax_cents

                # Handle optional product_id - if None, skip this item or handle appropriately
                product_id = item_data.get("product_id")
                if product_id is None:
                    continue  # Skip items without a product_id

                OrderItem.objects.create(
                    order=order,
                    product_id=product_id,
                    quantity=item_data["quantity"],
                    unit_price_cents=item_data["unit_price_cents"],
                    setup_cents=int(item_data.get("setup_cents", 0)),
                    tax_rate=tax_rate_decimal,
                    tax_cents=tax_cents,
                    line_total_cents=line_total_cents,
                    product_name=item_data["description"],
                    product_type="hosting",  # Default type
                    config=item_data.get("meta", {}),
                )

            # After creating items, ensure order totals are consistent with item data (includes setup fees)
            try:
                order.calculate_totals()
            except Exception:
                # Fallback to previously computed totals if calculation fails
                logger.warning("⚠️ [Orders] Failed to recalc totals after item creation; using precomputed totals")

            # Create status history entry
            OrderService._create_status_history(order, None, "draft", "Order created", created_by)

            # Log audit event
            log_security_event(
                "order_created",
                {
                    "order_number": order.order_number,
                    "customer_name": data.customer.name,
                    "order_id": str(order.id),
                    "customer_id": str(data.customer.id),
                    "total_cents": totals["total_cents"],
                    "user_id": str(created_by.id) if created_by else None,
                },
            )

            return Ok(order)

        except Exception as e:
            logger.exception(f"Failed to create order: {e}")
            return Err(f"Failed to create order: {e!s}")

    @staticmethod
    @transaction.atomic
    def update_order_status(order: Order, status_data: StatusChangeData) -> Result[Order, str]:
        """Update order status with validation and audit trail"""
        try:
            old_status = order.status

            # Validate status transition
            if not OrderService._is_valid_status_transition(old_status, status_data.new_status):
                return Err(f"Invalid status transition from {old_status} to {status_data.new_status}")

            # Enforce preflight validation on draft → pending
            if old_status == "draft" and status_data.new_status == "pending":
                try:
                    from .preflight import OrderPreflightValidationService  # noqa: PLC0415

                    OrderPreflightValidationService.assert_valid(order)
                    logger.info(
                        "✅ [Orders] Preflight validation passed for %s before pending",
                        order.order_number,
                    )
                except Exception as e:
                    logger.warning(
                        "⛔ [Orders] Preflight validation failed for %s: %s",
                        order.order_number,
                        e,
                    )
                    return Err(f"Preflight validation failed: {e!s}")

            # Update order status
            order.status = status_data.new_status
            order.save(update_fields=["status", "updated_at"])

            # Create status history entry
            OrderService._create_status_history(
                order, old_status, status_data.new_status, status_data.notes, status_data.changed_by
            )

            # Log audit event
            log_security_event(
                "order_status_changed",
                {
                    "order_number": order.order_number,
                    "order_id": str(order.id),
                    "old_status": old_status,
                    "new_status": status_data.new_status,
                    "user_id": str(status_data.changed_by.id) if status_data.changed_by else None,
                    "notes": status_data.notes,
                },
            )

            return Ok(order)

        except Exception as e:
            logger.exception(f"Failed to update order status: {e}")
            return Err(f"Failed to update order status: {e!s}")

    @staticmethod
    def _create_status_history(
        order: Order, old_status: str | None, new_status: str, notes: str, changed_by: User | None
    ) -> None:
        """Create order status history entry"""
        from .models import OrderStatusHistory  # noqa: PLC0415

        OrderStatusHistory.objects.create(
            order=order,
            old_status=old_status or "",  # Convert None to empty string
            new_status=new_status,
            notes=notes,
            changed_by=changed_by,
        )

    @staticmethod
    def _is_valid_status_transition(old_status: str, new_status: str) -> bool:
        """Validate order status transitions according to business rules"""

        # Define valid transitions based on Romanian business logic
        valid_transitions = {
            "draft": ["pending", "cancelled"],
            "pending": ["confirmed", "cancelled", "failed"],
            "confirmed": ["processing", "cancelled"],
            "processing": ["completed", "failed", "cancelled"],
            "completed": ["refunded", "partially_refunded"],  # Allow refunds from completed
            "cancelled": [],  # Terminal state
            "failed": ["pending", "cancelled"],  # Allow retry
            "refunded": [],  # Terminal state
            "partially_refunded": ["refunded"],  # Can complete refund
        }

        return new_status in valid_transitions.get(old_status, [])


# ===============================================================================
# ORDER SERVICE CREATION SERVICE
# ===============================================================================


class OrderServiceCreationService:
    """
    Service for creating Service records when orders become pending.

    This implements the industry standard approach where services are visible
    to customers immediately when an order becomes payable, following WHMCS/cPanel patterns.
    """

    @staticmethod
    @transaction.atomic
    def create_pending_services(order: Order) -> Result[list[Service], str]:
        """
        Create Service records for all order items when order transitions to pending.

        This makes services immediately visible in the customer's "My Services" section
        with status='pending', following industry best practices.

        Args:
            order: Order instance that is transitioning to pending status

        Returns:
            Result containing list of created services or error message
        """
        try:
            from apps.provisioning.models import Service  # noqa: PLC0415

            services_created = []

            logger.info(f"🔧 [ServiceCreation] Creating pending services for order {order.order_number}")

            for item in order.items.all():
                # Skip if service already exists for this item
                if item.service:
                    logger.info(f"🔧 [ServiceCreation] Service already exists for item {item.id}, skipping")
                    continue

                # Map product to service plan
                service_plan_result = OrderServiceCreationService._get_service_plan_for_product(item.product)
                if service_plan_result.is_err():
                    logger.warning(
                        f"⚠️ [ServiceCreation] Could not map product to service plan: {service_plan_result.error}"
                    )
                    continue

                service_plan = service_plan_result.unwrap()

                # Generate service name
                service_name = f"{item.product_name}"
                if item.domain_name:
                    service_name = f"{item.product_name} - {item.domain_name}"

                # Extract billing cycle from item config or use monthly as default
                billing_cycle = item.config.get("billing_cycle", "monthly")
                if billing_cycle not in ["monthly", "quarterly", "annual"]:
                    billing_cycle = "monthly"

                # Generate unique username (will be updated during provisioning)
                import time  # noqa: PLC0415

                username = f"tmp_{int(time.time())}_{order.id.hex[:8]}"

                # Create service with pending status
                service = Service.objects.create(
                    customer=order.customer,
                    service_plan=service_plan,
                    service_name=service_name,
                    domain=item.domain_name or "",
                    username=username,  # Temporary unique username
                    billing_cycle=billing_cycle,
                    price=item.unit_price / 100,  # Convert from cents to decimal
                    status="pending",  # Key status - visible to customer
                    # Link to order for tracking
                    admin_notes=f"Created from order {order.order_number}",
                )

                # Link the service to the order item
                item.service = service
                item.save(update_fields=["service"])

                services_created.append(service)

                logger.info(f"✅ [ServiceCreation] Created pending service {service.id} for item {item.id}")

                # Log audit event
                log_security_event(
                    "service_created_from_order",
                    {
                        "service_id": str(service.id),
                        "order_id": str(order.id),
                        "order_number": order.order_number,
                        "customer_id": str(order.customer.id),
                        "service_name": service.service_name,
                        "status": "pending",
                    },
                )

            if services_created:
                logger.info(
                    f"🎉 [ServiceCreation] Successfully created {len(services_created)} pending services for order {order.order_number}"
                )
            else:
                logger.info(
                    f"💡 [ServiceCreation] No new services created for order {order.order_number} (services may already exist)"
                )

            return Ok(services_created)

        except Exception as e:
            logger.exception(
                f"🔥 [ServiceCreation] Failed to create pending services for order {order.order_number}: {e}"
            )
            return Err(f"Failed to create pending services: {e}")

    @staticmethod
    def _get_service_plan_for_product(product: Product) -> Result[ServicePlan, str]:
        """
        Map a product to its corresponding service plan for service creation.

        This handles the Product → ServicePlan mapping needed for service creation.

        Args:
            product: Product instance from order item

        Returns:
            Result containing ServicePlan or error message
        """
        try:
            from apps.provisioning.models import ServicePlan  # noqa: PLC0415

            # Strategy 1: Check if product has a direct service plan reference
            if hasattr(product, "default_service_plan") and product.default_service_plan:
                return Ok(product.default_service_plan)

            # Strategy 2: Map based on product type
            product_type = product.product_type
            service_plan_mapping = {
                "shared_hosting": "shared_hosting",
                "vps": "vps",
                "dedicated": "dedicated",
                "cloud": "cloud",
                "domain": "domain",
                "ssl": "ssl",
                "email": "email",
                "backup": "backup",
            }

            plan_type = service_plan_mapping.get(product_type, "shared_hosting")

            # Find a service plan of the matching type
            service_plan = ServicePlan.objects.filter(plan_type=plan_type, is_active=True).first()

            if service_plan:
                logger.info(
                    f"🔧 [ServiceCreation] Mapped product {product.name} ({product_type}) to service plan {service_plan.name}"
                )
                return Ok(service_plan)

            # Strategy 3: Fallback to any active service plan
            fallback_plan = ServicePlan.objects.filter(is_active=True).first()
            if fallback_plan:
                logger.warning(
                    f"⚠️ [ServiceCreation] Using fallback service plan {fallback_plan.name} for product {product.name}"
                )
                return Ok(fallback_plan)

            return Err(f"No suitable service plan found for product {product.name} (type: {product_type})")

        except Exception as e:
            logger.exception(f"🔥 [ServiceCreation] Failed to map product to service plan: {e}")
            return Err(f"Failed to map product to service plan: {e}")

    @staticmethod
    def update_service_status_on_payment(order: Order) -> Result[list[Service], str]:
        """
        Update service status from 'pending' to 'provisioning' when payment is confirmed.

        This is called when order moves to 'processing' status after payment.

        Args:
            order: Order that has been paid

        Returns:
            Result containing list of updated services or error message
        """
        try:
            updated_services = []

            for item in order.items.all():
                if item.service and item.service.status == "pending":
                    item.service.status = "provisioning"
                    item.service.save(update_fields=["status"])
                    updated_services.append(item.service)

                    logger.info(f"🔄 [ServiceCreation] Updated service {item.service.id} status to provisioning")

                    # Log audit event
                    log_security_event(
                        "service_status_updated",
                        {
                            "service_id": str(item.service.id),
                            "order_id": str(order.id),
                            "old_status": "pending",
                            "new_status": "provisioning",
                            "reason": "payment_confirmed",
                        },
                    )

            return Ok(updated_services)

        except Exception as e:
            logger.exception(f"🔥 [ServiceCreation] Failed to update service status on payment: {e}")
            return Err(f"Failed to update service status: {e}")


# ===============================================================================
# ORDER QUERY SERVICE
# ===============================================================================


class OrderQueryService:
    """Service for order querying and filtering operations"""

    @staticmethod
    def get_orders_for_customer(customer: Customer, filters: OrderFilters | None = None) -> Result[list[Order], str]:
        """Get orders for a specific customer with optional filtering"""
        try:
            from .models import Order  # noqa: PLC0415

            queryset = Order.objects.filter(customer=customer).select_related("customer")

            if filters:
                if status := filters.get("status"):
                    queryset = queryset.filter(status=status)
                if order_number := filters.get("order_number"):
                    queryset = queryset.filter(order_number__icontains=order_number)
                if search := filters.get("search"):
                    queryset = queryset.filter(
                        models.Q(order_number__icontains=search)
                        | models.Q(customer_company__icontains=search)
                        | models.Q(customer_name__icontains=search)
                    )

            orders = list(queryset.order_by("-created_at"))
            return Ok(orders)

        except Exception as e:
            logger.exception(f"Failed to get orders for customer: {e}")
            return Err(f"Failed to get orders: {e!s}")

    @staticmethod
    def get_order_with_items(order_id: uuid.UUID, customer: Customer | None = None) -> Result[Order, str]:
        """Get order with related items, optionally scoped to customer"""
        try:
            from .models import Order  # noqa: PLC0415

            queryset = Order.objects.select_related("customer").prefetch_related(
                "items__product", "items__service", "status_history__changed_by"
            )

            if customer:
                queryset = queryset.filter(customer=customer)

            order = queryset.get(id=order_id)
            return Ok(order)

        except Order.DoesNotExist:
            return Err("Order not found")
        except Exception as e:
            logger.exception(f"Failed to get order with items: {e}")
            return Err(f"Failed to get order: {e!s}")
