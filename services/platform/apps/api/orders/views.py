"""
Order API Views for PRAHO Platform
DRF views for product catalog, order management, and cart calculations.
"""

import logging
import re
import uuid
from decimal import Decimal
from typing import Any

from django.core.cache import cache
from django.db import IntegrityError, transaction
from django.utils import timezone
from django.utils.translation import gettext_lazy as _
from rest_framework import status
from rest_framework.decorators import api_view, permission_classes, throttle_classes
from rest_framework.permissions import AllowAny
from rest_framework.request import Request
from rest_framework.response import Response
from rest_framework.throttling import ScopedRateThrottle

from apps.api.secure_auth import public_api_endpoint, require_customer_authentication
from apps.billing.models import Currency
from apps.common.request_ip import get_safe_client_ip
from apps.common.types import CurrencyCode, Err, Ok
from apps.customers.models import Customer
from apps.orders.models import Order
from apps.orders.preflight import OrderPreflightValidationService
from apps.orders.price_sealing import PriceSealingService
from apps.orders.services import OrderCreateData, OrderService, StatusChangeData
from apps.orders.vat_rules import CustomerVATInfo, OrderVATCalculator
from apps.products.models import Product, ProductPrice
from apps.provisioning.models import Service
from apps.provisioning.service_models import Server
from apps.provisioning.tasks import queue_service_provisioning

from .serializers import (
    CartCalculationInputSerializer,
    CartCalculationOutputSerializer,
    OrderCreateInputSerializer,
    OrderDetailSerializer,
    OrderListSerializer,
    ProductDetailSerializer,
    ProductListSerializer,
)

logger = logging.getLogger(__name__)

# Constants
ISO_COUNTRY_CODE_LENGTH = 2
IDEMPOTENCY_KEY_MIN_LENGTH = 16
IDEMPOTENCY_KEY_MAX_LENGTH = 64


# 🔒 SECURITY: Custom throttle classes for order endpoints
class OrderCreateThrottle(ScopedRateThrottle):
    """Throttling for order creation endpoints"""

    scope = "order_create"


class OrderCalculateThrottle(ScopedRateThrottle):
    """Throttling for cart calculation endpoints"""

    scope = "order_calculate"


class OrderListThrottle(ScopedRateThrottle):
    """Throttling for order listing endpoints"""

    scope = "order_list"


class ProductCatalogThrottle(ScopedRateThrottle):
    """Throttling for product catalog endpoints"""

    scope = "product_catalog"


@api_view(["GET"])
@permission_classes([AllowAny])
@throttle_classes([ProductCatalogThrottle])
@public_api_endpoint
def product_list(request: Request) -> Response:
    """
    Public endpoint — intentionally accessible without HMAC authentication.
    Product catalog information is not sensitive and must be accessible
    for the portal to display products to unauthenticated visitors.

    Supports filtering by product type and featured status.
    """

    # Get query parameters
    product_type = request.query_params.get("product_type")
    featured = request.query_params.get("featured") == "true"

    # Build queryset
    queryset = Product.objects.filter(is_active=True, is_public=True)

    if product_type:
        queryset = queryset.filter(product_type=product_type)

    if featured:
        queryset = queryset.filter(is_featured=True)

    # Order by sort_order, then by name
    queryset = queryset.prefetch_related("prices").order_by("sort_order", "name")

    # Serialize and return (pass request context for sealed price tokens)
    serializer = ProductListSerializer(queryset, many=True, context={"request": request})

    return Response({"results": serializer.data, "count": len(serializer.data)})


@api_view(["GET"])
@permission_classes([AllowAny])
@throttle_classes([ProductCatalogThrottle])
@public_api_endpoint
def product_detail(request: Request, slug: str) -> Response:
    """
    Public endpoint — intentionally accessible without HMAC authentication.
    Product catalog information is not sensitive and must be accessible
    for the portal to display products to unauthenticated visitors.
    """

    try:
        product = Product.objects.prefetch_related("prices").get(slug=slug, is_active=True, is_public=True)
    except Product.DoesNotExist:
        return Response({"error": "Product not found"}, status=status.HTTP_404_NOT_FOUND)

    serializer = ProductDetailSerializer(product, context={"request": request})
    return Response(serializer.data)


@api_view(["POST"])
@permission_classes([AllowAny])
@throttle_classes([OrderCalculateThrottle])
@require_customer_authentication
def calculate_cart_totals(  # noqa: PLR0912, PLR0915  # Complexity: multi-step business logic
    request: Request, customer: Customer
) -> Response:  # Complexity: order processing pipeline  # Complexity: multi-step business logic
    """
    Calculate cart totals with Romanian VAT compliance.
    Server-authoritative pricing - never trust client input.
    """

    logger.info(f"🛒 [Orders API] Cart calculation request from customer {customer.id}")
    logger.debug(f"🛒 [Orders API] Request data: {request.data}")

    # Validate input
    input_serializer = CartCalculationInputSerializer(data=request.data)
    if not input_serializer.is_valid():
        return Response(
            {"error": "Invalid input", "details": input_serializer.errors}, status=status.HTTP_400_BAD_REQUEST
        )

    validated_data = input_serializer.validated_data
    # customer parameter is injected by decorator and already validated
    customer_id = customer.id
    currency_code = validated_data["currency"]
    cart_items = validated_data["items"]

    try:
        # Get currency
        try:
            currency = Currency.objects.get(code=currency_code)
        except Currency.DoesNotExist:
            return Response({"error": f"Currency {currency_code} not supported"}, status=status.HTTP_400_BAD_REQUEST)

        # Convert cart items to internal format
        order_items = []
        warnings = []

        for item_data in cart_items:
            try:
                product_id = item_data.get("product_id")
                product_slug = item_data.get("product_slug")
                if product_id:
                    product = Product.objects.get(id=product_id, is_active=True, is_public=True)
                elif product_slug:
                    product = Product.objects.get(slug=product_slug, is_active=True, is_public=True)
                else:
                    warnings.append(
                        {"type": "missing_identifier", "message": "Cart item missing product_id and product_slug"}
                    )
                    continue

                # Get current pricing (server-authoritative)
                try:
                    product_price = ProductPrice.objects.get(product=product, currency=currency, is_active=True)
                except ProductPrice.DoesNotExist:
                    warnings.append(
                        {
                            "type": "pricing_unavailable",
                            "product_name": product.name,
                            "message": f"Pricing not available for {product.name}",
                        }
                    )
                    continue

                # Build order item data (include setup fee for accurate totals)
                # Include product_slug + billing_period as stable identifiers so callers
                # can map per-item totals deterministically (not by list index).
                order_items.append(
                    {
                        "product_id": product.id,
                        "product_slug": product.slug,
                        "billing_period": item_data.get("billing_period", "monthly"),
                        "quantity": item_data["quantity"],
                        "unit_price_cents": int(product_price.effective_monthly_price_cents),
                        "setup_cents": int(product_price.setup_cents),
                        "description": product.name,
                        "meta": item_data.get("config", {}),
                    }
                )

            except Product.DoesNotExist:
                identifier = item_data.get("product_id") or item_data.get("product_slug", "unknown")
                warnings.append({"type": "product_not_found", "message": f"Product not found: {identifier}"})

        # 🔒 SECURITY: Calculate totals with proper VAT compliance
        # Get customer for VAT calculation - DEFAULT TO ROMANIAN SETTINGS for compliance
        try:
            customer_obj = customer  # Already injected by @require_customer_authentication
            customer_country = getattr(customer_obj, "country", "RO") or "RO"
            is_business = bool(getattr(customer_obj, "company_name", ""))
            vat_number = (
                getattr(customer_obj.tax_profile, "vat_number", "") if hasattr(customer_obj, "tax_profile") else ""
            )

            # Normalize country - default to RO for compliance if unclear
            if not customer_country or customer_country.strip() == "":
                customer_country = "RO"
        except Customer.DoesNotExist:
            # Default to Romanian consumer for compliance
            customer_country = "RO"
            is_business = False
            vat_number = ""

        # Calculate subtotal from order items
        subtotal_cents = sum(item["unit_price_cents"] * item["quantity"] + item["setup_cents"] for item in order_items)

        # Calculate VAT with full compliance
        customer_vat_info: CustomerVATInfo = {
            "country": customer_country,
            "is_business": is_business,
            "vat_number": vat_number,
            "customer_id": str(customer_id),
            "order_id": "cart-calculation",
        }
        vat_result = OrderVATCalculator.calculate_vat(subtotal_cents=subtotal_cents, customer_info=customer_vat_info)

        totals = {
            "subtotal_cents": vat_result.subtotal_cents,
            "tax_cents": vat_result.vat_cents,
            "total_cents": vat_result.total_cents,
        }

        # Prepare response
        response_data = {
            "subtotal_cents": totals["subtotal_cents"],
            "tax_cents": totals["tax_cents"],
            "total_cents": totals["total_cents"],
            "vat_rate_percent": round(vat_result.vat_rate),
            "currency": currency_code,
            "warnings": warnings,
            "items": [
                {
                    "product_name": item["description"],
                    "product_slug": item["product_slug"],
                    "billing_period": item["billing_period"],
                    "quantity": item["quantity"],
                    "unit_price_cents": item["unit_price_cents"],
                    "setup_cents": item["setup_cents"],
                    "line_total_cents": item["unit_price_cents"] * item["quantity"] + item["setup_cents"],
                }
                for item in order_items
            ],
        }

        # Validate output
        output_serializer = CartCalculationOutputSerializer(data=response_data)
        if output_serializer.is_valid():
            logger.info(f"💰 [API] Cart calculated: {totals['total_cents']} cents for customer {customer_id}")
            return Response(output_serializer.validated_data)
        else:
            logger.error(f"🔥 [API] Output serializer error: {output_serializer.errors}")
            return Response({"error": "Calculation error"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    except Exception as e:
        logger.exception(f"🔥 [API] Cart calculation failed: {e}")
        return Response({"error": "Calculation failed"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


def _resolve_currency(raw_code: object) -> tuple[Currency | None, Response | None]:
    """Validate and resolve a currency code to a Currency instance.

    Returns (currency, None) on success or (None, error_response) on failure.
    """
    if not isinstance(raw_code, str):
        return None, Response(
            {"success": False, "errors": ["Currency code must be a string"], "warnings": []},
            status=status.HTTP_400_BAD_REQUEST,
        )
    code = raw_code.strip().upper()
    if not CurrencyCode.is_supported(code):
        return None, Response(
            {"success": False, "errors": [f"Unsupported currency: {code}"], "warnings": []},
            status=status.HTTP_400_BAD_REQUEST,
        )
    try:
        return Currency.objects.get(code=code), None
    except Currency.DoesNotExist:
        logger.error("Currency %s passes enum check but has no DB record", code)
        return None, Response(
            {"success": False, "errors": [f"Currency {code} is not configured"], "warnings": []},
            status=status.HTTP_400_BAD_REQUEST,
        )


@api_view(["POST"])
@permission_classes([AllowAny])  # No permissions required (auth handled by secure_auth)
@throttle_classes([OrderCalculateThrottle])
@require_customer_authentication
def preflight_order(  # noqa: PLR0911, PLR0915  # Complexity: multi-step business logic
    request: Request, customer: Customer
) -> Response:  # Complexity: order processing pipeline  # Complexity: multi-step business logic
    """
    🔎 Preflight validation for portal checkout.
    Validates customer profile, product/price availability, VAT scenario, and returns errors/warnings + totals preview.
    """
    logger.info(f"🔎 [API] Running preflight validation for customer {customer.id}")

    try:
        # Parse cart items from request
        cart_items = request.data.get("items", [])
        logger.info(f"🔎 [API] Cart items structure: {cart_items}")
        if not cart_items:
            return Response(
                {
                    "success": False,
                    "errors": ["Cart is empty"],
                    "warnings": [],
                },
                status=status.HTTP_400_BAD_REQUEST,
            )

        # Create a preview order data structure (without saving to DB)
        currency, error_response = _resolve_currency(request.data.get("currency", "RON"))
        if error_response is not None:
            return error_response

        # Build billing address from customer profile
        billing_address = OrderService.build_billing_address_from_customer(customer)
        logger.info(f"🔎 [API] Billing address data: {dict(billing_address)}")

        # Process cart items and create preview order items
        preview_items = []
        subtotal_cents = 0

        for cart_item in cart_items:
            # Get product and pricing — resolve by UUID or slug
            try:
                product_id = cart_item.get("product_id")
                product_slug = cart_item.get("product_slug")
                if product_id:
                    product = Product.objects.get(id=product_id, is_active=True, is_public=True)
                elif product_slug:
                    product = Product.objects.get(slug=product_slug, is_active=True, is_public=True)
                else:
                    return Response(
                        {
                            "success": False,
                            "errors": ["Cart item missing product_id and product_slug"],
                            "warnings": [],
                        },
                        status=status.HTTP_400_BAD_REQUEST,
                    )
                logger.info(f"🔎 [API] Found product: {product.name} (id={product.id})")

                price = product.get_price_for_period(currency.code, cart_item["billing_period"])
                logger.info(f"🔎 [API] Price lookup: {price} for {currency.code}/{cart_item['billing_period']}")
                if not price:
                    return Response(
                        {
                            "success": False,
                            "errors": [f"No price available for {product.name} - {cart_item['billing_period']}"],
                            "warnings": [],
                        },
                        status=status.HTTP_400_BAD_REQUEST,
                    )

                quantity = int(cart_item.get("quantity", 1))
                unit_price_cents = int(price.effective_monthly_price_cents)
                setup_cents = int(price.setup_cents or 0)

                # Calculate line total
                line_total = (unit_price_cents * quantity) + setup_cents
                subtotal_cents += line_total

                logger.info(
                    f"🔎 [API] Line calculation: {unit_price_cents}¢ x {quantity} + {setup_cents}¢ = {line_total}¢ (subtotal now: {subtotal_cents}¢)"
                )

                preview_items.append(
                    {
                        "product_name": product.name,
                        "product_id": product.id,
                        "billing_period": cart_item["billing_period"],
                        "quantity": quantity,
                        "unit_price_cents": unit_price_cents,
                        "setup_cents": setup_cents,
                    }
                )

            except Product.DoesNotExist:
                identifier = product_id or product_slug
                return Response(
                    {
                        "success": False,
                        "errors": [f"Product not found: {identifier}"],
                        "warnings": [],
                    },
                    status=status.HTTP_400_BAD_REQUEST,
                )

        # Calculate VAT using the VAT calculator
        company_name = billing_address.get("company_name", "")
        vat_number = billing_address.get("vat_number", "")
        country_raw = billing_address.get("country", "România")

        # Normalize country name to ISO code for VAT calculation - DEFAULT TO RO for compliance
        if country_raw in ["România", "Romania", "RO", ""] or not country_raw:
            country = "RO"
        else:
            country = country_raw.upper().strip()
            # If country code looks invalid, default to RO for compliance
            if len(country) != ISO_COUNTRY_CODE_LENGTH:
                country = "RO"
        is_business = bool(company_name)

        logger.info(
            f"🔎 [API] VAT calculation inputs: subtotal={subtotal_cents}¢, country={country}, is_business={is_business}, vat_number={vat_number}"
        )

        customer_vat_info: CustomerVATInfo = {
            "country": country,
            "is_business": is_business,
            "vat_number": vat_number or None,
            "customer_id": str(customer.id),
            "order_id": "preflight-preview",
        }
        vat_result = OrderVATCalculator.calculate_vat(subtotal_cents=subtotal_cents, customer_info=customer_vat_info)

        # Create a temporary order object for validation (not saved to DB)
        # Normalize billing address for validation (ensure country is ISO code)
        normalized_billing_address = dict(billing_address)
        normalized_billing_address["country"] = country  # Use the normalized country code

        temp_order = Order(
            id=uuid.uuid4(),
            customer=customer,
            currency=currency,
            status="draft",
            billing_address=normalized_billing_address,
            subtotal_cents=subtotal_cents,
            tax_cents=int(vat_result.vat_cents),
            total_cents=int(vat_result.total_cents),
        )

        # Mark as preflight order so validation uses our computed subtotal and cached VAT result.
        # Caching vat_result avoids a duplicate OrderVATCalculator.calculate_vat call inside validate().
        temp_order._preflight_subtotal_cents = subtotal_cents
        temp_order._preflight_vat_result = vat_result

        # Run preflight validation on the temporary order
        logger.info(
            f"🔎 [API] Running validation with subtotal={subtotal_cents}¢, tax={temp_order.tax_cents}¢, total={temp_order.total_cents}¢"
        )
        errors, warnings = OrderPreflightValidationService.validate(temp_order)

        # Convert errors to strings
        error_messages = [str(error) for error in errors]
        warning_messages = [str(warning) for warning in warnings]

        success = len(error_messages) == 0

        logger.info(
            f"🔎 [API] Preflight validation complete: success={success}, errors={len(error_messages)}, warnings={len(warning_messages)}"
        )

        return Response(
            {
                "success": success,
                "errors": error_messages,
                "warnings": warning_messages,
                "preview": {
                    "currency": currency.code,
                    "subtotal_cents": subtotal_cents,
                    "vat_cents": int(vat_result.vat_cents),
                    "total_cents": int(vat_result.total_cents),
                    "vat_reasoning": vat_result.reasoning,
                },
            }
        )

    except Exception:
        logger.exception("🔥 [API] Preflight validation failed for customer %s", customer.id)
        return Response(
            {
                "success": False,
                "errors": [str(_("Order validation encountered an unexpected error. Please try again."))],
                "warnings": [],
            },
            status=status.HTTP_500_INTERNAL_SERVER_ERROR,
        )


@api_view(["POST"])
@permission_classes([AllowAny])  # No permissions required (auth handled by secure_auth)
@throttle_classes([OrderCreateThrottle])
@require_customer_authentication
def create_order(  # noqa: C901, PLR0911, PLR0912, PLR0915  # Complexity: multi-step business logic
    request: Request, customer: Customer
) -> Response:  # Complexity: order processing pipeline  # Complexity: multi-step business logic
    """
    Create order from cart items with server-side pricing resolution.
    Supports idempotency keys to prevent duplicate orders and race conditions.
    """

    # 🔒 SECURITY: Extract and validate idempotency key
    idempotency_key = request.headers.get("Idempotency-Key") or request.data.get("idempotency_key")
    if not idempotency_key:
        return Response(
            {"error": "Idempotency-Key header or idempotency_key field required"}, status=status.HTTP_400_BAD_REQUEST
        )

    if len(idempotency_key) < IDEMPOTENCY_KEY_MIN_LENGTH or len(idempotency_key) > IDEMPOTENCY_KEY_MAX_LENGTH:
        return Response(
            {"error": "Idempotency key must be between 16-64 characters"}, status=status.HTTP_400_BAD_REQUEST
        )

    # 🔒 SECURITY: Validate key content to prevent cache key injection (M10)
    if not re.match(r"^[a-zA-Z0-9_-]+$", idempotency_key):
        return Response(
            {"error": "Idempotency key must contain only alphanumeric characters, hyphens, and underscores"},
            status=status.HTTP_400_BAD_REQUEST,
        )

    # 🔒 SECURITY: Check for existing order with this idempotency key
    cache_key = f"idempotency:order:{customer.id}:{idempotency_key}"
    existing_order_id = cache.get(cache_key)

    if existing_order_id:
        logger.info(f"🔄 [API] Returning existing order for idempotency key: {idempotency_key[:8]}...")
        try:
            existing_order = Order.objects.get(id=existing_order_id, customer=customer)
            serializer = OrderDetailSerializer(existing_order)
            return Response(
                {
                    "success": True,
                    "order": serializer.data,
                    "duplicate": True,  # Indicate this was a duplicate request
                },
                status=status.HTTP_200_OK,
            )
        except Order.DoesNotExist:
            # Order was deleted, clear cache and continue with creation
            cache.delete(cache_key)

    # DB fallback: check database for existing order when cache misses.
    # Runs BEFORE input validation so that retries with slightly different payloads
    # still return the existing order (correct idempotency semantics).
    if idempotency_key:
        db_existing = Order.objects.filter(customer=customer, idempotency_key=idempotency_key).first()
        if db_existing:
            logger.info(f"🔄 [API] DB fallback: found existing order for idempotency key: {idempotency_key[:8]}...")
            # Re-warm the cache for future lookups
            cache.set(cache_key, str(db_existing.id), timeout=3600)
            serializer = OrderDetailSerializer(db_existing)
            return Response(
                {
                    "success": True,
                    "order": serializer.data,
                    "duplicate": True,
                },
                status=status.HTTP_200_OK,
            )

    # Validate input after idempotency checks
    input_serializer = OrderCreateInputSerializer(data=request.data)
    if not input_serializer.is_valid():
        return Response(
            {"error": "Invalid input", "details": input_serializer.errors}, status=status.HTTP_400_BAD_REQUEST
        )

    validated_data = input_serializer.validated_data
    # customer parameter is injected by decorator and already validated
    customer_id = customer.id

    try:
        # Convert input to OrderCreateData
        # Build billing address from customer data (fetched from database)
        billing_address_data = OrderService.build_billing_address_from_customer(customer)

        # 🔒 SECURITY: Resolve product pricing with sealed token validation
        order_items = []
        price_warnings = []
        currency_code = validated_data["currency"]

        for item_data in validated_data["items"]:
            # Fetch product and price — resolve by UUID or slug
            try:
                product_id = item_data.get("product_id")
                product_slug = item_data.get("product_slug")
                if product_id:
                    product = Product.objects.get(id=product_id, is_active=True, is_public=True)
                elif product_slug:
                    product = Product.objects.get(slug=product_slug, is_active=True, is_public=True)
                else:
                    return Response(
                        {"error": "Cart item missing product_id and product_slug"},
                        status=status.HTTP_400_BAD_REQUEST,
                    )
            except Product.DoesNotExist:
                identifier = product_id or product_slug
                return Response(
                    {"error": f"Product not found: {identifier}"},
                    status=status.HTTP_400_BAD_REQUEST,
                )

            billing_period = item_data["billing_period"]
            price = product.get_price_for_period(currency_code, billing_period)
            if not price:
                return Response(
                    {"error": f"Pricing not available for {product.slug} ({billing_period}/{currency_code})"},
                    status=status.HTTP_400_BAD_REQUEST,
                )

            # 🔒 SECURITY: Validate sealed price token if provided
            sealed_token = item_data.get("sealed_price_token", "").strip()
            validated_price_data = None
            product_price_id_snapshot = price.id  # Default to current price ID

            if sealed_token:
                try:
                    # Get client IP for validation
                    client_ip = get_safe_client_ip(request)

                    # Unseal and validate token with IP binding
                    unsealed_data = PriceSealingService.unseal_price(sealed_token, client_ip)
                    validated_data_result = PriceSealingService.validate_price_against_database(
                        unsealed_data, expected_product_price_id=price.id
                    )

                    if validated_data_result["price_changed"]:
                        # Price has changed since token was created - add warning
                        price_warnings.append(
                            {
                                "type": "price_changed",
                                "product_name": product.name,
                                "message": f"Price for {product.name} has changed since added to cart",
                                "old_amount_cents": validated_data_result["sealed_amount_cents"],
                                "new_amount_cents": validated_data_result["current_amount_cents"],
                            }
                        )
                        logger.warning(
                            f"🔒 [API] Price changed for {product.slug}: "
                            f"{validated_data_result['sealed_amount_cents']} -> {validated_data_result['current_amount_cents']} cents"
                        )

                    validated_price_data = validated_data_result
                    product_price_id_snapshot = validated_data_result["product_price_id"]

                    logger.info(f"🔒 [API] Price token validated for {product.slug}")

                except Exception as e:
                    logger.error(f"🔥 [API] Price token validation failed for {product.slug}: {e}")
                    return Response(
                        {"error": f"Invalid sealed price token for {product.name}"},
                        status=status.HTTP_400_BAD_REQUEST,
                    )

            # Build order item with price snapshot in meta
            item_meta = item_data.get("config", {})
            item_meta["product_price_id"] = str(product_price_id_snapshot)  # 🔒 SECURITY: Snapshot ProductPrice.id
            if validated_price_data:
                item_meta["price_validation"] = {
                    "token_validated": True,
                    "price_changed": validated_price_data["price_changed"],
                    "validated_at": timezone.now().isoformat(),
                }

            order_items.append(
                {
                    "product_id": product.id,
                    "service_id": None,  # Not used for new orders
                    "quantity": item_data["quantity"],
                    "unit_price_cents": int(price.effective_monthly_price_cents),
                    "setup_cents": int(price.setup_cents),
                    "billing_period": billing_period,
                    "description": product.name,
                    "meta": item_meta,  # Include price snapshot
                }
            )

        order_create_data = OrderCreateData(
            customer=customer,
            items=order_items,  # type: ignore[arg-type]
            billing_address=billing_address_data,
            currency=validated_data["currency"],
            notes=validated_data.get("notes", ""),
            meta=validated_data.get("meta", {}),
            idempotency_key=idempotency_key,
        )

        # Create order using platform service (idempotency_key set atomically in create_order)
        try:
            result = OrderService.create_order(order_create_data)
        except IntegrityError as exc:
            # 🔒 SECURITY: Only catch idempotency race conditions — not financial check constraints.
            # The Order model has CheckConstraints (subtotal_non_negative, tax_non_negative, etc.)
            # that also raise IntegrityError. Re-raise immediately for any non-idempotency violation.
            if not any(marker in str(exc) for marker in Order._NON_RETRYABLE_CONSTRAINT_MARKERS):
                raise
            # Race condition — concurrent request already created an order with this idempotency key.
            # Return the existing order instead of failing.
            existing = Order.objects.filter(customer=customer, idempotency_key=idempotency_key).first()
            if existing:
                logger.info(f"🔄 [API] Idempotency race resolved: returning existing order {existing.order_number}")
                serializer = OrderDetailSerializer(existing)
                # Re-warm cache for future lookups
                cache_key = f"idempotency:order:{customer.id}:{idempotency_key}"
                cache.set(cache_key, str(existing.id), timeout=3600)
                return Response(
                    {"success": True, "order": serializer.data, "duplicate": True},
                    status=status.HTTP_200_OK,
                )
            # Idempotency constraint but no matching order found — re-raise as unexpected
            raise

        if isinstance(result, Ok):
            order = result.value
            serializer = OrderDetailSerializer(order)

            # Auto-pending promote if requested
            auto_pending = bool(request.data.get("auto_pending"))
            promoted = False
            preflight = None
            if auto_pending:
                try:
                    status_change = StatusChangeData(
                        new_status="pending", notes="Auto-pending from API", changed_by=None
                    )
                    promote_result = OrderService.update_order_status(order, status_change)
                    if promote_result.is_ok():
                        order.refresh_from_db()
                        promoted = True
                        serializer = OrderDetailSerializer(order)
                    else:
                        # Collect preflight errors for client visibility
                        errs, warns = OrderPreflightValidationService.validate(order)
                        preflight = {"errors": errs, "warnings": warns}
                except Exception as e:
                    logger.warning(f"⚠️ [API] Auto-pending failed for {order.order_number}: {e}")

            # 🔒 SECURITY: Store idempotency key in cache to prevent duplicate orders
            cache_key = f"idempotency:order:{customer.id}:{idempotency_key}"
            cache.set(cache_key, str(order.id), timeout=3600)  # Store for 1 hour

            logger.info(
                f"📦 [API] Order created: {order.order_number} for customer {customer_id} (idempotency: {idempotency_key[:8]}...)"
            )

            return Response(
                {
                    "success": True,
                    "order": serializer.data,
                    "auto_pending_attempted": auto_pending,
                    "promoted_to_pending": promoted,
                    "preflight": preflight,
                },
                status=status.HTTP_201_CREATED,
            )
        else:
            logger.error(f"🔥 [API] Order creation failed: {result.error}")
            return Response({"error": result.error}, status=status.HTTP_400_BAD_REQUEST)

    except Exception as e:
        logger.exception(f"🔥 [API] Order creation exception: {e}")
        return Response({"error": "Order creation failed"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@api_view(["POST"])
@permission_classes([AllowAny])  # No permissions required (auth handled by secure_auth)
@throttle_classes([OrderListThrottle])
@require_customer_authentication
def order_list(request: Request, customer: Customer) -> Response:
    """
    List orders for authenticated customer.
    """

    # customer parameter is injected by decorator and already validated
    customer_id = customer.id

    try:
        # Get customer orders
        orders = Order.objects.filter(customer_id=customer_id).order_by("-created_at")

        # Apply filters from request body
        request_data = request.data
        status_filter = request_data.get("status")
        if status_filter:
            orders = orders.filter(status=status_filter)

        serializer = OrderListSerializer(orders, many=True)

        return Response({"results": serializer.data, "count": len(serializer.data)})

    except Exception as e:
        logger.exception(f"🔥 [API] Order list failed: {e}")
        return Response({"error": "Failed to load orders"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@api_view(["POST"])
@permission_classes([AllowAny])  # No permissions required (auth handled by secure_auth)
@throttle_classes([OrderListThrottle])
@require_customer_authentication
def order_detail(request: Request, customer: Customer, order_id: str) -> Response:
    """
    Get order details for authenticated customer.
    """

    # customer parameter is injected by decorator and already validated
    customer_id = customer.id

    try:
        order = Order.objects.prefetch_related("items").get(id=order_id, customer_id=customer_id)

        serializer = OrderDetailSerializer(order)
        return Response(serializer.data)

    except Order.DoesNotExist:
        return Response({"error": "Order not found"}, status=status.HTTP_404_NOT_FOUND)
    except Exception as e:
        logger.exception(f"🔥 [API] Order detail failed: {e}")
        return Response({"error": "Failed to load order"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


def _get_server_for_product_type(product_type: str, server_model: Any) -> tuple[Any | None, bool]:
    """Resolve the best active provisioning server for a product type."""
    server_type_map = {
        "shared_hosting": "shared_hosting",
        "vps": "vps_host",
    }
    mapped_server_type = server_type_map.get(product_type)
    if mapped_server_type:
        server = server_model.objects.filter(server_type=mapped_server_type, status="active").first()
        if server:
            return server, False

    fallback_server = server_model.objects.filter(status="active").first()
    return fallback_server, fallback_server is not None


def _provision_confirmed_order_item(item: Any, customer: Any, order: Any) -> dict[str, Any]:
    """Provision one confirmed order item and return API-safe result data."""
    try:
        if not item.product.default_service_plan:
            logger.error(f"❌ Product {item.product.name} has no default_service_plan configured")
            return {
                "product": item.product.name,
                "error": "Product has no default service plan configured",
            }

        username_suffix = str(uuid.uuid4()).replace("-", "")[:8]
        username = f"{customer.id}_{username_suffix}"

        server, used_fallback = _get_server_for_product_type(item.product.product_type, Server)
        if server is None:
            logger.error("No active provisioning server for %s", item.product.product_type)
            return {"product": item.product.name, "error": "No provisioning server available"}
        if used_fallback:
            logger.warning("Using fallback server %s for %s", server.name, item.product_name)

        service = Service.objects.create(
            customer=customer,
            service_plan=item.product.default_service_plan,
            currency=order.currency,
            status="pending",
            service_name=item.product_name,
            domain=item.domain_name or "",
            username=username,
            billing_cycle="monthly",
            price=Decimal(item.unit_price_cents) / Decimal(100),
            setup_fee_paid=item.setup_cents > 0,
            server=server,
            provisioning_data={
                "order_id": str(order.id),
                "order_number": order.order_number,
                "order_item_id": str(item.id),
                "config": item.config or {},
            },
        )

        task_id = queue_service_provisioning(service)
        logger.info(f"🚀 Service provisioning initiated for {item.product.name}")
        return {
            "product": item.product.name,
            "service_id": str(service.id),
            "status": "queued",
            "task_id": task_id,
        }
    except Exception as e:
        logger.error(f"❌ Failed to provision service for {item.product.name}: {e}")
        return {"product": item.product.name, "error": "Provisioning failed"}


@api_view(["POST"])
@permission_classes([AllowAny])
@throttle_classes([OrderListThrottle])
@require_customer_authentication
def confirm_order(request: Request, customer: Customer, order_id: str) -> Response:  # noqa: PLR0911
    """
    Confirm order after successful payment and trigger service provisioning.
    """
    try:
        payment_intent_id = request.data.get("payment_intent_id")
        payment_status = request.data.get("payment_status")

        # Use atomic transaction for order confirmation and service creation
        with transaction.atomic():
            # Get order with row-level lock to prevent double-confirmation.
            # of=("self",) locks only the Order row, not related tables.
            order = (
                Order.objects.select_for_update(of=("self",))
                .prefetch_related("items")
                .get(id=order_id, customer_id=customer.id)
            )

            # Verify PaymentIntent belongs to this order (prevent cross-binding)
            if payment_intent_id:
                # M1: Validate Stripe PI ID format before doing anything with it.
                # Stripe PI IDs always match pi_[a-zA-Z0-9]{10,64}.
                # Coerce to str first — DRF may pass non-string types from JSON payloads.
                if not isinstance(payment_intent_id, str) or not re.match(
                    r"^pi_[a-zA-Z0-9]{10,64}$", payment_intent_id
                ):
                    return Response(
                        {"success": False, "error": "Invalid payment intent ID format"},
                        status=status.HTTP_400_BAD_REQUEST,
                    )
                # H2: Only allow PI binding on card-compatible orders.
                # Portal-created orders have blank payment_method (it's not set during creation).
                # A valid PI proves card payment, so promote blank → "card".
                # Reject only orders explicitly set to a non-card method (e.g., bank_transfer).
                if order.payment_method and order.payment_method != "card":
                    return Response(
                        {"success": False, "error": "Order payment method does not accept payment intents"},
                        status=status.HTTP_400_BAD_REQUEST,
                    )
                if not order.payment_method:
                    order.payment_method = "card"
                # Reject mismatched PI when order already has one assigned
                if order.payment_intent_id and payment_intent_id != order.payment_intent_id:
                    return Response(
                        {"success": False, "error": "Payment intent does not match this order"},
                        status=status.HTTP_400_BAD_REQUEST,
                    )

            # Idempotency guard — prevent double-processing
            if order.status not in ["pending"]:
                return Response(
                    {"success": False, "error": "Order already processed"},
                    status=status.HTTP_409_CONFLICT,
                )

            # Set payment_intent_id (and payment_method if promoted above) before
            # status change so the audit trail includes them.
            if payment_intent_id is not None:
                order.payment_intent_id = payment_intent_id
                order.save(update_fields=["payment_intent_id", "payment_method"])

            # Use OrderService.update_order_status() for proper state machine validation
            # and OrderStatusHistory creation (audit trail for this legally-significant transition).
            audit_user = None
            if hasattr(request, "user") and request.user.is_authenticated:
                audit_user = request.user

            status_change = StatusChangeData(
                new_status="confirmed",
                notes=f"Payment confirmed (PI: {payment_intent_id or 'N/A'}, status: {payment_status})",
                changed_by=audit_user,
            )
            status_result = OrderService.update_order_status(order, status_change)
            if isinstance(status_result, Err):
                logger.warning(
                    "⚠️ [API] Status update failed for order %s: %s",
                    order.order_number,
                    status_result.error,
                )
                return Response(
                    {"success": False, "error": "Order cannot be confirmed in its current state"},
                    status=status.HTTP_409_CONFLICT,
                )
            order.refresh_from_db()
            logger.info(f"✅ Order {order.order_number} confirmed after payment")

            # Collect provisionable items inside the atomic block, but dispatch outside
            provisionable_items = [
                item
                for item in order.items.all()
                if item.product.product_type in {"shared_hosting", "vps", "dedicated_server"}
            ]

        # Trigger service provisioning AFTER the transaction commits
        # to avoid dispatching work that references uncommitted data.
        provisioning_results = [_provision_confirmed_order_item(item, customer, order) for item in provisionable_items]

        return Response(
            {
                "success": True,
                "order_id": str(order.id),
                "order_number": order.order_number,
                "status": order.status,
                "provisioning": provisioning_results,
            }
        )

    except Order.DoesNotExist:
        return Response({"success": False, "error": "Order not found"}, status=status.HTTP_404_NOT_FOUND)
    except Exception as e:
        logger.exception(f"🔥 [API] Order confirmation failed: {e}")
        return Response(
            {"success": False, "error": "Failed to confirm order"},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR,
        )
