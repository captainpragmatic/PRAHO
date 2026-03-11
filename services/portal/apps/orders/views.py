"""
Order Views for PRAHO Portal
Product catalog, cart management, and order creation with Romanian compliance.
"""

import contextlib
import dataclasses
import functools
import hashlib
import hmac as _hmac_module
import json
import logging
import re
import time as _time_module
import uuid
from collections.abc import Callable
from datetime import UTC, datetime
from decimal import ROUND_HALF_EVEN, Decimal, InvalidOperation
from typing import Any
from urllib.parse import quote as _url_quote

from django.conf import settings
from django.contrib import messages
from django.core.cache import cache
from django.core.exceptions import ValidationError
from django.http import HttpRequest, HttpResponse, JsonResponse
from django.shortcuts import redirect, render
from django.urls import reverse_lazy
from django.utils import timezone
from django.utils.translation import gettext as _
from django.utils.translation import gettext_lazy as _l
from django.views.decorators.http import require_http_methods

from apps.api_client.services import PlatformAPIClient, PlatformAPIError
from apps.common.rate_limit_feedback import get_rate_limit_message, is_rate_limited_error
from apps.common.request_ip import get_safe_client_ip

from .security import OrderSecurityHardening
from .services import (
    CartCalculationService,
    GDPRCompliantCartSession,
    HMACPriceSealer,
    OrderCreationService,
)
from .validators import OrderInputValidator

logger = logging.getLogger(__name__)
MINI_CART_MAX_ITEMS = 3

ORDER_STEPS = [
    {"label": _l("Product Selection"), "icon": "orders", "url": reverse_lazy("orders:catalog")},
    {"label": _l("Cart Review"), "icon": "orders", "url": reverse_lazy("orders:cart_review")},
    {"label": _l("Checkout"), "icon": "credit-card", "url": reverse_lazy("orders:checkout")},
    {"label": _l("Confirmation"), "icon": "check"},
]


def _coerce_security_response(result: HttpResponse | object | None) -> HttpResponse | None:
    """
    Normalize security hardening hook responses.
    Tests sometimes patch these hooks with plain Mocks that only carry status_code.
    """
    if result is None:
        return None
    if isinstance(result, HttpResponse):
        return result

    status_code = getattr(result, "status_code", 400)
    try:
        status_code = int(status_code)
    except (TypeError, ValueError):
        status_code = 400

    return JsonResponse({"error": _("Request blocked by security policy.")}, status=status_code)


HTTP_UNPROCESSABLE_ENTITY = 422


def _cart_error_response(
    request: HttpRequest,
    template: str,
    context: dict[str, Any],
) -> HttpResponse:
    """Return an HTMX-friendly error response with retarget headers.

    Uses HTTP 422 so HTMX's ``event.detail.successful`` is False,
    preventing success toasts on error. HX-Retarget/HX-Reswap headers
    instruct HTMX where to render the error fragment.
    """
    response = render(request, template, context, status=HTTP_UNPROCESSABLE_ENTITY)
    response["HX-Retarget"] = "#cart-notifications"
    response["HX-Reswap"] = "innerHTML"
    return response


def require_customer_authentication(view_func: Callable[..., Any]) -> Any:
    """Decorator to ensure customer is authenticated"""

    @functools.wraps(view_func)
    def wrapper(request: HttpRequest, *args: Any, **kwargs: Any) -> Any:
        # Try request attributes first (set by middleware), fallback to session
        customer_id = getattr(request, "customer_id", None)
        user_id = getattr(request, "user_id", None)

        # Fallback: Try to get from session if not set by middleware
        if not user_id:
            user_id = request.session.get("user_id") or request.session.get("customer_id")
        if not customer_id:
            customer_id = (
                request.session.get("active_customer_id")
                or request.session.get("selected_customer_id")
                or request.session.get("customer_id")
            )

        if not customer_id or not user_id:
            messages.error(request, _("To place an order, you must be authenticated."))
            # POST-only endpoints — redirect to checkout after login, not back to the POST path.
            return redirect("/login/?next=" + _url_quote("/order/checkout/", safe="/"))

        return view_func(request, *args, **kwargs)

    return wrapper


def _get_customer_context(request: HttpRequest) -> tuple[str | None, str | None]:
    """Extract customer_id and user_id from request attributes or session.

    Returns (customer_id, user_id) — either may be None if not found.
    """
    customer_id = (
        getattr(request, "customer_id", None)
        or request.session.get("active_customer_id")
        or request.session.get("selected_customer_id")
        or request.session.get("customer_id")
    )
    user_id = getattr(request, "user_id", None) or request.session.get("user_id")
    return (str(customer_id) if customer_id else None), (str(user_id) if user_id else None)


def _parse_total_cents(order_total: str) -> int:
    """Convert order total string to cents using Decimal arithmetic.

    Returns 0 if conversion fails (caller should validate).
    """
    try:
        amount = Decimal(str(order_total)).quantize(Decimal("0.01"), rounding=ROUND_HALF_EVEN)
        return int(amount * 100)
    except (InvalidOperation, ValueError, TypeError):
        logger.error("💰 [Orders] Failed to convert order total to cents: %s", order_total)
        return 0


ALLOWED_PAYMENT_METHODS = frozenset({"bank_transfer", "card"})


@dataclasses.dataclass
class CheckoutContext:
    """Validated checkout request data extracted from a POST request."""

    cart: Any  # GDPRCompliantCartSession
    customer_id: str
    user_id: str
    payment_method: str
    cart_version: str
    notes: str
    idempotency_key: str
    agree_terms: bool


def _validate_checkout_request(request: HttpRequest) -> "CheckoutContext | HttpResponse":  # noqa: PLR0911
    """Validate a checkout POST request.

    Returns a CheckoutContext on success, or an HttpResponse (redirect/JsonResponse) on failure.
    """
    customer_id, user_id = _get_customer_context(request)

    cart = GDPRCompliantCartSession(request.session)

    if not cart.has_items():
        messages.error(request, _("Cannot create order with empty cart."))
        return redirect("orders:catalog")

    if not customer_id or not user_id:
        messages.error(request, _("To place an order, you must be authenticated."))
        # POST-only endpoint — redirect to checkout after login, not back to the POST path.
        return redirect("/login/?next=" + _url_quote("/order/checkout/", safe="/"))

    # Validate cart version to prevent stale mutations
    cart_version = request.POST.get("cart_version", "")
    current_version = cart.get_cart_version()
    if not cart_version or cart_version != current_version:
        is_ajax = request.headers.get("HX-Request") or request.headers.get("X-Requested-With") == "XMLHttpRequest"
        if is_ajax:
            return JsonResponse(
                {"error": _("Cart version mismatch. Please refresh and try again.")},
                status=400,
            )
        messages.error(request, _("Your cart was updated. Please review and try again."))
        return redirect("orders:checkout")

    # Validate payment method against allowlist
    payment_method = request.POST.get("payment_method", "")
    if not payment_method or payment_method not in ALLOWED_PAYMENT_METHODS:
        messages.error(request, _("Invalid payment method selected."))
        return redirect("orders:checkout")

    # Validate EU compliance terms acceptance
    agree_terms = request.POST.get("agree_terms", "") == "on"
    if not agree_terms:
        messages.error(request, _("You must agree to the terms and conditions."))
        return redirect("orders:checkout")

    return CheckoutContext(
        cart=cart,
        customer_id=customer_id,
        user_id=user_id,
        payment_method=payment_method,
        cart_version=cart_version,
        notes=request.POST.get("notes", "").strip(),
        idempotency_key=request.POST.get("idempotency_key", "").strip(),
        agree_terms=agree_terms,
    )


_PROFILE_KEYWORDS = ("contact", "email", "address", "billing", "city", "county", "postal", "country")


def _is_profile_error(error: object) -> bool:
    """Return True if the error string relates to an incomplete customer profile."""
    return any(keyword in str(error).lower() for keyword in _PROFILE_KEYWORDS)


def _create_and_process_order(request: HttpRequest, ctx: CheckoutContext) -> HttpResponse:  # noqa: C901, PLR0911, PLR0912, PLR0915
    """Shared order creation logic used by both create_order and process_payment.

    Handles idempotency, preflight, order creation, optional Stripe PaymentIntent,
    and redirects to confirmation.
    """
    # 🔒 SECURITY: DoS hardening — fail closed if cache is unavailable
    cache_failure = OrderSecurityHardening.fail_closed_on_cache_failure("order_create", "create_order")
    if cache_failure:
        messages.error(request, _("Service temporarily unavailable. Please try again later."))
        return redirect("orders:checkout")

    # 🔒 SECURITY: Reject oversized payloads
    size_check = OrderSecurityHardening.validate_request_size(request)
    if size_check:
        messages.error(request, _("Request is too large."))
        return redirect("orders:checkout")

    # 🔒 SECURITY: Reject suspicious field patterns
    pattern_check = OrderSecurityHardening.check_suspicious_patterns(request)
    if pattern_check:
        messages.error(request, _("Invalid request."))
        return redirect("orders:checkout")

    try:
        # Idempotency key fallback — includes session key + timestamp to prevent
        # same-cart collisions across separate checkout attempts.
        if not ctx.idempotency_key:
            session_key = (getattr(request, "session", None) and request.session.session_key) or ""
            ctx.idempotency_key = hashlib.sha256(
                f"{ctx.customer_id}:{ctx.cart_version}:{session_key}".encode()
            ).hexdigest()[:64]

        idem_cache_key = f"orders:idempotency:{ctx.customer_id}:{ctx.idempotency_key}"

        # 🔒 SECURITY: Atomic idempotency acquire — prevents TOCTOU race where two concurrent
        # requests both pass a non-atomic cache.get() check and create duplicate orders.
        # cache.add() is atomic: returns False if the key already exists, True if acquired.
        if not cache.add(idem_cache_key, "__in_progress__", timeout=300):
            # Key already held — check if it carries a real order_id or an in-progress marker
            cached_order_id = cache.get(idem_cache_key)
            if cached_order_id and cached_order_id != "__in_progress__":
                try:
                    uuid.UUID(str(cached_order_id))
                    return redirect("orders:confirmation", order_id=cached_order_id)
                except (ValueError, TypeError):
                    # Sentinel value like "__processed__" — order was created but ID missing.
                    messages.info(request, _("Your order is being processed. Please check your orders list."))
            elif cached_order_id == "__in_progress__":
                messages.info(request, _("Your order is being processed. Please wait a moment."))
            return redirect("orders:checkout")

        # We hold the idempotency lock — track if order was created on Platform so the
        # finally block can clean up the lock on failure (but preserve it if order exists).
        order_created_on_platform = False
        try:
            # Always run preflight validation — no bypass
            preflight_result = OrderCreationService.preflight_order(
                ctx.cart,
                ctx.customer_id,
                ctx.user_id,
                api_client_factory=PlatformAPIClient,
            )

            if not preflight_result.get("valid", False):
                errors = preflight_result.get("errors", [])
                logger.warning(
                    "🔒 [Orders] Blocking order creation for customer %s - validation failed: %s",
                    ctx.customer_id,
                    errors,
                )
                if any(_is_profile_error(e) for e in errors):
                    messages.error(request, _("We need more information to complete your order."))
                else:
                    error_details = " ".join(str(e) for e in errors[:3])
                    # Use %s substitution instead of .format() to avoid crashes when
                    # error_details contains curly braces (e.g. from untrusted API responses).
                    messages.error(request, _("Order validation failed: %s") % error_details)
                return redirect("orders:checkout")

            # Create order with auto-pending (promotes to pending if validation passes)
            result = OrderCreationService.create_draft_order(
                ctx.cart,
                ctx.customer_id,
                ctx.user_id,
                ctx.notes,
                auto_pending=True,
                idempotency_key=ctx.idempotency_key or None,
                api_client_factory=PlatformAPIClient,
            )

            if result.get("error"):
                messages.error(request, result["error"])
                return redirect("orders:checkout")

            # Order exists on Platform — protect the idempotency lock from here on.
            # Even if Stripe/messages/cache fail below, the order is real.
            order_created_on_platform = True

            order_data = result.get("order", {})
            if not order_data and result.get("order_id"):
                order_data = {
                    "id": result.get("order_id"),
                    "order_number": result.get("order_id"),
                    "status": result.get("status", "draft"),
                }

            order_id = order_data.get("id")
            order_number = order_data.get("order_number")
            order_status = order_data.get("status", "draft")

            # Promote the in-progress marker to the real order_id immediately after
            # extracting order data.  This must happen BEFORE any early-return path
            # (e.g. total_cents <= 0) so the lock always carries the real order_id.
            # Wrap in try/except: if cache.set() fails, the lock stays as "__processing__"
            # which would block retries until TTL expiry.  On failure, delete the lock
            # so the customer can retry (the order already exists on platform, and the
            # idempotency key on the platform side will return the existing order).
            try:
                cache.set(idem_cache_key, order_id or "__processed__", timeout=300)
            except Exception:
                logger.warning("⚠️ [Orders] cache.set failed promoting idempotency lock: %s", idem_cache_key)
                try:
                    cache.delete(idem_cache_key)
                except Exception:
                    logger.error("🔥 [Orders] cache.delete also failed for idempotency lock: %s", idem_cache_key)

            # Create Stripe PaymentIntent only for card payment method
            payment_intent_result = None
            if order_status == "pending" and ctx.payment_method == "card":
                order_total = order_data.get("total", "0")
                order_currency = order_data.get("currency_code", "RON")
                total_cents = _parse_total_cents(str(order_total))

                if total_cents <= 0:
                    logger.error(
                        "❌ Cannot create payment intent with total_cents=%d for order %s",
                        total_cents,
                        order_id,
                    )
                    messages.error(request, _("Unable to process payment. Please contact support."))
                    return redirect("orders:checkout")
                else:
                    try:
                        platform_api = PlatformAPIClient()
                        payment_intent_result = platform_api.post_billing(
                            "create-payment-intent/",
                            data={
                                "order_id": str(order_id),
                                "amount_cents": total_cents,
                                "currency": order_currency,
                                "customer_id": ctx.customer_id,
                                "order_number": order_number,
                                "gateway": "stripe",
                                "metadata": {
                                    "order_number": order_number,
                                    "customer_id": str(ctx.customer_id),
                                    "created_via": "portal_checkout",
                                },
                            },
                            user_id=int(ctx.user_id) if ctx.user_id and str(ctx.user_id).isdigit() else 0,
                        )

                        if payment_intent_result and payment_intent_result.get("success"):
                            logger.info("✅ Created payment intent for order %s", order_number)
                            request.session[f"payment_intent_{order_id}"] = {
                                "client_secret": payment_intent_result.get("client_secret"),
                                "payment_intent_id": payment_intent_result.get("payment_intent_id"),
                            }
                        else:
                            logger.error("❌ Failed to create payment intent: %s", payment_intent_result)
                    except Exception as e:
                        logger.error("🔥 Error creating payment intent for order %s: %s", order_id, e)

            # Set user-facing success/warning message
            if order_status == "pending":
                if ctx.payment_method == "bank_transfer":
                    messages.success(
                        request,
                        _("Order #%s was created successfully. Please complete bank transfer to activate it.")
                        % order_number,
                    )
                elif payment_intent_result and payment_intent_result.get("success"):
                    messages.info(request, _("Please complete your payment to activate your order."))
                else:
                    messages.warning(
                        request,
                        _("Order #%s was created successfully, but payment processing is temporarily unavailable.")
                        % order_number,
                    )
            else:
                messages.success(
                    request,
                    _("Order #%s was created successfully! You can view it in your orders list.") % order_number,
                )

            try:
                uuid.UUID(str(order_id))
                return redirect("orders:confirmation", order_id=order_id)
            except (ValueError, TypeError):
                return redirect("orders:checkout")

        finally:
            # On failure, release the idempotency lock so the customer can retry.
            # On success the lock now holds the real order_id — do not delete it.
            if not order_created_on_platform:
                try:
                    cache.delete(idem_cache_key)
                except Exception:
                    logger.warning("⚠️ [Orders] Failed to release idempotency lock: %s", idem_cache_key)

    except Exception as e:
        logger.error("🔥 [Orders] Unexpected error creating order: %s", e)
        messages.error(request, _("Error creating order. Please try again."))
        return redirect("orders:checkout")


@require_customer_authentication
def product_catalog(request: HttpRequest) -> HttpResponse:
    """
    Product catalog view with Romanian hosting products.
    Supports filtering by product type and featured products.
    """

    # Get filter parameters
    product_type = request.GET.get("type", "")
    featured_only = request.GET.get("featured") == "true"

    try:
        platform_api = PlatformAPIClient()

        # Build API query parameters
        params = {}
        if product_type:
            params["product_type"] = product_type
        if featured_only:
            params["featured"] = "true"

        # Fetch products from platform
        products_response = platform_api.get("/api/orders/products/", params=params)

        if not products_response or "results" not in products_response:
            raise PlatformAPIError("Invalid response format")

        products = products_response["results"]

        # Get cart for item count
        cart = GDPRCompliantCartSession(request.session)

        # Prepare product type filter options
        product_type_options = [
            ("", _("All Products")),
            ("shared_hosting", _("Shared Hosting")),
            ("vps", _("VPS Hosting")),
            ("dedicated", _("Dedicated Server")),
            ("domain", _("Domains")),
            ("ssl", _("SSL Certificates")),
            ("email", _("Email Hosting")),
        ]

        context = {
            "products": products,
            "product_type_filter": product_type,
            "featured_only": featured_only,
            "product_type_options": product_type_options,
            "cart_count": cart.get_item_count(),
            "cart_total_quantity": cart.get_total_quantity(),
            "order_steps": ORDER_STEPS,
            "current_step": 1,
        }

        logger.info(f"✅ [Catalog] Loaded {len(products)} products")

    except PlatformAPIError as e:
        # Orders uses messaging-only rate-limit UX (no automatic retry).
        # Order write operations (create, confirm-payment) are non-idempotent;
        # retrying could cause double-charges or duplicate orders.
        if is_rate_limited_error(e):
            logger.warning(f"⚠️ [Catalog] Rate-limited loading products: {e}")
            messages.warning(request, get_rate_limit_message(e.retry_after))
        else:
            logger.error(f"🔥 [Catalog] Failed to load products: {e}")
            messages.error(request, _("Error loading products. Please try again."))

        context = {
            "products": [],
            "error": True,
            "product_type_options": [],
            "cart_count": 0,
        }

    return render(request, "orders/product_catalog.html", context)


@require_customer_authentication
def product_detail(request: HttpRequest, product_slug: str) -> HttpResponse:
    """
    Product detail view with pricing options and configuration.
    """

    try:
        platform_api = PlatformAPIClient()

        # Fetch product details
        product = platform_api.get(f"/api/orders/products/{product_slug}/")

        if not product:
            messages.error(request, _("Product not found."))
            return redirect("orders:catalog")

        # Get cart for context
        cart = GDPRCompliantCartSession(request.session)

        # Check if product is already in cart
        existing_item = None
        for item in cart.get_items():
            if item["product_slug"] == product_slug:
                existing_item = item
                break

        context = {
            "product": product,
            "existing_item": existing_item,
            "cart_count": cart.get_item_count(),
            "order_steps": ORDER_STEPS,
            "current_step": 1,
        }

        logger.info(f"✅ [Product] Loaded product details: {product_slug}")

    except PlatformAPIError as e:
        if is_rate_limited_error(e):
            logger.warning(f"⚠️ [Product] Rate-limited loading product {product_slug}: {e}")
            messages.warning(request, get_rate_limit_message(e.retry_after))
        else:
            logger.error(f"🔥 [Product] Failed to load product {product_slug}: {e}")
            messages.error(request, _("Product not found."))
        return redirect("orders:catalog")

    return render(request, "orders/product_detail.html", context)


@require_customer_authentication
@require_http_methods(["POST"])
def add_to_cart(request: HttpRequest) -> HttpResponse:  # noqa: PLR0911
    """
    HTMX endpoint to add product to cart with validation.
    🔒 SECURITY: Enhanced with DoS hardening and uniform response timing.
    """

    # 🔒 SECURITY: Check cache availability and fail closed if needed
    cache_check = _coerce_security_response(
        OrderSecurityHardening.fail_closed_on_cache_failure("cart_ops", "add_to_cart")
    )
    if cache_check:
        return cache_check

    # 🔒 SECURITY: Validate suspicious patterns first (field-level checks), then total size.
    pattern_check = _coerce_security_response(OrderSecurityHardening.check_suspicious_patterns(request))
    if pattern_check:
        return pattern_check

    size_check = _coerce_security_response(OrderSecurityHardening.validate_request_size(request))
    if size_check:
        return size_check

    client_ip = get_safe_client_ip(request)

    # Optional HMAC seal validation for pre-sealed price submissions.
    price_seal_raw = request.POST.get("price_seal", "").strip()
    if price_seal_raw:
        try:
            sealed_data = json.loads(price_seal_raw)
        except json.JSONDecodeError:
            OrderSecurityHardening.uniform_response_delay()
            return JsonResponse({"error": _("Invalid price seal")}, status=401)

        if not HMACPriceSealer.verify_seal_metadata(sealed_data, client_ip):
            OrderSecurityHardening.uniform_response_delay()
            return JsonResponse({"error": _("Invalid price seal")}, status=401)

    try:
        # Get form data
        product_slug = request.POST.get("product_slug", "").strip()
        billing_period = request.POST.get("billing_period", "monthly")
        domain_name = request.POST.get("domain_name", "").strip()

        # 🔒 SECURITY: Validate inputs before processing (fail-fast on bad data)
        try:
            quantity = OrderInputValidator.validate_quantity(request.POST.get("quantity", 1))
            billing_period = OrderInputValidator.validate_billing_period(billing_period)
        except ValidationError as e:
            OrderSecurityHardening.uniform_response_delay()
            return JsonResponse({"error": str(e.message)}, status=400)

        # Parse configuration from JSON if provided
        config_json = request.POST.get("config", "{}")
        try:
            config = json.loads(config_json) if config_json else {}
        except json.JSONDecodeError:
            config = {}

        # Add to cart
        cart = GDPRCompliantCartSession(request.session)
        cart.add_item(
            product_slug=product_slug,
            quantity=quantity,
            billing_period=billing_period,
            domain_name=domain_name,
            config=config,
        )

        # 🔒 SECURITY: Apply uniform response delay
        OrderSecurityHardening.uniform_response_delay()

        # Return updated cart widget
        cart_items = cart.get_items()
        if cart_items:
            # Item was successfully added — fire cartAdded event so Alpine auto-opens mini-cart
            just_added_slug = product_slug
            # Find the item by slug rather than using cart_items[-1], which is wrong when
            # add_item() updates an existing item in-place instead of appending.
            added_item = next((i for i in cart_items if i["product_slug"] == product_slug), None)
            product_name = added_item["product_name"] if added_item else product_slug
            response = render(
                request,
                "orders/partials/cart_updated.html",
                {
                    "cart_count": cart.get_item_count(),
                    "cart_total_quantity": cart.get_total_quantity(),
                    "success_message": _("Product added to cart successfully!"),
                    "product_name": product_name,
                    "just_added_slug": just_added_slug,
                },
            )
            response["HX-Trigger"] = json.dumps({"cartAdded": {"slug": just_added_slug}})
            return response
        else:
            # No item was added (likely due to pricing issues)
            return _cart_error_response(
                request,
                "orders/partials/cart_error_notification.html",
                {
                    "error": _("Product is currently not available for purchase."),
                    "cart_count": cart.get_item_count(),
                    "cart_total_quantity": cart.get_total_quantity(),
                },
            )

    except ValidationError as e:
        logger.warning(f"⚠️ [Cart] Validation error: {e}")
        return _cart_error_response(
            request,
            "orders/partials/cart_error_notification.html",
            {"error": str(e), "cart_count": 0, "cart_total_quantity": 0},
        )
    except Exception as e:
        logger.error(f"🔥 [Cart] Unexpected error adding to cart: {e}")
        return _cart_error_response(
            request,
            "orders/partials/cart_error_notification.html",
            {
                "error": _("Error adding to cart. Please try again."),
                "cart_count": 0,
                "cart_total_quantity": 0,
            },
        )


@require_customer_authentication
@require_http_methods(["POST"])
def update_cart_item(request: HttpRequest) -> HttpResponse:  # noqa: PLR0911
    """
    HTMX endpoint to update cart item quantity.
    """

    # 🔒 SECURITY: Comprehensive DoS hardening checks
    cache_key = f"cart_update_{request.session.session_key or 'anon'}"
    cache_response = _coerce_security_response(
        OrderSecurityHardening.fail_closed_on_cache_failure(cache_key, "update_cart_item")
    )
    if cache_response:
        return cache_response

    size_response = _coerce_security_response(
        OrderSecurityHardening.validate_request_size(request, max_size_bytes=5120)  # 5KB limit
    )
    if size_response:
        return size_response

    suspicious_response = _coerce_security_response(OrderSecurityHardening.check_suspicious_patterns(request))
    if suspicious_response:
        return suspicious_response

    try:
        product_slug = request.POST.get("product_slug", "").strip()
        billing_period = request.POST.get("billing_period", "monthly")
        quantity = OrderInputValidator.validate_quantity(request.POST.get("quantity", 1))

        cart = GDPRCompliantCartSession(request.session)
        cart.update_item_quantity(product_slug, billing_period, quantity)

        # 🔒 SECURITY: Apply uniform response delay
        OrderSecurityHardening.uniform_response_delay()

        return render(
            request,
            "orders/partials/cart_item_updated.html",
            {
                "cart_count": cart.get_item_count(),
                "cart_total_quantity": cart.get_total_quantity(),
                "success_message": _("Quantity updated successfully!"),
            },
        )

    except ValidationError as e:
        return _cart_error_response(request, "orders/partials/cart_empty.html", {"error": str(e)})
    except (ValueError, InvalidOperation):
        return _cart_error_response(request, "orders/partials/cart_empty.html", {"error": _("Invalid quantity value.")})
    except Exception as e:
        logger.error(f"🔥 [Cart] Error updating cart item: {e}")
        return _cart_error_response(request, "orders/partials/cart_empty.html", {"error": _("Error updating cart.")})


@require_customer_authentication
@require_http_methods(["POST"])
def remove_from_cart(request: HttpRequest) -> HttpResponse:
    """
    HTMX endpoint to remove item from cart.
    """

    # 🔒 SECURITY: Comprehensive DoS hardening checks
    cache_key = f"cart_remove_{request.session.session_key or 'anon'}"
    cache_response = _coerce_security_response(
        OrderSecurityHardening.fail_closed_on_cache_failure(cache_key, "remove_from_cart")
    )
    if cache_response:
        return cache_response

    size_response = _coerce_security_response(
        OrderSecurityHardening.validate_request_size(request, max_size_bytes=2048)  # 2KB limit
    )
    if size_response:
        return size_response

    suspicious_response = _coerce_security_response(OrderSecurityHardening.check_suspicious_patterns(request))
    if suspicious_response:
        return suspicious_response

    try:
        product_slug = request.POST.get("product_slug", "").strip()
        billing_period = request.POST.get("billing_period", "monthly")

        cart = GDPRCompliantCartSession(request.session)
        cart.remove_item(product_slug, billing_period)

        # 🔒 SECURITY: Apply uniform response delay
        OrderSecurityHardening.uniform_response_delay()

        return render(
            request,
            "orders/partials/cart_updated.html",
            {
                "cart_count": cart.get_item_count(),
                "cart_total_quantity": cart.get_total_quantity(),
                "success_message": _("Product removed from cart!"),
            },
        )

    except ValidationError as e:
        return _cart_error_response(request, "orders/partials/cart_empty.html", {"error": str(e)})
    except Exception as e:
        logger.error(f"🔥 [Cart] Error removing from cart: {e}")
        return _cart_error_response(
            request, "orders/partials/cart_empty.html", {"error": _("Error removing from cart.")}
        )


@require_customer_authentication
def cart_review(request: HttpRequest) -> HttpResponse:
    """
    Cart review page with totals calculation and item management.
    """

    cart = GDPRCompliantCartSession(request.session)

    if not cart.has_items():
        messages.info(request, _("Your cart is empty."))
        return redirect("orders:catalog")

    # Calculate totals
    customer_id, user_id = _get_customer_context(request)

    calculation_result = None
    calculation_error = None

    try:
        calculation_result = CartCalculationService.calculate_cart_totals(
            cart, str(customer_id or ""), int(user_id or 0)
        )
    except ValidationError as e:
        calculation_error = str(e)
        logger.error(f"🔥 [Cart] Calculation error: {e}")

    context = {
        "cart": cart,
        "cart_items": cart.get_items(),
        "calculation": calculation_result,
        "calculation_error": calculation_error,
        "warnings": cart.get_warnings(),
        "order_steps": ORDER_STEPS,
        "current_step": 2,
    }

    return render(request, "orders/cart_review.html", context)


@require_customer_authentication
@require_http_methods(["POST"])
def calculate_totals_htmx(request: HttpRequest) -> HttpResponse:  # noqa: PLR0911
    """
    HTMX endpoint for cart total calculations with price change detection.
    """

    # 🔒 SECURITY: Comprehensive DoS hardening checks
    cache_key = f"cart_totals_{request.session.session_key or 'anon'}"
    cache_response = _coerce_security_response(
        OrderSecurityHardening.fail_closed_on_cache_failure(cache_key, "calculate_totals_htmx")
    )
    if cache_response:
        return cache_response

    size_response = _coerce_security_response(
        OrderSecurityHardening.validate_request_size(request, max_size_bytes=1024)  # 1KB limit
    )
    if size_response:
        return size_response

    suspicious_response = _coerce_security_response(OrderSecurityHardening.check_suspicious_patterns(request))
    if suspicious_response:
        return suspicious_response

    try:
        cart = GDPRCompliantCartSession(request.session)
        customer_id, user_id = _get_customer_context(request)

        # Debug logging for authentication parameters
        logger.info(f"🔍 [Cart] Calculate totals - customer_id: {customer_id}, user_id: {user_id}")

        if not user_id:
            logger.error(f"🔥 [Cart] Missing user_id parameter - user_id: {user_id}")
            return render(request, "orders/partials/cart_empty.html", status=400)

        if not cart.has_items():
            return render(request, "orders/partials/cart_empty.html")

        # Calculate totals
        calculation_result = CartCalculationService.calculate_cart_totals(
            cart, str(customer_id or ""), int(user_id or 0)
        )

        # 🔒 SECURITY: Apply uniform response delay
        OrderSecurityHardening.uniform_response_delay()

        return render(
            request,
            "orders/partials/cart_totals.html",
            {"calculation": calculation_result, "cart": cart, "warnings": cart.get_warnings()},
        )

    except ValidationError as e:
        logger.warning(f"⚠️ [Cart] Validation error in calculate_totals: {e}")
        return render(request, "orders/partials/cart_empty.html", status=400)
    except Exception as e:
        logger.error(f"🔥 [Cart] Calculation error: {e}")
        return render(request, "orders/partials/cart_empty.html", status=500)


@require_customer_authentication
def checkout(request: HttpRequest) -> HttpResponse:
    """
    Checkout page with preflight validation before order creation.
    Enforces company profile completeness before allowing order submission.
    """

    cart = GDPRCompliantCartSession(request.session)

    if not cart.has_items():
        messages.error(request, _("Cannot proceed with empty cart."))
        return redirect("orders:catalog")

    # Calculate totals for display
    customer_id, user_id = _get_customer_context(request)
    calculation_result = None
    preflight_result = None

    try:
        calculation_result = CartCalculationService.calculate_cart_totals(
            cart, str(customer_id or ""), int(user_id or 0)
        )

        # 🔎 SECURITY: Run preflight validation to check for issues
        preflight_result = OrderCreationService.preflight_order(cart, str(customer_id or ""), str(user_id or ""))

        # 🔒 CRITICAL: Check if preflight validation failed with profile-related errors
        if preflight_result and not preflight_result.get("valid", False):
            errors = preflight_result.get("errors", [])

            # Look for company profile completeness errors
            profile_related_errors = []
            for error in errors:
                error_str = str(error).lower()
                if any(
                    keyword in error_str
                    for keyword in ["contact", "email", "address", "billing", "city", "county", "postal", "country"]
                ):
                    profile_related_errors.append(error)

            # If we have profile-related errors, add contextual user guidance
            if profile_related_errors:
                logger.warning(
                    f"🔒 [Orders] Blocking checkout for customer {customer_id} due to incomplete profile: {profile_related_errors}"
                )
                # Add user-friendly message explaining what needs to be fixed
                messages.warning(request, _("We need more information to complete your order."))

    except ValidationError:
        messages.error(request, _("Error calculating order totals."))
        return redirect("orders:cart_review")

    # Pre-join cart items with per-item calculation data using slug-based lookup (B2)
    cart_items = cart.get_items()
    if calculation_result and calculation_result.get("items"):
        calc_lookup = {
            (ci.get("product_slug", ""), ci.get("billing_period", "")): ci for ci in calculation_result["items"]
        }
        for item in cart_items:
            key = (item.get("product_slug", ""), item.get("billing_period", ""))
            calc = calc_lookup.get(key)
            if calc:
                item["line_total_cents"] = calc.get("line_total_cents", 0)

    context = {
        "cart": cart,
        "cart_items": cart_items,
        "calculation": calculation_result,
        "warnings": cart.get_warnings(),
        "preflight": preflight_result,
        "can_submit": preflight_result.get("valid", False) if preflight_result else False,
        "order_steps": ORDER_STEPS,
        "current_step": 3,
    }

    return render(request, "orders/checkout.html", context)


@require_customer_authentication
@require_http_methods(["POST"])
def create_order(request: HttpRequest) -> HttpResponse:
    """Create order — handles bank transfer and no-JS Stripe fallback.

    🔒 SECURITY: Validates cart version to prevent stale mutations and enforces profile completeness.
    """
    result = _validate_checkout_request(request)
    if isinstance(result, HttpResponse):
        return result
    return _create_and_process_order(request, result)


@require_customer_authentication
@require_http_methods(["POST"])
def process_payment(request: HttpRequest) -> HttpResponse:
    """Process Stripe payment — delegates to shared order creation logic."""
    result = _validate_checkout_request(request)
    if isinstance(result, HttpResponse):
        return result
    return _create_and_process_order(request, result)


def _parse_order_timestamp(order_data: dict[str, Any]) -> None:
    """Parse ISO timestamp string to TZ-aware datetime for Django template rendering."""
    created_at_str = order_data.get("created_at", "")
    if created_at_str and isinstance(created_at_str, str):
        with contextlib.suppress(ValueError, TypeError):
            parsed_dt = datetime.fromisoformat(created_at_str)
            if parsed_dt.tzinfo is None:
                parsed_dt = parsed_dt.replace(tzinfo=UTC)
            order_data["created_at"] = parsed_dt


@require_customer_authentication
def order_confirmation(request: HttpRequest, order_id: str) -> HttpResponse:
    """
    Order confirmation page showing order details.
    """
    # 🔒 SECURITY: Validate order_id is a UUID before constructing any API path.
    # Django's <uuid:order_id> URL converter already rejects non-UUIDs with 404,
    # but this explicit check defends against future URL pattern changes and provides
    # a user-friendly redirect instead of a bare 404.
    try:
        uuid.UUID(str(order_id))
    except (ValueError, TypeError):
        messages.error(request, _("Invalid order identifier."))
        return redirect("orders:catalog")

    try:
        platform_api = PlatformAPIClient()
        customer_id, user_id = _get_customer_context(request)

        # Fetch order details from Platform API with HMAC authentication
        order_data = platform_api.post(
            f"orders/{order_id}/",
            data={
                "customer_id": customer_id,
                "timestamp": int(timezone.now().timestamp()),
                "action": "get_order_detail",
            },
            user_id=int(user_id or 0),
        )

        if not order_data or order_data.get("error"):
            messages.error(request, _("Order not found."))
            return redirect("orders:catalog")

        # 💳 NEW: Get payment intent for pending orders
        payment_info = None
        stripe_config = None
        if order_data.get("status") == "pending":
            # Get payment intent from session
            session_key = f"payment_intent_{order_id}"
            payment_info = request.session.get(session_key)

            if payment_info:
                try:
                    # Get Stripe configuration from Platform API
                    stripe_config_result = platform_api.get_billing("stripe-config/")
                    if stripe_config_result and stripe_config_result.get("success"):
                        stripe_config = stripe_config_result.get("config", {})
                        logger.info("✅ Retrieved Stripe configuration for checkout")
                    else:
                        logger.error(f"❌ Failed to get Stripe config: {stripe_config_result}")

                except Exception as e:
                    logger.error(f"🔥 Error getting Stripe config: {e}")

        # Parse ISO timestamp for template rendering
        _parse_order_timestamp(order_data)

        # Bank transfer details for pending bank_transfer orders
        bank_details: dict[str, str] = {}
        if order_data.get("payment_method") == "bank_transfer":
            if not getattr(settings, "COMPANY_BANK_IBAN", ""):
                logger.warning("⚠️ [Orders] COMPANY_BANK_IBAN not configured — bank transfer details unavailable")
            bank_details = {
                "iban": getattr(settings, "COMPANY_BANK_IBAN", "") or _("Not configured"),
                "bank_name": getattr(settings, "COMPANY_BANK_NAME", "") or _("Not configured"),
                "beneficiary": getattr(settings, "COMPANY_BANK_BENEFICIARY", "") or _("Not configured"),
            }

        context = {
            "order": order_data,
            "payment_info": payment_info,
            "stripe_config": stripe_config,
            "bank_details": bank_details,
            "order_steps": ORDER_STEPS,
            "current_step": 4,
        }

        return render(request, "orders/order_confirmation.html", context)

    except PlatformAPIError as e:
        if is_rate_limited_error(e):
            logger.warning(f"⚠️ [Orders] Rate-limited loading order {order_id}: {e}")
            messages.warning(request, get_rate_limit_message(e.retry_after))
        else:
            logger.error(f"🔥 [Orders] Failed to load order {order_id}: {e}")
            messages.error(request, _("Error loading order details."))
        return redirect("orders:catalog")


@require_customer_authentication
def mini_cart_content(request: HttpRequest) -> HttpResponse:
    """
    HTMX endpoint for mini-cart widget content.

    Accepts optional ``?just_added=<product_slug>`` query param so the template
    can highlight the newly-added item with a green pulse animation.
    """

    cart = GDPRCompliantCartSession(request.session)
    just_added_slug: str = request.GET.get("just_added", "")

    context = {
        "cart": cart,
        "cart_items": cart.get_items()[:MINI_CART_MAX_ITEMS],
        "total_items": cart.get_item_count(),
        "show_view_all": cart.get_item_count() > MINI_CART_MAX_ITEMS,
        "just_added_slug": just_added_slug,
    }

    return render(request, "orders/partials/mini_cart_content.html", context)


# ===============================================================================
# PAYMENT SUCCESS HANDLER
# ===============================================================================

from django.views.decorators.csrf import csrf_exempt  # noqa: E402

_WEBHOOK_REPLAY_WINDOW_SECONDS: int = 300  # 5 minutes
_WEBHOOK_NTP_SKEW_SECONDS: int = 2  # Forward clock skew tolerance for NTP jitter
_HMAC_SHA256_HEX_LENGTH: int = 64  # HMAC-SHA256 produces 64 lowercase hex chars


def _verify_platform_webhook(request: HttpRequest) -> bool:
    """Verify HMAC-SHA256 signature from Platform on webhook calls.

    Protocol
    --------
    * The Platform signs each webhook with HMAC-SHA256 using the shared
      ``PLATFORM_TO_PORTAL_WEBHOOK_SECRET``.
    * The signed payload is ``ts.body`` — the ASCII timestamp concatenated
      with a literal dot and the raw request body bytes.
    * The hex digest is sent in the ``X-Platform-Signature`` header; the
      timestamp string is sent in ``X-Platform-Timestamp``.

    Replay prevention
    -----------------
    After verifying the signature, the full 64-char hex signature is stored
    via ``cache.add()`` with a TTL equal to the replay-window (5 minutes).
    ``cache.add()`` is atomic and returns ``False`` when the key already
    exists, which rejects duplicate deliveries.

    **Limitation:** replay markers live only in the Django cache backend.
    If the cache is restarted (or the Portal pod is recycled with a
    non-persistent cache), previously-seen signatures will be accepted
    again.  This is an accepted risk for a stateless portal service;
    idempotency on the Platform side is the primary defense.

    Body serialization contract
    ---------------------------
    The Platform serializes the JSON body with compact separators
    (``separators=(",", ":")``) before signing, so the raw ``request.body``
    received here must match that encoding byte-for-byte.
    """
    secret: str = getattr(settings, "PLATFORM_TO_PORTAL_WEBHOOK_SECRET", "")
    if not secret:
        logger.error("[Webhook] PLATFORM_TO_PORTAL_WEBHOOK_SECRET not configured — rejecting all webhooks")
        return False
    sig: str = request.headers.get("X-Platform-Signature", "")
    if len(sig) != _HMAC_SHA256_HEX_LENGTH or not all(c in "0123456789abcdef" for c in sig):
        logger.warning("[Webhook] Invalid signature format")
        return False
    ts: str = request.headers.get("X-Platform-Timestamp", "")
    try:
        request_time = int(ts)
        current_time = int(_time_module.time())
        # Allow small forward skew for minor NTP jitter between platform and portal.
        timestamp_valid = -_WEBHOOK_NTP_SKEW_SECONDS <= (current_time - request_time) <= _WEBHOOK_REPLAY_WINDOW_SECONDS
    except (ValueError, TypeError):
        timestamp_valid = False
    if not timestamp_valid:
        logger.warning("[Webhook] Invalid or stale X-Platform-Timestamp")
        return False
    payload: bytes = ts.encode() + b"." + request.body
    expected: str = _hmac_module.new(secret.encode(), payload, hashlib.sha256).hexdigest()
    if not _hmac_module.compare_digest(sig, expected):
        return False
    # Full 64-char hex signature — no truncation needed, cache key length is not a constraint
    cache_key = f"webhook:sig:{sig}"
    if not cache.add(cache_key, 1, timeout=_WEBHOOK_REPLAY_WINDOW_SECONDS):
        logger.warning("[Webhook] Replay detected — signature already seen")
        return False
    return True


@csrf_exempt  # nosemgrep: no-csrf-exempt — HMAC-authenticated inter-service endpoint
@require_http_methods(["POST"])
def payment_success_webhook(request: HttpRequest) -> JsonResponse:
    """
    🔔 Handle payment success notifications from Platform webhooks

    This endpoint is called by the Platform service when a payment succeeds
    to clean up Portal session data and update UI state.
    """
    if not _verify_platform_webhook(request):
        logger.warning("[Webhook] Invalid platform signature — request rejected")
        return JsonResponse({"error": "Unauthorized"}, status=401)

    try:
        data = json.loads(request.body)
        order_id = data.get("order_id")
        payment_status = data.get("status")

        if not order_id:
            return JsonResponse({"error": "order_id required"}, status=400)

        logger.info(f"🔔 Payment webhook for order {order_id}: {payment_status}")

        # Clean up session data for completed payments
        if payment_status == "succeeded":
            # Clear payment intent from session (if exists)
            # Note: We can't access session without session key,
            # so this cleanup happens when user visits the site next

            logger.info(f"✅ Payment succeeded for order {order_id}")

        return JsonResponse({"success": True})

    except Exception:
        logger.exception("🔥 [Webhook] Error processing payment webhook")
        return JsonResponse({"error": "Webhook processing failed"}, status=500)


@require_customer_authentication
@require_http_methods(["POST"])
def confirm_payment(request: HttpRequest) -> JsonResponse:  # noqa: PLR0911, PLR0912, PLR0915, C901
    """
    Confirm payment and trigger service creation.
    Called after successful Stripe payment from frontend.
    """
    try:
        data = json.loads(request.body)
        payment_intent_id = data.get("payment_intent_id")
        order_id = data.get("order_id")
        gateway = data.get("gateway", "stripe")

        if not payment_intent_id or not order_id:
            return JsonResponse({"success": False, "error": "Missing payment_intent_id or order_id"}, status=400)

        # 🔒 SECURITY: Validate gateway against allowlist
        allowed_gateways = frozenset({"stripe"})
        if gateway not in allowed_gateways:
            return JsonResponse({"success": False, "error": "Invalid payment gateway"}, status=400)

        # Validate order_id format (must be a valid UUID)
        try:
            uuid.UUID(str(order_id))
        except (ValueError, AttributeError):
            return JsonResponse({"success": False, "error": "Invalid order identifier"}, status=400)

        # 🔒 SECURITY: Validate PI format before sending to any Platform endpoint.
        # Matches Platform's confirm_order regex — defense-in-depth at the Portal boundary.
        if not re.match(r"^pi_[a-zA-Z0-9]{10,64}$", str(payment_intent_id)):
            return JsonResponse({"success": False, "error": "Invalid payment reference"}, status=400)

        # Get customer context
        customer_id = getattr(request, "customer_id", None) or request.session.get("active_customer_id")
        user_id = getattr(request, "user_id", None) or request.session.get("user_id")

        if not customer_id:
            return JsonResponse({"success": False, "error": "Customer authentication required"}, status=401)

        if not user_id:
            return JsonResponse({"success": False, "error": "User authentication required"}, status=401)

        # 🔒 SECURITY: Idempotency guard — prevent double-processing of same payment
        idem_key = f"confirm_payment:{customer_id}:{payment_intent_id}"
        if not cache.add(idem_key, "processing", timeout=300):
            logger.warning("⚠️ [Orders] Duplicate confirm_payment blocked: %s", idem_key)
            # Return 200 with success:true — from the customer's perspective the payment
            # IS being processed.  A 409 would trigger the error path in the frontend JS
            # (which checks data.success), confusing the user.
            return JsonResponse(
                {"success": True, "status": "already_processing", "message": "Payment is already being processed"},
            )

        logger.info(f"💳 Confirming payment {payment_intent_id} for order {order_id}")

        # Track whether we succeeded — clear idem_key on failure so customer can retry
        payment_confirmed = False
        try:
            # Step 1: Confirm payment with platform
            api_client = PlatformAPIClient()

            # Call the billing/confirm-payment endpoint
            payment_result = api_client.post_billing(
                "confirm-payment/", {"payment_intent_id": payment_intent_id, "gateway": gateway}, user_id=int(user_id)
            )

            if not payment_result.get("success"):
                logger.error(f"❌ Payment confirmation failed: {payment_result.get('error')}")
                return JsonResponse(
                    {"success": False, "error": payment_result.get("error", "Payment confirmation failed")}, status=400
                )

            payment_status = payment_result.get("status")
            logger.info(f"✅ Payment confirmed with status: {payment_status}")

            # Step 2: If payment succeeded, update order status
            if payment_status == "succeeded":
                # Update order to confirmed status via API
                order_update_result = api_client.post(
                    f"orders/{order_id}/confirm/",
                    {
                        "payment_intent_id": payment_intent_id,
                        "payment_status": payment_status,
                        "customer_id": customer_id,
                    },
                    user_id=int(user_id),
                )

                if order_update_result.get("success"):
                    logger.info(f"✅ Order {order_id} confirmed and service provisioning triggered")
                    payment_confirmed = True

                    # Clear cart after successful payment
                    cart_service = GDPRCompliantCartSession(request.session)
                    cart_service.clear()

                    return JsonResponse(
                        {
                            "success": True,
                            "status": "confirmed",
                            "message": "Payment confirmed and service is being provisioned",
                        }
                    )
                else:
                    logger.error(f"⚠️ Payment succeeded but order update failed: {order_update_result.get('error')}")
                    # Keep idem_key: payment succeeded at Stripe, order confirmation should be retried
                    # by support or webhook, not by customer re-submitting
                    payment_confirmed = True
                    return JsonResponse(
                        {
                            "success": False,
                            "status": "payment_received_confirmation_pending",
                            "error": "Payment received but order confirmation is pending. Please contact support.",
                        }
                    )
            else:
                return JsonResponse(
                    {"success": False, "error": "Payment has not been completed. Please try again or contact support."},
                    status=400,
                )
        finally:
            # Clear idempotency key on failure so the customer can retry.
            # Keep it on success to prevent double-charging.
            # contextlib.suppress prevents cache errors from masking the return value.
            if not payment_confirmed:
                with contextlib.suppress(Exception):
                    cache.delete(idem_key)

    except json.JSONDecodeError:
        return JsonResponse({"success": False, "error": "Invalid request data"}, status=400)
    except PlatformAPIError as e:
        if is_rate_limited_error(e):
            logger.warning(f"⚠️ [Orders] Rate-limited during payment confirmation: {e}")
            return JsonResponse(
                {
                    "success": False,
                    "error": "Too many requests. Please wait and try again.",
                    "retry_after": e.retry_after,
                },
                status=429,
            )
        logger.error(f"🔥 Platform API error: {e}")
        return JsonResponse({"success": False, "error": "Failed to communicate with platform"}, status=500)
    except Exception as e:
        logger.error(f"🔥 Error confirming payment: {e}")
        return JsonResponse({"success": False, "error": "An unexpected error occurred"}, status=500)
