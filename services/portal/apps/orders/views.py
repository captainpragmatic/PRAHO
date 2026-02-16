"""
Order Views for PRAHO Portal
Product catalog, cart management, and order creation with Romanian compliance.
"""

import json
import logging
import uuid

from django.contrib import messages
from django.core.cache import cache
from django.core.exceptions import ValidationError
from django.http import HttpRequest, HttpResponse, JsonResponse
from django.shortcuts import redirect, render
from django.utils import timezone
from django.utils.translation import gettext as _
from django.views.decorators.http import require_http_methods

from apps.api_client.services import PlatformAPIClient, PlatformAPIError

from .security import OrderSecurityHardening
from .services import (
    CartCalculationService,
    CartRateLimiter,
    GDPRCompliantCartSession,
    HMACPriceSealer,
    OrderCreationService,
)

logger = logging.getLogger(__name__)
MINI_CART_MAX_ITEMS = 3


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


def require_customer_authentication(view_func):
    """Decorator to ensure customer is authenticated"""

    def wrapper(request: HttpRequest, *args, **kwargs):
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
            messages.error(request, _("Pentru a plasa o comandă, trebuie să fiți autentificat."))
            return redirect("/login/?next=" + request.get_full_path())

        return view_func(request, *args, **kwargs)

    return wrapper


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
            "breadcrumb_current": "products",
        }

        logger.info(f"✅ [Catalog] Loaded {len(products)} products")

    except PlatformAPIError as e:
        logger.error(f"🔥 [Catalog] Failed to load products: {e}")
        messages.error(request, _("Eroare la încărcarea produselor. Vă rugăm încercați din nou."))

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
            messages.error(request, _("Produsul nu a fost găsit."))
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
            "breadcrumb_current": "product_detail",
        }

        logger.info(f"✅ [Product] Loaded product details: {product_slug}")

    except PlatformAPIError as e:
        logger.error(f"🔥 [Product] Failed to load product {product_slug}: {e}")
        messages.error(request, _("Produsul nu a fost găsit."))
        return redirect("orders:catalog")

    return render(request, "orders/product_detail.html", context)


@require_customer_authentication
@require_http_methods(["POST"])
def add_to_cart(request: HttpRequest) -> HttpResponse:
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

    # 🔒 SECURITY: Enhanced rate limiting with IP tracking
    session_key = request.session.session_key
    if not session_key:
        # Force session creation if it doesn't exist yet
        request.session.save()
        session_key = request.session.session_key

    client_ip = CartRateLimiter.get_client_ip(request)
    if not isinstance(client_ip, str) or not client_ip:
        client_ip = request.META.get("REMOTE_ADDR", "127.0.0.1")

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

    if not CartRateLimiter.check_rate_limit(session_key, client_ip):
        OrderSecurityHardening.uniform_response_delay()  # Apply delay even on rate limit
        return JsonResponse({"error": _("Prea multe operații. Vă rugăm încetiniți.")}, status=429)

    try:
        # Get form data
        product_slug = request.POST.get("product_slug", "").strip()
        quantity = int(request.POST.get("quantity", 1))
        billing_period = request.POST.get("billing_period", "monthly")
        domain_name = request.POST.get("domain_name", "").strip()

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

        # 🔒 SECURITY: Record successful operation with IP tracking
        CartRateLimiter.record_operation(session_key, client_ip)

        # 🔒 SECURITY: Apply uniform response delay
        OrderSecurityHardening.uniform_response_delay()

        # Return updated cart widget
        cart_items = cart.get_items()
        if cart_items:
            # Item was successfully added
            return render(
                request,
                "orders/partials/cart_updated.html",
                {
                    "cart_count": cart.get_item_count(),
                    "cart_total_quantity": cart.get_total_quantity(),
                    "success_message": _("Product added to cart successfully!"),
                    "product_name": cart_items[-1]["product_name"],  # Last added item
                },
            )
        else:
            # No item was added (likely due to pricing issues)
            # Return with status 200 so HTMX processes it, but with error content
            return render(
                request,
                "orders/partials/cart_error_notification.html",
                {
                    "error": _("Product is currently not available for purchase."),
                    "cart_count": cart.get_item_count(),
                    "cart_total_quantity": cart.get_total_quantity(),
                },
                status=200,
            )

    except ValidationError as e:
        logger.warning(f"⚠️ [Cart] Validation error: {e}")
        return render(request, "orders/partials/error_message.html", {"error": str(e)}, status=400)
    except Exception as e:
        logger.error(f"🔥 [Cart] Unexpected error adding to cart: {e}")
        return render(
            request,
            "orders/partials/error_message.html",
            {"error": _("Eroare la adăugarea în coș. Vă rugăm încercați din nou.")},
            status=500,
        )


@require_customer_authentication
@require_http_methods(["POST"])
def update_cart_item(request: HttpRequest) -> HttpResponse:
    """
    HTMX endpoint to update cart item quantity.
    """

    # 🔒 SECURITY: Comprehensive DoS hardening checks
    cache_key = f"cart_update_{request.session.session_key or 'anon'}"
    cache_response = OrderSecurityHardening.fail_closed_on_cache_failure(cache_key, "update_cart_item")
    if cache_response:
        return cache_response

    size_response = OrderSecurityHardening.validate_request_size(request, max_size_bytes=5120)  # 5KB limit
    if size_response:
        return size_response

    suspicious_response = OrderSecurityHardening.check_suspicious_patterns(request)
    if suspicious_response:
        return suspicious_response

    # 🔒 SECURITY: Enhanced rate limiting with IP tracking
    session_key = request.session.session_key
    if not session_key:
        request.session.save()
        session_key = request.session.session_key

    client_ip = CartRateLimiter.get_client_ip(request)
    if not CartRateLimiter.check_rate_limit(session_key, client_ip):
        OrderSecurityHardening.uniform_response_delay()
        return JsonResponse({"error": _("Prea multe operații. Vă rugăm încetiniți.")}, status=429)

    try:
        product_slug = request.POST.get("product_slug", "").strip()
        billing_period = request.POST.get("billing_period", "monthly")
        quantity = int(request.POST.get("quantity", 1))

        cart = GDPRCompliantCartSession(request.session)
        cart.update_item_quantity(product_slug, billing_period, quantity)

        # 🔒 SECURITY: Record successful operation with IP tracking
        CartRateLimiter.record_operation(session_key, client_ip)

        # 🔒 SECURITY: Apply uniform response delay
        OrderSecurityHardening.uniform_response_delay()

        return render(
            request,
            "orders/partials/cart_item_updated.html",
            {
                "cart_count": cart.get_item_count(),
                "cart_total_quantity": cart.get_total_quantity(),
                "success_message": _("Cantitate actualizată cu succes!"),
            },
        )

    except ValidationError as e:
        return render(request, "orders/partials/error_message.html", {"error": str(e)}, status=400)
    except Exception as e:
        logger.error(f"🔥 [Cart] Error updating cart item: {e}")
        return render(
            request, "orders/partials/error_message.html", {"error": _("Eroare la actualizarea coșului.")}, status=500
        )


@require_customer_authentication
@require_http_methods(["POST"])
def remove_from_cart(request: HttpRequest) -> HttpResponse:
    """
    HTMX endpoint to remove item from cart.
    """

    # 🔒 SECURITY: Comprehensive DoS hardening checks
    cache_key = f"cart_remove_{request.session.session_key or 'anon'}"
    cache_response = OrderSecurityHardening.fail_closed_on_cache_failure(cache_key, "remove_from_cart")
    if cache_response:
        return cache_response

    size_response = OrderSecurityHardening.validate_request_size(request, max_size_bytes=2048)  # 2KB limit
    if size_response:
        return size_response

    suspicious_response = OrderSecurityHardening.check_suspicious_patterns(request)
    if suspicious_response:
        return suspicious_response

    # 🔒 SECURITY: Enhanced rate limiting with IP tracking
    session_key = request.session.session_key
    if not session_key:
        request.session.save()
        session_key = request.session.session_key

    client_ip = CartRateLimiter.get_client_ip(request)
    if not CartRateLimiter.check_rate_limit(session_key, client_ip):
        OrderSecurityHardening.uniform_response_delay()
        return JsonResponse({"error": _("Prea multe operații. Vă rugăm încetiniți.")}, status=429)

    try:
        product_slug = request.POST.get("product_slug", "").strip()
        billing_period = request.POST.get("billing_period", "monthly")

        cart = GDPRCompliantCartSession(request.session)
        cart.remove_item(product_slug, billing_period)

        # 🔒 SECURITY: Record successful operation with IP tracking
        CartRateLimiter.record_operation(session_key, client_ip)

        # 🔒 SECURITY: Apply uniform response delay
        OrderSecurityHardening.uniform_response_delay()

        return render(
            request,
            "orders/partials/cart_updated.html",
            {
                "cart_count": cart.get_item_count(),
                "cart_total_quantity": cart.get_total_quantity(),
                "success_message": _("Produs eliminat din coș!"),
            },
        )

    except ValidationError as e:
        return render(request, "orders/partials/error_message.html", {"error": str(e)}, status=400)
    except Exception as e:
        logger.error(f"🔥 [Cart] Error removing from cart: {e}")
        return render(
            request, "orders/partials/error_message.html", {"error": _("Eroare la eliminarea din coș.")}, status=500
        )


@require_customer_authentication
def cart_review(request: HttpRequest) -> HttpResponse:
    """
    Cart review page with totals calculation and item management.
    """

    cart = GDPRCompliantCartSession(request.session)

    if not cart.has_items():
        messages.info(request, _("Coșul dumneavoastră este gol."))
        return redirect("orders:catalog")

    # Calculate totals
    # Get authentication from middleware-set request attributes
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

    calculation_result = None
    calculation_error = None

    try:
        calculation_result = CartCalculationService.calculate_cart_totals(cart, customer_id, user_id)
    except ValidationError as e:
        calculation_error = str(e)
        logger.error(f"🔥 [Cart] Calculation error: {e}")

    context = {
        "cart": cart,
        "cart_items": cart.get_items(),
        "calculation": calculation_result,
        "calculation_error": calculation_error,
        "warnings": cart.get_warnings(),
        "breadcrumb_current": "cart",
    }

    return render(request, "orders/cart_review.html", context)


@require_customer_authentication
@require_http_methods(["POST"])
def calculate_totals_htmx(request: HttpRequest) -> HttpResponse:
    """
    HTMX endpoint for cart total calculations with price change detection.
    """

    # 🔒 SECURITY: Comprehensive DoS hardening checks
    cache_key = f"cart_totals_{request.session.session_key or 'anon'}"
    cache_response = OrderSecurityHardening.fail_closed_on_cache_failure(cache_key, "calculate_totals_htmx")
    if cache_response:
        return cache_response

    size_response = OrderSecurityHardening.validate_request_size(request, max_size_bytes=1024)  # 1KB limit
    if size_response:
        return size_response

    suspicious_response = OrderSecurityHardening.check_suspicious_patterns(request)
    if suspicious_response:
        return suspicious_response

    # 🔒 SECURITY: Enhanced rate limiting with IP tracking
    session_key = request.session.session_key
    if not session_key:
        request.session.save()
        session_key = request.session.session_key

    client_ip = CartRateLimiter.get_client_ip(request)
    if not CartRateLimiter.check_rate_limit(session_key, client_ip):
        OrderSecurityHardening.uniform_response_delay()
        return JsonResponse({"error": _("Prea multe operații. Vă rugăm încetiniți.")}, status=429)

    try:
        cart = GDPRCompliantCartSession(request.session)
        # Get authentication from middleware-set request attributes
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

        # Debug logging for authentication parameters
        logger.info(f"🔍 [Cart] Calculate totals - customer_id: {customer_id}, user_id: {user_id}")

        if not user_id:
            logger.error(f"🔥 [Cart] Missing user_id parameter - user_id: {user_id}")
            return render(
                request,
                "orders/partials/error_message.html",
                {"error": _("Authentication error. Please refresh the page.")},
                status=400,
            )

        if not cart.has_items():
            return render(request, "orders/partials/cart_empty.html")

        # Calculate totals
        calculation_result = CartCalculationService.calculate_cart_totals(cart, customer_id, user_id)

        # 🔒 SECURITY: Record successful operation with IP tracking
        CartRateLimiter.record_operation(session_key, client_ip)

        # 🔒 SECURITY: Apply uniform response delay
        OrderSecurityHardening.uniform_response_delay()

        return render(
            request,
            "orders/partials/cart_totals.html",
            {"calculation": calculation_result, "cart": cart, "warnings": cart.get_warnings()},
        )

    except ValidationError as e:
        return render(request, "orders/partials/error_message.html", {"error": str(e)}, status=400)
    except Exception as e:
        logger.error(f"🔥 [Cart] Calculation error: {e}")
        return render(
            request, "orders/partials/error_message.html", {"error": _("Eroare la calcularea totalurilor.")}, status=500
        )


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
    calculation_result = None
    preflight_result = None

    try:
        calculation_result = CartCalculationService.calculate_cart_totals(cart, customer_id, user_id)

        # 🔎 SECURITY: Run preflight validation to check for issues
        preflight_result = OrderCreationService.preflight_order(cart, customer_id, user_id)

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

    context = {
        "cart": cart,
        "cart_items": cart.get_items(),
        "calculation": calculation_result,
        "warnings": cart.get_warnings(),
        "preflight": preflight_result,
        "can_submit": preflight_result.get("valid", False) if preflight_result else False,
        "breadcrumb_current": "checkout",
    }

    return render(request, "orders/checkout.html", context)


@require_customer_authentication
@require_http_methods(["POST"])
def create_order(request: HttpRequest) -> HttpResponse:
    """
    Create draft order from cart (MVP: self-serve order creation).
    🔒 SECURITY: Validates cart version to prevent stale mutations and enforces profile completeness.
    """

    try:
        cart = GDPRCompliantCartSession(request.session)
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

        if not cart.has_items():
            messages.error(request, _("Cannot create order with empty cart."))
            return redirect("orders:catalog")

        # 🔒 SECURITY: Validate cart version to prevent stale mutations
        expected_version = request.POST.get("cart_version", "")
        current_version = cart.get_cart_version()
        if not expected_version or expected_version != current_version:
            return JsonResponse(
                {"error": _("Cart version mismatch. Please refresh and try again.")},
                status=400,
            )

        # Idempotency handling for duplicate submissions from client retries.
        idempotency_key = request.POST.get("idempotency_key", "").strip()
        idem_cache_key = f"orders:idempotency:{customer_id}:{idempotency_key}" if idempotency_key else None
        if idem_cache_key:
            cached_order_id = cache.get(idem_cache_key)
            if cached_order_id:
                try:
                    uuid.UUID(str(cached_order_id))
                    return redirect("orders:confirmation", order_id=cached_order_id)
                except (ValueError, TypeError):
                    return redirect("orders:checkout")

        # 🔒 CRITICAL: Re-run preflight validation before order creation to prevent bypassing validation
        # For explicit idempotency submissions, skip preflight to avoid duplicate upstream
        # calls and rely on authoritative create endpoint validation.
        if not idempotency_key:
            preflight_result = OrderCreationService.preflight_order(
                cart,
                customer_id,
                user_id,
                api_client_factory=PlatformAPIClient,
            )

            if not preflight_result.get("valid", False):
                errors = preflight_result.get("errors", [])
                logger.warning(
                    f"🔒 [Orders] Blocking order creation for customer {customer_id} - validation failed: {errors}"
                )

                # Check if these are profile-related errors
                profile_related_errors = []
                for error in errors:
                    error_str = str(error).lower()
                    if any(
                        keyword in error_str
                        for keyword in ["contact", "email", "address", "billing", "city", "county", "postal", "country"]
                    ):
                        profile_related_errors.append(error)

                if profile_related_errors:
                    messages.error(request, _("We need more information to complete your order."))
                else:
                    # Generic validation error message
                    error_details = " ".join(str(error) for error in errors[:3])  # Show first 3 errors
                    messages.error(request, _("Order validation failed: {}").format(error_details))

                return redirect("orders:checkout")

        # Get optional notes
        notes = request.POST.get("notes", "").strip()

        # Create order with auto-pending (promotes to pending if validation passes)
        result = OrderCreationService.create_draft_order(
            cart,
            customer_id,
            user_id,
            notes,
            auto_pending=True,
            idempotency_key=idempotency_key or None,
            api_client_factory=PlatformAPIClient,
        )

        if result.get("error"):
            messages.error(request, result["error"])
            return redirect("orders:checkout")

        order_data = result.get("order", {})
        if not order_data and result.get("order_id"):
            order_data = {
                "id": result.get("order_id"),
                "order_number": result.get("order_id"),
                "status": result.get("status", "draft"),
            }
        order_id = order_data.get("id")
        order_number = order_data.get("order_number")

        # Check if order was auto-promoted to pending
        order_status = order_data.get("status", "draft")

        # 💳 NEW: Create payment intent for pending orders
        payment_intent_result = None
        if order_status == "pending":
            try:
                # Get order details needed for payment intent
                order_total = order_data.get("total", "0")
                order_currency = order_data.get("currency_code", "RON")

                # Convert total from decimal to cents (Stripe requires amount in smallest currency unit)
                try:
                    total_cents = int(float(order_total) * 100)
                except (ValueError, TypeError):
                    logger.error(f"❌ Invalid order total format: {order_total}")
                    total_cents = 0

                # Call Platform API to create payment intent
                platform_api = PlatformAPIClient()
                payment_intent_result = platform_api.post_billing(
                    "create-payment-intent/",
                    data={
                        "order_id": str(order_id),
                        "amount_cents": total_cents,
                        "currency": order_currency,
                        "customer_id": customer_id,
                        "order_number": order_number,
                        "gateway": "stripe",
                        "metadata": {
                            "order_number": order_number,
                            "customer_id": str(customer_id),
                            "created_via": "portal_checkout",
                        },
                    },
                )

                if payment_intent_result and payment_intent_result.get("success"):
                    logger.info(f"✅ Created payment intent for order {order_number}")
                    # Store payment intent info in session for checkout page
                    request.session[f"payment_intent_{order_id}"] = {
                        "client_secret": payment_intent_result.get("client_secret"),
                        "payment_intent_id": payment_intent_result.get("payment_intent_id"),
                    }
                else:
                    logger.error(f"❌ Failed to create payment intent: {payment_intent_result}")

            except Exception as e:
                logger.error(f"🔥 Error creating payment intent for order {order_id}: {e}")
                # Continue without payment intent - user can still view order

        if order_status == "pending":
            if payment_intent_result and payment_intent_result.get("success"):
                messages.success(
                    request, _("Order #{} was created successfully and is ready for payment!").format(order_number)
                )
            else:
                messages.warning(
                    request,
                    _("Order #{} was created successfully, but payment processing is temporarily unavailable.").format(
                        order_number
                    ),
                )
        else:
            messages.success(
                request,
                _("Order #{} was created successfully! You can view it in your orders list.").format(order_number),
            )

        if idem_cache_key:
            cache.set(idem_cache_key, order_id or "__processed__", timeout=300)

        try:
            uuid.UUID(str(order_id))
            return redirect("orders:confirmation", order_id=order_id)
        except (ValueError, TypeError):
            return redirect("orders:checkout")

    except ValidationError as e:
        messages.error(request, str(e))
        return redirect("orders:checkout")
    except Exception as e:
        logger.error(f"🔥 [Orders] Unexpected error creating order: {e}")
        messages.error(request, _("Eroare la crearea comenzii. Vă rugăm încercați din nou."))
        return redirect("orders:checkout")


@require_customer_authentication
@require_http_methods(["POST"])
def process_payment(request: HttpRequest) -> HttpResponse:
    """
    Process payment for cart items using Stripe.
    This creates a payment intent and order, then redirects to Stripe Checkout.
    """

    payment_method = request.POST.get("payment_method", "stripe")

    # If bank transfer, create order directly
    if payment_method == "bank_transfer":
        return create_order(request)

    # For Stripe payment, we need to:
    # 1. Create the order first
    # 2. Create a Stripe payment intent
    # 3. Redirect to payment page

    try:
        cart = GDPRCompliantCartSession(request.session)
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

        if not cart.has_items():
            messages.error(request, _("Cannot proceed with empty cart."))
            return redirect("orders:catalog")

        # Validate cart version
        expected_version = request.POST.get("cart_version", "")
        if not cart.validate_cart_version(expected_version):
            messages.error(request, _("Cart was modified. Please review and try again."))
            return redirect("orders:cart_review")

        # Run preflight validation
        preflight_result = OrderCreationService.preflight_order(cart, customer_id, user_id)

        if not preflight_result.get("valid", False):
            errors = preflight_result.get("errors", [])
            logger.warning(f"🔒 [Payment] Validation failed: {errors}")
            messages.error(request, _("Order validation failed. Please check your information."))
            return redirect("orders:checkout")

        # Get notes and agree_terms
        notes = request.POST.get("notes", "").strip()
        agree_terms = request.POST.get("agree_terms", "") == "on"

        if not agree_terms:
            messages.error(request, _("You must agree to the terms and conditions."))
            return redirect("orders:checkout")

        # Create order ready for payment (pending status)
        result = OrderCreationService.create_draft_order(
            cart,
            customer_id,
            user_id,
            notes,
            auto_pending=True,  # Promote to pending for immediate payment processing
        )

        if result.get("error"):
            messages.error(request, result["error"])
            return redirect("orders:checkout")

        order_data = result.get("order", {})
        order_id = order_data.get("id")
        order_number = order_data.get("order_number")

        # Create Stripe payment intent
        try:
            platform_api = PlatformAPIClient()

            # Get order details needed for payment intent
            order_total = order_data.get("total", "0")
            order_currency = order_data.get("currency_code", "RON")

            # Convert total from decimal to cents (Stripe requires amount in smallest currency unit)
            try:
                total_cents = int(float(order_total) * 100)
            except (ValueError, TypeError):
                logger.error(f"❌ Invalid order total format: {order_total}")
                total_cents = 0

            # Create payment intent
            payment_result = platform_api.post_billing(
                "create-payment-intent/",
                data={
                    "order_id": str(order_id),
                    "amount_cents": total_cents,
                    "currency": order_currency,
                    "customer_id": customer_id,
                    "order_number": order_number,
                    "gateway": "stripe",
                    "metadata": {
                        "order_number": order_number,
                        "customer_id": str(customer_id),
                        "created_via": "portal_checkout",
                    },
                },
                user_id=int(user_id),
            )

            if payment_result and payment_result.get("success"):
                # Store payment intent info in session
                request.session[f"payment_intent_{order_id}"] = {
                    "client_secret": payment_result.get("client_secret"),
                    "payment_intent_id": payment_result.get("payment_intent_id"),
                }

                logger.info(f"✅ Created payment intent for order {order_number}")

                # Clear cart after successful order creation
                cart.clear()

                # Redirect to confirmation page where payment will be completed
                messages.info(request, _("Please complete your payment to activate your order."))
                return redirect("orders:confirmation", order_id=order_id)
            else:
                logger.error(f"❌ Failed to create payment intent: {payment_result}")
                messages.error(request, _("Payment initialization failed. Please try again."))
                return redirect("orders:checkout")

        except Exception as e:
            logger.error(f"🔥 Error creating Stripe checkout: {e}")
            messages.error(request, _("Payment processing is temporarily unavailable."))
            return redirect("orders:checkout")

    except Exception as e:
        logger.error(f"🔥 [Payment] Unexpected error: {e}")
        messages.error(request, _("Error processing payment. Please try again."))
        return redirect("orders:checkout")


@require_customer_authentication
def order_confirmation(request: HttpRequest, order_id: str) -> HttpResponse:
    """
    Order confirmation page showing order details.
    """

    try:
        platform_api = PlatformAPIClient()
        # Get authentication from middleware-set request attributes
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

        # Fetch order details from Platform API with HMAC authentication
        order_data = platform_api.post(
            f"orders/{order_id}/",
            data={
                "customer_id": customer_id,
                "timestamp": int(timezone.now().timestamp()),
                "action": "get_order_detail",
            },
            user_id=int(user_id),
        )

        if not order_data or order_data.get("error"):
            messages.error(request, _("Comanda nu a fost găsită."))
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

        context = {
            "order": order_data,
            "payment_info": payment_info,
            "stripe_config": stripe_config,
            "breadcrumb_current": "confirm",
        }

        return render(request, "orders/order_confirmation.html", context)

    except PlatformAPIError as e:
        logger.error(f"🔥 [Orders] Failed to load order {order_id}: {e}")
        messages.error(request, _("Eroare la încărcarea detaliilor comenzii."))
        return redirect("orders:catalog")


@require_customer_authentication
def mini_cart_content(request: HttpRequest) -> HttpResponse:
    """
    HTMX endpoint for mini-cart widget content.
    """

    cart = GDPRCompliantCartSession(request.session)

    context = {
        "cart": cart,
        "cart_items": cart.get_items()[:MINI_CART_MAX_ITEMS],
        "total_items": cart.get_item_count(),
        "show_view_all": cart.get_item_count() > MINI_CART_MAX_ITEMS,
    }

    return render(request, "orders/partials/mini_cart_content.html", context)


# ===============================================================================
# PAYMENT SUCCESS HANDLER
# ===============================================================================

from django.views.decorators.csrf import csrf_exempt


@csrf_exempt
@require_http_methods(["POST"])
def payment_success_webhook(request: HttpRequest) -> JsonResponse:
    """
    🔔 Handle payment success notifications from Platform webhooks

    This endpoint is called by the Platform service when a payment succeeds
    to clean up Portal session data and update UI state.
    """
    try:
        import json

        from django.http import JsonResponse

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

    except Exception as e:
        logger.error(f"🔥 Error processing payment webhook: {e}")
        return JsonResponse({"error": "Webhook processing failed"}, status=500)


@require_customer_authentication
@require_http_methods(["POST"])
def confirm_payment(request: HttpRequest) -> JsonResponse:
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

        # Get customer context
        customer_id = getattr(request, "customer_id", None) or request.session.get("active_customer_id")
        user_id = getattr(request, "user_id", None) or request.session.get("user_id")

        if not customer_id:
            return JsonResponse({"success": False, "error": "Customer authentication required"}, status=401)

        logger.info(f"💳 Confirming payment {payment_intent_id} for order {order_id}")

        # Step 1: Confirm payment with platform
        api_client = PlatformAPIClient()

        # Call the billing/confirm-payment endpoint
        payment_result = api_client.post_billing(
            "confirm-payment/", {"payment_intent_id": payment_intent_id, "gateway": gateway}, user_id=user_id
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
                {"payment_intent_id": payment_intent_id, "payment_status": payment_status, "customer_id": customer_id},
                user_id=user_id,
            )

            if order_update_result.get("success"):
                logger.info(f"✅ Order {order_id} confirmed and service provisioning triggered")

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
                return JsonResponse(
                    {
                        "success": True,
                        "status": "payment_received",
                        "message": "Payment received. Order is being processed.",
                        "warning": "Order confirmation pending",
                    }
                )
        else:
            return JsonResponse(
                {"success": False, "error": f"Payment not completed. Status: {payment_status}"}, status=400
            )

    except json.JSONDecodeError:
        return JsonResponse({"success": False, "error": "Invalid request data"}, status=400)
    except PlatformAPIError as e:
        logger.error(f"🔥 Platform API error: {e}")
        return JsonResponse({"success": False, "error": "Failed to communicate with platform"}, status=500)
    except Exception as e:
        logger.error(f"🔥 Error confirming payment: {e}")
        return JsonResponse({"success": False, "error": "An unexpected error occurred"}, status=500)
