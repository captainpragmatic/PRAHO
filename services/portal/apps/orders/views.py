"""
Order Views for PRAHO Portal
Product catalog, cart management, and order creation with Romanian compliance.
"""

import json
import logging
from typing import Any, Dict

from django.contrib import messages
from django.core.exceptions import ValidationError
from django.http import HttpRequest, HttpResponse, HttpResponseNotAllowed, JsonResponse
from django.shortcuts import redirect, render
from django.utils import timezone
from django.utils.translation import gettext as _
from django.views.decorators.http import require_http_methods

from apps.api_client.services import PlatformAPIClient, PlatformAPIError
from .services import (
    CartCalculationService, 
    CartRateLimiter, 
    GDPRCompliantCartSession, 
    OrderCreationService
)
from .security import OrderSecurityHardening

logger = logging.getLogger(__name__)


def require_customer_authentication(view_func):
    """Decorator to ensure customer is authenticated"""
    def wrapper(request: HttpRequest, *args, **kwargs):
        # Try request attributes first (set by middleware), fallback to session
        customer_id = getattr(request, 'customer_id', None) or request.session.get('customer_id')
        user_id = getattr(request, 'user_id', None) or request.session.get('user_id')
        
        if not customer_id or not user_id:
            messages.error(request, _('Pentru a plasa o comandă, trebuie să fiți autentificat.'))
            return redirect('/login/?next=' + request.get_full_path())
        
        return view_func(request, *args, **kwargs)
    return wrapper


@require_customer_authentication
def product_catalog(request: HttpRequest) -> HttpResponse:
    """
    Product catalog view with Romanian hosting products.
    Supports filtering by product type and featured products.
    """
    
    # Get filter parameters
    product_type = request.GET.get('type', '')
    featured_only = request.GET.get('featured') == 'true'
    
    try:
        platform_api = PlatformAPIClient()
        
        # Build API query parameters
        params = {}
        if product_type:
            params['product_type'] = product_type
        if featured_only:
            params['featured'] = 'true'
        
        # Fetch products from platform
        products_response = platform_api.get('/orders/products/', params=params)
        
        if not products_response or 'results' not in products_response:
            raise PlatformAPIError("Invalid response format")
        
        products = products_response['results']
        
        # Get cart for item count
        cart = GDPRCompliantCartSession(request.session)
        
        # Prepare product type filter options
        product_type_options = [
            ('', _('All Products')),
            ('shared_hosting', _('Shared Hosting')),
            ('vps', _('VPS Hosting')),
            ('dedicated', _('Dedicated Server')),
            ('domain', _('Domains')),
            ('ssl', _('SSL Certificates')),
            ('email', _('Email Hosting')),
        ]
        
        context = {
            'products': products,
            'product_type_filter': product_type,
            'featured_only': featured_only,
            'product_type_options': product_type_options,
            'cart_count': cart.get_item_count(),
            'cart_total_quantity': cart.get_total_quantity(),
            'breadcrumb_current': 'products',
        }
        
        logger.info(f"✅ [Catalog] Loaded {len(products)} products")
        
    except PlatformAPIError as e:
        logger.error(f"🔥 [Catalog] Failed to load products: {e}")
        messages.error(request, _('Eroare la încărcarea produselor. Vă rugăm încercați din nou.'))
        
        context = {
            'products': [],
            'error': True,
            'product_type_options': [],
            'cart_count': 0,
        }
    
    return render(request, 'orders/product_catalog.html', context)


@require_customer_authentication
def product_detail(request: HttpRequest, product_slug: str) -> HttpResponse:
    """
    Product detail view with pricing options and configuration.
    """
    
    try:
        platform_api = PlatformAPIClient()
        
        # Fetch product details
        product = platform_api.get(f'/orders/products/{product_slug}/')
        
        if not product:
            messages.error(request, _('Produsul nu a fost găsit.'))
            return redirect('orders:catalog')
        
        # Get cart for context
        cart = GDPRCompliantCartSession(request.session)
        
        # Check if product is already in cart
        existing_item = None
        for item in cart.get_items():
            if item['product_slug'] == product_slug:
                existing_item = item
                break
        
        context = {
            'product': product,
            'existing_item': existing_item,
            'cart_count': cart.get_item_count(),
            'breadcrumb_current': 'product_detail',
        }
        
        logger.info(f"✅ [Product] Loaded product details: {product_slug}")
        
    except PlatformAPIError as e:
        logger.error(f"🔥 [Product] Failed to load product {product_slug}: {e}")
        messages.error(request, _('Produsul nu a fost găsit.'))
        return redirect('orders:catalog')
    
    return render(request, 'orders/product_detail.html', context)


@require_customer_authentication
@require_http_methods(["POST"])
def add_to_cart(request: HttpRequest) -> HttpResponse:
    """
    HTMX endpoint to add product to cart with validation.
    🔒 SECURITY: Enhanced with DoS hardening and uniform response timing.
    """
    
    # 🔒 SECURITY: Check cache availability and fail closed if needed
    cache_check = OrderSecurityHardening.fail_closed_on_cache_failure('cart_ops', 'add_to_cart')
    if cache_check:
        return cache_check
    
    # 🔒 SECURITY: Validate request size and patterns
    size_check = OrderSecurityHardening.validate_request_size(request)
    if size_check:
        return size_check
    
    pattern_check = OrderSecurityHardening.check_suspicious_patterns(request)
    if pattern_check:
        return pattern_check
    
    # 🔒 SECURITY: Enhanced rate limiting with IP tracking
    session_key = request.session.session_key
    if not session_key:
        # Force session creation if it doesn't exist yet
        request.session.save()
        session_key = request.session.session_key
    
    client_ip = CartRateLimiter.get_client_ip(request)
    if not CartRateLimiter.check_rate_limit(session_key, client_ip):
        OrderSecurityHardening.uniform_response_delay()  # Apply delay even on rate limit
        return JsonResponse({
            'error': _('Prea multe operații. Vă rugăm încetiniți.')
        }, status=429)
    
    try:
        # Get form data
        product_slug = request.POST.get('product_slug', '').strip()
        quantity = int(request.POST.get('quantity', 1))
        billing_period = request.POST.get('billing_period', 'monthly')
        domain_name = request.POST.get('domain_name', '').strip()
        
        # Parse configuration from JSON if provided
        config_json = request.POST.get('config', '{}')
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
            config=config
        )
        
        # 🔒 SECURITY: Record successful operation with IP tracking
        CartRateLimiter.record_operation(session_key, client_ip)
        
        # 🔒 SECURITY: Apply uniform response delay
        OrderSecurityHardening.uniform_response_delay()
        
        # Return updated cart widget
        return render(request, 'orders/partials/cart_updated.html', {
            'cart_count': cart.get_item_count(),
            'cart_total_quantity': cart.get_total_quantity(),
            'success_message': _('Product added to cart successfully!'),
            'product_name': cart.get_items()[-1]['product_name']  # Last added item
        })
        
    except ValidationError as e:
        logger.warning(f"⚠️ [Cart] Validation error: {e}")
        return render(request, 'orders/partials/error_message.html', {
            'error': str(e)
        }, status=400)
    except Exception as e:
        logger.error(f"🔥 [Cart] Unexpected error adding to cart: {e}")
        return render(request, 'orders/partials/error_message.html', {
            'error': _('Eroare la adăugarea în coș. Vă rugăm încercați din nou.')
        }, status=500)


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
        return JsonResponse({
            'error': _('Prea multe operații. Vă rugăm încetiniți.')
        }, status=429)
    
    try:
        product_slug = request.POST.get('product_slug', '').strip()
        billing_period = request.POST.get('billing_period', 'monthly')
        quantity = int(request.POST.get('quantity', 1))
        
        cart = GDPRCompliantCartSession(request.session)
        cart.update_item_quantity(product_slug, billing_period, quantity)
        
        # 🔒 SECURITY: Record successful operation with IP tracking
        CartRateLimiter.record_operation(session_key, client_ip)
        
        # 🔒 SECURITY: Apply uniform response delay
        OrderSecurityHardening.uniform_response_delay()
        
        return render(request, 'orders/partials/cart_item_updated.html', {
            'cart_count': cart.get_item_count(),
            'cart_total_quantity': cart.get_total_quantity(),
            'success_message': _('Cantitate actualizată cu succes!')
        })
        
    except ValidationError as e:
        return render(request, 'orders/partials/error_message.html', {
            'error': str(e)
        }, status=400)
    except Exception as e:
        logger.error(f"🔥 [Cart] Error updating cart item: {e}")
        return render(request, 'orders/partials/error_message.html', {
            'error': _('Eroare la actualizarea coșului.')
        }, status=500)


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
        return JsonResponse({
            'error': _('Prea multe operații. Vă rugăm încetiniți.')
        }, status=429)
    
    try:
        product_slug = request.POST.get('product_slug', '').strip()
        billing_period = request.POST.get('billing_period', 'monthly')
        
        cart = GDPRCompliantCartSession(request.session)
        cart.remove_item(product_slug, billing_period)
        
        # 🔒 SECURITY: Record successful operation with IP tracking
        CartRateLimiter.record_operation(session_key, client_ip)
        
        # 🔒 SECURITY: Apply uniform response delay
        OrderSecurityHardening.uniform_response_delay()
        
        return render(request, 'orders/partials/cart_updated.html', {
            'cart_count': cart.get_item_count(),
            'cart_total_quantity': cart.get_total_quantity(),
            'success_message': _('Produs eliminat din coș!')
        })
        
    except ValidationError as e:
        return render(request, 'orders/partials/error_message.html', {
            'error': str(e)
        }, status=400)
    except Exception as e:
        logger.error(f"🔥 [Cart] Error removing from cart: {e}")
        return render(request, 'orders/partials/error_message.html', {
            'error': _('Eroare la eliminarea din coș.')
        }, status=500)


@require_customer_authentication
def cart_review(request: HttpRequest) -> HttpResponse:
    """
    Cart review page with totals calculation and item management.
    """
    
    cart = GDPRCompliantCartSession(request.session)
    
    if not cart.has_items():
        messages.info(request, _('Coșul dumneavoastră este gol.'))
        return redirect('orders:catalog')
    
    # Calculate totals
    # Try request attributes first (set by middleware), fallback to session
    customer_id = getattr(request, 'customer_id', None) or request.session.get('customer_id')
    user_id = getattr(request, 'user_id', None) or request.session.get('user_id')
    calculation_result = None
    calculation_error = None
    
    try:
        calculation_result = CartCalculationService.calculate_cart_totals(cart, customer_id, user_id)
    except ValidationError as e:
        calculation_error = str(e)
        logger.error(f"🔥 [Cart] Calculation error: {e}")
    
    context = {
        'cart': cart,
        'cart_items': cart.get_items(),
        'calculation': calculation_result,
        'calculation_error': calculation_error,
        'warnings': cart.get_warnings(),
        'breadcrumb_current': 'cart',
    }
    
    return render(request, 'orders/cart_review.html', context)


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
        return JsonResponse({
            'error': _('Prea multe operații. Vă rugăm încetiniți.')
        }, status=429)
    
    try:
        cart = GDPRCompliantCartSession(request.session)
        # Try request attributes first (set by middleware), fallback to session
        customer_id = getattr(request, 'customer_id', None) or request.session.get('customer_id')
        user_id = getattr(request, 'user_id', None) or request.session.get('user_id')
        
        # Debug logging for authentication parameters
        logger.info(f"🔍 [Cart] Calculate totals - customer_id: {customer_id}, user_id: {user_id}")
        
        if not customer_id or not user_id:
            logger.error(f"🔥 [Cart] Missing authentication parameters - customer_id: {customer_id}, user_id: {user_id}")
            return render(request, 'orders/partials/error_message.html', {
                'error': _('Authentication error. Please refresh the page.')
            }, status=400)
        
        if not cart.has_items():
            return render(request, 'orders/partials/cart_empty.html')
        
        # Calculate totals
        calculation_result = CartCalculationService.calculate_cart_totals(cart, customer_id, user_id)
        
        # 🔒 SECURITY: Record successful operation with IP tracking
        CartRateLimiter.record_operation(session_key, client_ip)
        
        # 🔒 SECURITY: Apply uniform response delay
        OrderSecurityHardening.uniform_response_delay()
        
        return render(request, 'orders/partials/cart_totals.html', {
            'calculation': calculation_result,
            'cart': cart,
            'warnings': cart.get_warnings()
        })
        
    except ValidationError as e:
        return render(request, 'orders/partials/error_message.html', {
            'error': str(e)
        }, status=400)
    except Exception as e:
        logger.error(f"🔥 [Cart] Calculation error: {e}")
        return render(request, 'orders/partials/error_message.html', {
            'error': _('Eroare la calcularea totalurilor.')
        }, status=500)


@require_customer_authentication
def checkout(request: HttpRequest) -> HttpResponse:
    """
    Checkout page with preflight validation before order creation.
    Enforces company profile completeness before allowing order submission.
    """
    
    cart = GDPRCompliantCartSession(request.session)
    
    if not cart.has_items():
        messages.error(request, _('Cannot proceed with empty cart.'))
        return redirect('orders:catalog')
    
    # Calculate totals for display
    # Try request attributes first (set by middleware), fallback to session
    customer_id = getattr(request, 'customer_id', None) or request.session.get('customer_id')
    user_id = getattr(request, 'user_id', None) or request.session.get('user_id')
    calculation_result = None
    preflight_result = None
    
    try:
        calculation_result = CartCalculationService.calculate_cart_totals(cart, customer_id, user_id)
        
        # 🔎 SECURITY: Run preflight validation to check for issues
        preflight_result = OrderCreationService.preflight_order(cart, customer_id, user_id)
        
        # 🔒 CRITICAL: Check if preflight validation failed with profile-related errors
        if preflight_result and not preflight_result.get('valid', False):
            errors = preflight_result.get('errors', [])
            
            # Look for company profile completeness errors
            profile_related_errors = []
            for error in errors:
                error_str = str(error).lower()
                if any(keyword in error_str for keyword in [
                    'contact', 'email', 'address', 'billing', 'city', 'county', 'postal', 'country'
                ]):
                    profile_related_errors.append(error)
            
            # If we have profile-related errors, add contextual user guidance
            if profile_related_errors:
                logger.warning(
                    f"🔒 [Orders] Blocking checkout for customer {customer_id} due to incomplete profile: {profile_related_errors}"
                )
                # Add user-friendly message explaining what needs to be fixed
                messages.warning(request, _(
                    'Your company profile information needs to be completed before placing orders. '
                    'Please ensure your billing address, contact details, and VAT information (if applicable) are filled out completely.'
                ))
        
    except ValidationError:
        messages.error(request, _('Error calculating order totals.'))
        return redirect('orders:cart_review')
    
    context = {
        'cart': cart,
        'cart_items': cart.get_items(),
        'calculation': calculation_result,
        'warnings': cart.get_warnings(),
        'preflight': preflight_result,
        'can_submit': preflight_result.get('valid', False) if preflight_result else False,
        'breadcrumb_current': 'checkout',
    }
    
    return render(request, 'orders/checkout.html', context)


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
        customer_id = getattr(request, 'customer_id', None) or request.session.get('customer_id')
        user_id = getattr(request, 'user_id', None) or request.session.get('user_id')
        
        if not cart.has_items():
            messages.error(request, _('Cannot create order with empty cart.'))
            return redirect('orders:catalog')
        
        # 🔒 SECURITY: Validate cart version to prevent stale mutations
        expected_version = request.POST.get('cart_version', '')
        if not cart.validate_cart_version(expected_version):
            messages.error(
                request, 
                _('Cart was modified by another session. Please review and try again.')
            )
            return redirect('orders:cart_review')
        
        # 🔒 CRITICAL: Re-run preflight validation before order creation to prevent bypassing validation
        preflight_result = OrderCreationService.preflight_order(cart, customer_id, user_id)
        
        if not preflight_result.get('valid', False):
            errors = preflight_result.get('errors', [])
            logger.warning(f"🔒 [Orders] Blocking order creation for customer {customer_id} - validation failed: {errors}")
            
            # Check if these are profile-related errors
            profile_related_errors = []
            for error in errors:
                error_str = str(error).lower()
                if any(keyword in error_str for keyword in [
                    'contact', 'email', 'address', 'billing', 'city', 'county', 'postal', 'country'
                ]):
                    profile_related_errors.append(error)
            
            if profile_related_errors:
                messages.error(request, _(
                    'Order cannot be created because your company profile information is incomplete. '
                    'Please complete your billing address, contact details, and VAT information before ordering.'
                ))
            else:
                # Generic validation error message
                error_details = ' '.join(str(error) for error in errors[:3])  # Show first 3 errors
                messages.error(request, _('Order validation failed: {}').format(error_details))
            
            return redirect('orders:checkout')
        
        # Get optional notes
        notes = request.POST.get('notes', '').strip()
        
        # Create order with auto-pending (promotes to pending if validation passes)
        result = OrderCreationService.create_draft_order(cart, customer_id, user_id, notes, auto_pending=True)
        
        if result.get('error'):
            messages.error(request, result['error'])
            return redirect('orders:checkout')
        
        order_data = result.get('order', {})
        order_id = order_data.get('id')
        order_number = order_data.get('order_number')
        
        # Check if order was auto-promoted to pending
        order_status = order_data.get('status', 'draft')
        if order_status == 'pending':
            messages.success(request, 
                _('Order #{} was created successfully and is ready for payment!').format(order_number)
            )
        else:
            messages.success(request, 
                _('Order #{} was created successfully! You can view it in your orders list.').format(order_number)
            )
        
        return redirect('orders:confirmation', order_id=order_id)
        
    except ValidationError as e:
        messages.error(request, str(e))
        return redirect('orders:checkout')
    except Exception as e:
        logger.error(f"🔥 [Orders] Unexpected error creating order: {e}")
        messages.error(request, _('Eroare la crearea comenzii. Vă rugăm încercați din nou.'))
        return redirect('orders:checkout')


@require_customer_authentication
def order_confirmation(request: HttpRequest, order_id: str) -> HttpResponse:
    """
    Order confirmation page showing order details.
    """
    
    try:
        platform_api = PlatformAPIClient()
        # Try request attributes first (set by middleware), fallback to session
        customer_id = getattr(request, 'customer_id', None) or request.session.get('customer_id')
        user_id = getattr(request, 'user_id', None) or request.session.get('user_id')
        
        # Fetch order details from Platform API with HMAC authentication
        order_data = platform_api.post(f'orders/{order_id}/', data={
            'customer_id': customer_id,
            'timestamp': int(timezone.now().timestamp()),
            'action': 'get_order_detail'
        }, user_id=int(user_id))
        
        if not order_data or order_data.get('error'):
            messages.error(request, _('Comanda nu a fost găsită.'))
            return redirect('orders:catalog')
        
        context = {
            'order': order_data,
            'breadcrumb_current': 'confirm',
        }
        
        return render(request, 'orders/order_confirmation.html', context)
        
    except PlatformAPIError as e:
        logger.error(f"🔥 [Orders] Failed to load order {order_id}: {e}")
        messages.error(request, _('Eroare la încărcarea detaliilor comenzii.'))
        return redirect('orders:catalog')


@require_customer_authentication
def mini_cart_content(request: HttpRequest) -> HttpResponse:
    """
    HTMX endpoint for mini-cart widget content.
    """
    
    cart = GDPRCompliantCartSession(request.session)
    
    context = {
        'cart': cart,
        'cart_items': cart.get_items()[:3],  # Show only first 3 items
        'total_items': cart.get_item_count(),
        'show_view_all': cart.get_item_count() > 3,
    }
    
    return render(request, 'orders/partials/mini_cart_content.html', context)