"""
Order API Views for PRAHO Platform
DRF views for product catalog, order management, and cart calculations.
"""

import logging
from typing import Any, Dict
from rest_framework import status
from rest_framework.decorators import api_view, throttle_classes, permission_classes
from rest_framework.permissions import AllowAny
from rest_framework.request import Request
from rest_framework.response import Response
from rest_framework.throttling import ScopedRateThrottle

from apps.api.secure_auth import require_customer_authentication
from apps.common.types import Ok
from apps.customers.models import Customer
from apps.orders.services import OrderService, OrderCreateData, BillingAddressData
from apps.products.models import Product
from apps.orders.preflight import OrderPreflightValidationService
from .serializers import (
    ProductListSerializer, ProductDetailSerializer, 
    OrderListSerializer, OrderDetailSerializer,
    CartCalculationInputSerializer, CartCalculationOutputSerializer,
    OrderCreateInputSerializer, CartItemInputSerializer
)

logger = logging.getLogger(__name__)


# 🔒 SECURITY: Custom throttle classes for order endpoints
class OrderCreateThrottle(ScopedRateThrottle):
    """Throttling for order creation endpoints"""
    scope = 'order_create'


class OrderCalculateThrottle(ScopedRateThrottle):
    """Throttling for cart calculation endpoints"""
    scope = 'order_calculate'


class OrderListThrottle(ScopedRateThrottle):
    """Throttling for order listing endpoints"""
    scope = 'order_list'


class ProductCatalogThrottle(ScopedRateThrottle):
    """Throttling for product catalog endpoints"""
    scope = 'product_catalog'


@api_view(['GET'])
@permission_classes([AllowAny])
@throttle_classes([ProductCatalogThrottle])
def product_list(request: Request) -> Response:
    """
    Public endpoint for product catalog listing.
    Supports filtering by product type and featured status.
    """
    
    # Get query parameters
    product_type = request.query_params.get('product_type')
    featured = request.query_params.get('featured') == 'true'
    
    # Build queryset
    queryset = Product.objects.filter(is_active=True, is_public=True)
    
    if product_type:
        queryset = queryset.filter(product_type=product_type)
    
    if featured:
        queryset = queryset.filter(is_featured=True)
    
    # Order by sort_order, then by name
    queryset = queryset.prefetch_related('prices').order_by('sort_order', 'name')
    
    # Serialize and return
    serializer = ProductListSerializer(queryset, many=True)
    
    return Response({
        'results': serializer.data,
        'count': len(serializer.data)
    })


@api_view(['GET'])
@permission_classes([AllowAny])
@throttle_classes([ProductCatalogThrottle])
def product_detail(request: Request, slug: str) -> Response:
    """
    Public endpoint for product detail by slug.
    """
    
    try:
        product = Product.objects.prefetch_related('prices').get(
            slug=slug, is_active=True, is_public=True
        )
    except Product.DoesNotExist:
        return Response({
            'error': 'Product not found'
        }, status=status.HTTP_404_NOT_FOUND)
    
    serializer = ProductDetailSerializer(product)
    return Response(serializer.data)


@api_view(['POST'])
@throttle_classes([OrderCalculateThrottle])
@require_customer_authentication
def calculate_cart_totals(request: Request, customer) -> Response:
    """
    Calculate cart totals with Romanian VAT compliance.
    Server-authoritative pricing - never trust client input.
    """
    
    # Validate input
    input_serializer = CartCalculationInputSerializer(data=request.data)
    if not input_serializer.is_valid():
        return Response({
            'error': 'Invalid input',
            'details': input_serializer.errors
        }, status=status.HTTP_400_BAD_REQUEST)
    
    validated_data = input_serializer.validated_data
    # customer parameter is injected by decorator and already validated
    customer_id = customer.id
    currency_code = validated_data['currency']
    cart_items = validated_data['items']
    
    try:
        # Import here to avoid circular imports
        from apps.orders.services import OrderCalculationService
        from apps.billing.models import Currency
        
        # Get currency
        try:
            currency = Currency.objects.get(code=currency_code)
        except Currency.DoesNotExist:
            return Response({
                'error': f'Currency {currency_code} not supported'
            }, status=status.HTTP_400_BAD_REQUEST)
        
        # Convert cart items to internal format
        order_items = []
        warnings = []
        
        for item_data in cart_items:
            try:
                product = Product.objects.get(id=item_data['product_id'])
                
                # Validate product is active
                if not product.is_active:
                    warnings.append({
                        'type': 'product_inactive',
                        'product_name': product.name,
                        'message': f'Product {product.name} is no longer available'
                    })
                    continue
                
                # Get current pricing (server-authoritative)
                from apps.products.models import ProductPrice
                
                try:
                    product_price = ProductPrice.objects.get(
                        product=product,
                        currency=currency,
                        billing_period=item_data['billing_period'],
                        is_active=True
                    )
                except ProductPrice.DoesNotExist:
                    warnings.append({
                        'type': 'pricing_unavailable',
                        'product_name': product.name,
                        'message': f'Pricing not available for {product.name} - {item_data["billing_period"]}'
                    })
                    continue
                
                # Build order item data (include setup fee for accurate totals)
                order_items.append({
                    'product_id': product.id,
                    'quantity': item_data['quantity'],
                    'unit_price_cents': int(product_price.effective_price_cents),
                    'setup_cents': int(product_price.setup_cents),
                    'description': product.name,
                    'meta': item_data.get('config', {})
                })
                
            except Product.DoesNotExist:
                warnings.append({
                    'type': 'product_not_found',
                    'message': f'Product not found: {item_data["product_id"]}'
                })
        
        # 🔒 SECURITY: Calculate totals with proper VAT compliance
        from apps.orders.vat_rules import OrderVATCalculator
        from apps.customers.models import Customer
        
        # Get customer for VAT calculation
        try:
            customer_obj = Customer.objects.get(id=customer_id)
            customer_country = getattr(customer_obj, 'country', 'RO')
            is_business = bool(getattr(customer_obj, 'company_name', ''))
            vat_number = getattr(customer_obj.tax_profile, 'vat_number', '') if hasattr(customer_obj, 'tax_profile') else ''
        except Customer.DoesNotExist:
            # Default to Romanian consumer
            customer_country = 'RO'
            is_business = False
            vat_number = ''
        
        # Calculate subtotal from order items
        subtotal_cents = sum(
            item['unit_price_cents'] * item['quantity'] + item['setup_cents'] 
            for item in order_items
        )
        
        # Calculate VAT with full compliance
        vat_result = OrderVATCalculator.calculate_vat(
            subtotal_cents=subtotal_cents,
            customer_country=customer_country,
            is_business=is_business,
            vat_number=vat_number,
            customer_id=str(customer_id)
        )
        
        totals = {
            'subtotal_cents': vat_result.subtotal_cents,
            'tax_cents': vat_result.vat_cents,
            'total_cents': vat_result.total_cents
        }
        
        # Prepare response
        response_data = {
            'subtotal_cents': totals['subtotal_cents'],
            'tax_cents': totals['tax_cents'], 
            'total_cents': totals['total_cents'],
            'currency': currency_code,
            'warnings': warnings,
            'items': []  # Could include per-item calculations if needed
        }
        
        # Validate output
        output_serializer = CartCalculationOutputSerializer(data=response_data)
        if output_serializer.is_valid():
            logger.info(f"💰 [API] Cart calculated: {totals['total_cents']} cents for customer {customer_id}")
            return Response(output_serializer.validated_data)
        else:
            logger.error(f"🔥 [API] Output serializer error: {output_serializer.errors}")
            return Response({
                'error': 'Calculation error'
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        
    except Exception as e:
        logger.exception(f"🔥 [API] Cart calculation failed: {e}")
        return Response({
            'error': 'Calculation failed'
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@api_view(['POST'])
@throttle_classes([OrderCalculateThrottle])
@require_customer_authentication
def preflight_order(request: Request, customer) -> Response:
    """
    🔎 Preflight validation for portal checkout.
    Validates customer profile, product/price availability, VAT scenario, and returns errors/warnings + totals preview.
    """
    try:
        data = request.data or {}
        currency_code = data.get('currency', 'RON')
        items = data.get('items', [])

        errors: list[str] = []
        warnings: list[str] = []

        # Basic customer profile checks (using customer entity)
        billing_address = getattr(customer, 'get_billing_address', lambda: None)()
        contact_email = getattr(customer, 'primary_email', '')
        contact_name = getattr(customer, 'name', '')
        if not contact_email:
            errors.append('Contact email is required')
        if not contact_name:
            errors.append('Contact name is required')
        if not billing_address:
            errors.append('Billing address is required')

        # Validate products/prices; compute subtotal
        subtotal_cents = 0
        for item in items:
            try:
                product = Product.objects.get(id=item['product_id'], is_active=True)
            except Product.DoesNotExist:
                errors.append(f"Product not found: {item.get('product_id')}")
                continue
            billing_period = item.get('billing_period', 'monthly')
            quantity = int(item.get('quantity', 1))
            price = product.get_price_for_period(currency_code, billing_period)
            if not price:
                errors.append(f"No price for {product.slug} in {currency_code}/{billing_period}")
                continue
            if quantity < 1:
                errors.append(f"Invalid quantity for {product.name}")
                continue
            subtotal_cents += (int(price.effective_price_cents) * quantity) + int(price.setup_cents)

        # VAT preview using rules
        vat_cents = 0
        total_cents = subtotal_cents
        vat_reasoning = ''
        if subtotal_cents > 0:
            from apps.orders.vat_rules import OrderVATCalculator
            tax_profile = getattr(customer, 'get_tax_profile', lambda: None)()
            vat_number = getattr(tax_profile, 'vat_number', None) or getattr(tax_profile, 'cui', None)
            country = (billing_address.country if billing_address else 'RO').upper()
            is_business = bool(getattr(customer, 'company_name', ''))
            vat_result = OrderVATCalculator.calculate_vat(
                subtotal_cents=subtotal_cents,
                customer_country=country,
                is_business=is_business,
                vat_number=vat_number,
                customer_id=str(customer.id),
                order_id=None,
            )
            vat_cents = int(vat_result.vat_cents)
            total_cents = int(vat_result.total_cents)
            vat_reasoning = vat_result.reasoning

        return Response({
            'success': len(errors) == 0,
            'errors': errors,
            'warnings': warnings,
            'preview': {
                'currency': currency_code,
                'subtotal_cents': subtotal_cents,
                'vat_cents': vat_cents,
                'total_cents': total_cents,
                'vat_reasoning': vat_reasoning,
            }
        })
    except Exception as e:
        logger.exception(f"🔥 [API] Preflight failed: {e}")
        return Response({'error': 'Preflight failed'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@api_view(['POST'])
@throttle_classes([OrderCreateThrottle])
@require_customer_authentication
def create_order(request: Request, customer) -> Response:
    """
    Create order from cart items with server-side pricing resolution.
    Supports idempotency keys to prevent duplicate orders and race conditions.
    """
    
    # 🔒 SECURITY: Extract and validate idempotency key
    idempotency_key = request.headers.get('Idempotency-Key') or request.data.get('idempotency_key')
    if not idempotency_key:
        return Response({
            'error': 'Idempotency-Key header or idempotency_key field required'
        }, status=status.HTTP_400_BAD_REQUEST)
    
    if len(idempotency_key) < 16 or len(idempotency_key) > 128:
        return Response({
            'error': 'Idempotency key must be between 16-128 characters'
        }, status=status.HTTP_400_BAD_REQUEST)
    
    # 🔒 SECURITY: Check for existing order with this idempotency key
    from django.core.cache import cache
    cache_key = f"idempotency:order:{customer.id}:{idempotency_key}"
    existing_order_id = cache.get(cache_key)
    
    if existing_order_id:
        logger.info(f"🔄 [API] Returning existing order for idempotency key: {idempotency_key[:8]}...")
        try:
            from apps.orders.models import Order
            existing_order = Order.objects.get(id=existing_order_id, customer=customer)
            serializer = OrderDetailSerializer(existing_order)
            return Response({
                'success': True,
                'order': serializer.data,
                'duplicate': True  # Indicate this was a duplicate request
            }, status=status.HTTP_200_OK)
        except Order.DoesNotExist:
            # Order was deleted, clear cache and continue with creation
            cache.delete(cache_key)
    
    # Validate input
    input_serializer = OrderCreateInputSerializer(data=request.data)
    if not input_serializer.is_valid():
        return Response({
            'error': 'Invalid input',
            'details': input_serializer.errors
        }, status=status.HTTP_400_BAD_REQUEST)
    
    validated_data = input_serializer.validated_data
    # customer parameter is injected by decorator and already validated
    customer_id = customer.id
    
    try:
        # Convert input to OrderCreateData
        # Build billing address from customer data
        billing_address_data = BillingAddressData(
            company_name=customer.company_name or '',
            contact_name=customer.name,
            email=customer.primary_email,
            phone=getattr(customer, 'phone', ''),
            address_line1=getattr(customer, 'address_line1', ''),
            address_line2=getattr(customer, 'address_line2', ''),
            city=getattr(customer, 'city', ''),
            county=getattr(customer, 'county', ''),
            postal_code=getattr(customer, 'postal_code', ''),
            country=getattr(customer, 'country', 'RO'),
            fiscal_code=getattr(customer.tax_profile, 'cui', '') if hasattr(customer, 'tax_profile') else '',
            registration_number=getattr(customer, 'registration_number', ''),
            vat_number=getattr(customer.tax_profile, 'vat_number', '') if hasattr(customer, 'tax_profile') else ''
        )
        
        # 🔒 SECURITY: Resolve product pricing with sealed token validation
        order_items = []
        price_warnings = []
        currency_code = validated_data['currency']
        
        for item_data in validated_data['items']:
            # Fetch product and price for selected billing period
            try:
                product = Product.objects.get(id=item_data['product_id'], is_active=True)
            except Product.DoesNotExist:
                logger.warning(f"⚠️ [API] Product not found during create_order: {item_data['product_id']}")
                continue

            billing_period = item_data['billing_period']
            price = product.get_price_for_period(currency_code, billing_period)
            if not price:
                logger.warning(
                    f"⚠️ [API] Pricing not found for product {product.slug} period {billing_period} currency {currency_code}"
                )
                continue

            # 🔒 SECURITY: Validate sealed price token if provided
            sealed_token = item_data.get('sealed_price_token', '').strip()
            validated_price_data = None
            product_price_id_snapshot = price.id  # Default to current price ID
            
            if sealed_token:
                try:
                    # Import here to avoid circular imports
                    from apps.orders.price_sealing import PriceSealingService, get_client_ip
                    
                    # Get client IP for validation
                    client_ip = get_client_ip(request)
                    
                    # Unseal and validate token with IP binding
                    unsealed_data = PriceSealingService.unseal_price(sealed_token, client_ip)
                    validated_data_result = PriceSealingService.validate_price_against_database(
                        unsealed_data, expected_product_price_id=price.id
                    )
                    
                    if validated_data_result['price_changed']:
                        # Price has changed since token was created - add warning
                        price_warnings.append({
                            'type': 'price_changed',
                            'product_name': product.name,
                            'message': f'Price for {product.name} has changed since added to cart',
                            'old_amount_cents': validated_data_result['sealed_amount_cents'],
                            'new_amount_cents': validated_data_result['current_amount_cents']
                        })
                        logger.warning(
                            f"🔒 [API] Price changed for {product.slug}: "
                            f"{validated_data_result['sealed_amount_cents']} -> {validated_data_result['current_amount_cents']} cents"
                        )
                    
                    validated_price_data = validated_data_result
                    product_price_id_snapshot = validated_data_result['product_price_id']
                    
                    logger.info(f"🔒 [API] Price token validated for {product.slug}")
                    
                except Exception as e:
                    logger.error(f"🔥 [API] Price token validation failed for {product.slug}: {e}")
                    # For now, continue with current pricing but log the issue
                    # In production, you might want to reject the order
                    pass

            # Build order item with price snapshot in meta
            item_meta = item_data.get('config', {})
            item_meta['product_price_id'] = str(product_price_id_snapshot)  # 🔒 SECURITY: Snapshot ProductPrice.id
            if validated_price_data:
                item_meta['price_validation'] = {
                    'token_validated': True,
                    'price_changed': validated_price_data['price_changed'],
                    'validated_at': timezone.now().isoformat()
                }

            order_items.append({
                'product_id': product.id,
                'service_id': None,  # Not used for new orders
                'quantity': item_data['quantity'],
                'unit_price_cents': int(price.effective_price_cents),
                'setup_cents': int(price.setup_cents),
                'billing_period': billing_period,
                'description': product.name,
                'meta': item_meta,  # Include price snapshot
            })
        
        order_create_data = OrderCreateData(
            customer=customer,
            items=order_items,
            billing_address=billing_address_data,
            currency=validated_data['currency'],
            notes=validated_data.get('notes', ''),
            meta=validated_data.get('meta', {})
        )
        
        # Create order using platform service
        result = OrderService.create_order(order_create_data)
        
        if isinstance(result, Ok):
            order = result.value
            serializer = OrderDetailSerializer(order)
            
            # Auto-pending promote if requested
            auto_pending = bool(request.data.get('auto_pending'))
            promoted = False
            preflight = None
            if auto_pending:
                try:
                    status_change = StatusChangeData(new_status='pending', notes='Auto-pending from API', changed_by=None)  # type: ignore[arg-type]
                    promote_result = OrderService.update_order_status(order, status_change)
                    if promote_result.is_ok():
                        order.refresh_from_db()
                        promoted = True
                        serializer = OrderDetailSerializer(order)
                    else:
                        # Collect preflight errors for client visibility
                        from apps.orders.preflight import OrderPreflightValidationService
                        errs, warns = OrderPreflightValidationService.validate(order)
                        preflight = { 'errors': errs, 'warnings': warns }
                except Exception as e:
                    logger.warning(f"⚠️ [API] Auto-pending failed for {order.order_number}: {e}")

            # 🔒 SECURITY: Store idempotency key to prevent duplicate orders
            cache_key = f"idempotency:order:{customer.id}:{idempotency_key}"
            cache.set(cache_key, order.id, timeout=3600)  # Store for 1 hour
            
            logger.info(f"📦 [API] Order created: {order.order_number} for customer {customer_id} (idempotency: {idempotency_key[:8]}...)")
            
            return Response({
                'success': True,
                'order': serializer.data,
                'auto_pending_attempted': auto_pending,
                'promoted_to_pending': promoted,
                'preflight': preflight
            }, status=status.HTTP_201_CREATED)
        else:
            logger.error(f"🔥 [API] Order creation failed: {result.error}")
            return Response({
                'error': result.error
            }, status=status.HTTP_400_BAD_REQUEST)
        
    except Exception as e:
        logger.exception(f"🔥 [API] Order creation exception: {e}")
        return Response({
            'error': 'Order creation failed'
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@api_view(['POST'])
@throttle_classes([OrderListThrottle])
@require_customer_authentication  
def order_list(request: Request, customer) -> Response:
    """
    List orders for authenticated customer.
    """
    
    # customer parameter is injected by decorator and already validated
    customer_id = customer.id
    
    try:
        # Get customer orders
        from apps.orders.models import Order
        
        orders = Order.objects.filter(customer_id=customer_id).order_by('-created_at')
        
        # Apply filters from request body
        request_data = request.data
        status_filter = request_data.get('status')
        if status_filter:
            orders = orders.filter(status=status_filter)
        
        serializer = OrderListSerializer(orders, many=True)
        
        return Response({
            'results': serializer.data,
            'count': len(serializer.data)
        })
        
    except Exception as e:
        logger.exception(f"🔥 [API] Order list failed: {e}")
        return Response({
            'error': 'Failed to load orders'
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@api_view(['POST'])
@throttle_classes([OrderListThrottle])
@require_customer_authentication
def order_detail(request: Request, customer, order_id: str) -> Response:
    """
    Get order details for authenticated customer.
    """
    
    # customer parameter is injected by decorator and already validated
    customer_id = customer.id
    
    try:
        from apps.orders.models import Order
        
        order = Order.objects.prefetch_related('items').get(
            id=order_id, 
            customer_id=customer_id
        )
        
        serializer = OrderDetailSerializer(order)
        return Response(serializer.data)
        
    except Order.DoesNotExist:
        return Response({
            'error': 'Order not found'
        }, status=status.HTTP_404_NOT_FOUND)
    except Exception as e:
        logger.exception(f"🔥 [API] Order detail failed: {e}")
        return Response({
            'error': 'Failed to load order'
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
