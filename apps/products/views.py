
# ===============================================================================
# PRODUCT CATALOG VIEWS - PRAHO PLATFORM
# ===============================================================================

from __future__ import annotations

import logging

from django.contrib import messages
from django.core.paginator import Paginator
from django.db import models, transaction
from django.db.models import Count, Q
from django.forms import modelform_factory
from django.http import HttpRequest, HttpResponse, JsonResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.utils.translation import gettext_lazy as _
from django.views.decorators.http import require_http_methods, require_POST

from apps.billing.models import Currency
from apps.common.decorators import staff_required
from apps.common.mixins import get_search_context
from apps.common.utils import json_error, json_success

from .models import Product, ProductPrice

logger = logging.getLogger(__name__)

# ===============================================================================
# PRODUCT LIST VIEW
# ===============================================================================

@staff_required
def product_list(request: HttpRequest) -> HttpResponse:
    """
    🛍️ Staff-only product catalog management with statistics and filtering
    Following PRAHO billing pattern for consistency and Romanian business context
    """
    try:
        # Get all products with prefetch for performance
        products_qs = Product.objects.prefetch_related(
            'prices__currency',
            'relationships_from__target_product',
            'relationships_to__source_product'
        )

        # Statistics for cards
        total_products = products_qs.count()
        active_products = products_qs.filter(is_active=True).count()
        public_products = products_qs.filter(is_public=True).count()
        featured_products = products_qs.filter(is_featured=True).count()

        # Product type distribution
        product_type_counts = dict(products_qs.values('product_type').annotate(
            count=Count('id')
        ).values_list('product_type', 'count'))

        # Search context
        search_context = get_search_context(request, 'search')
        search_query = search_context['search_query']

        # Apply search filter
        if search_query:
            products_qs = products_qs.filter(
                Q(name__icontains=search_query) |
                Q(slug__icontains=search_query) |
                Q(description__icontains=search_query) |
                Q(short_description__icontains=search_query)
            )

        # Apply filters
        product_type_filter = request.GET.get('product_type')
        if product_type_filter and product_type_filter != 'all':
            products_qs = products_qs.filter(product_type=product_type_filter)

        is_active_filter = request.GET.get('is_active')
        if is_active_filter == 'true':
            products_qs = products_qs.filter(is_active=True)
        elif is_active_filter == 'false':
            products_qs = products_qs.filter(is_active=False)

        is_public_filter = request.GET.get('is_public')
        if is_public_filter == 'true':
            products_qs = products_qs.filter(is_public=True)
        elif is_public_filter == 'false':
            products_qs = products_qs.filter(is_public=False)

        # Pagination
        paginator = Paginator(products_qs, 20)
        page_number = request.GET.get('page')
        products = paginator.get_page(page_number)

        # HTMX partial response for dynamic updates
        if request.headers.get('HX-Request'):
            return render(request, 'products/partials/product_table.html', {
                'products': products,
                'search_query': search_query,
            })

        context = {
            'products': products,
            'search_query': search_query,
            'product_type_filter': product_type_filter,
            'is_active_filter': is_active_filter,
            'is_public_filter': is_public_filter,
            
            # Statistics
            'total_products': total_products,
            'active_products': active_products,
            'public_products': public_products,
            'featured_products': featured_products,
            'product_type_counts': product_type_counts,
            
            # Filter choices
            'product_type_choices': Product.PRODUCT_TYPES,
            
            # Metadata
            'is_staff_user': True,
        }

        return render(request, 'products/product_list.html', context)

    except Exception as e:
        logger.error(f"🔥 [Products] Error in product list view: {e}")
        messages.error(request, _("❌ Error loading product catalog"))
        return redirect('dashboard')


@staff_required
def product_list_htmx(request: HttpRequest) -> HttpResponse:
    """HTMX endpoint for dynamic product list updates"""
    # Reuse the main view logic but always return partial
    response = product_list(request)
    if hasattr(response, 'context_data'):
        return render(request, 'products/partials/product_table.html', response.context_data)
    return response

# ===============================================================================
# PRODUCT DETAIL VIEW
# ===============================================================================

@staff_required
def product_detail(request: HttpRequest, slug: str) -> HttpResponse:
    """
    🔍 Product detail view with pricing, relationships, and management options
    """
    try:
        product = get_object_or_404(
            Product.objects.prefetch_related(
                'prices__currency',
                'relationships_from__target_product',
                'relationships_to__source_product',
                'bundle_items__bundle'
            ),
            slug=slug
        )

        # Get active prices grouped by currency
        prices_by_currency: dict[str, list[ProductPrice]] = {}
        for price in product.get_active_prices():
            currency_code = price.currency.code
            if currency_code not in prices_by_currency:
                prices_by_currency[currency_code] = []
            prices_by_currency[currency_code].append(price)

        # Get product relationships
        relationships_from = product.relationships_from.filter(is_active=True).select_related('target_product')
        relationships_to = product.relationships_to.filter(is_active=True).select_related('source_product')

        # Get bundles this product is part of
        bundle_memberships = product.bundle_items.filter(bundle__is_active=True).select_related('bundle')

        context = {
            'product': product,
            'prices_by_currency': prices_by_currency,
            'relationships_from': relationships_from,
            'relationships_to': relationships_to,
            'bundle_memberships': bundle_memberships,
            'is_staff_user': True,
        }

        return render(request, 'products/product_detail.html', context)

    except Exception as e:
        logger.error(f"🔥 [Products] Error in product detail view for slug {slug}: {e}")
        messages.error(request, _("❌ Error loading product details"))
        return redirect('products:product_list')

# ===============================================================================
# PRODUCT CREATE/EDIT VIEWS
# ===============================================================================

@staff_required
@require_http_methods(["GET", "POST"])
def product_create(request: HttpRequest) -> HttpResponse:
    """✨ Create new product with Romanian business context"""
    
    # Dynamic form creation
    product_form = modelform_factory(
        Product,
        fields=[
            'name', 'slug', 'description', 'short_description',
            'product_type', 'module', 'module_config',
            'is_active', 'is_featured', 'is_public',
            'requires_domain', 'domain_required_at_signup',
            'sort_order', 'meta_title', 'meta_description',
            'tags', 'includes_vat', 'meta'
        ]
    )
    
    if request.method == 'POST':
        form = product_form(request.POST)
        if form.is_valid():
            try:
                with transaction.atomic():
                    product = form.save()
                    logger.info(f"✅ [Products] Created product: {product.name} ({product.slug})")
                    messages.success(request, _(f"✅ Product '{product.name}' created successfully"))
                    return redirect('products:product_detail', slug=product.slug)
            except Exception as e:
                logger.error(f"🔥 [Products] Error creating product: {e}")
                messages.error(request, _("❌ Error creating product"))
        else:
            # Form validation failed - add error message but preserve form data
            messages.error(request, _("❌ Please correct the errors below. All required fields must be filled in."))
    else:
        form = product_form()
    
    # Convert choices to component format
    product_type_options = [
        {'value': choice[0], 'label': str(choice[1])} 
        for choice in Product.PRODUCT_TYPES
    ]
    
    context = {
        'form': form,
        'action': 'create',
        'product_type_choices': Product.PRODUCT_TYPES,
        'product_type_options': product_type_options,
        'is_staff_user': True,
    }
    
    return render(request, 'products/product_form.html', context)


@staff_required
@require_http_methods(["GET", "POST"])
def product_edit(request: HttpRequest, slug: str) -> HttpResponse:
    """✏️ Edit existing product"""
    
    product = get_object_or_404(Product, slug=slug)
    
    product_form = modelform_factory(
        Product,
        fields=[
            'name', 'slug', 'description', 'short_description',
            'product_type', 'module', 'module_config',
            'is_active', 'is_featured', 'is_public',
            'requires_domain', 'domain_required_at_signup',
            'sort_order', 'meta_title', 'meta_description',
            'tags', 'includes_vat', 'meta'
        ]
    )
    
    if request.method == 'POST':
        form = product_form(request.POST, instance=product)
        if form.is_valid():
            try:
                with transaction.atomic():
                    updated_product = form.save()
                    logger.info(f"✅ [Products] Updated product: {updated_product.name} ({updated_product.slug})")
                    messages.success(request, _(f"✅ Product '{updated_product.name}' updated successfully"))
                    return redirect('products:product_detail', slug=updated_product.slug)
            except Exception as e:
                logger.error(f"🔥 [Products] Error updating product: {e}")
                messages.error(request, _("❌ Error updating product"))
        else:
            # Form validation failed - add error message but preserve form data
            messages.error(request, _("❌ Please correct the errors below. All required fields must be filled in."))
    else:
        form = product_form(instance=product)
    
    # Convert choices to component format
    product_type_options = [
        {'value': choice[0], 'label': str(choice[1])} 
        for choice in Product.PRODUCT_TYPES
    ]
    
    context = {
        'form': form,
        'product': product,
        'action': 'edit',
        'product_type_choices': Product.PRODUCT_TYPES,
        'product_type_options': product_type_options,
        'is_staff_user': True,
    }
    
    return render(request, 'products/product_form.html', context)

# ===============================================================================
# PRODUCT STATUS TOGGLE VIEWS (HTMX)
# ===============================================================================

@staff_required
@require_POST
def product_toggle_active(request: HttpRequest, slug: str) -> JsonResponse:
    """🔄 Toggle product active status via HTMX"""
    try:
        product = get_object_or_404(Product, slug=slug)
        product.is_active = not product.is_active
        product.save(update_fields=['is_active'])
        
        logger.info(f"✅ [Products] Toggled active status for {product.name}: {product.is_active}")
        
        return json_success({
            'is_active': product.is_active,
            'message': _("Product status updated")
        })
        
    except Exception as e:
        logger.error(f"🔥 [Products] Error toggling active status for slug {slug}: {e}")
        return json_error(str(_("Failed to update product status")))


@staff_required
@require_POST
def product_toggle_public(request: HttpRequest, slug: str) -> JsonResponse:
    """👁️ Toggle product public visibility via HTMX"""
    try:
        product = get_object_or_404(Product, slug=slug)
        product.is_public = not product.is_public
        product.save(update_fields=['is_public'])
        
        logger.info(f"✅ [Products] Toggled public status for {product.name}: {product.is_public}")
        
        return json_success({
            'is_public': product.is_public,
            'message': _("Product visibility updated")
        })
        
    except Exception as e:
        logger.error(f"🔥 [Products] Error toggling public status for slug {slug}: {e}")
        return json_error(str(_("Failed to update product visibility")))


@staff_required
@require_POST
def product_toggle_featured(request: HttpRequest, slug: str) -> JsonResponse:
    """⭐ Toggle product featured status via HTMX"""
    try:
        product = get_object_or_404(Product, slug=slug)
        product.is_featured = not product.is_featured
        product.save(update_fields=['is_featured'])
        
        logger.info(f"✅ [Products] Toggled featured status for {product.name}: {product.is_featured}")
        
        return json_success({
            'is_featured': product.is_featured,
            'message': _("Product featured status updated")
        })
        
    except Exception as e:
        logger.error(f"🔥 [Products] Error toggling featured status for slug {slug}: {e}")
        return json_error(str(_("Failed to update product featured status")))

# ===============================================================================
# PRODUCT PRICING MANAGEMENT
# ===============================================================================

@staff_required
def product_prices(request: HttpRequest, slug: str) -> HttpResponse:
    """💰 Manage product pricing - Romanian RON focus"""
    try:
        product = get_object_or_404(Product, slug=slug)
        prices = product.prices.filter(is_active=True).select_related('currency').order_by('currency__code', 'billing_period')
        
        # Get available currencies (with RON first for Romanian business)
        currencies = Currency.objects.order_by(
            models.Case(
                models.When(code='RON', then=0),
                default=1
            ),
            'code'
        )
        
        context = {
            'product': product,
            'prices': prices,
            'currencies': currencies,
            'billing_period_choices': ProductPrice.BILLING_PERIODS,
            'is_staff_user': True,
        }
        
        return render(request, 'products/product_prices.html', context)
        
    except Exception as e:
        logger.error(f"🔥 [Products] Error loading prices for slug {slug}: {e}")
        messages.error(request, _("❌ Error loading product prices"))
        return redirect('products:product_detail', slug=slug)


@staff_required
@require_http_methods(["GET", "POST"])
def product_price_create(request: HttpRequest, slug: str) -> HttpResponse:
    """💰 Add new price to product"""
    
    product = get_object_or_404(Product, slug=slug)
    
    product_price_form = modelform_factory(
        ProductPrice,
        fields=[
            'currency', 'billing_period', 'amount_cents', 'setup_cents',
            'discount_percent', 'minimum_quantity', 'maximum_quantity',
            'promo_price_cents', 'promo_valid_until', 'is_active'
        ]
    )
    
    if request.method == 'POST':
        form = product_price_form(request.POST)
        if form.is_valid():
            try:
                with transaction.atomic():
                    price = form.save(commit=False)
                    price.product = product
                    price.save()
                    logger.info(f"✅ [Products] Created price for {product.name}: {price}")
                    messages.success(request, _("✅ Product price created successfully"))
                    return redirect('products:product_prices', slug=product.slug)
            except Exception as e:
                logger.error(f"🔥 [Products] Error creating price: {e}")
                messages.error(request, _("❌ Error creating product price"))
        else:
            # Form validation failed - add error message but preserve form data
            messages.error(request, _("❌ Please correct the errors below. All required fields must be filled in."))
    else:
        form = product_price_form()
    
    # Get available currencies and format for component
    currencies = Currency.objects.order_by('code')
    currency_options = [
        {'value': currency.code, 'label': f'{currency.code} ({currency.symbol})'} 
        for currency in currencies
    ]
    
    # Format billing period choices for component
    billing_period_options = [
        {'value': choice[0], 'label': str(choice[1])} 
        for choice in ProductPrice.BILLING_PERIODS
    ]
    
    context = {
        'form': form,
        'product': product,
        'currencies': currencies,
        'currency_options': currency_options,
        'billing_period_choices': ProductPrice.BILLING_PERIODS,
        'billing_period_options': billing_period_options,
        'action': 'create',
        'is_staff_user': True,
    }
    
    return render(request, 'products/product_price_form.html', context)
