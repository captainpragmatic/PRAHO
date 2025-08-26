"""
Django admin configuration for products app.
Romanian hosting provider product catalog management interface.
"""

from typing import ClassVar

from django.contrib import admin

from .models import (
    Product,
    ProductBundle,
    ProductBundleItem,
    ProductPrice,
    ProductRelationship,
)


@admin.register(Product)
class ProductAdmin(admin.ModelAdmin):
    """Admin interface for products."""

    list_display: ClassVar[list[str]] = (
        'name', 'slug', 'product_type', 'is_active', 'includes_vat',
        'is_featured', 'sort_order', 'created_at'
    )
    list_filter: ClassVar[list[str]] = (
        'is_active', 'product_type', 'is_featured', 'includes_vat',
        'is_public', 'created_at'
    )
    search_fields: ClassVar[list[str]] = ('name', 'slug', 'description', 'sku')
    prepopulated_fields: ClassVar[dict[str, tuple[str, ...]]] = {'slug': ('name',)}

    fieldsets: ClassVar[tuple] = (
        ('Basic Information', {
            'fields': ('name', 'slug', 'description', 'product_type', 'module')
        }),
        ('Status & Visibility', {
            'fields': ('is_active', 'is_featured', 'is_public', 'sort_order')
        }),
        ('Configuration', {
            'fields': ('module_config', 'includes_vat', 'requires_domain')
        }),
        ('SEO & Marketing', {
            'fields': ('meta_title', 'meta_description', 'tags')
        }),
        ('Configuration', {
            'fields': ('meta',),
            'classes': ('collapse',)
        })
    )

    readonly_fields: ClassVar[list[str]] = ('created_at', 'updated_at')


@admin.register(ProductPrice)
class ProductPriceAdmin(admin.ModelAdmin):
    """Admin interface for product prices."""

    list_display: ClassVar[list[str]] = (
        'product', 'currency', 'amount_cents', 'billing_period', 'is_active'
    )
    list_filter: ClassVar[list[str]] = ('currency', 'billing_period', 'is_active')
    search_fields: ClassVar[list[str]] = ('product__name', 'currency__code')

    fieldsets: ClassVar[tuple] = (
        ('Product & Currency', {
            'fields': ('product', 'currency')
        }),
        ('Pricing', {
            'fields': ('amount_cents', 'setup_cents', 'billing_period', 'is_active')
        }),
    )

    readonly_fields: ClassVar[list[str]] = ('created_at', 'updated_at')


@admin.register(ProductRelationship)
class ProductRelationshipAdmin(admin.ModelAdmin):
    """Admin interface for product relationships."""

    list_display: ClassVar[list[str]] = (
        'source_product', 'relationship_type', 'target_product', 'is_active'
    )
    list_filter: ClassVar[list[str]] = ('relationship_type', 'is_active')
    search_fields: ClassVar[list[str]] = ('source_product__name', 'target_product__name')

    fieldsets: ClassVar[tuple] = (
        ('Relationship', {
            'fields': ('source_product', 'relationship_type', 'target_product')
        }),
        ('Configuration', {
            'fields': ('is_active', 'meta')
        })
    )


@admin.register(ProductBundle)
class ProductBundleAdmin(admin.ModelAdmin):
    """Admin interface for product bundles."""

    list_display: ClassVar[list[str]] = ('name', 'discount_type', 'discount_value', 'is_active', 'created_at')
    list_filter: ClassVar[list[str]] = ('discount_type', 'is_active', 'created_at')
    search_fields: ClassVar[list[str]] = ('name', 'description')

    fieldsets: ClassVar[tuple] = (
        ('Bundle Information', {
            'fields': ('name', 'description', 'is_active')
        }),
        ('Discount Configuration', {
            'fields': ('discount_type', 'discount_value')
        }),
        ('Additional Data', {
            'fields': ('meta',),
            'classes': ('collapse',)
        })
    )

    readonly_fields: ClassVar[list[str]] = ('created_at', 'updated_at')


@admin.register(ProductBundleItem)
class ProductBundleItemAdmin(admin.ModelAdmin):
    """Admin interface for product bundle items."""

    list_display: ClassVar[list[str]] = ('bundle', 'product', 'quantity', 'is_required')
    list_filter: ClassVar[tuple[str, ...]] = ('bundle',)
    search_fields: ClassVar[list[str]] = ('bundle__name', 'product__name')

    fieldsets: ClassVar[tuple] = (
        ('Bundle Configuration', {
            'fields': ('bundle', 'product', 'quantity', 'is_required', 'override_price_cents')
        }),
    )
