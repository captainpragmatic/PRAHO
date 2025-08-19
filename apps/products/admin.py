"""
Django admin configuration for products app.
Romanian hosting provider product catalog management interface.
"""

from django.contrib import admin
from .models import Product, ProductPrice, ProductRelationship, ProductBundle, ProductBundleItem


@admin.register(Product)
class ProductAdmin(admin.ModelAdmin):
    """Admin interface for products."""
    
    list_display = [
        'name', 'slug', 'product_type', 'is_active', 'includes_vat', 
        'is_featured', 'sort_order', 'created_at'
    ]
    list_filter = [
        'is_active', 'product_type', 'is_featured', 'includes_vat', 
        'is_public', 'created_at'
    ]
    search_fields = ['name', 'slug', 'description', 'sku']
    prepopulated_fields = {'slug': ('name',)}
    
    fieldsets = (
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
    
    readonly_fields = ('created_at', 'updated_at')


@admin.register(ProductPrice)
class ProductPriceAdmin(admin.ModelAdmin):
    """Admin interface for product prices."""
    
    list_display = [
        'product', 'currency', 'amount_cents', 'billing_period', 'is_active'
    ]
    list_filter = ['currency', 'billing_period', 'is_active']
    search_fields = ['product__name', 'currency__code']
    
    fieldsets = (
        ('Product & Currency', {
            'fields': ('product', 'currency')
        }),
        ('Pricing', {
            'fields': ('amount_cents', 'setup_cents', 'billing_period', 'is_active')
        }),
    )
    
    readonly_fields = ('created_at', 'updated_at')


@admin.register(ProductRelationship)
class ProductRelationshipAdmin(admin.ModelAdmin):
    """Admin interface for product relationships."""
    
    list_display = [
        'source_product', 'relationship_type', 'target_product', 'is_active'
    ]
    list_filter = ['relationship_type', 'is_active']
    search_fields = ['source_product__name', 'target_product__name']
    
    fieldsets = (
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
    
    list_display = ['name', 'discount_type', 'discount_value', 'is_active', 'created_at']
    list_filter = ['discount_type', 'is_active', 'created_at']
    search_fields = ['name', 'description']
    
    fieldsets = (
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
    
    readonly_fields = ('created_at', 'updated_at')


@admin.register(ProductBundleItem)
class ProductBundleItemAdmin(admin.ModelAdmin):
    """Admin interface for product bundle items."""
    
    list_display = ['bundle', 'product', 'quantity', 'is_required']
    list_filter = ['bundle']
    search_fields = ['bundle__name', 'product__name']
    
    fieldsets = (
        ('Bundle Configuration', {
            'fields': ('bundle', 'product', 'quantity', 'is_required', 'override_price_cents')
        }),
    )
