# ===============================================================================
# PRODUCT CATALOG URLs - PRAHO PLATFORM
# ===============================================================================

from django.urls import path

from . import views

app_name = "products"

urlpatterns = [
    # Product management (staff only)
    path("", views.product_list, name="product_list"),
    path("htmx/", views.product_list_htmx, name="product_list_htmx"),
    path("create/", views.product_create, name="product_create"),
    path("<slug:slug>/", views.product_detail, name="product_detail"),
    path("<slug:slug>/edit/", views.product_edit, name="product_edit"),
    # HTMX toggle endpoints
    path("<slug:slug>/toggle-active/", views.product_toggle_active, name="product_toggle_active"),
    path("<slug:slug>/toggle-public/", views.product_toggle_public, name="product_toggle_public"),
    path("<slug:slug>/toggle-featured/", views.product_toggle_featured, name="product_toggle_featured"),
    # Pricing management
    path("<slug:slug>/prices/", views.product_prices, name="product_prices"),
    path("<slug:slug>/prices/create/", views.product_price_create, name="product_price_create"),
    path("<slug:slug>/prices/<uuid:price_id>/edit/", views.product_price_edit, name="product_price_edit"),
    path("<slug:slug>/prices/<uuid:price_id>/delete/", views.product_price_delete, name="product_price_delete"),
]
