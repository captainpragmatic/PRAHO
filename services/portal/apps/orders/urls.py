"""
URL Configuration for Orders App - PRAHO Portal
Product catalog, cart management, and order creation routes.
"""

from django.urls import path

from . import views

app_name = "orders"

urlpatterns = [
    # Main order flow (GET - idempotent)
    path("", views.product_catalog, name="catalog"),
    path("products/<slug:product_slug>/", views.product_detail, name="product_detail"),
    path("cart/", views.cart_review, name="cart_review"),
    path("checkout/", views.checkout, name="checkout"),
    path("confirmation/<uuid:order_id>/", views.order_confirmation, name="confirmation"),
    # Cart operations (POST - state changing)
    path("cart/add/", views.add_to_cart, name="add_to_cart"),
    path("cart/update/", views.update_cart_item, name="update_cart_item"),
    path("cart/remove/", views.remove_from_cart, name="remove_from_cart"),
    path("cart/calculate/", views.calculate_totals_htmx, name="calculate_totals"),
    # Order creation (POST)
    path("create/", views.create_order, name="create_order"),
    path("process-payment/", views.process_payment, name="process_payment"),
    # HTMX partials
    path("partials/mini-cart/", views.mini_cart_content, name="mini_cart_content"),
    # Payment webhooks
    path("payment/webhook/", views.payment_success_webhook, name="payment_webhook"),
    # Payment confirmation
    path("confirm-payment/", views.confirm_payment, name="confirm_payment"),
]
