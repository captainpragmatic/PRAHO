"""
Order API URLs for PRAHO Platform
RESTful endpoints for product catalog and order management.
"""

from django.urls import path

from . import views

app_name = 'orders'

urlpatterns = [
    # Product catalog (public endpoints)
    path('products/', views.product_list, name='product_list'),
    path('products/<slug:slug>/', views.product_detail, name='product_detail'),
    
    # Cart operations (customer authenticated)
    path('calculate/', views.calculate_cart_totals, name='calculate_cart'),
    path('preflight/', views.preflight_order, name='preflight_order'),
    
    # Order management (customer authenticated)
    path('create/', views.create_order, name='create_order'),
    path('', views.order_list, name='order_list'),
    path('<uuid:order_id>/', views.order_detail, name='order_detail'),
    path('<uuid:order_id>/confirm/', views.confirm_order, name='confirm_order'),
]
