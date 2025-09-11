# ===============================================================================
# ORDERS APP URLS - ORDER MANAGEMENT & LIFECYCLE
# ===============================================================================

from django.urls import path

from . import views

app_name = "orders"

urlpatterns = [
    # Order listing and management
    path("", views.order_list, name="order_list"),
    path("", views.order_list, name="list"),
    path("list/", views.order_list_htmx, name="order_list_htmx"),  # HTMX endpoint
    path("create/", views.order_create, name="order_create"),
    path("create/with-item/", views.order_create_with_item, name="order_create_with_item"),
    path("create/preview/", views.order_create_preview, name="order_create_preview"),  # HTMX preview
    # Order detail and lifecycle management
    path("<uuid:pk>/", views.order_detail, name="order_detail"),
    path("<uuid:pk>/", views.order_detail, name="detail"),
    path("<uuid:pk>/edit/", views.order_edit, name="order_edit"),
    path("<uuid:pk>/pdf/", views.order_pdf, name="order_pdf"),
    path("<uuid:pk>/send/", views.order_send, name="order_send"),
    # Order status workflow
    path("<uuid:pk>/status/", views.order_change_status, name="order_change_status"),
    path("<uuid:pk>/cancel/", views.order_cancel, name="order_cancel"),
    path("<uuid:pk>/refund/", views.order_refund, name="order_refund"),
    # path("<uuid:pk>/validate/", views.order_validate, name="order_validate"),  # Temporarily disabled
    path("<uuid:pk>/refund-request/", views.order_refund_request, name="order_refund_request"),
    path("<uuid:pk>/provision/", views.order_provision, name="order_provision"),
    # Order items management (HTMX powered)
    path("<uuid:pk>/items/", views.order_items_list, name="order_items_list"),
    path("<uuid:pk>/items/add/", views.order_item_create, name="order_item_create"),
    path("<uuid:pk>/items/add/", views.order_item_create, name="add_item"),
    path("<uuid:pk>/items/<uuid:item_pk>/edit/", views.order_item_edit, name="order_item_edit"),
    path("<uuid:pk>/items/<uuid:item_pk>/edit/", views.order_item_edit, name="update_item"),
    path("<uuid:pk>/items/<uuid:item_pk>/delete/", views.order_item_delete, name="order_item_delete"),
    # Order duplication and conversion
    path("<uuid:pk>/duplicate/", views.order_duplicate, name="order_duplicate"),
    path("<uuid:pk>/convert-to-invoice/", views.order_to_invoice, name="order_to_invoice"),
    # Reports and analytics
    path("reports/", views.order_reports, name="reports"),
    path("reports/export/", views.order_export, name="export"),
]
