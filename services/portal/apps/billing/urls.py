# ===============================================================================
# PORTAL BILLING URLS - CUSTOMER INVOICE INTERFACE 💳
# ===============================================================================

from django.urls import path

from . import views

app_name = "billing"

urlpatterns = [
    # Invoice list, search, and detail views
    path("invoices/", views.invoices_list_view, name="invoices_list"),
    path("invoices/search/", views.invoices_search_api, name="invoices_search_api"),
    path("invoices/<str:invoice_number>/", views.invoice_detail_view, name="invoice_detail"),
    path("invoices/<str:invoice_number>/pdf/", views.invoice_pdf_export, name="invoice_pdf_export"),
    # Proforma detail views
    path("proformas/<str:proforma_number>/", views.proforma_detail_view, name="proforma_detail"),
    path("proformas/<str:proforma_number>/pdf/", views.proforma_pdf_export, name="proforma_pdf_export"),
    # Dashboard widget and actions
    path("dashboard-widget/", views.billing_dashboard_widget, name="dashboard_widget"),
    path("sync/", views.sync_invoices_action, name="sync_invoices"),
    # Payment methods
    path("automatic-payments/", views.recurring_payments_view, name="recurring_payments"),
    path(
        "automatic-payments/authorize/begin/",
        views.recurring_authorization_begin,
        name="recurring_authorization_begin",
    ),
    path(
        "automatic-payments/authorize/complete/",
        views.recurring_authorization_complete,
        name="recurring_authorization_complete",
    ),
    path(
        "automatic-payments/authorize/withdraw/",
        views.recurring_authorization_withdraw,
        name="recurring_authorization_withdraw",
    ),
    path(
        "automatic-payments/subscriptions/toggle/",
        views.subscription_auto_payment,
        name="subscription_auto_payment",
    ),
    # Refund request
    path("invoices/<str:invoice_number>/refund/", views.request_refund_view, name="request_refund"),
]
