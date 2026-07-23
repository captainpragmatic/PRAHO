# ===============================================================================
# BILLING API URLS - CUSTOMER INVOICE ENDPOINTS 💳
# ===============================================================================

from django.urls import path

from . import views

app_name = "api_billing"

urlpatterns = [
    # Currency endpoints
    path("currencies/", views.currencies_api, name="currencies"),
    # Invoice endpoints
    path("documents/", views.customer_billing_documents_api, name="customer_billing_documents"),
    path("invoices/", views.customer_invoices_api, name="customer_invoices"),
    path("invoices/<str:invoice_number>/", views.customer_invoice_detail_api, name="customer_invoice_detail"),
    path("invoices/<str:invoice_number>/pdf/", views.invoice_pdf_export, name="invoice_pdf_export"),
    path("summary/", views.customer_invoice_summary_api, name="customer_invoice_summary"),
    # Proforma endpoints
    path("proformas/", views.customer_proformas_api, name="customer_proformas"),
    path("proformas/<str:proforma_number>/", views.customer_proforma_detail_api, name="customer_proforma_detail"),
    path("proformas/<str:proforma_number>/pdf/", views.proforma_pdf_export, name="proforma_pdf_export"),
    # Customer-controlled recurring card authorization and subscription enrollment
    path("recurring-payments/", views.recurring_payments_overview_api, name="recurring_payments_overview"),
    path(
        "recurring-payments/authorize/begin/",
        views.begin_recurring_authorization_api,
        name="begin_recurring_authorization",
    ),
    path(
        "recurring-payments/authorize/complete/",
        views.complete_recurring_authorization_api,
        name="complete_recurring_authorization",
    ),
    path(
        "recurring-payments/authorize/withdraw/",
        views.withdraw_recurring_authorization_api,
        name="withdraw_recurring_authorization",
    ),
    path(
        "recurring-payments/subscriptions/auto-payment/",
        views.subscription_auto_payment_api,
        name="subscription_auto_payment",
    ),
]
