# ===============================================================================
# BILLING APP URLS - INVOICE & PAYMENT MANAGEMENT
# ===============================================================================

from django.urls import path

from . import views

app_name = "billing"

urlpatterns = [
    # Combined listing (proformas + invoices)
    path("invoices/", views.billing_list, name="invoice_list"),  # Updated view name
    path("invoices/list/", views.billing_list_htmx, name="billing_list_htmx"),  # HTMX endpoint
    # Proforma list (for redirects and separate access)
    path("proformas/", views.proforma_list, name="proforma_list"),
    # Proforma management (only these can be created manually)
    path("proformas/create/", views.proforma_create, name="proforma_create"),
    path("proformas/<int:pk>/", views.proforma_detail, name="proforma_detail"),
    path("proformas/<int:pk>/edit/", views.proforma_edit, name="proforma_edit"),
    path("proformas/<int:pk>/pdf/", views.proforma_pdf, name="proforma_pdf"),
    path("proformas/<int:pk>/send/", views.proforma_send, name="proforma_send"),
    path("proformas/<int:pk>/convert/", views.proforma_to_invoice, name="proforma_to_invoice"),
    # Invoice management (read-only, auto-generated from proformas)
    path("invoices/<int:pk>/", views.invoice_detail, name="invoice_detail"),
    path("invoices/<int:pk>/edit/", views.invoice_edit, name="invoice_edit"),
    path("invoices/<int:pk>/pdf/", views.invoice_pdf, name="invoice_pdf"),
    path("invoices/<int:pk>/send/", views.invoice_send, name="invoice_send"),
    path("invoices/<int:pk>/refund/", views.invoice_refund, name="invoice_refund"),
    path("invoices/<int:pk>/refund-request/", views.invoice_refund_request, name="invoice_refund_request"),
    # Romanian e-Factura integration
    path("invoices/<int:pk>/e-factura/", views.generate_e_factura, name="e_factura"),
    # e-Factura Compliance Dashboard
    path("e-factura/", views.efactura_dashboard, name="efactura_dashboard"),
    path("e-factura/documents/", views.efactura_documents_htmx, name="efactura_documents_htmx"),
    path("e-factura/<str:pk>/", views.efactura_document_detail, name="efactura_document_detail"),
    path("e-factura/<int:pk>/submit/", views.efactura_submit, name="efactura_submit"),
    path("e-factura/<str:pk>/retry/", views.efactura_retry, name="efactura_retry"),
    # Payment management
    path("payments/", views.payment_list, name="payment_list"),
    path("invoices/<int:pk>/pay/", views.process_payment, name="process_payment"),
    path("proformas/<int:pk>/pay/", views.process_proforma_payment, name="process_proforma_payment"),
    # Reports
    path("reports/", views.billing_reports, name="reports"),
    path("reports/vat/", views.vat_report, name="vat_report"),

    # ===============================================================================
    # PAYMENT API ENDPOINTS FOR PORTAL CONSUMPTION
    # ===============================================================================

    # Payment Intent Management
    path("create-payment-intent/", views.api_create_payment_intent, name="api_create_payment_intent"),
    path("confirm-payment/", views.api_confirm_payment, name="api_confirm_payment"),

    # Subscription Management
    path("create-subscription/", views.api_create_subscription, name="api_create_subscription"),

    # Payment Methods & Configuration
    path("payment-methods/<str:customer_id>/", views.api_payment_methods, name="api_payment_methods"),
    path("stripe-config/", views.api_stripe_config, name="api_stripe_config"),

    # Refund Processing
    path("process-refund/", views.api_process_refund, name="api_process_refund"),
]
