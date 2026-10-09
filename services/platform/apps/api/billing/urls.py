# ===============================================================================
# BILLING API URLS - CUSTOMER INVOICE ENDPOINTS 💳
# ===============================================================================

from django.urls import path

from apps.billing import views as billing_views

from . import gift_views, views

app_name = "api_billing"

urlpatterns = [
    path("gift-cards/catalog/", gift_views.catalog, name="gift_card_catalog"),
    path("gift-cards/purchases/", gift_views.purchases, name="gift_card_purchases"),
    path("gift-cards/create/", gift_views.create, name="gift_card_create"),
    path("gift-cards/detail/", gift_views.detail, name="gift_card_detail"),
    path("gift-cards/funding/", gift_views.funding, name="gift_card_funding"),
    path("gift-cards/refresh/", gift_views.refresh, name="gift_card_refresh"),
    path("gift-cards/reveal/", gift_views.reveal, name="gift_card_reveal"),
    path("gift-cards/resend/", gift_views.resend, name="gift_card_resend"),
    path("gift-card-payment/", views.gift_card_payment_api, name="gift_card_payment"),
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
    # The portal's card-payment endpoints. They live in the billing app's views (plain Django
    # views that authenticate the signed customer themselves) but are served under /api/, the
    # only prefix Platform's Caddy configuration publishes on its hostname. Under /billing/
    # they were unreachable for a portal on its own host.
    path("create-payment-intent/", billing_views.api_create_payment_intent, name="api_create_payment_intent"),
    path("confirm-payment/", billing_views.api_confirm_payment, name="api_confirm_payment"),
    path("stripe-config/", billing_views.api_stripe_config, name="api_stripe_config"),
]
