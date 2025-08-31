from django.urls import path

from . import views

app_name = "integrations"

urlpatterns = [
    # ===============================================================================
    # WEBHOOK ENDPOINTS
    # ===============================================================================
    # Stripe webhooks
    path("webhooks/stripe/", views.StripeWebhookView.as_view(), name="stripe_webhook"),
    # Server management webhooks
    path("webhooks/virtualmin/", views.VirtualminWebhookView.as_view(), name="virtualmin_webhook"),
    # Payment provider webhooks
    path("webhooks/paypal/", views.PayPalWebhookView.as_view(), name="paypal_webhook"),
    # ===============================================================================
    # WEBHOOK MANAGEMENT API
    # ===============================================================================
    # Webhook status and statistics
    path("api/webhooks/status/", views.webhook_status, name="webhook_status"),
    # Manual webhook retry
    path("api/webhooks/<uuid:webhook_id>/retry/", views.retry_webhook, name="retry_webhook"),
]
