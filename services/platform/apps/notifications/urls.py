"""
🔒 Secure URL Configuration for PRAHO Notifications
All endpoints require appropriate authentication and include rate limiting.
"""

from django.urls import path

from . import views
from . import webhooks

app_name = "notifications"

urlpatterns = [
    # ===============================================================================
    # ADMIN EMAIL TEMPLATE MANAGEMENT
    # ===============================================================================
    path("admin/templates/", views.EmailTemplateListView.as_view(), name="template_list"),
    path("admin/templates/<uuid:pk>/", views.EmailTemplateDetailView.as_view(), name="template_detail"),
    # ===============================================================================
    # STAFF EMAIL LOG MONITORING
    # ===============================================================================
    path("admin/logs/", views.EmailLogListView.as_view(), name="email_log_list"),
    # ===============================================================================
    # SECURE API ENDPOINTS (Rate Limited)
    # ===============================================================================
    path("api/templates/", views.template_api, name="template_api"),
    path("api/templates/<uuid:template_id>/", views.template_api, name="template_detail_api"),
    path("api/stats/", views.email_stats_api, name="email_stats_api"),
    # ===============================================================================
    # SECURITY MONITORING
    # ===============================================================================
    path("api/security/monitoring/", views.security_monitoring_api, name="security_monitoring"),
    # ===============================================================================
    # EMAIL WEBHOOKS (ESP Delivery Tracking)
    # ===============================================================================
    path("webhooks/anymail/", webhooks.AnymailWebhookView.as_view(), name="webhook_anymail"),
    path("webhooks/ses/", webhooks.SESWebhookView.as_view(), name="webhook_ses"),
    path("webhooks/sendgrid/", webhooks.SendGridWebhookView.as_view(), name="webhook_sendgrid"),
    path("webhooks/mailgun/", webhooks.MailgunWebhookView.as_view(), name="webhook_mailgun"),
    # ===============================================================================
    # EMAIL UNSUBSCRIBE
    # ===============================================================================
    path("unsubscribe/", webhooks.UnsubscribeView.as_view(), name="unsubscribe"),
]
