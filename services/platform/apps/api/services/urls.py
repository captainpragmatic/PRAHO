# ===============================================================================
# SERVICES API URLS - CUSTOMER HOSTING SERVICES 📦
# ===============================================================================

from django.urls import path

from .dns_views import service_dns_recheck_api, service_dns_status_api
from .plan_change_views import plan_change_action_api, plan_change_status_api
from .request_views import service_request_api
from .views import (
    available_service_plans_api,
    customer_service_detail_api,
    customer_service_domains_api,
    customer_services_api,
    customer_services_summary_api,
    service_usage_stats_api,
    update_service_auto_renew_api,
)

app_name = "services"

urlpatterns = [
    # Services endpoints
    path("", customer_services_api, name="customer_services_list"),
    path("summary/", customer_services_summary_api, name="customer_services_summary"),
    path("plans/", available_service_plans_api, name="available_service_plans"),
    # Individual service endpoints
    path("<int:service_id>/", customer_service_detail_api, name="customer_service_detail"),
    path("<int:service_id>/domains/", customer_service_domains_api, name="customer_service_domains"),
    path("<int:service_id>/dns-status/", service_dns_status_api, name="service_dns_status"),
    path("<int:service_id>/dns-status/recheck/", service_dns_recheck_api, name="service_dns_recheck"),
    path("<int:service_id>/actions/", service_request_api, name="request_service_action"),
    path("<int:service_id>/plan-changes/<uuid:change_id>/status/", plan_change_status_api, name="plan_change_status"),
    path(
        "<int:service_id>/plan-changes/options/",
        plan_change_action_api,
        {"operation": "options"},
        name="plan_change_options",
    ),
    path(
        "<int:service_id>/plan-changes/quote/", plan_change_action_api, {"operation": "quote"}, name="plan_change_quote"
    ),
    path(
        "<int:service_id>/plan-changes/<uuid:change_id>/confirm/",
        plan_change_action_api,
        {"operation": "confirm"},
        name="plan_change_confirm",
    ),
    path(
        "<int:service_id>/plan-changes/<uuid:change_id>/payment-intent/",
        plan_change_action_api,
        {"operation": "payment-intent"},
        name="plan_change_payment_intent",
    ),
    path(
        "<int:service_id>/plan-changes/<uuid:change_id>/cancel/",
        plan_change_action_api,
        {"operation": "cancel"},
        name="plan_change_cancel",
    ),
    path(
        "<int:service_id>/plan-changes/safety-refresh/",
        plan_change_action_api,
        {"operation": "safety-refresh"},
        name="plan_change_safety_refresh",
    ),
    path("<int:service_id>/auto-renew/", update_service_auto_renew_api, name="update_service_auto_renew"),
    path("<int:service_id>/usage/", service_usage_stats_api, name="service_usage_stats"),
]
