# ===============================================================================
# CUSTOMER SERVICES URLS - PORTAL SERVICE 🔧
# ===============================================================================

from django.urls import path

from . import dns_views, plan_changes, views

app_name = "services"

urlpatterns = [
    # Main service views
    path("", views.service_list, name="list"),
    path("search/", views.service_search_api, name="search_api"),
    path("<int:service_id>/", views.service_detail, name="detail"),
    path("<int:service_id>/change-plan/", plan_changes.plan_change_index, name="change_plan"),
    path("<int:service_id>/change-plan/<uuid:change_id>/", plan_changes.plan_change_detail, name="plan_change_detail"),
    path(
        "<int:service_id>/change-plan/<uuid:change_id>/<str:action>/",
        plan_changes.plan_change_action,
        name="plan_change_action",
    ),
    path("<int:service_id>/dns/", dns_views.service_dns, name="dns"),
    path("plans/", views.service_plans, name="plans"),
    # Service management
    path("<int:service_id>/request-action/", views.service_request_action, name="request_action"),
    # HTMX endpoints
    path("<int:service_id>/usage/", views.service_usage, name="usage"),
    path("<int:service_id>/maintenance/", views.service_maintenance, name="maintenance"),
    # Dashboard widget
    path("widget/", views.services_dashboard_widget, name="dashboard_widget"),
]
