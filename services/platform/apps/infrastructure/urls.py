"""
Infrastructure App URL Configuration

URL routing for node deployment management interface.
"""

from django.urls import path

from . import views

app_name = "infrastructure"

urlpatterns = [
    # Dashboard
    path("", views.deployment_dashboard, name="dashboard"),
    # Node Deployments CRUD
    path("deployments/", views.deployment_list, name="deployment_list"),
    path("deployments/create/", views.deployment_create, name="deployment_create"),
    path("deployments/<uuid:pk>/", views.deployment_detail, name="deployment_detail"),
    path("deployments/<uuid:pk>/logs/", views.deployment_logs, name="deployment_logs"),
    path("deployments/<uuid:pk>/retry/", views.deployment_retry, name="deployment_retry"),
    path("deployments/<uuid:pk>/destroy/", views.deployment_destroy, name="deployment_destroy"),
    # Lifecycle operations
    path("deployments/<uuid:pk>/upgrade/", views.deployment_upgrade, name="deployment_upgrade"),
    path("deployments/<uuid:pk>/stop/", views.deployment_stop, name="deployment_stop"),
    path("deployments/<uuid:pk>/start/", views.deployment_start, name="deployment_start"),
    path("deployments/<uuid:pk>/reboot/", views.deployment_reboot, name="deployment_reboot"),
    path("deployments/<uuid:pk>/maintenance/", views.deployment_maintenance, name="deployment_maintenance"),
    # HTMX partials
    path(
        "deployments/<uuid:pk>/status/",
        views.deployment_status_partial,
        name="deployment_status_partial",
    ),
    path(
        "deployments/<uuid:pk>/logs-partial/",
        views.deployment_logs_partial,
        name="deployment_logs_partial",
    ),
    # API endpoints for hostname preview
    path(
        "api/hostname-preview/",
        views.hostname_preview_api,
        name="hostname_preview_api",
    ),
    # Configuration pages
    path("providers/", views.provider_list, name="provider_list"),
    path("providers/create/", views.provider_create, name="provider_create"),
    path("providers/<uuid:pk>/edit/", views.provider_edit, name="provider_edit"),
    path("sizes/", views.size_list, name="size_list"),
    path("sizes/create/", views.size_create, name="size_create"),
    path("sizes/<uuid:pk>/edit/", views.size_edit, name="size_edit"),
    path("regions/", views.region_list, name="region_list"),
    path("regions/<uuid:pk>/toggle/", views.region_toggle, name="region_toggle"),
    # Cost tracking
    path("costs/", views.cost_dashboard, name="cost_dashboard"),
    path("costs/history/", views.cost_history, name="cost_history"),
    path("api/costs/summary/", views.cost_api_summary, name="cost_api_summary"),
]
