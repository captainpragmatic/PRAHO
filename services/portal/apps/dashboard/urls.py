"""
URL configuration for PRAHO Portal Dashboard app
"""

from django.urls import path

from apps.common.account_health_views import account_status_banner_partial

from . import views

app_name = "dashboard"

urlpatterns = [
    path("", views.dashboard_view, name="dashboard"),
    path("account/", views.account_overview_view, name="account_overview"),
    path("account-status/", account_status_banner_partial, name="account_status_partial"),
]
