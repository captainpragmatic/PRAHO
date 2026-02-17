"""
URL configuration for PRAHO Portal Dashboard app
"""

from django.urls import path

from . import views

app_name = "dashboard"

urlpatterns = [
    path("", views.dashboard_view, name="dashboard"),
    path("account/", views.account_overview_view, name="account_overview"),
]
