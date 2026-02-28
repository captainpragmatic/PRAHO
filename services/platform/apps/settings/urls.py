"""
URL Configuration for PRAHO System Settings

Provides API endpoints and admin interfaces for dynamic platform configuration.
Follows PRAHO's URL patterns and security requirements.
"""

from __future__ import annotations

from django.urls import path

from . import views

app_name = "settings"

urlpatterns = [
    # ===============================================================================
    # PUBLIC API ENDPOINTS
    # ===============================================================================
    # Public settings (cached, no authentication required)
    path("api/public/", views.public_settings_api, name="public_settings_api"),
    # Health check
    path("api/health/", views.settings_health_check, name="health_check"),
    # ===============================================================================
    # STAFF API ENDPOINTS (Authentication Required)
    # ===============================================================================
    # Export/Import endpoints (must come before generic patterns)
    path("api/export/", views.export_settings, name="export_settings"),
    path("api/export/full/", views.export_settings_full, name="export_settings_full"),
    path("api/export/test/", views.test_export, name="test_export"),
    path("api/import/", views.import_settings, name="import_settings"),
    # Settings CRUD API
    path("api/", views.SettingsAPIView.as_view(), name="settings_api"),
    path("api/<str:key>/", views.SettingsAPIView.as_view(), name="setting_detail_api"),
    # Category-specific settings
    path("api/category/<str:category_key>/", views.category_settings_api, name="category_settings_api"),
    # Cache management
    path("api/cache/refresh/", views.refresh_cache, name="refresh_cache"),
    # ===============================================================================
    # DASHBOARD AND MANAGEMENT INTERFACES
    # ===============================================================================
    # Staff settings dashboard
    path("dashboard/", views.SettingsDashboardView.as_view(), name="dashboard"),
    # Settings management interface
    path("manage/", views.SettingsManagementView.as_view(), name="manage"),
    # HTMX partial for category content
    path("manage/category/<str:category_key>/", views.category_management_partial, name="category_management_partial"),
]
