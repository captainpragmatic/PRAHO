"""
URL Configuration for PRAHO System Settings

Three-surface settings UI (ADR-0042) plus the read-only staff API and
export/import utilities. Literal routes come before the group catch-all.
"""

from __future__ import annotations

from django.urls import path

from . import views

app_name = "settings"

urlpatterns = [
    # ── Staff API (read-only) + utilities ───────────────────────────────────
    path("api/health/", views.settings_health_check, name="health_check"),
    path("api/export/", views.export_settings, name="export_settings"),
    path("api/export/full/", views.export_settings_full, name="export_settings_full"),
    path("api/import/", views.import_settings, name="import_settings"),
    path("api/cache/refresh/", views.refresh_cache, name="refresh_cache"),
    path("api/", views.SettingsAPIView.as_view(), name="settings_api"),
    path("api/<str:key>/", views.SettingsAPIView.as_view(), name="setting_detail_api"),
    # ── Settings UI ─────────────────────────────────────────────────────────
    path("", views.settings_home, name="home"),
    path("save/", views.save_change_set, name="save_change_set"),
    path("search/", views.settings_search, name="search"),
    path("automation/", views.settings_automation, name="automation"),
    path("history/<str:key>/", views.setting_history, name="setting_history"),
    path("secret/<str:key>/clear/", views.secret_clear, name="secret_clear"),
    path("secret/<str:key>/", views.secret_set, name="secret_set"),
    path("test/<slug:integration>/", views.integration_test, name="integration_test"),
    # Group catch-all last: one page per catalog group
    path("<slug:group_slug>/", views.settings_group, name="group"),
]
