"""
URL patterns for audit and GDPR compliance.
"""

from django.urls import path

from . import views

app_name = "audit"

urlpatterns = [
    # GDPR Privacy Dashboard - Main entry point
    path("gdpr/", views.gdpr_dashboard, name="gdpr_dashboard"),
    # GDPR Data Export
    path("gdpr/export/request/", views.request_data_export, name="request_data_export"),
    path("gdpr/export/download/<uuid:export_id>/", views.download_data_export, name="download_data_export"),
    # GDPR Data Deletion
    path("gdpr/deletion/request/", views.request_data_deletion, name="request_data_deletion"),
    # GDPR Consent Management
    path("gdpr/consent/withdraw/", views.withdraw_consent, name="withdraw_consent"),
    path("gdpr/consent/update/", views.update_consent, name="update_consent"),
    # Staff GDPR Management Dashboard
    path("gdpr_management/", views.gdpr_management_dashboard, name="gdpr_management_dashboard"),
    path("gdpr_management/requests/", views.gdpr_export_requests_list, name="gdpr_export_requests_list"),
    path("gdpr_management/process/<uuid:export_id>/", views.process_export_request, name="process_export_request"),
    path("gdpr_management/detail/<uuid:export_id>/", views.gdpr_export_detail, name="gdpr_export_detail"),
    path("gdpr_management/download/<uuid:export_id>/", views.download_user_export, name="download_user_export"),
    # Enterprise Audit Management Dashboard
    path("management/", views.audit_management_dashboard, name="management_dashboard"),
    # Audit Logs (Enhanced Staff/Admin)
    path("logs/", views.audit_log, name="logs"),
    path("logs/list/", views.logs_list, name="logs_list"),
    path("logs/event/<uuid:event_id>/", views.event_detail, name="event_detail"),
    path("logs/export/", views.export_logs, name="export_logs"),
    # Advanced Search Features
    path("search/suggestions/", views.audit_search_suggestions, name="search_suggestions"),
    path("search/save/", views.save_search_query, name="save_search_query"),
    path("search/load/<uuid:query_id>/", views.load_saved_search, name="load_saved_search"),
    # Audit Data Integrity Monitoring
    path("integrity/", views.integrity_dashboard, name="integrity_dashboard"),
    path("integrity/check/", views.run_integrity_check, name="run_integrity_check"),
    # Audit Retention Management
    path("retention/", views.retention_dashboard, name="retention_dashboard"),
    path("retention/apply/", views.apply_retention_policies, name="apply_retention_policies"),
    # Security and Compliance Alerts
    path("alerts/", views.alerts_dashboard, name="alerts_dashboard"),
    path("alerts/<uuid:alert_id>/update/", views.update_alert_status, name="update_alert_status"),
    # Legacy/Admin URLs (Maintained for Backward Compatibility)
    path("log/", views.audit_log, name="log"),  # Kept for backward compatibility
    path("export/", views.export_data, name="export"),  # Redirects to GDPR dashboard
    path("logs/export/csv/", views.export_logs, name="export_logs_csv"),  # Legacy CSV export
]
