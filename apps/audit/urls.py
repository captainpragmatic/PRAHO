"""
URL patterns for audit and GDPR compliance.
"""

from django.urls import path

from . import views

app_name = 'audit'

urlpatterns = [
    # GDPR Privacy Dashboard - Main entry point
    path('gdpr/', views.gdpr_dashboard, name='gdpr_dashboard'),

    # GDPR Data Export
    path('gdpr/export/request/', views.request_data_export, name='request_data_export'),
    path('gdpr/export/download/<uuid:export_id>/', views.download_data_export, name='download_data_export'),

    # GDPR Data Deletion
    path('gdpr/deletion/request/', views.request_data_deletion, name='request_data_deletion'),

    # GDPR Consent Management
    path('gdpr/consent/withdraw/', views.withdraw_consent, name='withdraw_consent'),
    path('gdpr/consent/history/', views.consent_history, name='consent_history'),

    # Staff GDPR Management Dashboard
    path('gdpr_management/', views.gdpr_management_dashboard, name='gdpr_management_dashboard'),
    path('gdpr_management/requests/', views.gdpr_export_requests_list, name='gdpr_export_requests_list'),
    path('gdpr_management/process/<uuid:export_id>/', views.process_export_request, name='process_export_request'),
    path('gdpr_management/detail/<uuid:export_id>/', views.gdpr_export_detail, name='gdpr_export_detail'),
    path('gdpr_management/download/<uuid:export_id>/', views.download_user_export, name='download_user_export'),

    # Audit Logs (Staff/Admin)
    path('logs/', views.audit_log, name='logs'),
    path('logs/list/', views.logs_list, name='logs_list'),
    path('logs/event/<uuid:event_id>/', views.event_detail, name='event_detail'),
    path('logs/export/csv/', views.export_logs_csv, name='export_logs_csv'),

    # Legacy/Admin URLs
    path('log/', views.audit_log, name='log'),  # Kept for backward compatibility
    path('export/', views.export_data, name='export'),  # Redirects to GDPR dashboard
]
