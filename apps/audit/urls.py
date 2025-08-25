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
    
    # Legacy/Admin URLs
    path('log/', views.audit_log, name='log'),
    path('export/', views.export_data, name='export'),  # Redirects to GDPR dashboard
]
