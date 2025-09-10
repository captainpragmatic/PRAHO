"""
Portal Users URLs
Customer login/logout routes.
"""

from django.urls import path

from . import views

app_name = 'users'

urlpatterns = [
    path('login/', views.login_view, name='login'),
    path('logout/', views.logout_view, name='logout'),
    path('register/', views.register_view, name='register'),
    path('profile/', views.profile_view, name='profile'),
    path('password-reset/', views.password_reset_view, name='password_reset'),
    path('change-password/', views.change_password_view, name='change_password'),
    path('mfa/', views.mfa_management_view, name='mfa_management'),
    path('mfa/setup/totp/', views.mfa_setup_totp_view, name='mfa_setup_totp'),
    path('mfa/backup-codes/', views.mfa_backup_codes_view, name='mfa_backup_codes'),
    path('mfa/disable/', views.mfa_disable_view, name='mfa_disable'),
    path('privacy/', views.privacy_dashboard_view, name='privacy_dashboard'),
    path('data-export/', views.data_export_view, name='data_export'),
    path('consent-history/', views.consent_history_view, name='consent_history'),
]
