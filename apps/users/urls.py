"""
URL patterns for Users app
"""

from django.urls import path, include
from . import views

app_name = 'users'

urlpatterns = [
    # Authentication
    path('login/', views.login_view, name='login'),
    path('logout/', views.logout_view, name='logout'),
    path('register/', views.register_view, name='register'),
    
    # Password reset
    path('password-reset/', views.password_reset_view, name='password_reset'),
    path('password-reset/done/', views.password_reset_done_view, name='password_reset_done'),
    path('password-reset-confirm/<uidb64>/<token>/', views.password_reset_confirm_view, name='password_reset_confirm'),
    path('password-reset-complete/', views.password_reset_complete_view, name='password_reset_complete'),
    
    # Password change
    path('password-change/', views.password_change_view, name='password_change'),
    
    # Two-factor authentication
    path('2fa/setup/', views.mfa_method_selection, name='two_factor_setup'),  # Method selection first
    path('2fa/setup/totp/', views.two_factor_setup_totp, name='two_factor_setup_totp'),  # TOTP-specific
    path('2fa/setup/webauthn/', views.two_factor_setup_webauthn, name='two_factor_setup_webauthn'),  # WebAuthn-specific
    path('2fa/verify/', views.two_factor_verify, name='two_factor_verify'),
    path('2fa/backup-codes/', views.two_factor_backup_codes, name='two_factor_backup_codes'),
    path('2fa/regenerate-backup-codes/', views.two_factor_regenerate_backup_codes, name='two_factor_regenerate_backup_codes'),
    path('2fa/disable/', views.two_factor_disable, name='two_factor_disable'),
    
    # Profile management
    path('profile/', views.user_profile, name='user_profile'),
    
    # User management (admin)
    path('users/', views.UserListView.as_view(), name='user_list'),
    path('users/<int:pk>/', views.UserDetailView.as_view(), name='user_detail'),
    
    # API endpoints
    path('api/check-email/', views.api_check_email, name='api_check_email'),
]
