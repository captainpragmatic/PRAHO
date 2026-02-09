"""
URL patterns for Users app
"""

from django.urls import path

from . import views

app_name = "users"

urlpatterns = [
    # Staff Authentication Only
    path("login/", views.login_view, name="login"),
    path("logout/", views.logout_view, name="logout"),
    # Password change
    path("password-change/", views.password_change_view, name="password_change"),
    # Multi-factor authentication
    path("mfa/setup/", views.mfa_method_selection, name="mfa_setup"),  # Method selection first
    path(
        "mfa/method-selection/", views.mfa_method_selection, name="mfa_method_selection"
    ),  # Alternative name for tests
    path("mfa/setup/totp/", views.mfa_setup_totp, name="mfa_setup_totp"),  # TOTP-specific
    path("mfa/setup/webauthn/", views.mfa_setup_webauthn, name="mfa_setup_webauthn"),  # WebAuthn-specific
    path("mfa/verify/", views.mfa_verify, name="mfa_verify"),
    path("mfa/backup-codes/", views.mfa_backup_codes, name="mfa_backup_codes"),
    path(
        "mfa/regenerate-backup-codes/",
        views.mfa_regenerate_backup_codes,
        name="mfa_regenerate_backup_codes",
    ),
    path("mfa/disable/", views.mfa_disable, name="mfa_disable"),
    # Profile management
    path("profile/", views.user_profile, name="user_profile"),
    # User management (admin)
    path("users/", views.UserListView.as_view(), name="user_list"),
    path("users/<int:pk>/", views.UserDetailView.as_view(), name="user_detail"),
    # Password reset
    path("password-reset/", views.password_reset_view, name="password_reset"),
    path("password-reset/done/", views.password_reset_done_view, name="password_reset_done"),
    path("password-reset-confirm/<uidb64>/<token>/", views.password_reset_confirm_view, name="password_reset_confirm"),
    path("password-reset/complete/", views.password_reset_complete_view, name="password_reset_complete"),
    # API endpoints
    path("api/check-email/", views.api_check_email, name="api_check_email"),
]
