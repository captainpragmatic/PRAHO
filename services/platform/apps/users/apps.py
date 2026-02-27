"""
Django app configuration for Users app
"""

from django.apps import AppConfig


class UsersConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "apps.users"
    verbose_name = "Users"

    def ready(self) -> None:
        """Import signals and MFA models when the app is ready."""
        from . import mfa, signals  # noqa: F401 — register WebAuthnCredential model + connect signals
