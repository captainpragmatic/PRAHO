"""
Django app configuration for Provisioning app
"""

from django.apps import AppConfig


class ProvisioningConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "apps.provisioning"
    verbose_name = "Service Provisioning"

    def ready(self) -> None:
        """Import signals when the app is ready"""
        from . import signals  # Import general provisioning signals
        from . import virtualmin_signals  # Import Virtualmin-specific signals
