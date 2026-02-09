"""
Django app configuration for Infrastructure app
"""

from django.apps import AppConfig


class InfrastructureConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "apps.infrastructure"
    verbose_name = "Infrastructure Management"

    def ready(self):
        """Connect signals when app is ready"""
        # Import signals to register them
        from . import signals  # noqa: F401
