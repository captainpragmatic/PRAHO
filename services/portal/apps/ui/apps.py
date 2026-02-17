"""
UI app configuration for PRAHO Portal Service
"""

from django.apps import AppConfig


class UiConfig(AppConfig):
    """Configuration for portal UI components"""

    default_auto_field = "django.db.models.BigAutoField"
    name = "apps.ui"
    verbose_name = "Portal UI"
