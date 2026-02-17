"""
API Client app configuration for PRAHO Portal Service
"""

from django.apps import AppConfig


class ApiClientConfig(AppConfig):
    """Configuration for platform API client"""

    default_auto_field = "django.db.models.BigAutoField"
    name = "apps.api_client"
    verbose_name = "Platform API Client"
