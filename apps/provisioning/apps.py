"""
Django app configuration for Provisioning app
"""

from django.apps import AppConfig


class ProvisioningConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'apps.provisioning'
    verbose_name = 'Service Provisioning'
