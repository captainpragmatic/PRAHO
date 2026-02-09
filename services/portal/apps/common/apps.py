"""
Common app configuration for PRAHO Portal Service
"""

from django.apps import AppConfig


class CommonConfig(AppConfig):
    """Configuration for portal common utilities"""
    
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'apps.common'
    verbose_name = 'Portal Common'
