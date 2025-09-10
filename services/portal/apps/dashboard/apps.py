"""
Dashboard app configuration for PRAHO Portal Service
"""

from django.apps import AppConfig


class DashboardConfig(AppConfig):
    """Configuration for portal dashboard app"""
    
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'apps.dashboard'
    verbose_name = 'Portal Dashboard'
