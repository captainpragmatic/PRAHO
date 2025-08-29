"""
Django app configuration for Tickets app
"""

from django.apps import AppConfig


class TicketsConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'apps.tickets'
    verbose_name = 'Support Tickets'
    
    def ready(self) -> None:
        """Register signals when app is ready"""
        import apps.tickets.signals  # noqa: F401, PLC0415
