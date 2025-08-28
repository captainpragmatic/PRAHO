"""
Django app configuration for Orders app
"""

from django.apps import AppConfig


class OrdersConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'apps.orders'
    verbose_name = 'Orders'

    def ready(self) -> None:
        """Import signals when Django starts"""
        from . import (  # noqa: PLC0415 - Django app ready() pattern
            signals,  # noqa: F401
            signals_extended,  # noqa: F401
        )
