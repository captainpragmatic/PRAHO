"""
Orders App Configuration for PRAHO Portal
Handles product catalog, cart sessions, and order creation.
"""

from django.apps import AppConfig


class OrdersConfig(AppConfig):
    """Configuration for the orders application"""

    default_auto_field = "django.db.models.BigAutoField"
    name = "apps.orders"
    verbose_name = "Orders"

    def ready(self) -> None:
        """Initialize app-specific configurations"""
        # Import any signal handlers or initialization code
