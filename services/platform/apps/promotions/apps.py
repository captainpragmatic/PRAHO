"""
Promotions app configuration for PRAHO Platform.
"""

from django.apps import AppConfig


class PromotionsConfig(AppConfig):
    """Configuration for the Promotions app."""

    default_auto_field = "django.db.models.BigAutoField"
    name = "apps.promotions"
    verbose_name = "Promotions & Coupons"

    def ready(self) -> None:
        """Import signals when app is ready."""
        # Import signals to register them
        from . import signals  # noqa: F401
